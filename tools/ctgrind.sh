#!/usr/bin/env bash
#
# ctgrind-style constant-time verification, using valgrind's memcheck.
#
# Marks secret bytes as *undefined* and lets memcheck report any branch or index
# that depends on them. This is the mechanical answer to "does this code branch
# on secret data?", and it does not depend on a reader spotting every path.
#
# Reports are classified by whose code they are in: one that touches a
# `xchacha20_blake3_siv` frame fails the run, and everything else is counted and
# ignored as startup/teardown noise from libtest, std and glibc. Suppressing those
# by frame was the earlier approach and it was not durable -- the frames belong to
# three projects that version independently, and every mismatch read as a finding
# in this crate.
#
# It is a separate script because it needs three things verify.sh should not
# assume: valgrind, a statically linked test binary, and a suppression file.
#
# Usage:  tools/ctgrind.sh          # run the check (exit 0 = clean)
#         tools/ctgrind.sh --setup  # print how to obtain valgrind here
#
# Exit codes: 0 clean; 1 clean but the harness failed its own sanity checks;
#             99 a leak was detected.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if [ "${1:-}" = "--setup" ]; then
  cat <<'EOF'
valgrind is not installable here without root (sudo needs a password), but it
runs fine from an extracted package. libc6-dbg supplies the debug symbols that
valgrind needs to redirect `strcmp` in the dynamic linker — which is why the
test binary below is built *statically* instead: a static binary has no dynamic
linker to redirect, so the debuginfo is not needed.

    apt-get download valgrind libc6-dbg
    dpkg-deb -x valgrind_*.deb   ~/valgrind
    dpkg-deb -x libc6-dbg_*.deb  ~/valgrind     # harmless, unused for static

Then this script finds valgrind at ~/valgrind/usr/bin/valgrind (or $VALGRIND,
or on $PATH).
EOF
  exit 0
fi

# ── Locate valgrind ────────────────────────────────────────────────────
VG=""
for c in "${VALGRIND:-}" "$HOME/valgrind/usr/bin/valgrind" \
         "$(command -v valgrind 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then VG="$c"; break; fi
done
if [ -z "$VG" ]; then
  echo "SKIPPED: valgrind not found.  Run 'tools/ctgrind.sh --setup'." >&2
  exit 0
fi
# An extracted valgrind needs its own library directory, and it must be set
# *before* valgrind is invoked — otherwise even `--version` fails to start.
if [ -d "$HOME/valgrind/usr/libexec/valgrind" ]; then
  export VALGRIND_LIB="$HOME/valgrind/usr/libexec/valgrind"
fi
echo "using valgrind: $VG ($("$VG" --version 2>&1 | head -1))"

TARGET=x86_64-unknown-linux-gnu
SUPP=tests/ctgrind.supp
[ -f "$SUPP" ] || { echo "missing $SUPP" >&2; exit 1; }

# ── Build a static test binary ─────────────────────────────────────────
# `+crt-static` removes the dynamic linker, which removes the `strcmp`
# redirection valgrind cannot set up without root-installed libc debuginfo.
#
# `strip=none` overrides the release profile's `strip = true`. Without symbols
# valgrind prints `???` for every frame, and every suppression here matches on
# function names, so the file silently stops suppressing anything.
echo "building a static test binary..."
RUSTFLAGS="-C target-feature=+crt-static -C strip=none" \
  cargo test --release --target "$TARGET" --test ctgrind --no-run >/dev/null

BIN=$(ls -t "target/$TARGET/release/deps/"ctgrind-* 2>/dev/null \
      | grep -vE '\.(d|o)$' | head -1)
[ -n "$BIN" ] || { echo "could not find the ctgrind test binary" >&2; exit 1; }
echo "binary: $BIN"

# ── 1. The negative control must be detected ───────────────────────────
# Without this, the clean result below would be worthless: poisoning that never
# took effect also reports nothing. This test branches on a poisoned byte on
# purpose, so valgrind must report an error *through the suppressions*.
#
# The exit code alone is not enough, and that is not a hypothetical: before the
# control was fixed it produced no report at all (LLVM had turned the branch into
# a branchless `setcc`, which memcheck does not report), and this check was then
# satisfied by unrelated libtest startup noise -- exit 99 either way. So the
# report is required to *name the control* as well.
echo
echo "--- negative control (must be detected) ---"
set +e
ctrl_out="$("$VG" --error-exitcode=99 --suppressions="$SUPP" \
  "$BIN" --ignored --test-threads=1 deliberate_leak 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 99 ]; then
  echo "FAIL: the deliberate leak was NOT detected (exit $rc)." >&2
  echo "      The poisoning is not taking effect, so the check below would be" >&2
  echo "      vacuous. Do not trust a clean run until this reports 99." >&2
  exit 1
fi
if ! printf '%s\n' "$ctrl_out" | grep -q 'deliberate_leak_is_detected'; then
  echo "FAIL: valgrind exited 99 but no report names the control test." >&2
  echo "      That means the 99 came from startup noise, not from the poisoned" >&2
  echo "      branch, so nothing here has been shown to detect a leak." >&2
  exit 1
fi
n_leaks=$(printf '%s\n' "$ctrl_out" | grep -c "depends on uninitialised")
echo "ok: deliberate leak detected ($n_leaks report(s), naming the control)"

# ── 2. The real tests must be clean ────────────────────────────────────
#
# `--quiet` still prints error reports; only the banner and the summary are
# dropped. Everything memcheck reports is then classified by *whose* code it is
# in, rather than by the exact frames, because the latter are internal to
# libtest, Rust's std and glibc and change with every release of any of them --
# see tests/ctgrind.supp for the history of that.
echo
echo "--- constant-time check ---"
set +e
out="$("$VG" --error-exitcode=99 --suppressions="$SUPP" --quiet \
  "$BIN" --test-threads=1 \
  encrypt_does_not_branch_on_secrets \
  decrypt_does_not_branch_on_secrets \
  encrypt_in_place_does_not_branch_on_secrets \
  constant_time_eq_does_not_branch_on_operands 2>&1)"
rc=$?
set -e

# Count reports, and how many of them touch this crate.
counts="$(printf '%s\n' "$out" | awk -v m="xchacha20_blake3_siv" '
  /^==[0-9]+== .*(Conditional jump|Use of uninitialised|Invalid read|Invalid write|Syscall param|Mismatched)/ {
    if (seen) { total++; if (hit) bad++ } ; seen=1; hit=0
  }
  /^==[0-9]+==/ { if (index($0, m)) hit=1 }
  END { if (seen) { total++; if (hit) bad++ } ; print (total+0) " " (bad+0) }')"
read -r total in_crate <<EOF
$counts
EOF

if [ "$in_crate" -gt 0 ]; then
  echo "FAIL: memcheck reported $in_crate report(s) inside this crate:" >&2
  printf '%s\n' "$out" | grep -B2 -A12 'xchacha20_blake3_siv' | head -60 >&2
  echo "      Re-run without --quiet to see all of them; do NOT add a" >&2
  echo "      suppression before understanding what it is." >&2
  exit 99
fi

noise=$((total - in_crate))
echo
if [ "$rc" -ne 0 ] && [ "$rc" -ne 99 ]; then
  echo "FAIL: valgrind exited $rc" >&2
  exit "$rc"
fi
echo "PASS: nothing in this crate branches on secret data, beyond the two"
echo "      documented SIV accept/reject decisions (see tests/ctgrind.supp)."
if [ "$noise" -gt 0 ]; then
  echo "      ($noise report(s) outside this crate ignored: libtest, std and"
  echo "       glibc startup/teardown, whose frames differ per version. A report"
  echo "       that touched a xchacha20_blake3_siv frame would have failed here.)"
fi
exit 0