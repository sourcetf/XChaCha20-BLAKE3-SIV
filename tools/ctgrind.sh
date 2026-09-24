#!/usr/bin/env bash
#
# ctgrind-style constant-time verification, using valgrind's memcheck.
#
# Marks secret bytes as *undefined* and lets memcheck report any branch or index
# that depends on them. This is the mechanical answer to "does this code branch
# on secret data?", and it does not depend on a reader spotting every path.
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
echo
echo "--- negative control (must be detected) ---"
set +e
"$VG" --error-exitcode=99 --suppressions="$SUPP" --quiet \
  "$BIN" --ignored --test-threads=1 deliberate_leak >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 99 ]; then
  echo "FAIL: the deliberate leak was NOT detected (exit $rc)." >&2
  echo "      The poisoning is not taking effect, so the check below would be" >&2
  echo "      vacuous. Do not trust a clean run until this reports 99." >&2
  exit 1
fi
echo "ok: deliberate leak detected"

# ── 2. The real tests must be clean ────────────────────────────────────
echo
echo "--- constant-time check ---"
set +e
"$VG" --error-exitcode=99 --suppressions="$SUPP" --quiet \
  "$BIN" --test-threads=1 \
  encrypt_does_not_branch_on_secrets \
  decrypt_does_not_branch_on_secrets \
  encrypt_in_place_does_not_branch_on_secrets \
  constant_time_eq_does_not_branch_on_operands
rc=$?
set -e

echo
if [ "$rc" -eq 0 ]; then
  echo "PASS: no secret-dependent branch or index outside the two documented"
  echo "      SIV accept/reject decisions (see tests/ctgrind.supp)."
elif [ "$rc" -eq 99 ]; then
  echo "FAIL: memcheck reported an unsuppressed secret-dependent branch." >&2
  echo "      Re-run without --quiet to see it; do NOT add a suppression" >&2
  echo "      before understanding what it is." >&2
else
  echo "FAIL: valgrind exited $rc" >&2
fi
exit "$rc"