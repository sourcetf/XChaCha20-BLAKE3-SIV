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
# tests/ctgrind.supp is still used, but only to permit the crate's one
# unavoidable secret-dependent branch: the SIV accept/reject decision, which now
# lives in a function of its own so that the entry naming it cannot cover any
# other branch. Two checks keep that from being an assertion:
#
#   * this script refuses to run unless every entry in that file names
#     `accept_or_reject`;
#   * `--selftest` (on by default) plants a secret-dependent branch inside
#     `decrypt` and inside `decrypt_in_place_detached` in a throwaway copy and
#     requires the run there to *fail*. Before it existed, an entry naming both
#     entry points was quietly permitting every branch in them.
#
# It is a separate script because it needs three things verify.sh should not
# assume: valgrind, a statically linked test binary, and a suppression file.
#
# Usage:  tools/ctgrind.sh                      # run the check (exit 0 = clean)
#         tools/ctgrind.sh --no-default-features  # ...against the opt-out feature set
#         tools/ctgrind.sh --no-selftest        # skip the planted-leak control
#
# Extra arguments other than the two flags are passed to `cargo test`, so the
# constant-time check can be run against any feature combination. `hardened` is on
# by default and adds a second, recomputed tag comparison to each decrypt -- the kind
# of addition that could introduce a content-dependent branch -- so the combination
# worth running separately is the *opt-out* one (`--no-default-features`).
#         tools/ctgrind.sh --setup  # print how to obtain valgrind here
#
# Exit codes: 0 clean; 1 clean but the harness failed its own sanity checks;
#             3 could not run (no valgrind -- the caller must report that as a
#             skipped stage, not as a pass); 99 a leak was detected.
set -euo pipefail

SELFTEST=1
CARGO_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --selftest) SELFTEST=1 ;;
    --no-selftest) SELFTEST=0 ;;
    *) CARGO_ARGS+=("$arg") ;;
  esac
done

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
#
# An explicit `VALGRIND=...` is honoured *strictly*: if it is set, that is the only
# candidate, and an unusable value is "could not run" rather than a cue to fall through
# to some other valgrind on PATH. The fall-through was a real defect in the reverse
# direction too -- `tools/gate_selftest.sh` hides valgrind by exporting
# `VALGRIND=/nonexistent`, and on a machine with a system valgrind the old loop would
# have quietly used that one instead, so the control would have reported a tool failure
# that was really a hole in the control.
VG=""
if [ -n "${VALGRIND:-}" ]; then
  [ -x "$VALGRIND" ] && VG="$VALGRIND"
else
  for c in "$HOME/valgrind/usr/bin/valgrind" \
           "$(command -v valgrind 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then VG="$c"; break; fi
  done
fi
if [ -z "$VG" ]; then
  if [ -n "${VALGRIND:-}" ]; then
    echo "SKIPPED: VALGRIND=$VALGRIND is not an executable file." >&2
  else
    echo "SKIPPED: valgrind not found.  Run 'tools/ctgrind.sh --setup'." >&2
  fi
  # Exit 3, not 0: "could not run" has to be distinguishable from "ran and passed",
  # or a caller that only looks at the status counts this as a green check (which is
  # exactly what `verify.sh` did before it learned to map 3 to a skipped stage).
  exit 3
fi
# An extracted valgrind needs its own library directory, and it must be set
# *before* valgrind is invoked — otherwise even `--version` fails to start.
if [ -d "$HOME/valgrind/usr/libexec/valgrind" ]; then
  export VALGRIND_LIB="${VALGRIND_LIB:-$HOME/valgrind/usr/libexec/valgrind}"
fi
# valgrind has to actually start. A binary that exists but cannot (an extracted copy
# whose library dir is elsewhere) used to pass this line -- the command substitution
# inside `echo` swallowed the failure -- and then surface as "the deliberate leak was
# not detected", which reads as a finding about this crate rather than about the tool.
set +e
VG_VERSION="$("$VG" --version 2>&1)"
vg_rc=$?
set -e
if [ "$vg_rc" -ne 0 ] || [ -z "$VG_VERSION" ]; then
  echo "SKIPPED: valgrind at $VG cannot start (missing VALGRIND_LIB? see 'tools/ctgrind.sh --setup')" >&2
  exit 3
fi
echo "using valgrind: $VG ($VG_VERSION)"

TARGET=x86_64-unknown-linux-gnu
SUPP="$(pwd)/tests/ctgrind.supp"
[ -f "$SUPP" ] || { echo "missing tests/ctgrind.supp" >&2; exit 1; }

# `cargo test --no-run` honours CARGO_TARGET_DIR; find the binary where it actually
# wrote. Hard-coding `target/...` found a stale `ctgrind-*` (or none, and aborted exit 1,
# which verify.sh reads as a hard failure rather than the exit-3 "could not run").
# Resolved to an absolute path so it names the same directory inside the self-test copy,
# the way `tools/fi_instruction.sh` does it.
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  case "$CARGO_TARGET_DIR" in
    /*) TARGET_DIR="$CARGO_TARGET_DIR" ;;
    *)  TARGET_DIR="$(pwd)/$CARGO_TARGET_DIR" ;;
  esac
else
  TARGET_DIR="$(pwd)/target"
fi
DEPS_DIR="$TARGET_DIR/$TARGET/release/deps"

# ── The suppression file may only name the decision ────────────────────
# An entry permits every conditional jump in the function it names, so an entry
# naming an entry point reads as "the decision is permitted" while permitting any
# branch in a 60-line function. That is not hypothetical: it is how a planted
# leak inside `decrypt` passed this check. Only `accept_or_reject` may appear.
SUPP_FUNS="$(grep -v '^[[:space:]]*#' "$SUPP" | grep -o 'fun:.*' | sed 's/^fun://' || true)"
SUPP_COUNT="$(printf '%s\n' "$SUPP_FUNS" | grep -c . || true)"
SUPP_BAD="$(printf '%s\n' "$SUPP_FUNS" | grep -v 'accept_or_reject' | grep . || true)"
# ...and *every* non-comment line has to be a block marker, a Memcheck kind, or a
# frame naming accept_or_reject. This used to look only at `fun:` lines, so an
# `obj:` or `src:` entry -- which suppresses a whole object or source file just as
# effectively -- was invisible to it, while the header still claimed the file was
# refused unless every entry named the decision. (A block's *name* line -- the bare
# identifier between `{` and the first `Tool:kind` line, `siv-accept-or-reject-decision`
# here -- is allowed too; the first version of this check rejected the real file for it.) The name has to *end* with
# accept_or_reject (a Rust mangled name ends in its length-prefixed identifier), so
# `fun:not_accept_or_reject_but_wide` is rejected too. (`*` is allowed in the
# prefix: the mangled symbol carries a compiler-hash wildcard, `_RNvCs*_20…`, and
# the first version of this check rejected the real file for it.)
SUPP_OTHER="$(grep -v '^[[:space:]]*#' "$SUPP" | grep -v '^[[:space:]]*$' \
  | grep -vE '^[[:space:]]*(\{|\}|Memcheck:[A-Za-z0-9_:.-]+|[A-Za-z0-9_.-]+)[[:space:]]*$' \
  | grep -vE '^[[:space:]]*fun:(accept_or_reject|[A-Za-z0-9_$.*?]*16accept_or_reject)[[:space:]]*$' || true)"
if [ "$SUPP_COUNT" -lt 1 ] || [ -n "$SUPP_BAD" ] || [ -n "$SUPP_OTHER" ]; then
  echo "FAIL: tests/ctgrind.supp must suppress accept_or_reject and nothing else." >&2
  echo "      A frame naming anything else permits every branch in that function" >&2
  echo "      (how a planted leak inside decrypt once passed), and obj:/src: entries" >&2
  echo "      widen it just as effectively. Every frame line must be a fun: naming it." >&2
  if [ -n "$SUPP_OTHER" ]; then
    printf '%s\n' "$SUPP_OTHER" | sed 's/^/      rejected line: /' >&2
  fi
  printf '%s\n' "$SUPP_FUNS" | sed 's/^/      names: /' >&2
  exit 1
fi
echo "suppressions: $SUPP_COUNT entry/entries, all naming accept_or_reject"

# ── Build a static test binary ─────────────────────────────────────────
# `+crt-static` removes the dynamic linker, which removes the `strcmp`
# redirection valgrind cannot set up without root-installed libc debuginfo.
#
# `strip=none` overrides the release profile's `strip = true`. Without symbols
# valgrind prints `???` for every frame, and every suppression here matches on
# function names, so the file silently stops suppressing anything.
#
# The executable is taken from cargo's own JSON stream rather than from a glob over
# the deps directory. Two reasons, both measured:
#
#   * the self-test used to build a *planted* copy into this same directory, and since
#     the crate's identity (name, version, features, profile) decides `-C metadata`,
#     the planted binary carries the same file name as the clean one. A glob plus
#     `ls -t` then runs whichever was written last -- after one run, the planted one --
#     so a second `tools/ctgrind.sh` in the same tree failed in 0.8 s with 8 reports
#     inside `decrypt_in_place_detached`, on source that had not changed;
#   * a glob also picks up binaries from other configurations, which share the prefix.
cargo_ctgrind_executable() {  # reads cargo's `--message-format=json` stream on stdin
  python3 -c '
import json, sys
exes = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable"):
        continue
    if (m.get("target") or {}).get("name") == "ctgrind":
        exes.append(m["executable"])
print(exes[-1] if exes else "")
'
}

echo "building a static test binary..."
# Remove any previous ctgrind test binary first: a tree that already ran an earlier
# version of the self-test has a *planted* one sitting here under this name, and with
# the source unchanged cargo would call the target Fresh and hand that file back.
# Deleting it costs one relink (measured ~5 s) and heals such a tree.
rm -f "$DEPS_DIR"/ctgrind-*
BIN="$(RUSTFLAGS="-C target-feature=+crt-static -C strip=none" \
  cargo test --release --target "$TARGET" --test ctgrind --no-run --message-format=json \
    "${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}" 2>/dev/null | cargo_ctgrind_executable)"
[ -n "$BIN" ] || {
  echo "could not find the ctgrind test binary: cargo reported no executable for it" >&2
  exit 1
}
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
# `--nocapture` so the control's own verdict is visible: it checks with
# GET_VBITS that the poisoning took effect and with COUNT_ERRORS that memcheck
# recorded an error for the leak, and prints a marker once both hold.
ctrl_out="$("$VG" --error-exitcode=99 --suppressions="$SUPP" \
  "$BIN" --ignored --test-threads=1 --nocapture deliberate_leak 2>&1)"
rc=$?
set -e
# `case` rather than `printf ... | grep -q`, deliberately: this script runs with
# `set -o pipefail`, and `grep -q` exits as soon as it matches, which kills the
# writer with SIGPIPE and makes the *pipeline* fail even though the match was
# found. It only shows up when the captured output is large -- it passed locally
# and failed on a CI runner whose output is bigger.
ctrl_ok=0
case "$ctrl_out" in
  *CONTROL_LEAK_OBSERVED*) ctrl_ok=1 ;;
esac
if [ "$rc" -ne 99 ] || [ "$ctrl_ok" -ne 1 ]; then
  echo "FAIL: the deliberate leak was not detected (exit $rc)." >&2
  echo "      The control verifies itself, so this means either the poisoning" >&2
  echo "      is not reaching valgrind or the leak was optimized away -- and a" >&2
  echo "      clean result below would be meaningless. Output was:" >&2
  printf '%s\n' "$ctrl_out" | sed 's/^/      | /' >&2
  exit 1
fi
echo "ok: $(printf '%s\n' "$ctrl_out" | grep -o 'CONTROL_LEAK_OBSERVED.*')"


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

# Count reports on stdin, and how many of them touch this crate: prints
# "<total> <in_crate>". A report is "in this crate" when any frame in its stack
# names `xchacha20_blake3_siv` -- the frame names come from DWARF, so that holds
# whether the branch is in a library function, inlined into a test body, or in a
# function that did not exist when this script was written.
classify_reports() {
  awk -v m="xchacha20_blake3_siv" '
    /^==[0-9]+== .*(Conditional jump|Use of uninitialised|Invalid read|Invalid write|Syscall param|Mismatched)/ {
      if (seen) { total++; if (hit) bad++ } ; seen=1; hit=0
    }
    /^==[0-9]+==/ { if (index($0, m)) hit=1 }
    END { if (seen) { total++; if (hit) bad++ } ; print (total+0) " " (bad+0) }'
}

counts="$(printf '%s\n' "$out" | classify_reports)"
read -r total in_crate <<EOF
$counts
EOF

if [ "$in_crate" -gt 0 ]; then
  echo "FAIL: memcheck reported $in_crate report(s) inside this crate:" >&2
  printf '%s\n' "$out" | grep -B2 -A12 'xchacha20_blake3_siv' | awk 'NR<=60' >&2
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
# The four filters above must have matched four tests. A filter that matches
# nothing makes libtest print "0 passed" and exit 0, and valgrind then has nothing
# to report either -- so the count is the only thing that says the check ran at
# all. (Measured: renaming one test in tests/ctgrind.rs turned this whole stage
# into a silent no-op.)
if ! printf '%s\n' "$out" | grep -qE '^test result: ok\. 4 passed'; then
  echo "FAIL: the four named constant-time tests did not all run -- a renamed or" >&2
  echo "      moved test makes this check pass while testing nothing. Output was:" >&2
  printf '%s\n' "$out" | tail -25 >&2
  exit 1
fi
echo "PASS: nothing in this crate branches on secret data, beyond the one"
echo "      documented SIV accept/reject decision (see tests/ctgrind.supp)."
if [ "$noise" -gt 0 ]; then
  echo "      ($noise report(s) outside this crate ignored: libtest, std and"
  echo "       glibc startup/teardown, whose frames differ per version. A report"
  echo "       that touched a xchacha20_blake3_siv frame would have failed here.)"
fi

# ── 3. The suppression must not cover a branch outside the decision ────
#
# The entry in tests/ctgrind.supp names one function, and this is what proves the
# claim rather than asserting it: a secret-dependent branch planted *inside*
# `decrypt` must make the check above fail. That is the shape an earlier revision
# permitted -- its entries named `decrypt` and `decrypt_in_place_detached`
# themselves -- and the leak planted here is the one that passed then: a
# data-dependent trip count, which cannot be compiled into the branchless
# `setcc`/`cmov` forms memcheck ignores (see the measurements in tests/ctgrind.rs
# and `secret_dependent_branch` there).
#
# The plant is a throwaway copy: the tree under test is never modified, and the
# copy is removed on exit. Without this stage a clean result would mean "no branch
# in this crate is reported that is not covered by an entry", which is not the
# same claim as "nothing outside the decision branches on secrets".
if [ "$SELFTEST" -eq 1 ]; then
  echo
  echo "--- self-test: a branch inside decrypt must be caught ---"
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  mkdir -p "$WORK/tree"
  cp -r src tests tools Cargo.toml Cargo.lock benches "$WORK/tree/" 2>/dev/null \
    || cp -r src tests tools Cargo.toml Cargo.lock "$WORK/tree/"

  if ! python3 - "$WORK/tree" <<'PLANT'
import sys

p = sys.argv[1] + "/src/lib.rs"
s = open(p).read()
# Both decrypt entry points carry this line, so one patch covers both.
old = "    let auth_ok = computed_tag.ct_eq(tag);\n"
plant = old + """
    {
        // Planted by tools/ctgrind.sh --selftest. `key` is poisoned by the tests
        // below, so the loop's back-edge is a conditional jump on secret-derived
        // data -- and a trip count is not something the optimizer can turn into
        // a `setcc` or a `cmov`.
        let n = (key[0] & 3) as usize;
        let mut i = 0usize;
        while i < n {
            core::hint::black_box(i);
            i += 1;
        }
    }
"""
if s.count(old) != 2:
    sys.exit("the anchor accounts for %d of 2 decrypt entry points" % s.count(old))
open(p, "w").write(s.replace(old, plant))
PLANT
  then
    echo "FAIL: the leak could not be planted (the anchor moved), so this" >&2
    echo "      self-test would be vacuous -- fix it before trusting a run." >&2
    exit 1
  fi

  ( cd "$WORK/tree"
    # Its OWN target directory. Building into the main one -- which this did, on the
    # theory that the planted binary then sits where the script looks for it -- wrote
    # the leaky binary over the clean one (same crate, same metadata hash, same file
    # name) and the next run, whose build cargo called Fresh, ran it. The planted
    # binary is located by asking cargo now, so sharing a directory is not needed.
    export CARGO_TARGET_DIR="$WORK/tree/target"
    RUSTFLAGS="-C target-feature=+crt-static -C strip=none" \
      cargo test --release --target "$TARGET" --test ctgrind --no-run --message-format=json \
      "${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}" >"$WORK/planted-build.json" 2>/dev/null )
  planted_bin="$(cargo_ctgrind_executable < "$WORK/planted-build.json")"
  [ -n "$planted_bin" ] || { echo "FAIL: no planted test binary" >&2; exit 1; }

  set +e
  planted_out="$("$VG" --error-exitcode=99 --suppressions="$SUPP" --quiet \
    "$planted_bin" --test-threads=1 \
    decrypt_does_not_branch_on_secrets 2>&1)"
  set -e

  counts="$(printf '%s\n' "$planted_out" | classify_reports)"
  read -r _planted_total planted_in_crate <<EOF
$counts
EOF

  if [ "$planted_in_crate" -le 0 ]; then
    echo "FAIL: a secret-dependent branch planted inside decrypt was NOT" >&2
    echo "      reported, so the suppression is covering more than the" >&2
    echo "      accept/reject decision and a clean run above means nothing." >&2
    printf '%s\n' "$planted_out" | grep -B2 -A12 'xchacha20_blake3_siv' | awk 'NR<=40' >&2
    exit 1
  fi
  echo "ok: the planted leak was reported ($planted_in_crate report(s) inside"
  echo "    this crate), so the suppression covers only the decision."
fi

exit 0