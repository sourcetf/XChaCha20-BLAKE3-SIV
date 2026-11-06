#!/usr/bin/env bash
# Refuse a `cargo test` run in which a test binary executed nothing.
#
# Usage: test_vacuity_guard.sh <log-file> [<test-args>]
#
#   <log-file>   a captured `cargo test` log, with ANSI escapes and CRs already stripped
#                (every caller does that, because cargo colours `Running` and an
#                ANSI-wrapped header does not match the anchored patterns below)
#   <test-args>  the feature/arg string the run used (e.g. "--all-features"), used only to
#                decide the feature-gated exemptions below
#
# One definition for the Linux `test` matrix, the `windows` leg and the `msrv` leg: the
# guard used to be copy-pasted, and a copy that took `test result:`'s *last* line (always
# doc-tests) silently checked nothing. Exit 0 when the run is sound, 1 when a binary ran
# nothing (or the log cannot be parsed), so a caller can fail its step on the status.
set -euo pipefail

log="${1:?usage: test_vacuity_guard.sh <log-file> [<test-args>]}"
test_args="${2:-}"

if [ ! -f "$log" ]; then
  echo "::error::test-vacuity guard: the log $log does not exist, so nothing was checked" >&2
  exit 1
fi

# A target whose summary reported zero passed executed nothing, even if it reported
# ignored tests: marking the whole target `#[ignore]` is the same vacuous result as
# emptying it. The exemptions are the targets legitimately zero-passed in a configuration.
zero_scan() {
  awk '
    /^[[:space:]]*Running / {
      target = ""
      for (k = 1; k <= NF; k++) if ($k ~ /\.rs$/) { target = $k; break }
      next
    }
    /^[[:space:]]*Doc-tests / { target = "doc-tests"; next }
    /^test result:/ {
      p = $4 + 0; f = $6 + 0; i = $8 + 0; x = $12 + 0
      if (p == 0) {
        if (target == "") target = "<unattributed>"
        printf "%s\t%d\t%d\t%d\n", target, p, i, x
        n++
      }
    }
    END { exit (n > 0) ? 0 : 1 }
  ' "$1"
}

zero_targets="$(mktemp)"
trap 'rm -f "$zero_targets"' EXIT
zero_scan "$log" > "$zero_targets" || true

bad=0
if [ -s "$zero_targets" ]; then
  while IFS=$'\t' read -r target _p i x; do
    # Normalise a Windows target path (`tests\timing.rs`) to the slash form the cases use.
    target="${target//\\//}"
    case "$target" in
      # The rustdoc harness: in configurations that compile out the one example that
      # runs it legitimately has nothing to run, and a doctest cannot be "silently
      # emptied" the way a test file can -- it *is* the source text.
      doc-tests)
        echo "note: the doctest harness reported no runnable examples in this configuration" ;;
      # Excluded by `--skip timing`, which libtest reports as `0 tests` rather than as
      # `filtered`. It has its own blocking presence check and its own advisory run.
      tests/timing.rs)
        echo "note: tests/timing.rs is skipped by --skip timing and runs in the timing jobs" ;;
      # All `#[ignore]`d outside the static valgrind build. Require the five ignored
      # tests to still be present: deleting them would also produce a zero-passed
      # summary, which is the vacuous case this guard exists for.
      tests/ctgrind.rs)
        if [ "${i:-0}" -lt 5 ]; then
          echo "::error::tests/ctgrind.rs reported 0 passed but only $i ignored tests; the valgrind tests were removed or filtered out"
          bad=1
        else
          echo "note: tests/ctgrind.rs is valgrind-only; $i ignored tests are still present"
        fi ;;
      # Whole-file `#![cfg(feature)]` gates: empty only in a leg that does not enable the
      # feature; in the leg that turns it on -- including through `ultra`, which implies
      # `locked` -- zero passed is the regression this guard catches, and `ignored` does
      # not excuse it.
      tests/locked.rs)
        case "$test_args" in
          *locked*|*ultra*|*all-features*)
            echo "::error::tests/locked.rs reported 0 passed (ignored $i, filtered $x) in a leg that enables locked ($test_args)"
            bad=1 ;;
          *) echo "note: tests/locked.rs is empty because this leg does not enable locked" ;;
        esac ;;
      tests/ultra.rs)
        case "$test_args" in
          *ultra*|*all-features*)
            echo "::error::tests/ultra.rs reported 0 passed (ignored $i, filtered $x) in a leg that enables ultra ($test_args)"
            bad=1 ;;
          *) echo "note: tests/ultra.rs is empty because this leg does not enable ultra" ;;
        esac ;;
      "<unattributed>")
        echo "::error::a summary line could not be attributed to a test target -- the log format changed, so this guard proved nothing"
        bad=1 ;;
      *)
        echo "::error::$target reported 0 passed (ignored $i, filtered $x): every test was removed, gated out, or marked #[ignore]"
        bad=1 ;;
    esac
  done < "$zero_targets"
fi

# Every binary cargo ran must also have reported: a target that produced no summary line
# at all was compiled and never executed. `Running` appears for every binary, so a count
# mismatch is the witness.
ran="$(grep -cE '^[[:space:]]+Running (unittests|tests/)' "$log" || true)"
reported="$(grep -cE '^test result:' "$log" || true)"
if [ "${reported:-0}" -lt "${ran:-0}" ]; then
  echo "::error::cargo ran ${ran} test binaries but only ${reported} reported a result"
  bad=1
fi

# Positive control, in the same script: the guard must reject a summary that reports zero
# passed, including the all-ignored shape. Without it, a pattern that stops matching is
# indistinguishable from a suite that is clean.
vacuous="$(mktemp)"
printf '     Running tests/vacuous.rs (target/debug/deps/vacuous)\ntest result: ok. 0 passed; 0 failed; 7 ignored; 0 measured; 0 filtered out\n' > "$vacuous"
control="$(zero_scan "$vacuous" || true)"
rm -f "$vacuous"
case "$control" in
  *"tests/vacuous.rs"*)
    : ;;
  *)
    echo "::error::the zero-test parser did not detect a vacuous summary -- it cannot fail, so it proves nothing (output: $control)"
    bad=1 ;;
esac

if [ "$bad" -ne 0 ]; then
  exit 1
fi
echo "cargo test: ${ran} test binaries ran and reported (${reported} result lines, doc-tests included)"
