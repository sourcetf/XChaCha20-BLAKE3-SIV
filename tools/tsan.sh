#!/usr/bin/env bash
#
# ThreadSanitizer over the concurrency test, with its own negative control.
#
# `-Zbuild-std` is not optional.  std ships *uninstrumented*, and mixing an
# instrumented crate with an uninstrumented std is an ABI mismatch that rustc
# refuses outright:
#
#   error: mixing `-Zsanitizer` will cause an ABI mismatch in crate `regex_syntax`
#   note: `-Zsanitizer=thread` in this crate is incompatible with `-Zsanitizer`
#         being unset in dependency `panic_unwind`
#
# Rebuilding std takes a couple of minutes and needs the *nightly* toolchain's
# rust-src component:
#
#   rustup component add rust-src --toolchain nightly
#
# Two runs, in this order, because a clean result from a sanitizer that is not
# actually in the binary looks identical to a clean result from one that is:
#
#   1. `deliberate_race_is_detected` (tests/threads.rs) must be *reported*;
#   2. `concurrent_use_agrees_across_threads` must then be clean.
#
# Usage: tools/tsan.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# A direct `tools/tsan.sh` has to find rustup/cargo itself; every sibling tool does
# this, and without it a stock rustup install (`~/.cargo/bin` not on PATH) died with
# "rustup is not on PATH" instead of running. Before the rustup checks below, because
# it is those checks that fail on a rustup-installed toolchain.
export PATH="$HOME/.cargo/bin:$PATH"

# The nightly toolchain and *its* rust-src are what `-Zbuild-std` runs under; a bare
# `rustup component list --installed` answers for the default toolchain and used to
# turn "rustup is not on PATH" into "rust-src is not installed" (and would pass on a
# machine whose default toolchain has rust-src while nightly does not).
#
# Exit 3, not 1: a missing toolchain is "could not run", which is the code the repository
# reserves for that (ctgrind.sh, cache_profile.sh, fi_check.sh, stack_residue.sh all answer
# 3 for the same reason) and which verify.sh maps to SKIPPED -- a caller that explicitly
# asked for `--tsan` still gets a failure, because an explicitly named stage that did not
# run is fatal there.
if ! command -v rustup >/dev/null 2>&1; then
  echo "tsan: rustup is not on PATH, so the nightly toolchain and rust-src cannot be" >&2
  echo "  checked; run this where rustup is available (exit 3: could not run)." >&2
  exit 3
fi
if ! cargo +nightly --version >/dev/null 2>&1; then
  # Single quotes: this message used to be a double-quoted string split across two
  # `echo`s, so the backticks around `rustup toolchain install nightly` were command
  # substitution -- measured with a stub `rustup` first on PATH: the message ran it with
  # the arguments `toolchain` and `install nightly` and printed the stub's output
  # instead of the instruction.
  echo 'tsan: the nightly toolchain is required for -Zbuild-std; run' >&2
  echo '  rustup toolchain install nightly   (exit 3: could not run).' >&2
  exit 3
fi
# `grep -q` exits at the first match, which used to close the pipe under `pipefail` and
# make `rustup` die with SIGPIPE (141) -- the same trap verify.sh's tool preflight
# documents. A here-string lets rustup finish writing.
if ! grep -q '^rust-src' <<< "$(rustup component list --installed --toolchain nightly 2>/dev/null)"; then
  echo "tsan: the nightly toolchain's rust-src component is required for -Zbuild-std; run:" >&2
  echo "  rustup component add rust-src --toolchain nightly (exit 3: could not run)." >&2
  exit 3
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

export RUSTFLAGS="-Zsanitizer=thread"
args=(-Zbuild-std --target x86_64-unknown-linux-gnu --release --features pure)

echo "=== 1/2 negative control: a deliberate race must be reported ==="
control_rc=0
cargo +nightly test --locked "${args[@]}" --test threads -- --ignored deliberate_race_is_detected \
  > "$out" 2>&1 || control_rc=$?
if grep -q "WARNING: ThreadSanitizer: data race" "$out"; then
  echo "OK: the control's race was reported (the sanitizer is in the binary)"
elif [ "$control_rc" -ne 0 ]; then
  echo "FAIL: the ThreadSanitizer control could not run (exit $control_rc), so this" >&2
  echo "stage proves nothing. This is not a race verdict. Full output:" >&2
  cat "$out" >&2
  exit 3
else
  echo "FAIL: ThreadSanitizer reported no race for a deliberate one." >&2
  echo "That is the vacuous case: this script cannot say anything about the real" >&2
  echo "run until the control is detected. Full output:" >&2
  cat "$out" >&2
  exit 1
fi

echo "=== 2/2 the crate's own concurrent test must be clean ==="
# Capture the status instead of letting `set -e` act on it: TSan exits 66 when it reports a
# race, so a bare command aborted the script *before* the `grep` below and the
# "reported a race" diagnosis was dead code (measured with a fake cargo that emits a
# warning and exits 66: the tool exited 66 with no message).
run_rc=0
cargo +nightly test --locked "${args[@]}" --test threads > "$out" 2>&1 || run_rc=$?
if grep -q "WARNING: ThreadSanitizer" "$out"; then
  echo "FAIL: ThreadSanitizer reported a race in this crate:" >&2
  grep -A20 "WARNING: ThreadSanitizer" "$out" >&2
  exit 1
fi
if [ "$run_rc" -ne 0 ]; then
  echo "FAIL: the concurrent test exited $run_rc under ThreadSanitizer without a race" >&2
  echo "report, so this is a build/run failure rather than a clean run. Full output:" >&2
  tail -20 "$out" >&2
  exit 1
fi
grep -E "^test result" "$out"
# A `threads` target whose concurrent test was renamed or cfg'd out would print
# "0 passed" and look clean; the named test's own line is what says it ran.
if ! grep -q "^test concurrent_use_agrees_across_threads ... ok" "$out"; then
  echo "FAIL: the concurrent test did not run, so step 2 proves nothing about it:" >&2
  tail -20 "$out" >&2
  exit 1
fi
echo "OK: no data race reported, and the control shows the run could have said so"
