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

# The nightly toolchain and *its* rust-src are what `-Zbuild-std` runs under; a bare
# `rustup component list --installed` answers for the default toolchain and used to
# turn "rustup is not on PATH" into "rust-src is not installed" (and would pass on a
# machine whose default toolchain has rust-src while nightly does not).
if ! command -v rustup >/dev/null 2>&1; then
  echo "FAIL: rustup is not on PATH, so the nightly toolchain and rust-src cannot be" >&2
  echo "  checked; run this where rustup is available." >&2
  exit 1
fi
if ! cargo +nightly --version >/dev/null 2>&1; then
  echo "FAIL: the nightly toolchain is required for -Zbuild-std; run:" >&2
  echo "  rustup toolchain install nightly" >&2
  exit 1
fi
if ! rustup component list --installed --toolchain nightly 2>/dev/null | grep -q '^rust-src'; then
  echo "FAIL: the nightly toolchain's rust-src component is required for -Zbuild-std; run:" >&2
  echo "  rustup component add rust-src --toolchain nightly" >&2
  exit 1
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

export RUSTFLAGS="-Zsanitizer=thread"
args=(-Zbuild-std --target x86_64-unknown-linux-gnu --release --features pure)

echo "=== 1/2 negative control: a deliberate race must be reported ==="
cargo +nightly test "${args[@]}" --test threads -- --ignored deliberate_race_is_detected \
  > "$out" 2>&1 || true
if grep -q "WARNING: ThreadSanitizer: data race" "$out"; then
  echo "OK: the control's race was reported (the sanitizer is in the binary)"
else
  echo "FAIL: ThreadSanitizer reported no race for a deliberate one." >&2
  echo "That is the vacuous case: this script cannot say anything about the real" >&2
  echo "run until the control is detected. Full output:" >&2
  cat "$out" >&2
  exit 1
fi

echo "=== 2/2 the crate's own concurrent test must be clean ==="
cargo +nightly test "${args[@]}" --test threads > "$out" 2>&1
if grep -q "WARNING: ThreadSanitizer" "$out"; then
  echo "FAIL: ThreadSanitizer reported a race in this crate:" >&2
  grep -A20 "WARNING: ThreadSanitizer" "$out" >&2
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
