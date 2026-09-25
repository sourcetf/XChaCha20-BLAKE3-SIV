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
# Rebuilding std takes a couple of minutes and needs the `rust-src` component:
#
#   rustup component add rust-src
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

if ! rustup component list --installed 2>/dev/null | grep -q '^rust-src'; then
  echo "FAIL: the rust-src component is required for -Zbuild-std; run:" >&2
  echo "  rustup component add rust-src" >&2
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
echo "OK: no data race reported, and the control shows the run could have said so"
