#!/usr/bin/env bash
#
# A gate that answers "I could not run" must not answer it with exit 0.
#
# That was a real defect here, twice in the same shape: `verify.sh` counted a stage as
# *run and passed* when the stage's tool had printed `SKIPPED: ...` and exited 0, so
# `--deep` could report "all requested checks passed" without the constant-time check
# having executed at all. The convention is now **exit 3** -- "could not run", distinct
# from 0 (ran and passed), 1 (ran and failed) and 99 (a leak) -- and every caller maps
# it to a skipped stage.
#
# This is the control for that convention. It hides the tooling and looks at the exit
# status, so a tool that regresses to `exit 0` fails *here*, not in a summary line
# nobody reads. The hiding is done with a non-executable `valgrind` stub first on
# `PATH`: the tools probe `command -v valgrind` and then require `-x`, so the stub
# makes them see nothing, on a machine with or without a system valgrind. `HOME` is
# hidden too, for the extracted-copy path they check first.
#
# Usage:  tools/gate_selftest.sh
# Exit codes: 0 every gate honours the convention; 1 one of them does not.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
REAL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
REAL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
CARGO_BIN_DIR="$(dirname "$(command -v cargo)")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A non-executable `valgrind`: visible to `command -v`, rejected by `[ -x ]`.
STUB="$WORK/stub"
mkdir -p "$STUB"
printf '#!/bin/sh\nexit 0\n' > "$STUB/valgrind"
chmod -x "$STUB/valgrind"
HIDDEN_HOME="$WORK/home"
# A hidden `HOME` also has to hide the *extracted* valgrind the tools check first, so
# it gets a non-executable one too -- the same trick as the stub, one path earlier.
mkdir -p "$HIDDEN_HOME/valgrind/usr/bin"
printf '#!/bin/sh\nexit 0\n' > "$HIDDEN_HOME/valgrind/usr/bin/valgrind"
chmod -x "$HIDDEN_HOME/valgrind/usr/bin/valgrind"

fail=0

hidden_run() {  # prints output, returns the tool's status
  local out rc
  set +e
  # `CARGO_HOME` and `RUSTUP_HOME` are passed through explicitly: hiding `HOME`
  # hides the toolchain too, and this check is about the valgrind lookup, not about
  # whether rustup can find its own state.
  out=$(PATH="$STUB:$CARGO_BIN_DIR:/usr/bin:/bin" HOME="$HIDDEN_HOME" \
        CARGO_HOME="$REAL_CARGO_HOME" RUSTUP_HOME="$REAL_RUSTUP_HOME" \
        VALGRIND=/nonexistent "$@" 2>&1)
  rc=$?
  set -e
  printf '%s' "$out"
  return "$rc"
}

check_exit_3() {  # label, command...
  local label="$1"; shift
  local out
  set +e
  out="$(hidden_run "$@")"
  local rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: $label exited 0 with the tooling hidden. That is the defect this" >&2
    echo "      file exists for: a caller cannot tell it from a pass." >&2
    printf '%s\n' "$out" | head -3 | sed 's/^/      | /' >&2
    fail=1
    return
  fi
  if [ "$rc" -ne 3 ]; then
    echo "FAIL: $label exited $rc with the tooling hidden, expected 3." >&2
    printf '%s\n' "$out" | head -3 | sed 's/^/      | /' >&2
    fail=1
    return
  fi
  echo "  ok: $label -> exit 3 (could not run)"
}

echo "gate contract: 'could not run' is exit 3, never 0"
check_exit_3 "tools/ctgrind.sh"       bash tools/ctgrind.sh
check_exit_3 "tools/cache_profile.sh" bash tools/cache_profile.sh 4
check_exit_3 "tools/mutation_check.sh" bash tools/mutation_check.sh

# The tool's own exit status only helps if the caller honours it: `verify.sh` calls
# `tools/ctgrind.sh` directly, and that is where the skip used to be absorbed. The
# mapping is asserted by its text, anchored on the comparison, so a refactor that
# removes the handling fails here instead of silently turning skips back into passes.
if grep -q 'if \[ "\$ctgrind_rc" -eq 3 \]' verify.sh; then
  echo "  ok: verify.sh maps ctgrind's exit 3 to a skipped stage"
else
  echo "FAIL: verify.sh no longer maps tools/ctgrind.sh's exit 3 to a skipped stage," >&2
  echo "      so a run without valgrind would count as a pass again." >&2
  fail=1
fi

# And the same invariant for anything else that shells out to a tool which can
# answer "could not run": every such call site must compare against 3.
for tool in tools/ctgrind.sh tools/cache_profile.sh tools/mutation_check.sh; do
  if grep -q '^ *exit 3' "$tool"; then
    echo "  ok: $tool has an exit-3 path"
  else
    echo "FAIL: $tool has no 'exit 3' path; if it can answer 'could not run' it must" >&2
    echo "      say so with a status a caller can distinguish from success." >&2
    fail=1
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "gate contract: FAILED" >&2
  exit 1
fi
echo "gate contract: every tool that can answer 'could not run' uses exit 3, and"
echo "               verify.sh reports it as a skipped stage"
