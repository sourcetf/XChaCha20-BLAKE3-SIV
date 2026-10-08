#!/usr/bin/env bash
#
# A gate that answers "I could not run" must not answer it with exit 0.
#
# That was a real defect here, twice in the same shape: `verify.sh` counted a stage as
# *run and passed* when the stage's tool had printed `SKIPPED: ...` and exited 0, so
# `--deep` could report "all requested checks passed" without the constant-time check
# having executed at all. The convention is now **exit 3** -- "could not run", distinct
# from 0 (ran and passed), 1 (ran and failed) and 99 (a leak) -- and `verify.sh` records
# it as a skipped stage (a stage the caller named is failed instead of skipped).
#
# This is the control for that convention. It hides the tooling and looks at the exit
# status, so a tool that regresses to `exit 0` fails *here*, not in a summary line
# nobody reads. The hiding is done with a non-executable `valgrind` stub first on
# `PATH`: the tools probe `command -v valgrind` and then require `-x`, so the stub
# makes them see nothing, on a machine with or without a system valgrind. `HOME` is
# hidden too, for the extracted-copy path they check first.
#
# Usage:  tools/gate_selftest.sh
# Exit codes: 0 every gate honours the convention; 1 one of them does not; 3 the
# recursion guard refused to run (XSIV_IN_GATE_SELFTEST was already set).
set -euo pipefail

# Hard recursion guard. This file runs `verify.sh`, and `verify.sh` runs this file; the
# call there is marker-guarded, but if that guard is ever removed the two would spin
# forever instead of failing (measured: nested `verify.sh --ctgrind` processes, no
# output, no exit). A second entry point is a mistake, and it says so.
if [ "${XSIV_IN_GATE_SELFTEST:-}" = "1" ]; then
  echo "gate contract: refusing to recurse (XSIV_IN_GATE_SELFTEST is already set)" >&2
  exit 3
fi

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
REAL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
REAL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
REAL_HOME="$HOME"
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

# A throwaway `HOME` whose `cargo` is a stub with the given exit status.
#
# Needed because `verify.sh` and `tools/fi_check.sh` both prepend `$HOME/.cargo/bin` to
# `PATH` themselves, so a stub that is only *on* PATH loses to the real toolchain: an
# earlier version of the two checks below did that and silently ran the real five-minute
# campaign instead of the stub. Pointing `HOME` at this makes the stub win, which is what
# "the toolchain cannot run" has to mean for these checks.
make_fake_home() {  # <cargo exit status>
  local home="$WORK/home-$1"
  mkdir -p "$home/.cargo/bin"
  printf '#!/bin/sh\nexit %s\n' "$1" > "$home/.cargo/bin/cargo"
  chmod +x "$home/.cargo/bin/cargo"
  printf '%s\n' "$home"
}

# A throwaway `HOME` whose `cargo` *succeeds* while reporting that no test ran.
#
# This is check 3's stub, and it exists because a failing `cargo` (the one above)
# never reaches `tools/fi_check.sh`'s `assert_tests_ran` guard: the campaign stops
# at the build. A stub that succeeds and prints the `0 passed` line a name filter
# that matched nothing produces is what makes that guard observable from here.
make_zero_test_home() {
  local home="$WORK/home-zero-tests"
  mkdir -p "$home/.cargo/bin"
  cat > "$home/.cargo/bin/cargo" <<'STUB'
#!/bin/sh
printf '%s\n' 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
exit 0
STUB
  chmod +x "$home/.cargo/bin/cargo"
  printf '%s\n' "$home"
}

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
# `ctgrind` only: with valgrind hidden that is the mutation that answers 3, and asking
# for just it keeps this control from running the `kat` mutation's real builds (it needs
# no valgrind, so it would run them) every time.
check_exit_3 "tools/mutation_check.sh" bash tools/mutation_check.sh ctgrind

# The tool's own exit status only helps if the caller honours it, so what follows is
# *behavioural*. An earlier version grepped `verify.sh` for the exact string
# `if [ "$ctgrind_rc" -eq 3 ]` and each tool for a line starting with `exit 3`: both are
# satisfied only by the implementation they were written against, so a rewrite that keeps
# the behaviour (`case $rc in 3)`, `exit "$E_COULD_NOT_RUN"`) read as a failure, and
# neither could see a tool that was not in the list at all -- an audit injected an `exit 0`
# skip into `tools/fi_check.sh` and this file stayed green.

# 1. A stage the caller *named* must not be skipped and then reported as a success. The
#    core stages are made instant by a `cargo` that succeeds, so this exercises verify.sh's
#    skip handling and nothing else.
HOME_OK="$(make_fake_home 0)"
set +e
vs_out="$(XSIV_IN_GATE_SELFTEST=1 \
          PATH="$HOME_OK/.cargo/bin:$STUB:$CARGO_BIN_DIR:/usr/bin:/bin" HOME="$HOME_OK" \
          VALGRIND=/nonexistent timeout 300 bash ./verify.sh --ctgrind 2>&1)"
vs_rc=$?
set -e
if [ "$vs_rc" -eq 124 ]; then
  echo "FAIL: verify.sh did not finish within 300 s with a stub toolchain, so the stub" >&2
  echo "      is not the toolchain it used." >&2
  fail=1
elif [ "$vs_rc" -eq 0 ]; then
  echo "FAIL: verify.sh exited 0 after --ctgrind was asked for and skipped. A stage the" >&2
  echo "      caller named must not come back as a success." >&2
  printf '%s\n' "$vs_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif ! printf '%s\n' "$vs_out" | grep -q 'named on the command line and did not run'; then
  echo "FAIL: verify.sh exited $vs_rc for an explicitly named, skipped stage but did not" >&2
  echo "      say so, so it may be failing for an unrelated reason." >&2
  printf '%s\n' "$vs_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: verify.sh fails (exit $vs_rc) when a stage it was asked for is skipped"
fi

# 2. A campaign that cannot run must not report itself complete. `tools/fi_check.sh` answers
#    3 only for an *environmental* build failure (out of disk, or a build the kernel killed);
#    a `cargo` that simply fails makes it exit 1, so the invariant here is "non-zero, and not
#    the completion line", with a `cargo` that fails.
HOME_FAIL="$(make_fake_home 1)"
set +e
fi_out="$(HOME="$HOME_FAIL" PATH="$HOME_FAIL/.cargo/bin:/usr/bin:/bin" \
          timeout 300 bash tools/fi_check.sh 2>&1)"
fi_rc=$?
set -e
if [ "$fi_rc" -eq 0 ] || [ "$fi_rc" -eq 124 ] \
   || printf '%s\n' "$fi_out" | grep -q 'campaign complete'; then
  echo "FAIL: tools/fi_check.sh reported success (exit $fi_rc) with a cargo that fails." >&2
  echo "      A campaign that could not run must not answer 0 -- the same defect this file" >&2
  echo "      exists for, one tool further out." >&2
  printf '%s\n' "$fi_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/fi_check.sh -> exit $fi_rc with a failing cargo (no silent skip)"
fi

# 3. The zero-tests guard *inside* the campaign must fire. An audit deleted both
#    `assert_tests_ran` call sites from `tools/fi_check.sh` and this file stayed
#    green: check 2 above cannot see it, because a failing `cargo` stops the
#    campaign at the build and the guard is never reached. Here every cargo
#    invocation succeeds and prints the `test result: ok. 0 passed; ...` line a
#    name filter that matched nothing produces, so the guard is the only thing
#    between that log and a `pass` verdict. The campaign must fail *without judging
#    a row*: an `  OK` or `  FAIL <row> expected ...` line means a zero-test log was
#    read as a verdict, which is the vacuous pass the guard exists to stop.
#    (Behavioural, not a text check: it pins "the campaign refuses zero-test
#    evidence", so a rewrite that keeps the refusal keeps this green. With the
#    row-path guard present the baseline call site is never reached under this
#    stub, so it is not separately exercised.)
HOME_ZERO="$(make_zero_test_home)"
set +e
zero_out="$(HOME="$HOME_ZERO" PATH="$HOME_ZERO/.cargo/bin:/usr/bin:/bin" \
            timeout 300 bash tools/fi_check.sh 2>&1)"
zero_rc=$?
set -e
if [ "$zero_rc" -eq 0 ] || [ "$zero_rc" -eq 124 ] \
   || printf '%s\n' "$zero_out" | grep -q 'campaign complete'; then
  echo "FAIL: tools/fi_check.sh reported success (exit $zero_rc) with a cargo that" >&2
  echo "      succeeds but runs no tests. A row judged on such a log proves nothing." >&2
  printf '%s\n' "$zero_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif [ "$zero_rc" -ne 1 ]; then
  echo "FAIL: tools/fi_check.sh exited $zero_rc on a zero-test log; a campaign that" >&2
  echo "      refuses such a log fails with 1 (0 would be a silent pass, 3 a silent" >&2
  echo "      skip), so this is not the guard firing." >&2
  printf '%s\n' "$zero_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif printf '%s\n' "$zero_out" | grep -qE '^  (OK|FAIL) '; then
  echo "FAIL: tools/fi_check.sh judged a row (exit $zero_rc) from a log in which" >&2
  echo "      zero tests ran. The guard (assert_tests_ran) is what refuses such a" >&2
  echo "      log, so this is what deleting it looks like from here." >&2
  printf '%s\n' "$zero_out" | grep -E '^  (OK|FAIL) ' | head -3 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/fi_check.sh -> exit $zero_rc on a zero-test log, before any row verdict"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "gate contract: FAILED" >&2
  exit 1
fi
echo "gate contract: the three tools checked here use exit 3 under"
echo "               hidden tooling; verify.sh fails when a stage it was asked for is"
echo "               skipped; a campaign that cannot run does not report completion;"
echo "               and a campaign whose cargo runs no tests does not judge a row."
