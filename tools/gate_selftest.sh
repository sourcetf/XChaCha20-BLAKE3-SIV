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
# The checks below also pin the guards that keep a stage from passing while checking
# nothing -- each of them was deletable, or makeable always-true, without this file
# noticing, measured in throwaway copies:
#
#   * `verify.sh`'s Miri ran-count wrapper (a stub `cargo` that succeeds and reports
#     no test is what a filter matching nothing looks like; the run must fail);
#   * `verify.sh`'s zero-test guard on the main test stages (the same stub, printing
#     the `0 passed` line a gutted suite produces; the run must fail with the
#     guard's message, not reach its summary);
#   * `tools/stack_residue.sh`'s exit-3 mapping (a failing `cargo` must answer 3,
#     not 0 or cargo's 101);
#   * `tools/cache_profile.sh --trace`'s determinism control (a fake valgrind whose
#     same-input runs differ must produce exit 3, not a PASS);
#   * `tools/ctgrind.sh`'s suppression validator (a widened `fun:decrypt` entry in a
#     scratch tree must be rejected before anything is built).
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
CARGO_BIN_DIR="$(dirname "$(command -v cargo)")"
# The restricted PATHs below deliberately drop the job's Python prefix to control
# which `cargo` runs. Python's reference dependency is not part of that experiment:
# keep the interpreter that `python3` resolves to (setup-python on CI) on the probes'
# PATH, and pin the user-site base so a throwaway HOME does not hide a `blake3`
# installed with `pip --user`.
PYTHON_BIN_DIR="$(dirname "$(command -v python3)")"
# The interpreter this script runs its Python checks with (the same variable name
# `verify.sh` uses; a bare `"$PYTHON"` without this line is exactly the unbound-variable
# defect check 10 exists to catch).
PYTHON="${PYTHON:-python3}"
PYTHON_USER_BASE="$(python3 -m site --user-base 2>/dev/null || true)"
if [ -n "$PYTHON_USER_BASE" ]; then
  export PYTHONUSERBASE="$PYTHON_USER_BASE"
fi

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
#
# For status 0 the stub also has to *look like* a successful `cargo test`, because
# verify.sh's main test stages now require at least one passed test per invocation
# (the guard check 8 pins); a stub that exited 0 printing nothing would trip that
# guard before the stage the check under test is about. `test` is matched as a whole
# argument (so `--all-targets` and `--test-threads` do not count), and `miri` is
# matched first, because the Miri runs must NOT look like a successful test run --
# check 4 is about what the stage does when they report nothing.
make_fake_home() {  # <cargo exit status>
  local home="$WORK/home-$1"
  mkdir -p "$home/.cargo/bin"
  {
    printf '#!/bin/sh\n'
    printf 'status=%s\n' "$1"
    cat <<'STUB'
case " $* " in
  *" miri "*) exit "$status" ;;
  *" test "*) printf '%s\n' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s' ;;
esac
exit "$status"
STUB
  } > "$home/.cargo/bin/cargo"
  chmod +x "$home/.cargo/bin/cargo"
  # A `rustup` shim too: verify.sh's TSAN preflight asks
  # `rustup component list --installed --toolchain nightly` before it calls `run_tool`,
  # and without one the stage *skips* -- so check 11's `--tsan` arm never reached
  # `run_tool` and could not see a missing definition at all (measured: moving
  # `run_tool` back into the later block left that arm green). The shim answers
  # `rust-src`, which is the one component the preflight greps for, and does nothing
  # else; the stub `cargo` failing is what keeps the stage short after it.
  cat > "$home/.cargo/bin/rustup" <<'STUB'
#!/bin/sh
case " $* " in
  *" component list "*) printf '%s\n' 'rust-src (installed)' ;;
esac
exit 0
STUB
  chmod +x "$home/.cargo/bin/rustup"
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

# Check 8's stub: a *named* test binary that reports zero passed. The bare summary
# above makes verify.sh take its "no Running headers" fallback, so it cannot exercise
# the per-target loop (a deleted/renamed target is the case that loop exists for).
make_zero_target_home() {
  local home="$WORK/home-zero-target"
  mkdir -p "$home/.cargo/bin"
  cat > "$home/.cargo/bin/cargo" <<'STUB'
#!/bin/sh
printf '%s\n' '     Running tests/decision.rs (target/release/deps/decision)'
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
  out=$(PATH="$STUB:$CARGO_BIN_DIR:$PYTHON_BIN_DIR:/usr/bin:/bin" HOME="$HIDDEN_HOME" \
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
          PATH="$HOME_OK/.cargo/bin:$STUB:$CARGO_BIN_DIR:$PYTHON_BIN_DIR:/usr/bin:/bin" HOME="$HOME_OK" \
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
#    a `cargo` that simply fails makes it exit 1, so the invariant here is "non-zero, not
#    the completion line, and the tool's own build-failure reason". The reason is required
#    because a bare non-zero exit does not distinguish the campaign refusing a build it
#    could not run from *any* early failure -- an unconditional `exit 1` at the top of
#    `tools/fi_check.sh` satisfied the old form of this check (an audit's point).
HOME_FAIL="$(make_fake_home 1)"
set +e
fi_out="$(HOME="$HOME_FAIL" PATH="$HOME_FAIL/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
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
elif ! printf '%s\n' "$fi_out" | grep -q 'does not build'; then
  echo "FAIL: tools/fi_check.sh exited $fi_rc with a failing cargo but without its own" >&2
  echo "      build-failure reason, so this is not the campaign refusing a build it" >&2
  echo "      could not run: an early unconditional exit looks the same from here." >&2
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
#    read as a verdict, which is the vacuous pass the guard exists to stop. The exit
#    status and the row scan are behavioural; on top of them the tool's own reason
#    for refusing the log (`matched no tests`) is required, because an unconditional
#    `exit 1` at the top of `tools/fi_check.sh` satisfies the first two (an audit's
#    point) while proving nothing about `assert_tests_ran`. With the row-path guard
#    present the baseline call site is never reached under this stub, so it is not
#    separately exercised.
HOME_ZERO="$(make_zero_test_home)"
HOME_ZERO_TARGET="$(make_zero_target_home)"
set +e
zero_out="$(HOME="$HOME_ZERO" PATH="$HOME_ZERO/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
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
elif ! printf '%s\n' "$zero_out" | grep -qE 'matched no tests|no "test result" line'; then
  echo "FAIL: tools/fi_check.sh exited $zero_rc on a zero-test log, but without the" >&2
  echo "      zero-test guard's own reason, so this is not assert_tests_ran firing:" >&2
  echo "      an unconditional exit 1 at the top of the tool reads the same from here." >&2
  printf '%s\n' "$zero_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/fi_check.sh -> exit $zero_rc on a zero-test log, before any row verdict"
fi

# 4. The Miri stage's ran-count guard must fire. Miri is slow and often absent, so
#    the wrapper that reads libtest's `N passed` line is the only thing between a
#    filter that matches nothing and a UB stage counted as run: libtest exits 0 on
#    "0 passed". A `cargo` stub that succeeds and prints nothing is what a
#    zero-match Miri run looks like from the caller's side, so this check needs no
#    miri installation -- and if the wrapper is deleted, or made always-true, the
#    run reaches its summary with the stage counted as passed.
set +e
miri_out="$(XSIV_IN_GATE_SELFTEST=1 \
            PATH="$HOME_OK/.cargo/bin:$STUB:$CARGO_BIN_DIR:$PYTHON_BIN_DIR:/usr/bin:/bin" HOME="$HOME_OK" \
            timeout 300 bash ./verify.sh --miri 2>&1)"
miri_rc=$?
set -e
if [ "$miri_rc" -eq 0 ] || [ "$miri_rc" -eq 124 ]; then
  echo "FAIL: verify.sh exited $miri_rc for --miri with a cargo that succeeds and" >&2
  echo "      reports no test run. A Miri filter that matches nothing must fail the" >&2
  echo "      stage, not pass it (libtest exits 0 on '0 passed')." >&2
  printf '%s\n' "$miri_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif ! printf '%s\n' "$miri_out" | grep -q 'reported no passed test'; then
  echo "FAIL: verify.sh exited $miri_rc for --miri but not with the ran-count" >&2
  echo "      guard's message, so it may be failing for an unrelated reason." >&2
  printf '%s\n' "$miri_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: verify.sh --miri -> exit $miri_rc when every filter matches nothing"
fi

# 5. `tools/stack_residue.sh`'s exit-3 mapping must stay. A build that cannot run
#    is "could not run" (3), which verify.sh records as a skipped stage. Mapped to
#    0, the caller cannot tell it from a measurement that ran and found nothing;
#    mapped to cargo's own 101, it arrives at verify.sh's advisory branch as a
#    compiler-layout change. A `cargo` stub that fails is the environmental case
#    the mapping exists for. The tool's own reason is required on top of the
#    status, for the same reason checks 2, 3, 4, 6, 7 and 8 require theirs: an
#    unconditional `exit 3` at the top of `tools/stack_residue.sh` satisfies a
#    status-only check while the measurement never runs -- and with the mapping
#    right, the status alone cannot say which of the two happened.
HOME_101="$(make_fake_home 101)"
set +e
sr_out="$(HOME="$HOME_101" PATH="$HOME_101/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
          timeout 300 bash tools/stack_residue.sh 2>&1)"
sr_rc=$?
set -e
if [ "$sr_rc" -eq 0 ] || [ "$sr_rc" -eq 124 ]; then
  echo "FAIL: tools/stack_residue.sh exited $sr_rc with a cargo that fails to build." >&2
  echo "      'The measurement could not run' must be exit 3; 0 reads as 'measured," >&2
  echo "      nothing found' and any other code as a finding or a raw error." >&2
  printf '%s\n' "$sr_out" | tail -3 | sed 's/^/      | /' >&2
  fail=1
elif [ "$sr_rc" -ne 3 ]; then
  echo "FAIL: tools/stack_residue.sh exited $sr_rc with a failing cargo, expected 3." >&2
  printf '%s\n' "$sr_out" | tail -3 | sed 's/^/      | /' >&2
  fail=1
elif ! printf '%s\n' "$sr_out" | grep -q 'the measurement could not run'; then
  echo "FAIL: tools/stack_residue.sh exited 3 with a failing cargo but without its" >&2
  echo "      own could-not-run reason, so this is not the mapping firing: an" >&2
  echo "      unconditional exit 3 reads the same from here." >&2
  printf '%s\n' "$sr_out" | tail -3 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/stack_residue.sh -> exit 3 when its build cannot run"
fi

# 5b. The wrapper must pass the tool's *own* void-measurement status through, not flatten
#     it into 3. The convention above is exit 4 = "the scan's positive control did not
#     fire, so a PASS would be vacuous", and verify.sh treats 4 as a hard failure while 3
#     is a skipped stage. A wrapper that allows only 0 and 1 rewrites 4 to 3, which
#     reclassifies a blind probe as missing tooling and makes every `4)` branch in
#     verify.sh and ci.yml dead code -- measured before this check existed. The stub below
#     is a `cargo` whose `run` answers 4, which is exactly what the tool returns: the
#     wrapper's mapping is the subject, so nothing needs to be built.
make_exit4_home() {
  local home="$WORK/home-exit4"
  mkdir -p "$home/.cargo/bin"
  cat > "$home/.cargo/bin/cargo" <<'STUB'
#!/bin/sh
case " $* " in
  *" run "*) exit 4 ;;
esac
# `fetch --offline` and anything else: fail, so the wrapper takes its online path and
# still reaches `cargo run`.
exit 1
STUB
  chmod +x "$home/.cargo/bin/cargo"
  printf '%s\n' "$home"
}
HOME_4="$(make_exit4_home)"
set +e
sr4_out="$(HOME="$HOME_4" PATH="$HOME_4/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
           timeout 300 bash tools/stack_residue.sh 2>&1)"
sr4_rc=$?
set -e
if [ "$sr4_rc" -eq 124 ]; then
  echo "FAIL: tools/stack_residue.sh did not finish within 300 s under the exit-4 stub, so" >&2
  echo "      the stub is not the cargo it used." >&2
  fail=1
elif [ "$sr4_rc" -ne 4 ]; then
  echo "FAIL: tools/stack_residue.sh exited $sr4_rc when its program reported a void" >&2
  echo "      measurement (4), expected 4. Mapping it to 3 turns 'the probe is blind, do" >&2
  echo "      not trust a PASS' into 'the tooling is missing', which verify.sh records as a" >&2
  echo "      skipped stage and CI reports as 'could not run'." >&2
  printf '%s\n' "$sr4_out" | tail -3 | sed 's/^/      | /' >&2
  fail=1
elif printf '%s\n' "$sr4_out" | grep -q 'SKIPPED'; then
  echo "FAIL: tools/stack_residue.sh exited 4 but printed the 'SKIPPED: could not run'" >&2
  echo "      message, so the status and the reason disagree; 4 must pass through as a" >&2
  echo "      void measurement, not as an infrastructure skip." >&2
  printf '%s\n' "$sr4_out" | tail -3 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/stack_residue.sh -> exit 4 passes through (void measurement is not a skip)"
fi

# 6. `tools/cache_profile.sh --trace`'s determinism control must fire. The mode
#    compares address traces, so two runs of the same input that differ mean the
#    environment cannot hold a layout; without the control the mode compares two
#    keys anyway and prints PASS. The fake valgrind below answers `--version` and
#    emits a one-line lackey-format trace; the *third* invocation (the enc phase
#    runs zero, ones, zero2 -- see the loop there) differs from the first, which is
#    exactly the condition the control exists to catch. `setarch` is stubbed too,
#    so the check does not depend on the host having it.
FAKEVG="$WORK/fakevg"
mkdir -p "$FAKEVG"
cat > "$FAKEVG/valgrind" <<'FAKE'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo "valgrind-3.22.0-fake"; exit 0; fi
n=$(cat "$FAKE_VG_COUNTER" 2>/dev/null || echo 0)
n=$((n + 1)); printf '%s\n' "$n" > "$FAKE_VG_COUNTER"
printf 'I  400000,1\n'
if [ "$n" -eq 3 ] || [ "$n" -eq 6 ]; then printf 'L  400101,4\n'; else printf 'L  400100,4\n'; fi
FAKE
cat > "$FAKEVG/setarch" <<'FAKE'
#!/bin/sh
shift   # --addr-no-randomize
exec "$@"
FAKE
chmod +x "$FAKEVG/valgrind" "$FAKEVG/setarch"
rm -f "$WORK/vgcount"
set +e
cp_out="$(HOME="$HOME_OK" PATH="$FAKEVG:$HOME_OK/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
          VALGRIND="$FAKEVG/valgrind" FAKE_VG_COUNTER="$WORK/vgcount" \
          timeout 300 bash tools/cache_profile.sh --trace 4 2>&1)"
cp_rc=$?
set -e
if [ "$cp_rc" -eq 0 ] || [ "$cp_rc" -eq 124 ]; then
  echo "FAIL: cache_profile.sh --trace exited $cp_rc on an environment whose" >&2
  echo "      same-input runs differ. The determinism control is what refuses a" >&2
  echo "      verdict there; without it the false PASS reads as 'no leak'." >&2
  printf '%s\n' "$cp_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif [ "$cp_rc" -ne 3 ] || ! printf '%s\n' "$cp_out" | grep -q 'not reproducible'; then
  echo "FAIL: cache_profile.sh --trace exited $cp_rc, not 3 with the layout-not-" >&2
  echo "      reproducible refusal, so this is not the determinism control." >&2
  printf '%s\n' "$cp_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/cache_profile.sh --trace -> exit 3 when the layout is not reproducible"
fi

# 7. `tools/ctgrind.sh`'s suppression validator must reject an entry that names
#    anything but the decision: a `fun:decrypt` entry is how a planted leak inside
#    `decrypt` once passed the check. This runs a scratch tree with a widened entry
#    and the same fake valgrind (it only needs to answer `--version`); the
#    validator runs before the build, so nothing is compiled when it is present --
#    and when it is deleted the run proceeds into the build, where the stub cargo
#    leaves it failing for an unrelated reason, which the message check below
#    distinguishes.
VCOPY="$WORK/ctgrind-supp"
mkdir -p "$VCOPY/tools" "$VCOPY/tests"
cp tools/ctgrind.sh "$VCOPY/tools/"
cat tests/ctgrind.supp > "$VCOPY/tests/ctgrind.supp"
printf '\n# planted by tools/gate_selftest.sh: a frame that is not the decision\nfun:decrypt\n' \
  >> "$VCOPY/tests/ctgrind.supp"
set +e
supp_out="$(HOME="$HOME_OK" PATH="$FAKEVG:$HOME_OK/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
            VALGRIND="$FAKEVG/valgrind" timeout 300 bash "$VCOPY/tools/ctgrind.sh" 2>&1)"
supp_rc=$?
set -e
if [ "$supp_rc" -eq 0 ] || [ "$supp_rc" -eq 124 ]; then
  echo "FAIL: tools/ctgrind.sh exited $supp_rc with a widened suppression entry." >&2
  echo "      A frame naming anything but accept_or_reject permits every branch in" >&2
  echo "      that function; the validator is what refuses it." >&2
  printf '%s\n' "$supp_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif ! printf '%s\n' "$supp_out" | grep -q 'must suppress accept_or_reject and nothing else'; then
  echo "FAIL: tools/ctgrind.sh exited $supp_rc for a widened suppression, but not" >&2
  echo "      with the validator's message, so it may have failed for another reason." >&2
  printf '%s\n' "$supp_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: tools/ctgrind.sh -> exit $supp_rc on a suppression entry naming decrypt"
fi
# 7b. The same validator must reject valgrind's any-frames wildcard. It did not: the
#     block-name alternative in its allow-list was `[A-Za-z0-9_.-]+`, which matches
#     `...`, so a bare `...` line was read as a block name and accepted (measured: the
#     validator printed "1 entry/entries, all naming accept_or_reject" and went on to
#     build). One `...` inside the block widens the permission to every call site of
#     the decision, which is precisely what naming the function is for.
for wildcard_place in after before; do
  WCOPY="$WORK/ctgrind-wildcard-$wildcard_place"
  mkdir -p "$WCOPY/tools" "$WCOPY/tests"
  cp tools/ctgrind.sh "$WCOPY/tools/"
  if [ "$wildcard_place" = after ]; then
    cat tests/ctgrind.supp > "$WCOPY/tests/ctgrind.supp"
    printf '\n%s\n' '...' >> "$WCOPY/tests/ctgrind.supp"
  else
    # The widening form: any caller of the frame below it, i.e. every branch in the
    # decrypt entry points.
    awk 'BEGIN{done=0} /^\{$/ && !done {print; print "   ..."; done=1; next} {print}' \
      tests/ctgrind.supp > "$WCOPY/tests/ctgrind.supp"
  fi
  set +e
  wc_out="$(HOME="$HOME_OK" PATH="$FAKEVG:$HOME_OK/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
            VALGRIND="$FAKEVG/valgrind" timeout 300 bash "$WCOPY/tools/ctgrind.sh" 2>&1)"
  wc_rc=$?
  set -e
  if [ "$wc_rc" -eq 0 ] || [ "$wc_rc" -eq 124 ]; then
    echo "FAIL: tools/ctgrind.sh exited $wc_rc with a bare '...' ($wildcard_place" >&2
    echo "      the frame line). Valgrind reads it as \"any frames\", so the single" >&2
    echo "      permitted decision becomes every branch at every call site." >&2
    printf '%s\n' "$wc_out" | tail -5 | sed 's/^/      | /' >&2
    fail=1
  elif ! printf '%s\n' "$wc_out" | grep -q "bare '\.\.\.' frame wildcard"; then
    echo "FAIL: tools/ctgrind.sh exited $wc_rc for a '...' entry ($wildcard_place the" >&2
    echo "      frame line), but not with the wildcard check's message, so it may" >&2
    echo "      have failed for another reason." >&2
    printf '%s\n' "$wc_out" | tail -5 | sed 's/^/      | /' >&2
    fail=1
  else
    echo "  ok: tools/ctgrind.sh -> exit $wc_rc on a '...' wildcard ($wildcard_place the frame)"
  fi
done

# 7c. `verify.sh`'s `deny_check` must print its "which database answered" note only when
#     that database actually produced a verdict, and must name what went wrong when nothing
#     did. Both halves were broken: the note was printed *before* the offline retry, so a
#     retry that died on the advisory-database lock printed a claim of a verdict next to the
#     proof that none existed (measured by holding `db.lock` and running `--deep`).
#
#     The function is *extracted* from verify.sh and driven with a stub `cargo`, rather than
#     reached through a whole `--deny` run: the stage also invokes `cargo audit`, and a stub
#     that has to satisfy both would test the stub. Extraction keeps the code under test the
#     shipped code -- and the last `ok:` below says so, because a stale extractor would
#     otherwise pass silently.
DENY_FN="$WORK/deny_check.sh"
"$PYTHON" - "$PWD/verify.sh" "$DENY_FN" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
i = src.index("    deny_check() {  # <dir>")
j = src.index("\n    deny_check .\n", i)
body = src[i:j]
# Dedent the four-space block indent so the file can be sourced on its own.
lines = [l[4:] if l.startswith("    ") else l for l in body.split("\n")]
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
deny_case() {  # <mode>; prints the function's output and RESULT=<rc>
  (
    cargo() {
      # Scan the whole argument list: the real calls are `cargo deny --locked check` and
      # `cargo deny --locked --offline check`, so a stub keyed on `$2` sees `--locked` and
      # misclassifies every retry as an online attempt (which is what a first draft did --
      # and it "failed" the offline-ok case, so the control noticed).
      local a offline=0
      for a in "$@"; do [ "$a" = "--offline" ] && offline=1; done
      if [ "$offline" -eq 1 ]; then
        case "$mode" in
          lock)       echo "failed to acquire advisory database lock" >&2; return 1 ;;
          offline-ok) echo "advisories ok, bans ok, licenses ok, sources ok"; return 0 ;;
          *)          echo "error: 1 denied warning found!"; return 1 ;;
        esac
      fi
      case "$mode" in
        lock|offline-ok) echo "failed to fetch advisory database" >&2; return 1 ;;
        *)               echo "error: 1 denied warning found!"; return 1 ;;
      esac
    }
    sleep() { :; }
    . "$DENY_FN"
    deny_check .
    echo "RESULT=$?"
  ) 2>&1
}
for mode in lock offline-ok finding; do
  set +e
  dc_out="$(mode="$mode" deny_case "$mode")"
  set -e
  note=absent; grep -q 'was re-checked against the cached' <<< "$dc_out" && note=present
  case "$mode:$note" in
    lock:absent)       echo "  ok: deny_check on a held advisory lock -> no verdict claimed" ;;
    offline-ok:present) echo "  ok: deny_check on a successful offline retry -> note printed" ;;
    finding:absent)    echo "  ok: deny_check on a real advisory -> no offline note" ;;
    *) echo "FAIL: deny_check's offline note is $note in the '$mode' case, which is the" >&2
       echo "      wrong side: it claims a cached-database verdict exactly when none was" >&2
       echo "      produced, or hides one when it was." >&2
       printf '%s\n' "$dc_out" | tail -4 | sed 's/^/      | /' >&2
       fail=1 ;;
  esac
  case "$mode" in
    lock)       if ! grep -q 'could not read the advisory database' <<< "$dc_out"; then
                  echo "FAIL: deny_check on a held advisory lock did not name the lock as" >&2
                  echo "      the reason, so a reader sees a bare 'FAILED: cargo-deny'." >&2
                  printf '%s\n' "$dc_out" | tail -4 | sed 's/^/      | /' >&2
                  fail=1
                fi ;;
    finding)    if ! grep -q 'RESULT=1' <<< "$dc_out"; then
                  echo "FAIL: deny_check did not fail on a real advisory (rc=$?)." >&2
                  fail=1
                fi ;;
    offline-ok) if ! grep -q 'RESULT=0' <<< "$dc_out"; then
                  echo "FAIL: deny_check failed a clean offline verdict." >&2
                  fail=1
                fi ;;
  esac
done

# 8. The main test stages' zero-test guard must fire. `cargo test` exits 0 when every
#    test target is empty or filtered out, printing "test result: ok. 0 passed" -- a
#    vacuous green for the stage that carries the advertised unit + differential suite.
#    The stub names a real target (`Running tests/decision.rs`) and then reports zero
#    passed for it, so verify.sh takes its per-target branch rather than the bare-summary
#    fallback: the deleted/renamed-target guard is the one this check must exercise.
#    `XSIV_IN_GATE_SELFTEST=1` keeps this check from re-running the gate self-test
#    itself; the skip it records is not what fails the run here, the guard's `exit 1`
#    is (the message check below says which fired).
set +e
zero_vs_out="$(XSIV_IN_GATE_SELFTEST=1 \
               PATH="$HOME_ZERO_TARGET/.cargo/bin:$STUB:$CARGO_BIN_DIR:$PYTHON_BIN_DIR:/usr/bin:/bin" HOME="$HOME_ZERO_TARGET" \
               timeout 300 bash ./verify.sh 2>&1)"
zero_vs_rc=$?
set -e
if [ "$zero_vs_rc" -eq 0 ] || [ "$zero_vs_rc" -eq 124 ]; then
  echo "FAIL: verify.sh exited $zero_vs_rc with a cargo that succeeds and runs no" >&2
  echo "      tests. The main test stages must require at least one passed test per" >&2
  echo "      invocation: libtest exits 0 on '0 passed', so without the guard a" >&2
  echo "      gutted test suite reports the stage as passed." >&2
  printf '%s\n' "$zero_vs_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
elif ! printf '%s\n' "$zero_vs_out" | grep -q 'cargo test run for'; then
  echo "FAIL: verify.sh exited $zero_vs_rc with no tests run, but not with the" >&2
  echo "      zero-test guard's message, so it may be failing for another reason." >&2
  printf '%s\n' "$zero_vs_out" | tail -5 | sed 's/^/      | /' >&2
  fail=1
else
  echo "  ok: verify.sh -> exit $zero_vs_rc when a named target reports 0 passed"
fi

echo
# 10. The script itself must be executable end to end. Two defects of the "the gate is
#     broken, not the code" kind shipped in `verify.sh` at once and CI could not see
#     either, because CI does not run those two stages:
#
#       * `run_tool` was *called* from the TSAN stage (line 888) while its definition sat
#         in the later `RUN_TOOLS` block (line 997), so `--tsan` -- and `--deep`/`--all`,
#         which set `RUN_TSAN=1` -- died with `run_tool: command not found` (127) before
#         any later stage ran;
#       * the Kani stage's harness count used `"$PYTHON"`, which the script never
#         assigned, so `set -u` aborted `--kani-only`/`--deep`/`--all` with `unbound
#         variable` (1) before the count guard it was added for could run.
#
#     Both are static properties, so they are checked statically: shell functions must be
#     defined before their first call, and every variable the script expands must be
#     assigned in it, defaulted with `${NAME:-…}`, or on the environment allowlist below.
#     (`bash -n` parses neither, and running the stages needs the real toolchains.)
#     The python probe runs under `set -e`; it must not abort the gate before check 11
#     has run, so its failure is captured with `|| rc=$?` rather than left to the shell.
rc=0
"$PYTHON" - verify.sh <<'PYCHECK' || rc=$?
import re
import sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()

# Environment variables the script may read without assigning: set by the caller, the
# shell, or CI, and none of them is a place a definition could be forgotten.
ALLOWED = {
    "PATH", "HOME", "PWD", "OLDPWD", "SHELL", "USER", "TMPDIR", "TERM", "LANG", "LC_ALL",
    "RUNNER_TEMP", "GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "CI", "CARGO", "CARGO_HOME",
    "CARGO_TARGET_DIR", "RUSTUP_HOME", "RUSTFLAGS", "RUST_BACKTRACE", "VALGRIND",
    "FUZZ_SECONDS", "CC", "CFLAGS", "AR", "CXX", "HOST", "TARGET", "XSIV_IN_GATE_SELFTEST",
}
ASSIGN = re.compile(r"(?:^|\s)(?:export\s+|readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
# Limit: a static scanner cannot see that an assignment sits in an `if false` branch or
# behind a never-taken case arm, so `if false; then PYTHON=x; fi` counts here as an
# assignment. That gap is closed end to end by check 11, which runs `--kani-only` under
# the stub toolchain and fails on the `unbound variable` the dead assignment actually
# produces -- not by more spellings in this check.
USE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\b")
DEFAULTED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-")
# `for x in …`, `while read -r x y`, `local x` and `case`-less shells assign without `=`.
FOR = re.compile(r"^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\b")
READ = re.compile(r"(?:^|[|;&(]\s*)read\s+(.*)$")
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
assigned = set()
defaulted = set()
for line in lines:
    # A comment that *mentions* an assignment is not an assignment. The USE loop below
    # already skips comment lines; the ASSIGN collection did not, so replacing
    # `PYTHON="${PYTHON:-python3}"` with a comment that quotes it passed this check while
    # the variable was genuinely unbound at run time (measured).
    if line.lstrip().startswith("#"):
        continue
    for m in ASSIGN.finditer(line):
        assigned.add(m.group(1))
    for m in DEFAULTED.finditer(line):
        defaulted.add(m.group(1))
    m = FOR.match(line)
    if m:
        assigned.add(m.group(1))
    m = READ.search(line)
    if m:
        for word in m.group(1).split():
            if word.startswith("-"):
                continue
            if NAME.match(word):
                assigned.add(word)
problems = []
for i, line in enumerate(lines, 1):
    if line.lstrip().startswith("#"):
        continue
    for m in USE.finditer(line):
        name = m.group(1)
        # Only the environment-style names: `$PYTHON` (the defect this replaces) is
        # upper-case, while the lower-case ones in embedded `awk`/`sed` programs are that
        # language's own variables and cannot be told apart from shell locals by a check
        # this size. A missing *lower-case* shell variable is a much smaller risk -- it is
        # almost always a `local` or a `for` binding, both of which bash reports at use.
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", name):
            continue
        if name in assigned or name in defaulted or name in ALLOWED:
            continue
        problems.append(f"verify.sh:{i}: ${name} is never assigned in this script")

# Function definitions and their first call: a shell function only exists once the
# definition has been *executed*, so a call earlier in the file cannot succeed.
defs = {}
for i, line in enumerate(lines, 1):
    m = re.match(r"\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", line)
    if m and m.group(1) not in defs:
        defs[m.group(1)] = i
for name, defline in defs.items():
    # A call may carry environment prefixes: `XSIV_FEATURES=ultra run_tool …`. The old
    # matcher required the name at line start, so a pre-definition call spelled with a
    # prefix (`VAR=v run_tool …`) was invisible -- measured: when *every* pre-definition
    # call used a prefix, no check fired for the function. Allow any run of
    # `NAME=value` words before the name, and any shell separator before those.
    call = re.compile(
        r"(?:^|[\s;&|(])"
        r"(?:(?:[A-Za-z_][A-Za-z0-9_]*=\S*)\s+)*"
        + re.escape(name)
        + r"\s"
    )
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if i >= defline:
            break
        if call.search(line):
            problems.append(
                f"verify.sh:{i}: `{name}` is called before its definition at line {defline}; "
                "a shell function only exists once its definition has run"
            )
            break

if problems:
    print("FAIL: verify.sh cannot run as written:", file=sys.stderr)
    for p in problems:
        print(f"      {p}", file=sys.stderr)
    sys.exit(1)
print("  ok: verify.sh defines every function before its first call and assigns every variable it expands")
PYCHECK
if [ "$rc" -ne 0 ]; then fail=1; fi

# 11. Same two defects, end to end rather than statically: with a *stub* toolchain the
#     `--tsan` and `--kani-only` stages must get as far as their own skip/verdict logic.
#     Neither may die with `command not found` (127) or on an unbound variable -- both were
#     shipped at once and neither is visible to CI, which does not run these stages.
#     `--kani-only` goes straight to the Kani stage (nothing before it), so this is cheap;
#     the stub `cargo` fails, which is what makes the stages short.
for flag in --tsan --kani-only; do
  set +e
  vo="$("$PYTHON" -c "import sys;print('x')" >/dev/null 2>&1; \
       XSIV_IN_GATE_SELFTEST=1 HOME="$HOME_OK" \
       PATH="$HOME_OK/.cargo/bin:$PYTHON_BIN_DIR:/usr/bin:/bin" \
       timeout 300 bash ./verify.sh "$flag" 2>&1)"
  vrc=$?
  set -e
  if printf '%s\n' "$vo" | grep -qE 'command not found|unbound variable'; then
    echo "FAIL: verify.sh $flag died on a shell error rather than reaching its own logic:" >&2
    printf '%s\n' "$vo" | grep -E 'command not found|unbound variable' | head -2 | sed 's/^/      | /' >&2
    fail=1
  elif [ "$vrc" -eq 127 ]; then
    echo "FAIL: verify.sh $flag exited 127 (a name it calls does not exist)" >&2
    fail=1
  elif [ "$vrc" -eq 124 ]; then
    echo "FAIL: verify.sh $flag did not finish within 300 s under the stub toolchain" >&2
    fail=1
  else
    echo "  ok: verify.sh $flag -> exit $vrc without a shell-level failure"
  fi
done

echo "gate contract: the tools checked here answer exit 3 under hidden tooling;"
echo "               verify.sh fails a stage it was asked for that did not run, and"
echo "               its Miri ran-count guard fails a run that reports no passed"
echo "               test; its main test stages fail a run in which a named target"
echo "               reports 0 passed; stack_residue.sh answers 3 for a build that"
echo "               cannot run; the cache-profile trace mode refuses a verdict on a"
echo "               layout it cannot hold; the ctgrind suppression validator rejects"
echo "               a widened entry; a campaign that cannot run does not report"
echo "               completion; and a campaign whose cargo runs no tests does not"
echo "               judge a row."

# The final verdict. It must come *after* every check: an earlier version put it before
# checks 10 and 11, so a FAIL printed by either of them never changed the exit status --
# the gate reported the very defect class it exists for and still exited 0 (measured).
if [ "$fail" -ne 0 ]; then
  echo "gate contract: FAILED" >&2
  exit 1
fi
