#!/usr/bin/env bash
#
# Fault-injection campaign over the accept/reject decision.
#
# A mutation check asks "does a check catch a bug?". This asks a different question:
# "does a countermeasure survive a fault?", where the fault is written down as a
# source change. Each row of the table below names four things -- the fault, the
# build it is applied to, the test that acts as the detector, and what the detector
# must do -- and a row failing means the code no longer behaves the way this file
# claims.
#
# Two of the expectations are deliberately not "reject":
#
#   * `wipe-skipped` is a *defensive* property, not a forgery one: the detector must
#     FAIL, because a skipped wipe is a defect that the security test is supposed to
#     catch.
#   * `computed-tag-replaced` is a *known limit*: replacing the computed tag with the
#     received one satisfies both gates, because both compare the same two values.
#     It is pinned here so that a change in that behaviour -- in either direction --
#     is noticed, and it is the executable version of the README's "not defended"
#     row. A real glitch cannot be expressed as a source change; this is the closest
#     thing a source-level fault model has to one.
#
# What this is not: validation against a real glitch, and not a claim that the fault
# model matches any particular piece of silicon. Nothing here substitutes for a
# fault-injection bench.
#
# Usage:  tools/fi_check.sh
# Exit codes: 0 = every row behaved as stated; 1 = a row did not, or a patch could
# not be applied (which means this file, not the code, needs looking at).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

WORK="$(mktemp -d)"
# Keep the logs on failure: every FAIL message below points at a file under $WORK,
# and an unconditional cleanup deleted them in the same exit that printed the path
# (an audit noted the pointer was dead on arrival). A successful run cleans up.
trap 'rc=$?; if [ "$rc" -eq 0 ]; then rm -rf "$WORK"; else echo "fault-campaign logs kept in $WORK (exit $rc)" >&2; fi' EXIT

# Every row (and every baseline) gets its OWN target directory, and the reason is a
# defect this shared-directory version had: cargo calls a build Fresh by comparing the
# output's mtime against the sources', so a row whose sources happen to be *older* than
# the shared dir's outputs silently runs the previous row's binary. The rows used to
# stay ahead of that by copying in order, but the clean baseline below is built *after*
# the row it belongs to is copied -- so with one shared directory the first
# `expect=fail` row ran the unmutated baseline binary and reported "expected fail, got
# pass". Correctness must not depend on the order of `cp` and `cargo` in time; a private
# directory per row costs one rebuild of the crate per row (its dependencies are
# small) and cannot.
# `CARGO_TARGET_DIR` is passed per invocation rather than exported, so no state leaks
# between rows.

# Sources only. `Cargo.toml` names its benchmark targets explicitly, so `benches/`
# has to come along or the manifest does not resolve at all.
copy_tree() {
  mkdir -p "$1"
  cp -r src tests benches Cargo.toml Cargo.lock "$1/" 2>/dev/null || true
  cp -r src tests benches Cargo.toml Cargo.lock "$1/"
}

# Require the run's log to show that tests actually ran.
#
# `cargo test -- <filter>` whose filter matches nothing prints "0 passed; ... N filtered
# out" and exits 0, so an argument that silently became a *name filter* turns the row into a
# vacuous OK. Measured, and the reason this guard exists: the `dual-mac-blocks-tag-
# substitution` row passed the bare word `ultra` instead of `--features ultra`, so it was
# `cargo test --test decision ultra` -- zero tests, exit 0, verdict OK, for as long as the
# row existed. Every row now has to show a test count.
assert_tests_ran() {  # <log> <row name>
  local log="$1" name="$2"
  local line
  line="$(grep -E '^test result:' "$log" | tail -1 || true)"
  if [ -z "$line" ]; then
    printf 'FAIL %-22s no "test result" line in the log, so cargo test never ran a test\n' "$name" >&2
    printf '                        binary -- see %s\n' "$log" >&2
    exit 1
  fi
  local passed failed
  passed="$(printf '%s' "$line" | sed -n 's/.* \([0-9]\+\) passed.*/\1/p')"
  failed="$(printf '%s' "$line" | sed -n 's/.* \([0-9]\+\) failed.*/\1/p')"
  if [ "${passed:-0}" -eq 0 ] && [ "${failed:-0}" -eq 0 ]; then
    printf 'FAIL %-22s the filter matched no tests (%s), so this row proves nothing\n' \
      "$name" "$line" >&2
    exit 1
  fi
}

# A clean baseline, cached per (features, test target): the detector must PASS on an
# unmutated tree, or an `expect=fail` row below could be satisfied by a detector that was
# already failing for an unrelated reason. Cached because copying and building the tree
# is the expensive part of this campaign, and several rows share a configuration.
declare -A BASELINE_PASSES=()
baseline_passes() {  # <features> <test target>
  local key="$1|$2"
  if [ -z "${BASELINE_PASSES[$key]:-}" ]; then
    local dir="$WORK/baseline-$(printf '%s' "$key" | tr -c 'a-zA-Z0-9' '_')"
    copy_tree "$dir"
    local args=(--quiet --release --test "$2")
    if [ -n "$1" ]; then
      # shellcheck disable=SC2206
      args+=($1)
    fi
    if ( cd "$dir" && CARGO_TARGET_DIR="$dir/target" cargo test "${args[@]}" ) > "$WORK/baseline.log" 2>&1; then
      assert_tests_ran "$WORK/baseline.log" "baseline($key)"
      BASELINE_PASSES[$key]=yes
    else
      BASELINE_PASSES[$key]=no
    fi
  fi
  [ "${BASELINE_PASSES[$key]}" = yes ]
}

# A row: run <name> <features> <detector test target> <expected: pass|fail> <patch fn>
run_row() {
  local name="$1" features="$2" target="$3" expect="$4" patch="$5"
  local dir="$WORK/$name"
  copy_tree "$dir"
  "$patch" "$dir"
  local args=(--quiet --release --test "$target")
  if [ -n "$features" ]; then
    # A raw cargo flag string, so a row can ask for the opt-out configuration
    # (`--no-default-features`) as well as a feature set: `hardened` is on by
    # default, so "the plain decision" is now a *removal*, not an addition.
    # shellcheck disable=SC2206
    args+=($features)
  fi

  # The patch has to leave a tree that BUILDS. "The detector failed" must mean the test
  # failed, not that the planted change did not compile -- for the `expect=fail` rows that
  # distinction *is* the row, and an audit turned `branch-forced` green by replacing the
  # semantic patch with a `compile_error!`, since any non-zero `cargo test` exit was read
  # as detection.
  if ! ( cd "$dir" && CARGO_TARGET_DIR="$dir/target" cargo test --no-run "${args[@]}" ) > "$WORK/$name.build.log" 2>&1; then
    printf 'FAIL %-22s the mutated tree does not build, so the detector never ran\n' "$name" >&2
    printf '                        -- see %s\n' "$LOG_KEEP/$name.build.log" >&2
    tail -20 "$WORK/$name.build.log" >&2
    exit 1
  fi

  # ...and an `expect=fail` row additionally needs the detector to be capable of passing
  # on an unmutated tree, or it would "detect" a pre-existing failure.
  if [ "$expect" = "fail" ] && ! baseline_passes "$features" "$target"; then
    printf 'FAIL %-22s the detector already fails on an UNMUTATED tree, so this row\n' "$name" >&2
    printf '                        would pass vacuously -- see %s\n' "$LOG_KEEP/baseline.log" >&2
    exit 1
  fi

  local got=pass
  if ! ( cd "$dir" && CARGO_TARGET_DIR="$dir/target" cargo test "${args[@]}" ) > "$WORK/$name.log" 2>&1; then
    got=fail
  fi
  assert_tests_ran "$WORK/$name.log" "$name"
  if [ "$got" = "$expect" ]; then
    printf '  OK   %-22s %-22s %s (detector %s)\n' "$name" "$features" "$expect" "$target"
    return 0
  fi
  printf '  FAIL %-22s expected %s, got %s -- see %s\n' "$name" "$expect" "$got" "$LOG_KEEP/$name.log" >&2
  tail -20 "$WORK/$name.log" >&2
  exit 1
}

# ── patches ────────────────────────────────────────────────────────────────
patch_none() { :; }

# One neutralised branch, on the first gate. In the default build that branch *is*
# the decision -- the second gate is compiled out there -- so the forgery goes
# through; in the `hardened` build it is gate 0, and gate 1 has to reject. One edit,
# two rows, and the pair is the point: the first row is this campaign's "the fault is
# real" evidence, the second is what the second gate buys.
patch_first_gate_neutralised() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
# "This gate passes whatever its comparison said" -- what a corrupted comparison or a
# skipped branch amounts to. `true`, not `false &&`: the gate writes a slot now, so
# forcing it to reject would prove nothing about a forgery getting through.
old = "    if bool::from(gate0) {"
assert s.count(old) == 1, f"gate0 sites: {s.count(old)}"
open(p, "w").write(s.replace(old, "    if true {", 1))
PY
}

# The call site's serial checks: one neutralised is not enough (the other still
# rejects), both is (and that is two faults).
#
# The patterns are anchored on a leading newline so they name the *decrypt* call sites
# only. There is a third pair of checks -- `ultra`'s encrypt-side cross-check, indented
# one level deeper inside its `#[cfg(feature = "ultra")]` block -- and an unanchored
# four-space pattern matches inside it too, which is why the assertion below reported
# "first-check sites: 3" the first time this ran after that site was added. It is not
# patched here: a fault that neutralises *it* makes `encrypt` hand out a ciphertext the
# peer will refuse, which is availability rather than authenticity, and every forgery
# row here is about the decrypt decision.
patch_first_check_neutralised() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "\n    if decision0.is_err() {"
assert s.count(old) == 2, f"decrypt first-check sites: {s.count(old)}"
open(p, "w").write(s.replace(old, "\n    if false && decision0.is_err() {", 1))
PY
}

patch_both_checks_neutralised() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
for old in ("\n    if decision0.is_err() {", "\n    if decision1.is_err() {"):
    assert s.count(old) == 2, f"{old!r}: {s.count(old)}"
    s = s.replace(old, "\n    if false {")
open(p, "w").write(s)
PY
}
# The names the campaign rows below use; both are this one edit, because the source
# has one decision body (see the comment on `accept_or_reject`).
patch_branch_accept() { patch_first_gate_neutralised "$@"; }
patch_gate0_branch() { patch_first_gate_neutralised "$@"; }

patch_gate0_value() {  # the first gate's comparison result is corrupted, not its branch
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
# One site per decrypt entry point. This count is also the guard on the
# *duplication*: `hardened` gets its strength from the two gates being two
# computations, so the expression has to appear once per entry point. A refactor
# that shares one gate between both entry points -- or between the two gates of one
# entry point -- fails here instead of quietly leaving a gate that is decoration.
old = "        let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);"
assert s.count(old) == 2, f"first-gate expressions: {s.count(old)}"
open(p, "w").write(s.replace(old, "        let first = subtle::Choice::from(1u8);", 1))
PY
}

# The same fault as `patch_gate0_value`, with the second gate turned into a *copy*
# of the first. The forgery is then accepted, and that is the point of the pair of
# rows: `gate0-value-forced` passes because the second gate is a recomputation, and
# this one fails because it is not. Together they show the recomputation is what
# does the work, rather than the presence of two `if` statements.
patch_gates_shared() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
first = "        let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);"
assert s.count(first) == 2, f"first-gate expressions: {s.count(first)}"
s = s.replace(first, "        let first = subtle::Choice::from(1u8);", 1)

# The second gate, whose text moved when the two cfg arms appeared (see the comment in
# src/lib.rs): the patch replaces the shared binding's *guard* so the two `if`s read one
# value, which is the fault this row models.
second = """        let second = gate_pair;
"""
assert s.count(second) == 2, f"second gates: {s.count(second)}"
s = s.replace(second, "        let second = first;\n", 1)
open(p, "w").write(s)
PY
}

# The attack `dual-mac` exists for: make the stored tag equal the received one. Every
# gate then compares two equal values and is satisfied -- unless a second, independent
# computation disagrees, which is what this patch leaves in place.
patch_recomputed_tag_ignored() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    let mut computed_tag = derive_tag(&k_in, &k_out, nonce, aad, &plaintext);"
assert s.count(old) == 1, f"computed_tag sites: {s.count(old)}"
open(p, "w").write(s.replace(old, "    let mut computed_tag = *tag;", 1))
PY
}

# The fault the gates structurally cannot see: make the tag stop depending on the message.
# `encrypt` and `decrypt` run the same broken function, so they still agree with each other,
# every gate finds computed == received, and `dual-mac`'s recomputation goes through the same
# function and agrees as well. What breaks is commitment: one observed tag then authenticates
# any ciphertext under that (key, nonce, aad). `ultra`'s independent implementation is a
# different program whose tag does commit, so it disagrees and the forgery is rejected.
patch_message_independent_mac() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    msg: &[u8],\n) -> [u8; TAG_LEN] {\n"
assert s.count(old) == 1, f"derive_tag signature sites: {s.count(old)}"
# Shadow the parameter: everything downstream keeps working, on the empty message.
s = s.replace(old, old + "    // PLANTED: the message no longer reaches the tag.\n    let msg: &[u8] = &[];\n", 1)
open(p, "w").write(s)
PY
}

patch_tag_replaced() {  # the tag computation is faulted away entirely
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    let mut computed_tag = derive_tag(&k_in, &k_out, nonce, aad, &plaintext);"
assert s.count(old) == 1, f"computed_tag: {s.count(old)}"
open(p, "w").write(s.replace(old, "    let mut computed_tag = *tag;", 1))
PY
}

# The *in-place* failure path's wipe, which is the one a test can observe: the
# buffer is the caller's, so leaving the unverified plaintext in it is visible.
#
# The wipes live in the *callers*, after each serial check (`zeroize_slice(buffer)`
# in the two decrypt entry points); `accept_or_reject` itself does not wipe. An
# earlier revision of this comment said the decision wiped on rejection, which was
# the shape before the wipes moved to the call sites. A fault that skips the
# decision call never reaches the earlier one, so this patch removes every
# `zeroize_slice(buffer);` site; removing only one would leave a defect that is not
# a defect, and the row would read "expected fail, got pass" (which is how the
# first version of this row failed, on a wipe no test could see).
#
# The allocating path (`decrypt`) wipes its plaintext before dropping it, and that
# one is *not* in this campaign because no test can see it: the memory is freed
# either way, so a skipped wipe there is only detectable by reading the code.
patch_wipe_skipped() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    zeroize_slice(buffer);"
# The 4-space pattern also matches inside the 8-space one, so this covers the
# decision's wipes and the entry point's in one pass.
assert s.count(old) >= 2, f"in-place wipe sites: {s.count(old)}"
# The replacement has to COMPILE. `let _ = &mut buffer;` was here and does not: the
# parameter is `buffer: &mut [u8]` and the *binding* is not declared `mut`, so taking
# `&mut buffer` is E0596 ("cannot borrow as mutable, as it is not declared as mutable").
# Nothing built, and because this row's detector "failed" by failing to compile, the row
# reported OK while testing nothing. The build check in `run_row` is what flushed that
# out; `core::hint::black_box(&mut buffer)` fails for the same reason, so the no-op is a
# read of the slice instead.
open(p, "w").write(s.replace(old, "    let _ = buffer.len();"))
PY
}

# ── the campaign ───────────────────────────────────────────────────────────
LOG_KEEP="$WORK"
echo "fault-injection campaign over the accept/reject decision:"
echo

# The detector must be satisfiable on a clean hardened build, or the rows below
# would be measuring a test that fails for unrelated reasons.
run_row clean-hardened      "--features hardened"      decision pass patch_none
run_row clean-plain         "--no-default-features"    decision pass patch_none

# Unhardened decision, one skipped instruction: the forgery goes through. This is
# what the hardening is for, and it is also this campaign's "the fault is real"
# evidence -- if it ever stops failing, the rows below mean less.
run_row branch-forced       "--no-default-features"    decision fail patch_branch_accept

# Hardened decision, the same single fault, and a corrupted gate *value* rather
# than a skipped branch: the other gate has to reject both times.
run_row gate0-branch-skipped "--features hardened"      decision pass patch_gate0_branch
run_row gate0-value-forced   "--features hardened"      decision pass patch_gate0_value

# ...and the same corrupted value with the second gate reduced to a copy of the
# first: the forgery is accepted. This row is why the one above means something --
# it shows the *recomputation* is what rejects the forgery, not the mere presence of
# a second `if`. Without it, "two gates" would be a claim about the source text.
run_row gates-shared         "--features hardened"      decision fail patch_gates_shared

# Known limit, pinned: if the computed tag *is* the received tag, both gates are
# satisfied. Expressed as a source change because a fault model at this level has
# nothing better; a memory fault that achieves the same on real silicon is what the
# README's "not defended" row is about.
run_row computed-tag-replaced "--features hardened"     decision fail patch_tag_replaced

# The call site, one check at a time and then both: the first row is what the two-slot
# shape buys (the second check still rejects), the second is the same attack with two
# faults, which no software measure defends against and which is pinned rather than
# left implicit.
run_row one-check-neutralised  "--features hardened"  decision pass patch_first_check_neutralised
run_row both-checks-neutralised "--features hardened" decision fail patch_both_checks_neutralised

# `dual-mac`: the same stored-tag substitution, on a build that recomputes the tag
# independently. The recomputation disagrees with the substituted value, so the forgery
# is *rejected* -- which is the whole return on the feature's cost, and the reason a
# `ultra` user gets something the default build does not. (Without `dual-mac` the row
# above shows the opposite: both builds accept it.)
#
# The feature argument is `--features ultra`, not `ultra`: this row carried the bare word
# for as long as it existed, which made it `cargo test --test decision ultra` -- `ultra` is
# then a *test-name filter*, zero tests ran, and the row reported OK without testing
# anything (an audit found it; `assert_tests_ran` above is the guard).
run_row dual-mac-blocks-tag-substitution "--features ultra" decision pass patch_recomputed_tag_ignored

# ...and the same fault with the witness *removed*. `ultra` implies `dual-mac`, so the row
# above passes even if `dual-mac`'s recomputation were dead -- the independent
# implementation would reject the substitution on its own, and the row would read as
# evidence for `dual-mac` when it was really evidence for the witness. This row runs on
# `hardened,dual-mac` (no witness), so only the recomputation can reject it; together the
# two rows isolate each layer's contribution.
run_row dual-mac-isolated "--features hardened,dual-mac" decision pass patch_recomputed_tag_ignored

# The pair that shows what a *second implementation* buys, and what it does not: the same
# message-independent MAC fault, which the gates and `dual-mac` cannot see (they recompute
# through the broken function), and which `ultra`'s independent implementation catches because
# it is a different program whose tag commits to the message.
run_row msg-independent-mac-hardened "--features hardened,dual-mac" mac_commitment fail patch_message_independent_mac
run_row msg-independent-mac-witness  "--features ultra"             mac_commitment pass patch_message_independent_mac

# Defensive, not about forgery: a skipped wipe is a defect the security test catches.
run_row wipe-skipped        "--no-default-features"    security fail patch_wipe_skipped

echo
echo "campaign complete: every row behaved as documented"
