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
trap 'rm -rf "$WORK"' EXIT
# One target directory for every row: only the local crate is rebuilt each time.
export CARGO_TARGET_DIR="$WORK/target"

# Sources only. `Cargo.toml` names its benchmark targets explicitly, so `benches/`
# has to come along or the manifest does not resolve at all.
copy_tree() {
  mkdir -p "$1"
  cp -r src tests benches Cargo.toml Cargo.lock "$1/" 2>/dev/null || true
  cp -r src tests benches Cargo.toml Cargo.lock "$1/"
}

# A row: run <name> <features> <detector test target> <expected: pass|fail> <patch fn>
run_row() {
  local name="$1" features="$2" target="$3" expect="$4" patch="$5"
  local dir="$WORK/$name"
  copy_tree "$dir"
  "$patch" "$dir"
  local args=(--quiet --release --test "$target")
  [ -n "$features" ] && args+=(--features "$features")
  local got=pass
  if ! ( cd "$dir" && cargo test "${args[@]}" ) > "$WORK/$name.log" 2>&1; then
    got=fail
  fi
  if [ "$got" = "$expect" ]; then
    printf '  OK   %-22s %-9s %s (detector %s)\n' "$name" "$features" "$expect" "$target"
    return 0
  fi
  printf '  FAIL %-22s expected %s, got %s -- see %s\n' "$name" "$expect" "$got" "$LOG_KEEP/$name.log" >&2
  tail -20 "$WORK/$name.log" >&2
  exit 1
}

# ── patches ────────────────────────────────────────────────────────────────
patch_none() { :; }

patch_branch_accept() {  # one skipped instruction on the unhardened decision
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    if bool::from(auth_ok) {"
assert s.count(old) == 2, f"decision sites: {s.count(old)}"
# First occurrence only: one fault, on the allocating entry point.
open(p, "w").write(s.replace(old, "    if true || bool::from(auth_ok) {", 1))
PY
}

patch_gate0_branch() {  # one skipped instruction on the hardened decision
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "        if !bool::from(gates.0) {"
assert s.count(old) == 2, f"gate0 sites: {s.count(old)}"
open(p, "w").write(s.replace(old, "        if false && !bool::from(gates.0) {", 1))
PY
}

patch_gate0_value() {  # the first gate's comparison result is corrupted, not its branch
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "        computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag),\n"
assert s.count(old) == 4, f"gate expressions: {s.count(old)}"
open(p, "w").write(s.replace(old, "        subtle::Choice::from(1u8),\n", 1))
PY
}

patch_tag_replaced() {  # the tag computation is faulted away entirely
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    let mut computed_tag = derive_tag(&mac_key, key, nonce, aad, &plaintext);"
assert s.count(old) == 1, f"computed_tag: {s.count(old)}"
open(p, "w").write(s.replace(old, "    let mut computed_tag = *tag;", 1))
PY
}

# The *in-place* failure path's wipe, which is the one a test can observe: the
# buffer is the caller's, so leaving the unverified plaintext in it is visible.
#
# The allocating path (`decrypt`) wipes its plaintext before dropping it, and that
# one is *not* in this campaign because no test can see it: the memory is freed
# either way, so a skipped wipe there is only detectable by reading the code. Saying
# so here is the point -- the first version of this row mutated that unreachable one
# and the campaign reported "expected fail, got pass", which is exactly what a
# mutation nothing can catch looks like.
patch_wipe_skipped() {
  python3 - "$1/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "        zeroize_slice(buffer);"
assert s.count(old) >= 1, "in-place wipe sites"
open(p, "w").write(s.replace(old, "        let _ = &mut buffer;"))
PY
}

# ── the campaign ───────────────────────────────────────────────────────────
LOG_KEEP="$WORK"
echo "fault-injection campaign over the accept/reject decision:"
echo

# The detector must be satisfiable on a clean hardened build, or the rows below
# would be measuring a test that fails for unrelated reasons.
run_row clean-hardened      "hardened" decision    pass patch_none
run_row clean-default       ""         decision    pass patch_none

# Unhardened decision, one skipped instruction: the forgery goes through. This is
# what the hardening is for, and it is also this campaign's "the fault is real"
# evidence -- if it ever stops failing, the rows below mean less.
run_row branch-forced       ""         decision    fail patch_branch_accept

# Hardened decision, the same single fault, and a corrupted gate *value* rather
# than a skipped branch: the other gate has to reject both times.
run_row gate0-branch-skipped "hardened" decision   pass patch_gate0_branch
run_row gate0-value-forced   "hardened" decision   pass patch_gate0_value

# Known limit, pinned: if the computed tag *is* the received tag, both gates are
# satisfied. Expressed as a source change because a fault model at this level has
# nothing better; a memory fault that achieves the same on real silicon is what the
# README's "not defended" row is about.
run_row computed-tag-replaced "hardened" decision  fail patch_tag_replaced

# Defensive, not about forgery: a skipped wipe is a defect the security test catches.
run_row wipe-skipped        ""         security    fail patch_wipe_skipped

echo
echo "campaign complete: every row behaved as documented"
