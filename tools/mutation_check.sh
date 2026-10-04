#!/usr/bin/env bash
#
# Verify the verifier: inject a known bug into a throwaway copy of the tree and
# require a *named check* to fail.
#
# Why this exists: the ctgrind harness once passed while being completely
# vacuous -- its negative control was compiled into a branchless `setcc` that
# memcheck does not report, and the "must exit 99" check was satisfied by
# unrelated startup noise. Nothing in a normal green run could reveal that. A
# mutation check can: if the check still passes with a deliberate
# constant-time leak in the tree, the check is not measuring anything.
#
# Each mutation names the check that must catch it, so a failure here means
# either the mutation stopped applying (the source moved) or the check stopped
# working. Both need a human.
#
# Usage:  tools/mutation_check.sh            # all mutations
#         tools/mutation_check.sh ctgrind    # one of them
#
# Exit codes: 0 all mutations were caught; 1 one was not (or could not be applied);
#             3 a mutation could not be *run* (no valgrind), which is not the same as
#             caught and must not be reported as "all mutations were caught".
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Copy the sources only: the build artefacts are worth nothing here and would
# make the copy slow.
copy_tree() {
  local dest="$1"
  mkdir -p "$dest"
  cp -r src tests tools Cargo.toml Cargo.lock benches "$dest/"
}

# 1. Secret-dependent comparison in both decrypt paths. `ctgrind` must report it.
mutate_ctgrind() {
  local dir="$1"
  python3 - "$dir" <<'PY'
import sys
p = sys.argv[1] + "/src/lib.rs"
s = open(p).read()
old = "let auth_ok = computed_tag.ct_eq(tag);"
new = "let auth_ok = subtle::Choice::from((computed_tag == *tag) as u8);"
assert s.count(old) == 2, f"expected 2 sites, found {s.count(old)}"
open(p, "w").write(s.replace(old, new))
PY
}

# 2. A changed domain separator. The KATs and the differential fixture must fail.
mutate_kat() {
  local dir="$1"
  python3 - "$dir" <<'PY'
import sys
p = sys.argv[1] + "/src/lib.rs"
s = open(p).read()
old = 'pub const SUBKEY_DOMAIN: [u8; 4] = *b"XSIV";'
assert old in s, "SUBKEY_DOMAIN declaration moved"
open(p, "w").write(s.replace(old, 'pub const SUBKEY_DOMAIN: [u8; 4] = *b"XSIX";'))
PY
}

run_ctgrind() {
  local dir="$1"
  # Valgrind first, before the build: the driver's preflight already answers 3 when
  # none is found, but one that exists and *cannot start* (a broken extracted copy,
  # a missing VALGRIND_LIB) used to be read as "the mutation was not caught" -- the
  # one classification this tool must not confuse, since it is about the detector,
  # not the environment.
  local vg
  vg="$(find_valgrind)"
  if [ -z "$vg" ]; then
    echo "SKIPPED: no valgrind found (see tools/ctgrind.sh --setup)" >&2
    return 3
  fi
  if [ -d "$HOME/valgrind/usr/libexec/valgrind" ]; then
    export VALGRIND_LIB="${VALGRIND_LIB:-$HOME/valgrind/usr/libexec/valgrind}"
  fi
  if ! "$vg" --version >/dev/null 2>&1; then
    echo "SKIPPED: $vg exists but cannot start (missing VALGRIND_LIB? see tools/ctgrind.sh --setup)" >&2
    return 3
  fi
  ( cd "$dir"
    local bin
    # Ask cargo for the executable rather than globbing the deps directory: `ls -t` takes
    # the newest match, which is the binary just built only by an ordering this script
    # would be relying on silently. (Same fix as `tools/ctgrind.sh`, where a glob picked up
    # the self-test's planted binary.)
    bin="$(CARGO_TARGET_DIR="$dir/target-ctgrind" \
             RUSTFLAGS="-C target-feature=+crt-static -C strip=none" \
             cargo test --release --target x86_64-unknown-linux-gnu --test ctgrind --no-run \
               --no-default-features --message-format=json 2>/dev/null \
           | python3 -c '
import json, sys
exes = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
       and (m.get("target") or {}).get("name") == "ctgrind":
        exes.append(m["executable"])
print(exes[-1] if exes else "")
')"
    [ -n "$bin" ] || { echo "could not build the ctgrind binary"; return 2; }
    # The same classification the real check uses: a report inside this crate
    # means the leak was seen.
    local out
    out="$("$vg" --quiet --suppressions=tests/ctgrind.supp "$bin" \
      --test-threads=1 encrypt_does_not_branch_on_secrets \
      decrypt_does_not_branch_on_secrets encrypt_in_place_does_not_branch_on_secrets \
      constant_time_eq_does_not_branch_on_operands 2>&1 || true)"
    case "$out" in
      *xchacha20_blake3_siv*) return 1 ;;   # caught: the check would fail
      *) return 0 ;;                        # not caught
    esac
  )
}

# The valgrind to use, or nothing. One function so the preflight in the driver and the
# check itself cannot disagree.
#
# An explicit `VALGRIND=` is honoured *strictly*, the same rule as `tools/ctgrind.sh`: if
# it is set, it is the only candidate, so an unusable value means "could not run" rather
# than a cue to fall through to a system valgrind. Without that, the hiding
# `tools/gate_selftest.sh` does with `VALGRIND=/nonexistent` would be defeated on a
# machine that has one, and the control would report a tool defect that is really a hole
# in the control.
find_valgrind() {
  if [ -n "${VALGRIND:-}" ]; then
    [ -x "$VALGRIND" ] && printf '%s\n' "$VALGRIND"
    return 0
  fi
  local c
  for c in "$HOME/valgrind/usr/bin/valgrind" "$(command -v valgrind 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 0
}

# Returns 1 when the suite fails (the mutation was caught), 0 when it passes.
# The driver's convention is "1 = caught", so cargo's own exit status is mapped
# rather than passed through -- cargo reports 101 for a failing test run, which
# would otherwise read as an unrelated error.
#
# 2 means "the mutated tree does not build". That is *not* a caught mutation: the
# detector never ran, and collapsing a compile error into "caught" is how this row
# could report success while checking nothing (an audit pointed it out). The build is
# therefore separated from the run.
run_kat() {
  local dir="$1"
  ( cd "$dir" && CARGO_TARGET_DIR="$dir/target-kat" \
      cargo test --release --lib --no-run >/dev/null 2>&1 ) || return 2
  local status=0
  ( cd "$dir" && CARGO_TARGET_DIR="$dir/target-kat" cargo test --release --lib >/dev/null 2>&1 ) || status=$?
  if [ "$status" -eq 0 ]; then return 0; fi
  return 1
}

check_one() {
  local name="$1" mutation="$2" check="$3"
  local dir="$WORK/$name"
  echo "--- $name ---"
  echo "    mutation: $4"
  echo "    must be caught by: $check"
  # Baseline first: the check must PASS on an unmutated copy. Without it a "caught"
  # verdict cannot be interpreted -- the check could be failing for a reason of its own
  # (an unbuildable tree, a pre-existing test failure, a broken suppression), which
  # would make every mutation look caught. `run_kat` in particular mapped *any*
  # non-zero exit to "caught", so a patch that only broke the build passed this row.
  copy_tree "$dir.baseline"
  set +e
  "$check" "$dir.baseline"
  local base=$?
  set -e
  case "$base" in
    3) echo "    could not run the baseline (tooling unavailable)"; return 3 ;;
    0) echo "    baseline: $check passes on the unmutated tree" ;;
    *) echo "FAIL: $check does not pass on an UNMUTATED tree (exit $base), so a" >&2
       echo "      'caught' verdict for $name would be meaningless. Fix the check" >&2
       echo "      before trusting this row." >&2
       return 1 ;;
  esac
  copy_tree "$dir"
  set +e
  "$mutation" "$dir"
  local patch_status=$?
  set -e
  if [ "$patch_status" -ne 0 ]; then
    echo "FAIL: the mutation for $name could not be applied (patch exited $patch_status," >&2
    echo "      which usually means its anchor moved in the source). The header lists" >&2
    echo "      this as exit 1: it is neither 'caught' nor 'not caught'." >&2
    return 1
  fi
  set +e
  "$check" "$dir"
  local status=$?
  set -e
  case "$status" in
    1) echo "    ok: caught" ;;
    2) echo "FAIL: the mutated tree does not build, so $check never ran and this row" >&2
       echo "      proves nothing. A mutation must be a semantic fault, not a syntax one." >&2
       return 1 ;;
    # `return 3`, not a bare `echo`: the driver distinguishes "not caught" from
    # "could not run", and a skip that returns 0 makes the whole tool report
    # "all mutations were caught" without having tested anything.
    3) echo "    could not run (tooling unavailable)"; return 3 ;;
    *) echo "FAIL: $name was NOT caught by $check. Either the mutation no longer" >&2
       echo "      applies or $check stopped working -- both need a human." >&2
       return 1 ;;
  esac
}

want="${1:-all}"
case "$want" in
  all|ctgrind|kat) ;;
  *)
    echo "FAIL: unknown mutation '$want' (want all, ctgrind or kat)" >&2
    # Without this the two `if`s below match nothing, nothing runs, and the tool
    # reports "all mutations were caught" -- a green verdict for no work at all.
    exit 1 ;;
esac
rc=0
skipped=0
if [ "$want" = "all" ] || [ "$want" = "ctgrind" ]; then
  # Preflight, so "no valgrind" answers exit 3 *before* the baseline copy, its build and
  # the mutation's build. The lookup cannot disagree with `run_ctgrind`'s because both
  # call `find_valgrind`. It also keeps `tools/gate_selftest.sh` cheap: it hides valgrind,
  # and without this it would pay two full builds to learn what it already knows.
  if [ -z "$(find_valgrind)" ]; then
    echo "--- ctgrind ---"
    echo "    SKIPPED: no valgrind found (see tools/ctgrind.sh --setup); not running the"
    echo "    baseline or the mutation."
    skipped=$((skipped + 1))
  else
    # `|| status=$?` rather than `set +e; check_one ...; status=$?; set -e`: `check_one`
    # turns errexit back on inside itself (and the `set -e` there is shell-wide), so a
    # failing `return` used to terminate the driver on the spot -- before the
    # classification below and before the "failure comes first" summary at the end.
    # The `||` list is an errexit-exempt context, so the verdict survives to be
    # classified.
    status=0
    check_one ctgrind mutate_ctgrind run_ctgrind \
      "ct_eq -> == in both decrypt paths" || status=$?
    # `check_one` answers 1 for "not caught" and 3 for "could not run": the first is a
    # finding about the check, the second is a gap in it, and collapsing them into one
    # exit status is how a skipped run becomes a green one.
    if [ "$status" -eq 3 ]; then skipped=$((skipped + 1)); elif [ "$status" -ne 0 ]; then rc=1; fi
  fi
fi
if [ "$want" = "all" ] || [ "$want" = "kat" ]; then
  status=0
  check_one kat mutate_kat run_kat "SUBKEY_DOMAIN XSIV -> XSIX" || status=$?
  if [ "$status" -eq 3 ]; then skipped=$((skipped + 1)); elif [ "$status" -ne 0 ]; then rc=1; fi
fi
# The failure comes first. This used to exit 3 whenever anything was skipped, which
# swallowed a real "NOT caught" into the exit-3 "tooling unavailable" the callers record
# as a skipped stage -- the one direction this repository refuses.
if [ "$rc" -ne 0 ]; then
  echo
  echo "one or more mutations were NOT caught" >&2
  if [ "$skipped" -gt 0 ]; then
    echo "($skipped other mutation(s) could not be run here; that is a gap in this" >&2
    echo " check, not a pass)" >&2
  fi
  exit "$rc"
fi
if [ "$skipped" -gt 0 ]; then
  echo
  echo "$skipped mutation(s) could not be run (tooling unavailable): that is a gap" >&2
  echo "in this check, not a pass." >&2
  exit 3
fi
echo
echo "all mutations were caught"
exit 0
