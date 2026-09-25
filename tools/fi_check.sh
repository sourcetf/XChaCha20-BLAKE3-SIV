#!/usr/bin/env bash
#
# Fault-injection check of the accept/reject decision: write the fault down, apply
# it to both builds, and require the outcomes to differ.
#
# This is not a mutation check looking for a bug. It fixes a fault *model* -- "the
# first accept/reject test always passes", which is what a glitch that skips one
# instruction leaves behind -- and then:
#
#   hardened, clean        -> tests/decision.rs MUST PASS  (the test is satisfiable)
#   default  + fault       -> tests/decision.rs MUST FAIL  (the forgery is accepted)
#   hardened + same fault  -> tests/decision.rs MUST PASS  (the second gate rejects)
#
# The middle one is the point: it shows the fault is real rather than hypothetical,
# which is what makes the third meaningful. If the middle one ever stops failing,
# this check reports that it has gone vacuous instead of quietly passing.
#
# What this is not: validation against a real glitch. Nothing here substitutes for
# a fault-injection bench, and the README says so.
#
# Usage:  tools/fi_check.sh
# Exit codes: 0 = all three configurations behaved as expected; 1 = otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Sources only; one shared target directory so the dependencies are built once.
# `Cargo.toml` names its benchmark targets explicitly, so `benches/` has to come
# along or the manifest does not resolve at all.
copy_tree() {
  mkdir -p "$1"
  cp -r src tests benches examples Cargo.toml Cargo.lock "$1/" 2>/dev/null || true
  cp -r src tests benches Cargo.toml Cargo.lock "$1/"
}
export CARGO_TARGET_DIR="$WORK/target"

run_decision() {  # dir, extra cargo args...
  local dir="$1"; shift
  ( cd "$dir" && cargo test --quiet --release "$@" --test decision >/dev/null 2>&1 )
}

# 0. The test must be satisfiable on a clean hardened build, or the two runs below
#    would be measuring nothing.
dir="$WORK/clean"; copy_tree "$dir"
if run_decision "$dir" --features hardened; then
  echo "OK   hardened, no fault: forgeries rejected"
else
  echo "FAIL hardened build fails tests/decision.rs with no fault injected" >&2
  exit 1
fi

# 1. The unhardened decision: one skipped instruction accepts a forgery. If this
#    ever passes, the fault has stopped being real and the check is vacuous.
dir="$WORK/default"; copy_tree "$dir"
python3 - "$dir/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "    if bool::from(auth_ok) {"
assert s.count(old) == 2, f"expected 2 decision sites, found {s.count(old)}"
open(p, "w").write(s.replace(old, "    if true || bool::from(auth_ok) {"))
PY
if run_decision "$dir"; then
  echo "FAIL with the decision forced to accept, tests/decision.rs still passed." >&2
  echo "     The fault is no longer real, so its survival on the hardened build" >&2
  echo "     would prove nothing. Look at how the decision is written now." >&2
  exit 1
fi
echo "OK   default build, one gate skipped: forgery accepted (the fault is real)"

# 2. The hardened decision: the *same* single fault must not be enough.
dir="$WORK/hardened"; copy_tree "$dir"
python3 - "$dir/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "        if !bool::from(gates.0) {"
assert s.count(old) == 2, f"expected 2 first-gate sites, found {s.count(old)}"
open(p, "w").write(s.replace(old, "        if false && !bool::from(gates.0) {"))
PY
if run_decision "$dir" --features hardened; then
  echo "OK   hardened build, same fault: forgery still rejected"
else
  echo "FAIL one skipped gate was enough to accept a forgery on the hardened build" >&2
  exit 1
fi

echo "fault-injection check: as expected in all three configurations"
