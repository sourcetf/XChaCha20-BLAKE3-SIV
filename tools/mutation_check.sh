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
# Exit codes: 0 all mutations were caught; 1 one was not (or could not be applied).
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
  ( cd "$dir"
    CARGO_TARGET_DIR="$dir/target-ctgrind" \
      RUSTFLAGS="-C target-feature=+crt-static -C strip=none" \
      cargo test --release --target x86_64-unknown-linux-gnu --test ctgrind --no-run >/dev/null 2>&1
    local bin
    bin="$(ls -t "$dir"/target-ctgrind/x86_64-unknown-linux-gnu/release/deps/ctgrind-* 2>/dev/null | grep -vE '\.(d|o)$' | head -1)"
    [ -n "$bin" ] || { echo "could not build the ctgrind binary"; return 2; }
    # The same classification the real check uses: a report inside this crate
    # means the leak was seen.
    local vg
    vg=""
    for c in "${VALGRIND:-}" "$HOME/valgrind/usr/bin/valgrind" "$(command -v valgrind 2>/dev/null || true)"; do
      if [ -n "$c" ] && [ -x "$c" ]; then vg="$c"; break; fi
    done
    if [ -z "$vg" ]; then
      echo "SKIPPED: no valgrind found (see tools/ctgrind.sh --setup)" >&2
      return 3
    fi
    if [ -d "$HOME/valgrind/usr/libexec/valgrind" ]; then
      export VALGRIND_LIB="$HOME/valgrind/usr/libexec/valgrind"
    fi
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

# Returns 1 when the suite fails (the mutation was caught), 0 when it passes.
# The driver's convention is "1 = caught", so cargo's own exit status is mapped
# rather than passed through -- cargo reports 101 for a failing test run, which
# would otherwise read as an unrelated error.
run_kat() {
  local dir="$1"
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
  copy_tree "$dir"
  "$mutation" "$dir"
  set +e
  "$check" "$dir"
  local status=$?
  set -e
  case "$status" in
    1) echo "    ok: caught" ;;
    3) echo "    SKIPPED (tooling unavailable)" ;;
    *) echo "FAIL: $name was NOT caught by $check. Either the mutation no longer" >&2
       echo "      applies or $check stopped working -- both need a human." >&2
       return 1 ;;
  esac
}

want="${1:-all}"
rc=0
if [ "$want" = "all" ] || [ "$want" = "ctgrind" ]; then
  check_one ctgrind mutate_ctgrind run_ctgrind \
    "ct_eq -> == in both decrypt paths" || rc=1
fi
if [ "$want" = "all" ] || [ "$want" = "kat" ]; then
  check_one kat mutate_kat run_kat "SUBKEY_DOMAIN XSIV -> XSIX" || rc=1
fi
if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations were caught"
else
  echo
  echo "one or more mutations were NOT caught" >&2
fi
exit "$rc"
