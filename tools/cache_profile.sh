#!/usr/bin/env bash
#
# Cache side-channel checks that a software host can actually run.
#
# Why this exists. ctgrind catches secret-dependent *branches and indices* in the
# source, and the timing screen measures wall-clock on one machine. Neither says
# anything about the cache behaviour of the compiled code. These two checks do, at
# two different sensitivities:
#
#   default (counts)  cachegrind simulates a cache hierarchy and a branch predictor
#                     and reports counts. Two runs that differ only in the *values*
#                     of secrets must produce identical counts.
#   --trace           valgrind's lackey logs every memory access (address and size,
#                     not value). The traces of those same two runs must be
#                     byte-identical, which catches leaks the counts cannot: a
#                     secret-dependent index into a table that stays cache-resident
#                     changes which line is touched and no counter at all. (That is
#                     not a hypothetical -- the first self-test written for this
#                     script planted exactly that leak and the counts called it
#                     identical, correctly and uselessly.)
#
# Both modes are compared against `examples/xsiv_stdin.rs`, which takes key, nonce,
# AAD and message from stdin, so the two sides differ in the value of a secret and
# in nothing else.
#
# What neither is: a measurement of real hardware. Cachegrind models a generic cache
# and a simple predictor; lackey sees addresses under an emulator, with ASLR turned
# off for the run. Real CPUs have prefetchers, replacement policies, shared-cache
# interference and speculation that none of this models. A measurement can detect a
# leak; it can never prove the absence of one.
#
# Usage: tools/cache_profile.sh [vectors]           # counts mode
#        tools/cache_profile.sh --trace [vectors]   # address-trace mode
#        tools/cache_profile.sh --selftest [vectors] [--trace]
#
# Exit codes: 0 = as expected; 1 = a profile depended on a secret, or a check could
# not run, or the self-test found that this tool cannot detect a planted leak.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

VALGRIND="${VALGRIND:-$HOME/valgrind/usr/bin/valgrind}"
if [ ! -x "$VALGRIND" ]; then
  echo "SKIPPED: no valgrind at $VALGRIND (tools/ctgrind.sh --setup can fetch one)" >&2
  # 3 = could not run; see the exit-code list in this file's header and the
  # convention `tools/gate_selftest.sh` checks.
  exit 3
fi
export VALGRIND_LIB="${VALGRIND_LIB:-$HOME/valgrind/usr/libexec/valgrind}"

# Vector files: `$1` vectors, key byte `$2`, lengths scaled by `$3`. `-` is the
# empty field in this format: an empty string collapses under whitespace splitting
# and shifts the columns, which is how the first version of this script made the
# driver panic instead of failing the comparison.
gen() {  # count, key byte, length scale
  python3 - "$1" "$2" "${3:-1}" <<'PY'
import sys
n, byte, scale = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
for i in range(n):
    size = (1 + (i * 37) % 1024) * scale
    aad = byte * (i % 5) if i % 5 else "-"
    print(byte * 32, byte * 24, aad, "aa" * size)
PY
}

cargo build --release --quiet --example xsiv_stdin

# ── Address-trace mode ──
if [ "${1:-}" = "--trace" ]; then
  shift
  vectors="${1:-12}"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  gen "$vectors" 00 > "$work/t-zero.txt"
  gen "$vectors" ff > "$work/t-ones.txt"
  for side in zero ones; do
    # ASLR off: the comparison is over addresses, so the same code has to be at the
    # same addresses in both runs. That requirement is this mode's main caveat -- it
    # needs a controlled layout, which is not a statement about a hostile process.
    setarch --addr-no-randomize "$VALGRIND" --tool=lackey --trace-mem=yes \
      ./target/release/examples/xsiv_stdin < "$work/t-$side.txt" 2>&1 \
      | grep -E "^[ILSM] " > "$work/$side.trace" || true
  done
  # A trace that carries no load/store lines is not a trace. This valgrind, extracted
  # from a package rather than installed, cannot start external tools at all: it looks
  # for them under the prefix it was built with, and `VALGRIND_LIB` only redirects the
  # core. The first version of this mode filtered on `^[ILSM] ` and compared the
  # *error message* that came back instead -- two runs of identical text, reported as
  # "identical address traces". Exit 3 means "could not run", which the self-test
  # treats as its own failure rather than as a detection.
  loads="$(grep -c '^[LSM] ' "$work/zero.trace" || true)"
  if [ "${loads:-0}" -eq 0 ]; then
    echo "SKIPPED: no load/store lines in the trace -- valgrind here cannot start the" >&2
    echo "         lackey tool (see the comment above). The counts mode is unaffected." >&2
    exit 3
  fi
  if cmp -s "$work/zero.trace" "$work/ones.trace"; then
    echo "PASS: identical address traces for two different keys"
    echo "      ($(wc -l < "$work/zero.trace") memory accesses compared)"
    exit 0
  fi
  echo "FAIL: the address trace depends on the values of a secret" >&2
  diff "$work/zero.trace" "$work/ones.trace" | head -10 >&2
  exit 1
fi

# ── Self-test: plant a leak a *cache-resident* table hides from the counts, and
# require the mode under test to catch it. A self-test that cannot fail proves
# nothing, so this checks the exit status rather than printing what came out. ──
if [ "${1:-}" = "--selftest" ]; then
  mode="${2:-}"; count="${3:-32}"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  cp -r src tests examples benches tools Cargo.toml Cargo.lock "$work/" 2>/dev/null || true
  cp -r src tests examples tools Cargo.toml Cargo.lock "$work/"
  python3 - "$work/src/lib.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "    let mut material = [0u8; 44];"
assert s.count(old) == 1, s.count(old)
# A secret-dependent index into a 4 MiB table: the classic cache-timing leak, sized
# past the cache so that even the counts can see it. The trace mode should see it
# regardless of size; both are checked below.
s = s.replace(old, """    // Deliberately leaky, for tools/cache_profile.sh --selftest, and written the way
    // a deliberate leak has to be written: `black_box(&TABLE)` hides the pointer, so
    // the load cannot be folded away or its address predicted. Two earlier versions
    // of this self-test failed to leak for exactly that reason -- a `static` of one
    // repeated value was constant-folded, and a run-time stack table was still
    // simplified enough that no secret-dependent address reached the trace. The table
    // is 4 MiB so that even cachegrind's counts move, and the index selects one cache
    // line out of 65536.
    static TABLE: [u8; 4 << 20] = [7u8; 4 << 20];
    let table: &[u8; 4 << 20] = core::hint::black_box(&TABLE);
    let idx = ((tag[0] as usize) << 12) & ((1 << 22) - 1);
    let mut material = [0u8; 44];
    material[0] = core::hint::black_box(table[idx] ^ tag[1]);""", 1)
open(p, "w").write(s)
PY
  echo "self-test: planted a secret-dependent table access into a throwaway copy"
  inner=0
  if ( cd "$work" && exec "$0" $mode "$count" ) > "$work/selftest.log" 2>&1; then
    echo "FAIL: the planted leak left the profile identical, so $mode cannot detect" >&2
    echo "      that class and its PASS elsewhere means correspondingly less." >&2
    tail -20 "$work/selftest.log" >&2
    exit 1
  else
    inner=$?
  fi
  if [ "$inner" = 3 ]; then
    echo "FAIL: $mode could not run here, so the self-test cannot conclude anything" >&2
    echo "      about it. Exit 3 is 'could not run', not 'detected'." >&2
    exit 1
  fi
  echo "OK: the planted leak is detected by $mode"
  grep -E "^(FAIL|[-+](D1mr|DLmr|L|S|I) )" "$work/selftest.log" | head -4
  exit 0
fi

# ── Counts mode (default) ──
vectors="${1:-64}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
gen "$vectors" 00 > "$work/in-zero.txt"
gen "$vectors" ff > "$work/in-ones.txt"
gen "$vectors" 00 2 > "$work/in-longer.txt"

# `--cache-sim=yes` explicitly: with only `--branch-sim=yes` this valgrind emits
# branch events *instead of* the cache events, which would quietly make the whole
# comparison about branches alone.
profile() {  # in-file, out-file
  "$VALGRIND" --tool=cachegrind --cache-sim=yes --branch-sim=yes \
    --cachegrind-out-file="$2" ./target/release/examples/xsiv_stdin \
    < "$1" > /dev/null 2>&1
}

# Read the counters out of the profile rather than out of `cg_annotate`'s text
# output: the file names its own events, so this cannot drift from a version's
# spelling.
counters() {  # cg-file
  awk -F': ' '
    /^events: /  { ev = $2 }
    /^summary: / {
      split(ev, names, " "); split($2, vals, " ")
      for (i = 1; i <= length(names); i++) print names[i], vals[i]
    }' "$1"
}

profile "$work/in-zero.txt" "$work/zero.cg"
profile "$work/in-zero.txt" "$work/zero-again.cg"
profile "$work/in-ones.txt" "$work/ones.cg"
profile "$work/in-longer.txt" "$work/longer.cg"
counters "$work/zero.cg" > "$work/zero.sum"
counters "$work/zero-again.cg" > "$work/zero-again.sum"
counters "$work/ones.cg" > "$work/ones.sum"
counters "$work/longer.cg" > "$work/longer.sum"

# Negative control: a *public* difference (message lengths) must move the counters.
if [ ! -s "$work/zero.sum" ]; then
  echo "FAIL: no counters were extracted -- the profile is empty, so any comparison" >&2
  echo "      here would be vacuous. Is valgrind working?" >&2
  exit 1
fi
if diff -q "$work/zero.sum" "$work/longer.sum" > /dev/null; then
  echo "FAIL: control runs with different message lengths produced identical" >&2
  echo "      counters, so this mode cannot detect anything." >&2
  exit 1
fi
if ! diff -q "$work/zero.sum" "$work/zero-again.sum" > /dev/null; then
  echo "FAIL: two runs on the *same* input produced different counters, so this mode" >&2
  echo "      cannot separate a leak from its own noise and both verdicts below are" >&2
  echo "      meaningless." >&2
  diff -u "$work/zero.sum" "$work/zero-again.sum" >&2
  exit 1
fi
echo "control: the same input twice gives identical counters (the mode is repeatable)"
echo "control: different message lengths change the counters, as they must"

if diff -u "$work/zero.sum" "$work/ones.sum" > "$work/diff"; then
  echo "PASS: identical cache and branch profiles for two different keys"
  echo "      ($(wc -l < "$work/zero.sum") counters over $vectors vectors per side;"
  echo "       see the header for what this does and does not catch)"
else
  echo "FAIL: the cache or branch profile depends on the key" >&2
  cat "$work/diff" >&2
  exit 1
fi
