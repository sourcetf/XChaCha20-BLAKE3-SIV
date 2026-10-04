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
# Set `XSIV_FEATURES` to run the same differential against a feature combination --
# `XSIV_FEATURES=ultra tools/cache_profile.sh` is the one that matters, because `ultra`
# adds a second implementation (another ChaCha20/BLAKE3, its own buffers) to the path
# that handles the key, and a secret-dependent access in it would be invisible to every
# other check here. The variable is read by the self-test's inner invocation too, so the
# planted-leak control runs in the same configuration as the check it guards.
#
# Exit codes, matching the repository convention: 0 = as expected; 1 = a profile
# depended on a secret, or the self-test found that this tool cannot detect a planted
# leak; 3 = could not run (no valgrind, no `lackey`, or an inner run that could not
# start) -- 3 and not 1, so a caller can tell "found something" from "did not look",
# and `verify.sh` records it as a skipped stage instead of a pass. (This list said 1 for
# "could not run" until an audit compared it with the code.)
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

# Feature flags for the example under test. Empty (the default) is the default build.
FEATURES="${XSIV_FEATURES:-}"

# Same lookup as `tools/ctgrind.sh`: the host this was developed on has valgrind
# extracted under `$HOME` (no root to install it), while CI installs it system-wide.
# This used to be a hard-coded `$HOME` path, which on a runner meant "not found" and
# -- while that answered exit 0 -- this entire differential (and the self-test inside
# it) silently did not run there. It is now searched for, and not finding it is exit 3.
VALGRIND="${VALGRIND:-}"
if [ -z "$VALGRIND" ]; then
  for c in "$HOME/valgrind/usr/bin/valgrind" "$(command -v valgrind 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then VALGRIND="$c"; break; fi
  done
fi
if [ -z "$VALGRIND" ] || [ ! -x "$VALGRIND" ]; then
  echo "SKIPPED: no valgrind found (tools/ctgrind.sh --setup can fetch one)" >&2
  # 3 = could not run; see the exit-code list in this file's header and the
  # convention `tools/gate_selftest.sh` checks.
  exit 3
fi
# An extracted copy needs its own library directory; a system one does not.
if [ -d "$HOME/valgrind/usr/libexec/valgrind" ]; then
  export VALGRIND_LIB="${VALGRIND_LIB:-$HOME/valgrind/usr/libexec/valgrind}"
fi

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

# `cargo build` honours CARGO_TARGET_DIR, so the runs below must use the same directory.
# Hard-coding `./target` profiled a stale binary while building into $CARGO_TARGET_DIR,
# and -- because a stale binary still produces identical counters -- could PASS.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build --release --quiet --example xsiv_stdin ${FEATURES:+--features "$FEATURES"}

# Which configuration the verdicts below are about. Printed in every mode, so a log that
# says PASS says what it passed *for*.
echo "configuration: ${FEATURES:-default features}"

# ── Address-trace mode ──
if [ "${1:-}" = "--trace" ]; then
  shift
  vectors="${1:-12}"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  gen "$vectors" 00 > "$work/t-zero.txt"
  gen "$vectors" ff > "$work/t-ones.txt"
  # Two phases, encrypt-only and round-trip: `decrypt` is the path the hardening is
  # about, and it is never entered by the encrypt-only pass.
  for phase in enc roundtrip; do
    extra=()
    [ "$phase" = roundtrip ] && extra=(--roundtrip)
    for side in zero ones; do
      # ASLR off: the comparison is over addresses, so the same code has to be at the
      # same addresses in both runs. That requirement is this mode's main caveat -- it
      # needs a controlled layout, which is not a statement about a hostile process.
      setarch --addr-no-randomize "$VALGRIND" --tool=lackey --trace-mem=yes \
        "$TARGET_DIR/release/examples/xsiv_stdin" ${extra[@]+"${extra[@]}"} \
        < "$work/t-$side.txt" 2>&1 \
        | grep -E "^[ILSM] " > "$work/$phase-$side.trace" || true
    done
    # A trace that carries no load/store lines is not a trace. This valgrind, extracted
    # from a package rather than installed, cannot start external tools at all: it looks
    # for them under the prefix it was built with, and `VALGRIND_LIB` only redirects the
    # core. The first version of this mode filtered on `^[ILSM] ` and compared the
    # *error message* that came back instead -- two runs of identical text, reported as
    # "identical address traces". Exit 3 means "could not run", which the self-test
    # treats as its own failure rather than as a detection.
    loads="$(grep -c '^[LSM] ' "$work/$phase-zero.trace" || true)"
    if [ "${loads:-0}" -eq 0 ]; then
      echo "SKIPPED: no load/store lines in the $phase trace -- valgrind here cannot" >&2
      echo "         start the lackey tool (see the comment above)." >&2
      exit 3
    fi
    if cmp -s "$work/$phase-zero.trace" "$work/$phase-ones.trace"; then
      echo "PASS: identical $phase address traces for two different keys"
      echo "      ($(wc -l < "$work/$phase-zero.trace") memory accesses compared)"
    else
      echo "FAIL: the $phase address trace depends on the values of a secret" >&2
      diff "$work/$phase-zero.trace" "$work/$phase-ones.trace" | head -10 >&2
      exit 1
    fi
  done
  exit 0
fi

# ── Self-test: plant a leak a *cache-resident* table hides from the counts, and
# require the mode under test to catch it. A self-test that cannot fail proves
# nothing, so this checks the exit status rather than printing what came out. ──
if [ "${1:-}" = "--selftest" ]; then
  shift
  # `--selftest [vectors] [--trace]`: loop rather than reading fixed positions, or
  # `--selftest 4` read the vector count as the mode and `--selftest 12 --trace` read
  # `--trace` as the count -- the inner run then silently did counts mode, not trace.
  mode=""; count="32"
  for arg in "$@"; do
    case "$arg" in
      --trace) mode="--trace" ;;
      ''|*[!0-9]*)
        echo "usage: tools/cache_profile.sh --selftest [vectors] [--trace]" >&2
        exit 1 ;;
      *) count="$arg" ;;
    esac
  done
  # `$mode` is the mode flag for the inner run (`--trace` or nothing), which is what the
  # messages below have to name -- an earlier version printed it as if it were a mode
  # name and reported "detected by " with an empty field.
  mode_name="${mode:-counts}"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  # One copy. This used to be two (`... 2>/dev/null || true` then a plain retry that
  # listed fewer trees); GNU `cp -r` nests into directories that already exist, so the
  # second copied everything again as `$work/src/src`, `$work/tools/tools`, ... and, being
  # the unguarded one, aborted the script on a full disk.
  cp -r src tests examples benches tools Cargo.toml Cargo.lock "$work/"
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
    //
    // The *count* of touched entries depends on the secret too, and that half is not
    // decoration: a single access per call is invisible to the counts (the same one
    // miss whichever line it lands on), so with only the line above this self-test
    // passed while measuring nothing but the harness's own input parsing -- an audit
    // showed the "detected" verdict was that parsing difference, not the leak. Both
    // halves are planted so each mode is exercised by a leak of the class it claims:
    // the counts see the extra accesses, the trace sees the secret-dependent address.
    static TABLE: [u8; 4 << 20] = [7u8; 4 << 20];
    let table: &[u8; 4 << 20] = core::hint::black_box(&TABLE);
    let idx = ((tag[0] as usize) << 12) & ((1 << 22) - 1);
    let n = ((tag[0] ^ tag[1]) & 7) as usize;
    let mut acc = 0u8;
    let mut i = 0usize;
    while i <= n {
        acc ^= core::hint::black_box(table[(idx + (i << 12)) & ((1 << 22) - 1)]);
        i += 1;
    }
    let mut material = [0u8; 44];
    material[0] = core::hint::black_box(acc ^ tag[1]);""", 1)
open(p, "w").write(s)
PY
  echo "self-test: planted a secret-dependent table access into a throwaway copy"
  echo "self-test: the copy is built with the same features as this run (${FEATURES:-default})"
  inner=0
  # Exec the *copy*, not `$0`. With a relative `$0` this worked by accident (the copy is
  # in `$work/tools/`), but an absolute `$0` would re-exec the unpatched original, which
  # re-runs this self-test and re-execs again -- a fork bomb instead of a test.
  #
  # `CARGO_TARGET_DIR` is overridden to a directory inside `$work`, and that is not
  # cosmetic: the inner run builds the *planted* copy, and pointing it at the caller's
  # target directory leaves a leaky example binary there for the next invocation to
  # profile. Measured: pristine PASS, pristine again PASS, self-test OK, then pristine
  # FAIL on unchanged source -- the same shape as the defect `tools/ctgrind.sh` had.
  if ( cd "$work" && CARGO_TARGET_DIR="$work/target" exec "$work/tools/cache_profile.sh" $mode "$count" ) > "$work/selftest.log" 2>&1; then
    echo "FAIL: the planted leak left the profile identical, so $mode_name cannot detect" >&2
    echo "      that class and its PASS elsewhere means correspondingly less." >&2
    tail -20 "$work/selftest.log" >&2
    exit 1
  else
    inner=$?
  fi
  if [ "$inner" = 3 ]; then
    # The inner run could not run (e.g. valgrind here cannot start `lackey`). That is the
    # repository's "could not run" answer -- exit 3 -- not a detection and not a failure of
    # the detector, so propagate 3 and let the caller map it to a skipped stage, exactly as
    # it does for the differential run itself. Exit 1 stays reserved for a self-test that
    # *ran* and left the planted leak undetected (the branch above), which is a real defect.
    echo "SKIPPED: $mode_name could not run here, so the self-test cannot conclude anything" >&2
    echo "         about it. Exit 3 is 'could not run', not 'detected'." >&2
    exit 3
  fi
  # A non-zero inner exit is not by itself the planted leak being detected: the inner
  # run's own controls can fail (an audit showed the pristine counts verdict once failed
  # on the harness's input parsing, which would have satisfied an "any non-zero"
  # self-test). Require the inner log to carry the mode's actual key-dependence verdict.
  case "$mode" in
    --trace) expect_fail='FAIL: the (enc|roundtrip) address trace depends on the values of a secret' ;;
    *)       expect_fail='FAIL: the (enc|roundtrip) cache or branch profile depends on the key' ;;
  esac
  if ! grep -Eq "$expect_fail" "$work/selftest.log"; then
    echo "FAIL: the inner run failed, but not with the planted leak's key-dependence" >&2
    echo "      verdict, so this self-test cannot say $mode_name detects that class." >&2
    tail -20 "$work/selftest.log" >&2
    exit 1
  fi
  echo "OK: the planted leak is detected by $mode_name"
  # `|| true`: under `set -o pipefail` a `grep` with no match (or a `head` that closes
  # the pipe early) would make this line -- and so the script -- exit non-zero straight
  # after printing OK.
  grep -E "^(FAIL|[-+](D1mr|DLmr|L|S|I) )" "$work/selftest.log" | head -4 || true
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
profile() {  # args..., then in-file and out-file are last two
  local extra=("${@:1:$#-2}")
  local in="${@: -2:1}" out="${@: -1}"
  "$VALGRIND" --tool=cachegrind --cache-sim=yes --branch-sim=yes \
    --cachegrind-out-file="$out" "$TARGET_DIR/release/examples/xsiv_stdin" \
    ${extra[@]+"${extra[@]}"} < "$in" > /dev/null 2>&1
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

# Two phases: encrypt-only, then round-trip. The second one is where `decrypt` runs at
# all, and under `ultra` it is where a second implementation handles the key -- the
# encrypt-only columns above say nothing about either.
for phase in enc roundtrip; do
  extra=()
  [ "$phase" = roundtrip ] && extra=(--roundtrip)
  profile "${extra[@]+"${extra[@]}"}" "$work/in-zero.txt" "$work/$phase-zero.cg"
  profile "${extra[@]+"${extra[@]}"}" "$work/in-zero.txt" "$work/$phase-zero-again.cg"
  profile "${extra[@]+"${extra[@]}"}" "$work/in-ones.txt" "$work/$phase-ones.cg"
  profile "${extra[@]+"${extra[@]}"}" "$work/in-longer.txt" "$work/$phase-longer.cg"
  counters "$work/$phase-zero.cg" > "$work/$phase-zero.sum"
  counters "$work/$phase-zero-again.cg" > "$work/$phase-zero-again.sum"
  counters "$work/$phase-ones.cg" > "$work/$phase-ones.sum"
  counters "$work/$phase-longer.cg" > "$work/$phase-longer.sum"

  # Negative control: a *public* difference (message lengths) must move the counters.
  if [ ! -s "$work/$phase-zero.sum" ]; then
    echo "FAIL: no counters were extracted from the $phase phase -- the profile is" >&2
    echo "      empty, so any comparison here would be vacuous. Is valgrind working?" >&2
    exit 1
  fi
  if diff -q "$work/$phase-zero.sum" "$work/$phase-longer.sum" > /dev/null; then
    echo "FAIL: $phase control runs with different message lengths produced identical" >&2
    echo "      counters, so this mode cannot detect anything." >&2
    exit 1
  fi
  if ! diff -q "$work/$phase-zero.sum" "$work/$phase-zero-again.sum" > /dev/null; then
    echo "FAIL: two $phase runs on the *same* input produced different counters, so" >&2
    echo "      this mode cannot separate a leak from its own noise and both verdicts" >&2
    echo "      below are meaningless." >&2
    diff -u "$work/$phase-zero.sum" "$work/$phase-zero-again.sum" >&2
    exit 1
  fi
  # The round-trip phase must do *more* work than the encrypt-only one, or the flag it
  # passes is not reaching the example and the "decrypt is covered" claim is empty.
  if [ "$phase" = roundtrip ]; then
    enc_ir="$(awk '$1 == "Ir" { print $2 }' "$work/enc-zero.sum")"
    rt_ir="$(awk '$1 == "Ir" { print $2 }' "$work/roundtrip-zero.sum")"
    if [ -z "$enc_ir" ] || [ -z "$rt_ir" ] || [ "$rt_ir" -le "$enc_ir" ]; then
      echo "FAIL: the round-trip phase does not execute more instructions than the" >&2
      echo "      encrypt-only phase ($enc_ir -> $rt_ir), so it is not reaching" >&2
      echo "      \`decrypt\` and this run would be reporting the encrypt path twice." >&2
      exit 1
    fi
    echo "control (roundtrip): the round-trip phase executes more instructions than the"
    echo "        encrypt-only one ($enc_ir -> $rt_ir), so it does reach \`decrypt\`"
  fi
  echo "control ($phase): the same input twice gives identical counters"
  echo "control ($phase): different message lengths change the counters, as they must"

  if diff -u "$work/$phase-zero.sum" "$work/$phase-ones.sum" > "$work/$phase.diff"; then
    echo "PASS ($phase): identical cache and branch profiles for two different keys"
    echo "      ($(wc -l < "$work/$phase-zero.sum") counters over $vectors vectors per side;"
    echo "       see the header for what this does and does not catch)"
  else
    echo "FAIL: the $phase cache or branch profile depends on the key" >&2
    cat "$work/$phase.diff" >&2
    exit 1
  fi
done
