#!/usr/bin/env bash
#
# Instruction-level fault injection, in software: corrupt one byte at a time in the
# compiled decision code and see what a forgery does.
#
# Measured on this machine, full sweeps: 1 accepting byte in 5526 and 13 accepting
# single-bit flips in 44208 for the default (hardened) build; 9 in 4268 and 152 in 34144
# for the opt-out one. **These are an earlier revision's figures** -- taken after the
# offset-mapping fix but before the driver's aggregation fix (the `cat` of the shards'
# accepted-offset files merged a last line with no trailing newline into the next file, so
# a printed total was `true count - (files with entries - 1)`). The README's fault table
# quotes the later local full re-run, where the same region reads opt-out `17`/`163` and
# hardened `1`/`5`; the counts also move with the code, so neither set is a constant.
# **Not zero**, and that is the corrected picture -- see the
# criterion comment below, which also records the offset bug that made an earlier
# version of this script report zero. The hardened build's map is printed beside the
# opt-out one so the difference is visible as a number rather than asserted.
#
# The swept ranges are the two decrypt entry points *and* `accept_or_reject`, which
# holds the decision itself (`#[inline(never)]`, see src/lib.rs): the entry points no
# longer contain the branch, so a range list built from `decrypt` alone would sweep
# around it. Every byte of that function is scanned either way.
#
# Why this and not only tools/fi_check.sh: that one writes faults down as *source*
# changes, which is a model of the fault and nothing more. This walks the actual
# machine code of the decision and its call sites in a built binary, damages one
# place at a time, and runs the decision test. Every run therefore answers the
# question a glitch asks: "if this byte were wrong, would a forgery still be
# rejected?" -- with no bench, on ordinary hardware.
#
# Two models, because they fail differently:
#
#   * `nop` (default) replaces one byte with `0x90`, the "neutralise this
#     instruction" fault. It biases towards rejection, so it is the weaker question.
#   * `--bits` flips one bit, the "corrupt this instruction" fault. This is the one
#     that finds what the source cannot remove: a conditional jump's opcode is one bit
#     from its inverse (`je` 0x84 / `jne` 0x85) and its target is a few bits from any
#     address in the function. The count is published in the README's table as a
#     pinned residual -- the accept decision of any branch-based implementation is one
#     bit from being wrong -- rather than claimed away.
#
# What each mode sweeps, because the difference is the point:
#
#   default (full)  every byte of the two entry points *and* of `accept_or_reject`, in
#                   three configurations. This is the measurement the README's table
#                   carries: ~19 KB of region and ~150k faults in the bit-flip model.
#                   Measured on a 16-core host with `--jobs 16`: under two minutes for
#                   the `nop` sweep, about nine for `bits`. It runs in the scheduled
#                   `wide` job and locally.
#   --quick         every byte of `accept_or_reject` *only*, in the same three
#                   configurations and both models -- 18-25 bytes each, seconds to a
#                   minute. It runs in the mutation job on every push. An earlier
#                   version sampled every thirteenth byte of the whole region and
#                   measured 47 minutes on a shared runner, which is not a push-time
#                   check; the decision is where every layer of this crate lives, and the
#                   residual elsewhere is a nightly number rather than a per-push one.
#
# An earlier estimate of half an hour for the `nop` sweep was really the per-patch
# *timeout* being hit by branches whose NOP turns a loop into a spin, and a five-second
# timeout fixed that.
#
# Every faulted child runs under per-process limits -- 256 MiB of address space, a CPU
# backstop, a capped capture file, coredumps off, and `nice` -- and the shard checks at
# startup (by allocating past the cap) that the limits are actually enforced, exiting 3
# if they are not. This is containment, not a verdict change: a fault that allocates or
# prints without bound dies and is counted `crashed`, exactly as one that segfaults is.
# Without it, such a fault takes the *host's* runner agent down and the job dies as
# "the hosted runner lost communication with the server" (measured: 17 of 42 sweep jobs
# on the 2026-10-21 dispatch of the 20-shard sweep, run 39628640338), losing the rest of
# that shard's slice. A platform that does not enforce the address-space limit therefore
# makes the sweep exit 3 rather than run uncontained -- including it in the class of
# things this tool refuses to report a verdict from.
#
# What this is still not: a fault model. A real glitch can hit a register or a bus
# rather than the instruction stream, can be timed relative to the data it is meant to
# disturb, and can be *targeted* rather than uniform. This enumerates two uniform
# single-fault models over the instruction stream and nothing else.
#
# Usage: tools/fi_instruction.sh [--quick] [--bits] [--jobs N]
#                                  [--shard I/N --report FILE]
#        (--jobs defaults to the core count, capped at 16; the sweep shards across cores.
#         --shard splits the work across *jobs* instead, and requires --report: the shards'
#         JSON reports are combined by tools/fi_instruction_verdict.py. Without --shard,
#         --report is an error rather than a silently ignored flag -- a caller who asks
#         for a report and gets a passing run with no file has been told the wrong thing.)
#        (--jobs defaults to the core count, capped at 16; the sweep shards across cores)
# Exit codes: 0 = every layer is at least as good as the one below it; 1 = otherwise,
#             or the machinery failed; 3 = the sweep could not run -- the scanned
#             instruction set is empty, or it is not exactly the byte set the symbol
#             map describes (checked against an independent nm/objdump extraction the
#             shards do not use), which is a count problem, not a verdict (verify.sh
#             reports 3 as a skipped stage). The `nop` model used to have no way to
#             say that: with the offset list emptied it reported three zero rows and
#             exited 0, and with the ranges parsed wrong it reported a plausible
#             smaller map.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CC="${CC:-$HOME/.local/bin/cc}"

# The detector every verdict below rests on: `run()` reads an exit status, and an
# exit status is only that test's verdict if the test ran. The baseline guard in
# `scan` requires the test's own `... ok` line before any fault is swept.
DECISION_TEST="a_forged_tag_must_not_be_accepted"

WORK="$(mktemp -d)"
# Keep the work directory on failure: the FAIL messages below point at files under
# $WORK (`*.accepted_decision`, the per-shard logs), and an unconditional cleanup
# deleted them in the same exit that printed the path -- the defect `fi_check.sh`
# already fixed for its own logs. A successful run cleans up.
trap 'rc=$?; if [ "$rc" -eq 0 ]; then rm -rf "$WORK"; else echo "instruction-sweep logs kept in $WORK (exit $rc)" >&2; fi' EXIT
export CARGO_TARGET_DIR="$WORK/target"

quick=""
MODEL="nop"
JOBS=""
SHARD=""
REPORT=""
for arg in "$@"; do
  case "$arg" in
    --quick) quick="--quick" ;;
    --bits) MODEL="bits" ;;
    --jobs) JOBS="next" ;;
    --jobs=*) JOBS="${arg#--jobs=}" ;;
    --shard) SHARD="next" ;;
    --shard=*) SHARD="${arg#--shard=}" ;;
    --report) REPORT="next" ;;
    --report=*) REPORT="${arg#--report=}" ;;
    *)
      if [ "$JOBS" = "next" ]; then JOBS="$arg"
      elif [ "$SHARD" = "next" ]; then SHARD="$arg"
      elif [ "$REPORT" = "next" ]; then REPORT="$arg"
      else
        echo "FAIL: unknown argument $arg" >&2; exit 1
      fi ;;
  esac
done
# The sweep is thousands of short-lived process launches and one file rewrite each, so it
# shards across cores by default: each shard owns a *copy* of the binary (two processes
# cannot rewrite one file) and a disjoint slice of the offsets. Measured on a 32-core
# host: the full `nop` sweep for three configurations went from ~15 minutes sequential to
# under two.
if [ -z "$JOBS" ]; then
  JOBS="$(nproc 2>/dev/null || echo 4)"
  [ "$JOBS" -gt 16 ] && JOBS=16
fi
case "$JOBS" in (*[!0-9]*|"") echo "FAIL: --jobs wants a number, got '$JOBS'" >&2; exit 1 ;; esac
[ "$JOBS" -ge 1 ] || { echo "FAIL: --jobs wants a positive number" >&2; exit 1; }

# `--shard I/N` splits the sweep across *jobs* instead of across cores. The work of all
# three configurations is partitioned into `JOBS * N` slices and this invocation runs the
# slices `I-1, I-1+N, I-1+2N, ...` -- exactly 1/N of every configuration's bytes, disjoint
# from the other shards' and, together with them, the whole region. It exists because the
# scheduled job measured about five hours for the full sweep on a hosted runner (the sweep
# step of `Deep checks` #183 ran 2 h 47 min and was killed with the job at five hours), and
# there were exactly two ways to fit a budget: shard the work, or cut the region. The
# region is not negotiable -- the finding the sweep exists for (six single-byte faults in
# `decrypt` that skipped the call and accepted a forgery) came from *outside* the decision
# -- so the work is sharded, and a shard that is missing is a failure rather than a smaller
# sweep.
#
# Each shard writes a JSON report (`--report`, required with `--shard`) that
# `tools/fi_instruction_verdict.py` combines into the same verdict this script prints when
# run unsharded. A shard checks only what it can check alone: that it swept exactly its own
# slice, and that the builds which must never accept a forgery (hardened, ultra) have no
# accepting fault inside the decision in that slice.
shard_i=""; shard_n=""
if [ -n "$SHARD" ]; then
  shard_i="${SHARD%%/*}"; shard_n="${SHARD##*/}"
  case "$shard_i$shard_n" in (*[!0-9]*|"")
    echo "FAIL: --shard wants I/N, got '$SHARD'" >&2; exit 1 ;; esac
  if [ "$shard_n" -lt 1 ] || [ "$shard_i" -lt 1 ] || [ "$shard_i" -gt "$shard_n" ]; then
    echo "FAIL: --shard wants 1 <= I <= N, got '$SHARD'" >&2; exit 1
  fi
  if [ -z "$REPORT" ] || [ "$REPORT" = "next" ]; then
    echo "FAIL: --shard requires --report FILE: the verdict job reads the shards' reports," >&2
    echo "      and a shard whose numbers reach nobody is a sweep nobody checks." >&2
    exit 1
  fi
else
  # `--report` without `--shard` used to be accepted and silently ignored: the run passed
  # and no file appeared, which tells the caller the opposite of what happened (found by a
  # third-party pass). The unsharded run computes the full verdict itself and has nothing to
  # write a shard report from, so the honest answer is to refuse.
  if [ -n "$REPORT" ]; then
    echo "FAIL: --report needs --shard: a report describes one shard's slice, and the" >&2
    echo "      unsharded run prints its verdict directly. Use --shard I/N --report FILE," >&2
    echo "      or drop --report." >&2
    exit 1
  fi
fi

# The test executable cargo just built, taken from its own JSON stream rather than from a
# glob over the deps directory. The glob version (`ls -t …/decision-* | head -1`) picked the
# *newest* match, which is the binary just built only as long as every scan builds a
# different configuration in order -- an ordering, not an invariant, and one this driver
# depends on silently. Asking cargo removes the guess. (Same fix as `tools/ctgrind.sh`,
# where the glob picked up a planted binary and made the second run of the tool fail on
# unchanged source.)
cargo_decision_executable() {  # reads cargo's `--message-format=json` stream on stdin
  python3 -c '
import json, sys
exes = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable"):
        continue
    if (m.get("target") or {}).get("name") == "decision":
        exes.append(m["executable"])
print(exes[-1] if exes else "")
'
}

# The detector's own positive control, model-independent and run before any sweep.
#
# The baseline guard inside `scan` only makes the unpatched binary *report* the
# decision test's `... ok` line; it cannot tell a sensitive detector from a blind one.
# With every assertion in tests/decision.rs weakened -- `x.is_err()` written as
# `x.is_err() || true` -- the test still passes, the `... ok` line still appears, and
# every fault below reads as "rejected": in the default (`nop`) model the all-zero map
# and exit 0 are byte-identical to a healthy run (measured: an audit blinded all eight
# assertions and `--quick` printed the same counts and exited 0). The `bits` model's
# opt-out control does catch that detector, but it is compiled out of the default
# invocation's verdict -- verify.sh runs the two models as separate stages, so a `nop`
# stage whose control never ran would still be green.
#
# So the control checks the detector itself rather than the sweep: a scratch copy of
# the crate forces `accept_or_reject` to accept (both gate slots take the Ok arm),
# and the decision test must then *report* the forgery -- the same "forged tag
# accepted" line `run()` reads as an acceptance. A blinded detector does not print it,
# and no fault map is trusted until this passes.
detector_sensitivity_control() {
  local dir="$WORK/sensitivity"
  mkdir -p "$dir"
  cp -r src tests benches Cargo.toml Cargo.lock "$dir/"
  python3 - "$dir/src/lib.rs" <<'PY'
import sys

p = sys.argv[1]
s = open(p).read()
# One text replacing each gate with a constant `true`: both slots then take the Ok
# arm, and `decrypt` accepts whatever it is given. The anchor must be unique --
# counts are asserted so a refactor that moves the gates fails the control loudly
# instead of planting nothing.
a, b = "bool::from(gate0)", "bool::from(gate1)"
if s.count(a) != 1 or s.count(b) != 1:
    sys.exit("the gates are not where this control expects them: %d x %s, %d x %s"
             % (s.count(a), a, s.count(b), b))
open(p, "w").write(s.replace(a, "true", 1).replace(b, "true", 1))
PY
  local bin
  # shellcheck disable=SC2086
  bin="$(cd "$dir" && CARGO_TARGET_DIR="$WORK/sensitivity/target" \
           cargo test --release --test decision --no-run \
             --config 'profile.release.strip=false' --message-format=json 2>/dev/null \
         | cargo_decision_executable)"
  [ -n "$bin" ] || {
    echo "FAIL: the detector sensitivity control could not build the forced-accept copy" >&2
    exit 1
  }
  set +e
  local out rc
  out="$("$bin" "$DECISION_TEST" 2>&1)"; rc=$?
  set -e
  if ! printf '%s\n' "$out" | grep -q "forged tag accepted"; then
    echo "FAIL: the decision test is not sensitive to an accepted forgery: a copy whose" >&2
    echo "      accept_or_reject accepts everything was run and '$DECISION_TEST' did NOT" >&2
    echo "      report it (binary exit $rc). Every fault below would read as 'rejected'" >&2
    echo "      with no detector behind it; fix the test before trusting this sweep." >&2
    printf '%s\n' "$out" | tail -5 | sed 's/^/      | /' >&2
    exit 1
  fi
  echo "detector sensitivity control: the forced-accept copy is reported by the decision test"
}

# The driver's own extraction of the swept byte ranges, from the same two tools the
# shards read (`nm -S`, `objdump -h`) but through a *different* path: shell field
# splitting and `$((16#...))` arithmetic here, the shard's Python `int(x, 16)` there.
# The two extractions are compared byte-for-byte before any count below is trusted,
# so a parse change on either side is a could-not-run (3) rather than a plausible-
# looking smaller map. Two measured mutations this exists for: replacing the symbol
# size with a constant (`int(f[0],16), 4` in the shard's parse -- every range shrinks
# to four bytes, the sweep stops covering the decision function, and the old
# count-vs-count guard could not see it because both sides came from the same list),
# and dropping the VMA->file-offset conversion (`addr - text_vaddr + text_off`
# written as `addr` -- every range shifts by the ~4 KiB between `.text`'s VMA and its
# file offset).
#
# Prints "<start> <size> <name>" per line, decimal file offsets, in `nm` order --
# the same format and order the shard writes to its `.ranges` file, so the
# comparison is `cmp` rather than a re-parse. Returns non-zero if the .text header
# cannot be read.
derive_ranges() {  # <binary> <quick?>
  local bin="$1" quick="$2"
  local hdr text_vaddr text_off
  hdr="$(objdump -h "$bin" 2>/dev/null)" || return 1
  # `objdump -h` columns are `Idx Name Size VMA LMA File off Algn`; the file offset is
  # the fourth number after the name (see the shard's own note on the LMA trap).
  text_vaddr="$(printf '%s\n' "$hdr" | awk '$2 == ".text" { print $4; exit }')"
  text_off="$(printf '%s\n' "$hdr" | awk '$2 == ".text" { print $6; exit }')"
  [ -n "$text_vaddr" ] && [ -n "$text_off" ] || return 1

  local addr size typ sym rest start
  while read -r addr size typ sym rest; do
    # Only `<addr> <size> <type> <name>` lines: a symbol without a size puts its
    # type where the size would be, and the shard's parser skips those too
    # (`len(f) >= 4 and f[2] in ("t", "T")`).
    case "$size" in ''|*[!0-9a-fA-F]*) continue ;; esac
    case "$typ" in t|T) ;; *) continue ;; esac
    case "$sym" in *decrypt*|*accept_or_reject*) ;; *) continue ;; esac
    if [ "$quick" = "--quick" ]; then
      case "$sym" in *accept_or_reject*) ;; *) continue ;; esac
    fi
    start=$((16#$addr - 16#$text_vaddr + 16#$text_off))
    printf '%d %d %s\n' "$start" "$((16#$size))" "$sym"
  done < <(nm -S "$bin" 2>/dev/null)
}

# The driver-side witness that the swept byte set is the one the symbol map describes,
# in two parts, both from data extracted along a path the shards do not use:
#
#   1. every shard's `.ranges` file must equal `derive_ranges` byte-for-byte -- an
#      independent nm/objdump extraction, not a recomputation of the shard's own;
#   2. the union of the offsets the shards recorded must be exactly the union of the
#      ranges: every offset inside some range, and every range every byte of it. A
#      per-range count == size is the strongest form of the first-and-last-byte
#      check: distinct offsets inside an interval of `size` integers number at most
#      `size`, so equality means the first byte, the last byte and every byte between
#      are all present. A stride > 1 (the one mutation the old guard *did* catch, by
#      comparing two expansions of the same list) is still caught here, by the count
#      falling short rather than by arithmetic on the stride.
#
# A mismatch is exit 3 ("could not run"), never a pass and never a verdict: the sweep
# would have examined a different byte set than the map it prints.
# The same witness as `check_scan_witness`, for an invocation that owns only some of the
# slices: every recorded offset must (a) lie inside a covered range and (b) belong to one of
# this invocation's slices, and each range must have yielded exactly the offsets this
# invocation owns. Unsharded, every index is owned and this reduces to the original check;
# sharded, it is what stops a shard from sweeping someone else's bytes, skipping its own, or
# sweeping a stride the map does not have.
check_scan_witness_shard() {  # <label> <expected-ranges> <nshards> <owned indices...>
  local label="$1" expected="$2" nshards="$3"; shift 3
  local owned="$*" union bad
  union="$(mktemp)"
  cat "$WORK"/shard-"$label"-*.bin.scanned_offsets 2>/dev/null | sort -n -u > "$union" || true
  if [ ! -s "$union" ]; then
    echo "FAILED: the sweep recorded no examined offset at all, so the map below would" >&2
    echo "         describe a sweep that did not happen. That is a could-not-run (3), not" >&2
    echo "         a verdict -- and zero accepting faults from a zero-instruction sweep is" >&2
    echo "         the one reading that must never come back as a pass." >&2
    rm -f "$union"; exit 3
  fi
  if ! bad="$(awk -v nshards="$nshards" -v owned="$owned" '
    BEGIN { nm = split(owned, m, " "); for (k = 1; k <= nm; k++) mine[m[k]] = 1 }
    # File 1: ranges ("<start> <size> <name>", file-offset space, in the order the shards
    # enumerated them). File 2: the union of the scanned offsets this invocation recorded.
    FNR == NR {
      nr++; rs[nr] = $1 + 0; rl[nr] = $2 + 0; rn[nr] = $3
      base[nr] = (nr > 1) ? base[nr-1] + rl[nr-1] : 0
      next
    }
    { no++; off[no] = $1 + 0 }
    END {
      bad = 0
      for (i = 1; i <= no; i++) {
        inside = 0
        for (j = 1; j <= nr; j++) {
          if (off[i] >= rs[j] && off[i] < rs[j] + rl[j]) {
            if (!(((base[j] + (off[i] - rs[j])) % nshards) in mine)) {
              bad++
              if (bad <= 4) printf "scanned offset %d belongs to slice %d, which this invocation does not own (%d shards)\n", off[i], (base[j] + (off[i] - rs[j])) % nshards, nshards
            }
            inside = 1; break
          }
        }
        if (!inside) { bad++; if (bad <= 4) printf "scanned offset %d lies outside every covered range\n", off[i] }
      }
      for (j = 1; j <= nr; j++) {
        want = 0
        for (l = 0; l < rl[j]; l++) if (((base[j] + l) % nshards) in mine) want++
        count = 0
        for (i = 1; i <= no; i++) if (off[i] >= rs[j] && off[i] < rs[j] + rl[j]) count++
        if (count != want) {
          bad++
          if (bad <= 4) printf "range %s: %d offsets examined, %d owned by this invocation\n", rn[j], count, want
        }
      }
      if (bad) { printf "%d problem(s)\n", bad; exit 1 }
    }' "$expected" "$union")"; then
    echo "FAILED: the examined offsets are not this invocation's slice of the map: $bad" >&2
    echo "         (tools/fi_instruction.sh's --shard comment says what that means.) That" >&2
    echo "         is a could-not-run (3), not a verdict." >&2
    rm -f "$union"; exit 3
  fi
  rm -f "$union"
}

check_scan_witness() {  # <label> <expected-ranges> ; union of shard .scanned_offsets
  local label="$1" expected="$2" union bad
  union="$(mktemp)"
  cat "$WORK"/shard-"$label"-*.bin.scanned_offsets 2>/dev/null | sort -n -u > "$union" || true
  if [ ! -s "$union" ]; then
    echo "FAILED: the sweep recorded no examined offset at all, so the map below would" >&2
    echo "         describe a sweep that did not happen. That is a could-not-run (3), not" >&2
    echo "         a verdict -- and zero accepting faults from a zero-instruction sweep is" >&2
    echo "         the one reading that must never come back as a pass." >&2
    rm -f "$union"
    exit 3
  fi
  bad="$(awk '
    # File 1: ranges ("<start> <size> <name>" in file-offset space). File 2: the union
    # of the scanned offsets the shards recorded, decimal, sorted, unique.
    FNR == NR { nr++; rs[nr] = $1 + 0; rl[nr] = $2 + 0; rn[nr] = $3; next }
    { no++; off[no] = $1 + 0 }
    END {
      bad = 0
      for (i = 1; i <= no; i++) {
        inside = 0
        for (j = 1; j <= nr; j++) {
          if (off[i] >= rs[j] && off[i] < rs[j] + rl[j]) { inside = 1; break }
        }
        if (!inside) {
          bad++
          if (bad <= 4) printf "scanned offset %d lies outside every covered range\n", off[i]
        }
      }
      for (j = 1; j <= nr; j++) {
        count = 0
        for (i = 1; i <= no; i++) {
          if (off[i] >= rs[j] && off[i] < rs[j] + rl[j]) count++
        }
        if (count != rl[j]) {
          bad++
          if (bad <= 12) {
            printf "range [%d..%d) (%s): %d of %d byte(s) scanned\n",
                   rs[j], rs[j] + rl[j] - 1, rn[j], count, rl[j]
          }
        }
      }
      if (bad == 0) print "OK"
    }' "$expected" "$union")"
  rm -f "$union"
  if [ "$bad" != "OK" ]; then
    echo "FAILED: the scanned offsets do not cover the ranges the symbol map describes" >&2
    echo "         (--quick narrows the ranges; it does not stride through them), so the" >&2
    echo "         map below would describe a sweep that did not happen. That is a" >&2
    echo "         could-not-run (3), not a verdict." >&2
    printf '%s\n' "$bad" | sed 's/^/         /' >&2
    exit 3
  fi
}

scan() {  # label, features
  local label="$1" features="$2"
  local bin
  # shellcheck disable=SC2086
  bin="$(cargo test --release --test decision --no-run \
           --config 'profile.release.strip=false' --message-format=json $features 2>/dev/null \
         | cargo_decision_executable)"
  [ -n "$bin" ] || {
    echo "FAIL: no decision binary (cargo reported no executable for it)" >&2
    exit 1
  }

  # The named test has to have RUN, not merely left the binary exiting 0. libtest
  # exits 0 for a binary whose tests are all `#[ignore]`d, renamed or `#[cfg]`-ed
  # out ("test result: ok. 0 passed"), and every fault below would then read as
  # "rejected" with no detector behind it. The test's own `... ok` line is the
  # witness, the same one `tools/tsan.sh` requires of its concurrent test. This
  # says the test ran; that it would still *report* an acceptance is the separate,
  # model-independent property `detector_sensitivity_control` proves above, before
  # any sweep starts.
  set +e
  base_out="$("$bin" 2>&1)"; base_rc=$?
  set -e
  if [ "$base_rc" -eq 0 ]; then
    case "$base_out" in
      *"test $DECISION_TEST ... ok"*) ;;
      *)
        echo "FAIL: the unpatched decision binary exits 0 without reporting" >&2
        echo "      'test $DECISION_TEST ... ok' -- the detector did not run," >&2
        echo "      so every fault below would read as rejected with nothing behind it." >&2
        printf '%s\n' "$base_out" | tail -5 | sed 's/^/      | /' >&2
        exit 1 ;;
    esac
  fi

  # The driver's independent extraction of the ranges, taken before the shards run
  # and compared with theirs after. If this cannot be computed the sweep has no
  # witness, which is a could-not-run rather than a map to trust.
  local expected_ranges="$WORK/$label.expected_ranges"
  if ! derive_ranges "$bin" "$quick" > "$expected_ranges"; then
    echo "FAILED: could not re-derive the swept ranges from nm/objdump directly, so" >&2
    echo "         the sweep below would run without an independent witness of the byte" >&2
    echo "         set it covers. That is a could-not-run (3), not a verdict." >&2
    exit 3
  fi
  if [ ! -s "$expected_ranges" ]; then
    echo "FAILED: the independent nm/objdump extraction found no decrypt or" >&2
    echo "         accept_or_reject range at all, so it cannot witness what the shards" >&2
    echo "         sweep. That is a could-not-run (3), not a verdict." >&2
    exit 3
  fi

  local shard pids=()
  # Which core-slices this invocation runs: all of them, or -- with `--shard I/N` -- every
  # N-th one. The union over I = 1..N is the full worker set, hence the whole byte set with
  # each byte swept once; see the `--shard` comment above.
  local nshards="$JOBS" my_shards
  if [ -n "$shard_i" ]; then
    nshards=$((JOBS * shard_n))
    my_shards="$(seq $((shard_i - 1)) "$shard_n" $((nshards - 1)))"
  else
    my_shards="$(seq 0 $((JOBS - 1)))"
  fi
  for shard in $my_shards; do
    cp "$bin" "$WORK/shard-$label-$shard.bin"
    scan_shard "$WORK/shard-$label-$shard.bin" "$label" "$quick" "$MODEL" "$shard" "$nshards" &
    pids+=("$!")
  done
  # A shard answers 3 for "the sweep could not run" (its count guard fired: the
  # scan set is empty or shorter than the ranges imply). That is not a failed
  # verdict, so it must not be flattened into the exit-1 branch below -- verify.sh
  # reports 3 as a skipped stage and 1 as a finding.
  local pid rc failed=0 could_not_run=0
  for pid in "${pids[@]}"; do
    rc=0
    wait "$pid" || rc=$?
    if [ "$rc" -eq 3 ]; then
      could_not_run=1
    elif [ "$rc" -ne 0 ]; then
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || { echo "FAIL: a sweep shard failed" >&2; exit 1; }
  [ "$could_not_run" -eq 0 ] || { echo "SKIPPED: a sweep shard could not run (see above)" >&2; exit 3; }
  # The counts are the union over shards; the shards are disjoint by construction, so
  # summing distinct offsets is the same set the sequential scan would have produced.
  # Two counts per configuration: every accepting byte, and the subset inside
  # `accept_or_reject` (the decision itself) -- the driver gates on the second.
  cat "$WORK"/shard-"$label"-*.bin.accepted 2>/dev/null | grep -c . > "$WORK/$label.count" || true
  cat "$WORK"/shard-"$label"-*.bin.accepted_decision 2>/dev/null | grep -c . \
    > "$WORK/$label.decision" || true

  # Independent witness #1: the ranges the shards swept must equal the driver's own
  # extraction from nm/objdump, byte for byte. All shards parse the same binary, so a
  # shard whose file disagrees with the driver's is sweeping (or reporting) a
  # different byte set than the map describes -- the constant-size and dropped-
  # conversion mutations land here, at exit 3 instead of a smaller plausible map.
  local rfile
  for shard in $my_shards; do
    rfile="$WORK/shard-$label-$shard.bin.ranges"
    if [ ! -f "$rfile" ] || ! cmp -s "$expected_ranges" "$rfile"; then
      echo "FAILED: shard $((shard + 1))'s range list does not match an independent" >&2
      echo "         nm/objdump extraction of the same binary (the driver's, in shell)," >&2
      echo "         so the sweep and the symbol map it reports are not describing the" >&2
      echo "         same bytes. That is a could-not-run (3), not a verdict." >&2
      if [ -f "$rfile" ]; then
        diff -u "$expected_ranges" "$rfile" 2>/dev/null | head -20 | sed 's/^/         /' >&2 || true
      else
        echo "         (the shard left no range file at all)" >&2
      fi
      exit 3
    fi
  done

  # Independent witness #2: the offsets the shards actually recorded must be exactly
  # the ranges (inside a range, and every byte of each range; see check_scan_witness).
  # This is where a stride > 1 lands: the ranges still parse correctly, but the union
  # of examined offsets no longer fills them. With `--shard`, "exactly the ranges"
  # becomes "exactly this invocation's slice of them" (check_scan_witness_shard).
  if [ -n "$shard_i" ]; then
    check_scan_witness_shard "$label" "$expected_ranges" "$nshards" $my_shards
  else
    check_scan_witness "$label" "$expected_ranges"
  fi
  # What this invocation swept, and what the whole region holds: the verdict job needs
  # both to prove that the shards' coverage is exhaustive and disjoint (a missing shard
  # must fail there rather than look like less work).
  cat "$WORK"/shard-"$label"-*.bin.scanned_offsets 2>/dev/null | sort -n -u | grep -c . \
    > "$WORK/$label.scanned" || true
  awk '{ s += $2 } END { print s + 0 }' "$expected_ranges" > "$WORK/$label.covered_total"
}

# The scanner, run once per shard with (binary, label, quick, model, shard, nshards):
# offsets are partitioned modulo `nshards` and each shard may only touch its own copy of
# the binary. The verdicts are per fault, so the shards are independent by construction
# and their accepted sets are disjoint.
scan_shard() {  # bin, label, quick, model, shard, nshards
  python3 - "$@" <<'PY'
import re
import errno
import os
import resource
import subprocess
import sys
import tempfile
import time

binpath, label, quick, model = sys.argv[1], sys.argv[2], sys.argv[3] == "--quick", sys.argv[4]
shard, nshards = int(sys.argv[5]), int(sys.argv[6])

# Where `.text` lives in the file, so a virtual address from `nm` can be turned into
# a file offset.
# `objdump -h` columns are `Idx Name Size VMA LMA File off Algn` -- **four** numbers
# after the name, and the file offset is the *fourth*. Taking the third (LMA) instead
# is a silent 4 KiB shift on this binary (`.text` VMA 0x2bac0, file offset 0x2aac0), so
# every fault would land outside the region it was meant to test while the tool still
# printed a plausible map. The assertion below is what keeps that from coming back: the
# bytes at the computed file offset must be the instruction `objdump -d` shows at that
# address.
hdr = subprocess.run(["objdump", "-h", binpath], capture_output=True, text=True).stdout
text = re.search(
    r"\.text\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", hdr
)
if not text:
    sys.exit("FAIL: no .text section with a file offset")
_, text_vaddr, _text_lma, text_off = (int(x, 16) for x in text.groups())

# The functions that contain the decision, with their sizes: the two entry points
# around it, and the decision itself -- `#[inline(never)]` keeps it in a symbol of
# its own (see `accept_or_reject` in src/lib.rs), so without this the branch the
# scan exists to sweep would sit outside every range.
syms = subprocess.run(["nm", "-S", binpath], capture_output=True, text=True).stdout
ranges = []
for line in syms.splitlines():
    f = line.split()
    if len(f) >= 4 and f[2] in ("t", "T"):
        name = f[3]
        if "decrypt" in name or "accept_or_reject" in name:
            addr, size = int(f[0], 16), int(f[1], 16)
            if size:
                ranges.append((addr, size, name))
if not ranges:
    sys.exit("FAIL: no decrypt or accept_or_reject symbols -- was the binary stripped?")

# `--quick` sweeps the *decision function* only, and every byte of it. The entry points
# around it are ~19 KB of region in the three configurations, and sweeping even a
# thirteenth of that on every push measured 47 minutes on a shared runner -- for a
# sample that asserts nothing the full sweep does not. What the push-time check is for is
# the decision, which is 18-25 bytes per configuration and where every layer this crate
# has is implemented; the residual elsewhere is a nightly measurement with a written-down
# number. So quick mode keeps stride 1 and narrows the ranges instead of coarsening the
# sample, which also means its opt-out control *can* be asserted (the whole decision is
# swept either way).
if quick:
    ranges = [r for r in ranges if "accept_or_reject" in r[2]]
    if not ranges:
        sys.exit("FAIL: no accept_or_reject symbol to sweep in quick mode")

# Which symbol each swept byte belongs to, so an accepting fault can be attributed:
# "the decision itself" and "the entry point around it" are different findings, and the
# counts across configurations are only comparable per symbol (`ultra`'s `decrypt` and
# `decrypt_in_place_detached` contain more code -- the witness call, an extra gate
# operand, a ciphertext copy -- so their raw totals are naturally larger).
def symbol_of(off):
    for addr, size, name in ranges:
        start = addr - text_vaddr + text_off
        if start <= off < start + size:
            return name
    return "<outside>"

covered = [(a - text_vaddr + text_off, s, n) for a, s, n in ranges]

with open(binpath, "rb") as fh:
    original = fh.read()

# The mapping must name the code it claims to. A wrong offset is invisible in the
# output -- the sweep still runs, still reports a map -- so it is checked here, against
# `objdump -d` itself, before a single fault is written.
disasm = subprocess.run(["objdump", "-d", binpath], capture_output=True, text=True).stdout
shown = {}
for line in disasm.splitlines():
    mm = re.match(r"\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s", line)
    if mm:
        shown[int(mm.group(1), 16)] = bytes(int(b, 16) for b in mm.group(2).split())
checked = 0
for addr, size, _name in ranges:
    if addr not in shown:
        continue
    off = addr - text_vaddr + text_off
    if original[off : off + len(shown[addr])] != shown[addr]:
        sys.exit(
            f"FAIL: the virtual->file mapping is wrong at {addr:#x} "
            f"(file offset {off:#x}); .text VMA {text_vaddr:#x}, file offset "
            f"{text_off:#x}. Every fault below would land in the wrong place."
        )
    checked += 1
if checked == 0:
    sys.exit("FAIL: no instruction from the swept ranges could be cross-checked")
total = sum(s for _, s, _ in covered)
stride = 1

def reopen_for_write(path):
    """Open the shard's binary for writing, retrying the kernel's transient
    `ETXTBSY` ("text file busy").

    The binary is written, closed, executed, reopened and restored per fault, because
    executing a file that is open for writing is `ETXTBSY`. `subprocess.run` reaps its
    child before returning, so the reopen *should* always succeed -- but the full
    16-shard sweep reproduced `ETXTBSY` four times in this environment (WSL2), which
    aborted the whole scan from inside a `finally:` and left no summary at all. Treat it
    as transient and retry; a persistent refusal still raises, so a real problem is not
    swallowed.
    """
    for attempt in range(60):
        try:
            return open(path, "r+b")
        except OSError as e:
            if e.errno != errno.ETXTBSY or attempt == 59:
                raise
            time.sleep(0.05)
    raise AssertionError("unreachable")


# Limits on every child, so one pathological fault cannot take the machine down
# instead of being classified.
#
# Measured, not hypothetical: on the 2026-10-21 dispatch of the 20-shard wide sweep
# (run 39628640338) 17 of the 42 sweep jobs died with "The hosted runner lost
# communication with the server. Anything in your workflow that terminates the runner
# process, starves it for CPU/Memory, or blocks its network access can cause this
# error." The step was killed mid-sweep by *the runner's own box*, not by a verdict.
# A corrupted instruction can turn a bounded loop into an unbounded one; a five-second
# window is enough to reach gigabytes, and the kernel then kills the largest thing on
# the box, which can be the runner agent. The fault is a legitimate result either way
# -- what must not happen is that it destroys the rest of the shard's slice, because
# the scan then says nothing about the thousands of faults it never reached.
#
# RLIMIT_AS is 256 MiB: the unpatched decision test runs to completion under a 64 MiB
# cap (measured with `ulimit -v`), so this is a 4x margin, and four concurrent children
# (one per core on a hosted runner) then cannot ask for more than 1 GiB in total. RLIMIT_FSIZE caps the capture file `run` writes to; RLIMIT_CPU is a
# backstop behind the five-second wall clock; coredumps are off so a crashing child
# cannot fill the disk. A child that hits a limit dies, and `run` classifies that as
# "crashed" -- the verdict a corrupted instruction that segfaults already gets, so
# containment changes how the process ends and not what the sweep concludes.
#
# The children are also niced: a fault that turns a loop into a spin runs at 100% for
# the full five-second timeout, and the sweep runs one child per core, so the runner's
# own agent competes with them for the CPU it needs to keep its connection alive. That
# work is batch work; it should yield to the process deciding whether the job is still
# healthy. `nice` costs nothing when the box is otherwise idle.
ADDRESS_SPACE_LIMIT = 256 << 20
CAPTURE_BYTES = 1 << 20
CAPTURE_FILE_BYTES = 4 << 20
CPU_SECONDS = 15
CHILD_NICE = 10


def _set_limit(which, want):
    """Lower `which` to `want`, or to the hard limit if that is already lower.

    Raising above the hard limit would make `setrlimit` fail inside the forked child,
    which never reaches exec: every fault would then be classified `crashed` and the
    map would read clean. Clamping instead keeps the containment at whatever the host
    allows -- and the probe below still proves that whatever limit was set is enforced.
    """
    _soft, hard = resource.getrlimit(which)
    if hard != resource.RLIM_INFINITY:
        want = min(want, hard)
    resource.setrlimit(which, (want, want))


def child_limits():
    _set_limit(resource.RLIMIT_AS, ADDRESS_SPACE_LIMIT)
    _set_limit(resource.RLIMIT_CPU, CPU_SECONDS)
    _set_limit(resource.RLIMIT_FSIZE, CAPTURE_FILE_BYTES)
    _set_limit(resource.RLIMIT_CORE, 0)
    os.nice(CHILD_NICE)


# One capture file, truncated before each fault. Output goes here rather than through
# `capture_output=True` for the same reason: a corrupted instruction can also turn a
# bounded print into an unbounded one, and `communicate` would then accumulate it in
# this shard process's memory, where no rlimit applies.
capture = tempfile.TemporaryFile()


def run():
    # Bytes, decoded with `errors="replace"`: a corrupted binary that crashes can
    # write non-UTF-8 to stderr, and `text=True` turned that into a
    # `UnicodeDecodeError` escaping the shard (measured in the full sweep: 0xe1 and
    # 0xf0 at offsets 90 and 17). The verdict only looks for one ASCII needle, so a
    # replaced byte cannot change it.
    capture.seek(0)
    capture.truncate(0)
    r = subprocess.run(
        [binpath],
        stdout=capture.fileno(),
        stderr=subprocess.STDOUT,
        timeout=5,  # a NOPed
        # branch inside a loop hangs; the test itself needs milliseconds, so anything
        # past a few seconds is that hang, not a slow success
        preexec_fn=child_limits,
    )
    if r.returncode == 0:
        return "rejected"
    size = capture.seek(0, os.SEEK_END)
    capture.seek(0)
    if size <= CAPTURE_BYTES:
        blob = capture.read()
    else:
        # A child that floods the log must not push the needle -- libtest writes a
        # failing test's captured output near the end -- past what is examined, so both
        # ends are read; neither read exceeds the cap.
        blob = capture.read(CAPTURE_BYTES)
        capture.seek(size - CAPTURE_BYTES)
        blob += capture.read(CAPTURE_BYTES)
    if "forged tag accepted" in blob.decode("utf-8", "replace"):
        return "accepted"
    return "crashed"


# A baseline: unpatched, the test must pass.
base = run()
if base != "rejected":
    sys.exit(f"FAIL: the unpatched binary reports {base}, so nothing below is meaningful")


def could_not_run(msg):
    """Exit 3: the sweep could not run. That is not a verdict -- verify.sh records
    3 as a skipped stage -- and it is the only honest answer for a scan set that
    does not cover what the symbol map says it should."""
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(3)


# Positive control for the limits: a child that allocates well past the cap must die
# *of the cap*. RLIMIT_AS is enforced on Linux and only partially elsewhere, and a limit
# that is silently not in effect is the same failure this control exists to prevent --
# the sweep would look contained while one fault could still take the runner down
# mid-slice. 5 x 64 MiB = 320 MiB, above the 256 MiB cap and bounded if the limit is
# absent. The probe answers 7 for "the allocation was refused" and 0 for "it was not",
# so a control that fails for some third reason (the limit machinery itself broken)
# reads as neither and is reported as what it is.
_allocation_probe = (
    "b = []\n"
    "try:\n"
    "    for _ in range(5):\n"
    "        b.append(bytearray(64 << 20))\n"
    "except MemoryError:\n"
    "    raise SystemExit(7)\n"
    "raise SystemExit(0)\n"
)
_probe = subprocess.run(
    [sys.executable, "-c", _allocation_probe],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=60,
    preexec_fn=child_limits,
)
if _probe.returncode != 7:
    could_not_run(
        f"the child limits are not in effect: a process allocating 320 MiB under "
        f"RLIMIT_AS={ADDRESS_SPACE_LIMIT} exited {_probe.returncode} instead of "
        f"reporting the refused allocation (7), so one exploding fault could again "
        f"take the host down instead of being classified"
    )


# The fault, per model: `nop` writes 0x90 over a byte; `bits` flips one bit of it.
accepted, crashed, untouched = [], 0, 0
offs = [off + i for off, size, _n in covered for i in range(0, size, stride)]

# This shard's slice of the offsets. Every fault is a self-contained run of the binary,
# so the shards cannot interact; the union over shards is what the sequential scan
# produced, and the caller sums the accepted sets.
offs = offs[shard::nshards]
if not offs and total == 0:
    # The covered range itself is empty, not merely this shard's slice of it: with
    # --jobs above the number of offsets, empty slices are normal and must stay clean.
    could_not_run("the covered ranges contain no instruction byte to sweep")

# This shard's examined offsets, as the offsets themselves rather than as a count,
# written before the sweep so the driver can check the byte set this shard set out
# to cover even if it dies mid-run. The *witness* that the set is the one the symbol
# map describes is the driver's, deliberately: it re-derives the ranges from
# nm/objdump down a different path (shell arithmetic rather than this parse),
# compares them byte-for-byte with this shard's `.ranges`, and then checks this
# offset list against them. Guards here that recomputed `expected` from `covered`
# only compared two expansions of the same list and could never fire.
with open(sys.argv[1] + ".scanned_offsets", "w") as fh:
    fh.write("".join(f"{off}\n" for off in offs))
faults = (
    [(off, 0) for off in offs]
    if model == "nop"
    else [(off, 1 << bit) for off in offs for bit in range(8)]
)
for off, bit in faults:
    # Two single-byte writes per fault rather than rewriting the whole binary: the
    # first version rewrote it twice per byte, which is ~20 GB of I/O for this scan
    # and was a large part of why it took so long.
    # Two single-byte writes per fault instead of rewriting the binary twice, which
    # was ~20 GB of I/O for this scan. The handle cannot stay open across the run --
    # executing a file that is open for writing is ETXTBSY -- so it is written,
    # closed, executed, reopened and restored.
    with reopen_for_write(binpath) as fh:
        fh.seek(off)
        was = fh.read(1)[0]
        if model == "nop":
            if was == 0x90:
                continue
            damaged = b"\x90"
        else:
            damaged = bytes([was ^ bit])
        fh.seek(off)
        fh.write(damaged)
    try:
        verdict = run()
    except subprocess.TimeoutExpired:
        verdict = "crashed"
    finally:
        with reopen_for_write(binpath) as fh:
            fh.seek(off)
            fh.write(bytes([was]))
    if verdict == "accepted":
        accepted.append(off)
    elif verdict == "crashed":
        crashed += 1
    else:
        untouched += 1

print(f"  {label:<16} shard {shard + 1:>2}/{nshards} [{model}] scanned {len(faults):5d}  "
      f"rejected {untouched:5d}  crashed {crashed:5d}  ACCEPTED {len(accepted):3d}")
if accepted:
    # One line of the file around each accepting byte, so the map is usable, and the
    # symbol it belongs to, so the number can be read: an accepting byte in the decision
    # function and one in the entry point around it are different findings.
    in_decision = [off for off in accepted if "accept_or_reject" in symbol_of(off)]
    print(f"    accepting bytes (shard {shard + 1}): {len(accepted)} "
          f"-- {len(in_decision)} of them inside the decision function")
    for off in accepted[:8]:
        sym = symbol_of(off)
        short = sym.split("::")[-1] if "::" in sym else sym
        print(f"      0x{off:x} [{short}]  "
              + " ".join(f"{b:02x}" for b in original[off-3:off+4]))
    if len(accepted) > 8:
        print(f"      ... and {len(accepted) - 8} more")
# Machine-readable for the caller: every accepting byte, and the subset that is inside
# `accept_or_reject` -- two files, because the driver gates on the second one.
# A trailing newline on both files, always: the driver aggregates with
# `cat shard-*.accepted | grep -c .`, and without it the last line of one shard's file
# merges with the first line of the next, so the printed total was
# `true count - (files with entries - 1)` (measured: 4 printed as 3, 15 as 7).
with open(sys.argv[1] + ".accepted", "w") as fh:
    fh.write("".join(f"{x}\n" for x in accepted))
with open(sys.argv[1] + ".accepted_decision", "w") as fh:
    fh.write("".join(f"{x}\n" for x in accepted if "accept_or_reject" in symbol_of(x)))
with open(sys.argv[1] + ".ranges", "w") as fh:
    # The ranges as this shard handles them: file offsets (the same VMA->file-offset
    # mapping the sweep uses), sizes and symbol names, in `nm` order and in the same
    # text the driver's independent extraction prints, so the driver can `cmp` the
    # two. Dropping the mapping here changes every line and the comparison fires.
    fh.write("".join(f"{start} {size} {name}\n" for start, size, name in covered))
PY
}

detector_sensitivity_control
scan "plain (no hardened)"  "--no-default-features"
scan "hardened (default)"   "--features hardened"
# `ultra` adds the independent second implementation, so a byte corrupted in the shared
# KDF/MAC/SIMD code no longer has to be caught by the gate alone: the crate's own answer
# stops matching the witness's, and the gate that ANDs the agreement in rejects. This row
# is where that shows up as a number -- the mechanism the accepting sites live in
# (decoder desynchronisation in shared code) is exactly the code the witness does not share.
scan "ultra"                "--features ultra"

# ── Shard mode: report this slice and stop ──
# The cross-configuration verdict needs all three configurations' totals *and* the whole
# region, so it cannot be computed from one slice: `tools/fi_instruction_verdict.py` does it
# from the shards' reports. What a slice *can* check alone is the condition that must never
# hold in any of them -- an accepting fault inside the decision of a build that must not
# accept a forged tag -- and that runs before the report is written, so a slice carrying
# such a fault fails its own job rather than waiting for the aggregation.
if [ -n "$shard_i" ]; then
  shard_hardened_d="$(cat "$WORK/hardened (default).decision")"
  shard_ultra_d="$(cat "$WORK/ultra.decision")"
  shard_bad=0
  if [ "$shard_hardened_d" -ne 0 ] || [ "$shard_ultra_d" -ne 0 ]; then
    echo "FAIL: shard $shard_i/$shard_n found $shard_hardened_d accepting fault(s) inside" >&2
    echo "      the decision in the hardened build and $shard_ultra_d in the ultra one." >&2
    echo "      Neither build may accept a forged tag." >&2
    shard_bad=1
  fi
  python3 - "$REPORT" "$shard_i" "$shard_n" "$MODEL" "$WORK" <<'PY'
import hashlib, json, os, sys
report, i, n, model, work = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
def read(name):
    try:
        return int(open(os.path.join(work, name)).read().strip() or "0")
    except OSError:
        return 0

def digest(label):
    """SHA-256 over the union of this shard's examined offsets, per configuration.

    The verdict script can check *counts*, and counts can be written by hand; this is the
    part that says which bytes the numbers came from. Sharded, the offsets live in one file
    per core-slice (`shard-<label>-<n>.bin.scanned_offsets`), so the digest is taken over
    their union *in the same order and deduplication the witness uses*: a report copied from
    another shard, re-labelled, or invented fails the verdict even if its numbers are
    consistent.
    """
    import glob
    parts = []
    for path in sorted(glob.glob(os.path.join(work, f"shard-{label}-*.bin.scanned_offsets"))):
        try:
            with open(path, "rb") as fh:
                parts.extend(int(line) for line in fh.read().split() if line.strip())
        except OSError:
            pass
    if not parts:
        return None
    body = "\n".join(str(o) for o in sorted(set(parts))) + "\n"
    return hashlib.sha256(body.encode()).hexdigest()

configs = {}
for label in ("plain (no hardened)", "hardened (default)", "ultra"):
    configs[label] = {
        "scanned": read(label + ".scanned"),
        "covered_total": read(label + ".covered_total"),
        "accepting_total": read(label + ".count"),
        "accepting_inside_decision": read(label + ".decision"),
        "offsets_sha256": digest(label),
    }
with open(report, "w") as fh:
    json.dump({"shard": i, "n": n, "model": model, "configs": configs}, fh, indent=1, sort_keys=True)
print(f"shard {i}/{n} ({model} model): report written to {report}")
PY
  [ "$shard_bad" -eq 0 ] || exit 1
  echo "shard $shard_i/$shard_n: this slice is clean; the verdict is the aggregation job's"
  exit 0
fi

default_n="$(cat "$WORK/plain (no hardened).count")"
hardened_n="$(cat "$WORK/hardened (default).count")"
ultra_n="$(cat "$WORK/ultra.count")"
default_d="$(cat "$WORK/plain (no hardened).decision")"
hardened_d="$(cat "$WORK/hardened (default).decision")"
ultra_d="$(cat "$WORK/ultra.decision")"
echo
# What the criterion is, and why it is scoped to the decision function.
#
# The sweep finds accepting faults in every configuration, and "zero" was never a
# defensible target: the raw count is dominated by *decoder desynchronisation* in the
# code around the decision -- corrupting the second byte of a multi-byte instruction makes
# the following bytes execute as different instructions, and no source-level structure
# prevents the CPU from running different code. It also makes the raw counts incomparable
# across configurations, which is what a first version of this gate got wrong: `ultra`'s
# entry points contain more code than `hardened`'s (a call to the witness, an extra gate
# operand, a ciphertext copy), so a longer region naturally collects more accepting bytes
# even when every one of them is outside the decision.
#
# What *is* comparable, and what the three features are actually about, is the decision
# function itself: `accept_or_reject`. The property asserted here is
#
#   * no single-byte fault -- neutralised byte or flipped bit -- inside `accept_or_reject`
#     accepts a forgery in the `hardened` or `ultra` build;
#   * the opt-out build *does* have such a byte in the bit-flip model, or this scan is not
#     reaching the decision at all. That is the sweep's own positive control, and it is
#     model-specific for a reason worth writing down: the opt-out decision is one
#     `test`/`je` pair, and flipping the bit that turns `je` into `jne` falls through into
#     the *accept* store. Overwriting that byte with `0x90` does not do that -- the next
#     byte then decodes as part of a different instruction, and the run crashes instead of
#     accepting -- so in the `nop` model this control cannot hold and is not required.
#     (Both models are still swept in full; only this control is model-specific. The
#     *detector*'s sensitivity -- that it would report an acceptance at all -- is the
#     separate, model-independent control `detector_sensitivity_control` runs above,
#     before any sweep.)
#   * all six counts are printed, so a regression outside the decision is visible as a
#     number rather than absorbed by a threshold.
#
# Absolute counts are machine-code dependent (the README says as much about the map), so
# the gate is a comparison rather than a number to hit.
ok=1
if [ "$hardened_d" -ne 0 ] || [ "$ultra_d" -ne 0 ]; then
  echo "FAIL: $hardened_d accepting fault(s) inside the decision in the hardened build" >&2
  echo "      and $ultra_d in the ultra one. The second gate (and, under ultra, the" >&2
  echo "      independent implementation) exist so that no single fault in the decision" >&2
  echo "      accepts. See $WORK/*.accepted_decision for the bytes (the directory is" >&2
  echo "      kept on failure)." >&2
  ok=0
fi
if [ "$MODEL" = "bits" ] && [ "$default_d" -eq 0 ]; then
  echo "FAIL: the opt-out build has no accepting bit-flip inside the decision, so this" >&2
  echo "      sweep is not reaching the decision function and the rows above mean nothing." >&2
  echo "      Flipping the opcode bit of its single 'je' is supposed to fall through into" >&2
  echo "      the accept store -- that is the defect the hardened build exists to remove." >&2
  ok=0
fi
[ "$ok" -eq 1 ] || exit 1
echo "instruction-level FI [$MODEL${quick:+, quick}] accepting faults:"
printf '                      %-22s %6s total, %4s inside the decision\n' \
  "opt-out" "$default_n" "$default_d"
printf '                      %-22s %6s total, %4s inside the decision\n' \
  "hardened (default)" "$hardened_n" "$hardened_d"
printf '                      %-22s %6s total, %4s inside the decision\n' \
  "ultra" "$ultra_n" "$ultra_d"
echo "                      (the decision is what the layers are for: zero there in the"
echo "                       hardened and ultra builds)"
if [ -n "$quick" ]; then
  echo "                      quick mode sweeps the decision function only (every byte,"
  echo "                      both models, all three configurations); the entry points"
  echo "                      around it are the full sweep's region."
fi
