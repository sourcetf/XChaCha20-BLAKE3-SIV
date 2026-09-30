#!/usr/bin/env bash
#
# Instruction-level fault injection, in software: corrupt one byte at a time in the
# compiled decision code and see what a forgery does.
#
# Measured on this machine, full sweeps: 1 accepting byte in 5526 and 13 accepting
# single-bit flips in 44208 for the default (hardened) build; 9 in 4268 and 152 in 34144
# for the opt-out one. **Not zero**, and that is the corrected picture -- see the
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
# Cost: about seven minutes for the full `nop` sweep and about one for `--quick`
# (every seventh byte), which is why the full one runs in the scheduled `wide` job and
# `--quick` runs in the mutation job on every push. `--bits` is eight times its `nop`
# counterpart, so it is run with `--quick` on every push and in full nightly. An
# earlier estimate of half an hour for the `nop` sweep was really the per-patch
# *timeout* being hit by branches whose NOP turns a loop into a spin, and a
# five-second timeout fixed that.
#
# What this is still not: a fault model. A real glitch can hit a register or a bus
# rather than the instruction stream, can be timed relative to the data it is meant to
# disturb, and can be *targeted* rather than uniform. This enumerates two uniform
# single-fault models over the instruction stream and nothing else.
#
# Usage: tools/fi_instruction.sh [--quick] [--bits] [--jobs N]
#        (--jobs defaults to the core count, capped at 16; the sweep shards across cores)
# Exit codes: 0 = every layer is at least as good as the one below it; 1 = otherwise,
#             or the machinery failed.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CC="${CC:-$HOME/.local/bin/cc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="$WORK/target"

quick=""
MODEL="nop"
JOBS=""
for arg in "$@"; do
  case "$arg" in
    --quick) quick="--quick" ;;
    --bits) MODEL="bits" ;;
    --jobs) JOBS="next" ;;
    --jobs=*) JOBS="${arg#--jobs=}" ;;
    *)
      if [ "$JOBS" = "next" ]; then JOBS="$arg"; else
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

scan() {  # label, features
  local label="$1" features="$2"
  cargo test --release --test decision --no-run \
    --config 'profile.release.strip=false' $features > /dev/null 2>&1
  local bin
  bin="$(ls -t "$CARGO_TARGET_DIR"/release/deps/decision-* | grep -v '\.d$' | head -1)"
  [ -n "$bin" ] || { echo "FAIL: no decision binary" >&2; exit 1; }

  local shard pids=()
  for shard in $(seq 0 $((JOBS - 1))); do
    cp "$bin" "$WORK/shard-$label-$shard.bin"
    scan_shard "$WORK/shard-$label-$shard.bin" "$label" "$quick" "$MODEL" "$shard" "$JOBS" &
    pids+=("$!")
  done
  local pid failed=0
  for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
  done
  [ "$failed" -eq 0 ] || { echo "FAIL: a sweep shard failed" >&2; exit 1; }
  # The counts are the union over shards; the shards are disjoint by construction, so
  # summing distinct offsets is the same set the sequential scan would have produced.
  # Two counts per configuration: every accepting byte, and the subset inside
  # `accept_or_reject` (the decision itself) -- the driver gates on the second.
  cat "$WORK"/shard-"$label"-*.bin.accepted 2>/dev/null | grep -c . > "$WORK/$label.count" || true
  cat "$WORK"/shard-"$label"-*.bin.accepted_decision 2>/dev/null | grep -c . \
    > "$WORK/$label.decision" || true
  cat "$WORK"/shard-"$label"-0.bin.ranges > "$WORK/$label.ranges" 2>/dev/null || true
}

# The scanner, run once per shard with (binary, label, quick, model, shard, nshards):
# offsets are partitioned modulo `nshards` and each shard may only touch its own copy of
# the binary. The verdicts are per fault, so the shards are independent by construction
# and their accepted sets are disjoint.
scan_shard() {  # bin, label, quick, model, shard, nshards
  python3 - "$@" <<'PY'
import re
import subprocess
import sys

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
# `--quick` samples every thirteenth byte rather than every seventh: the sweep now covers
# three configurations, and the largest of them (`ultra`) is bigger than the other two
# together, so the coarse stride is what keeps the per-push cost near what it was. The
# full sweeps (stride 1) are the ones that assert anything -- quick mode's own note says so
# -- and they run in the `wide` job and locally.
stride = 13 if quick else 1

def run():
    r = subprocess.run([binpath], capture_output=True, text=True, timeout=5)  # a NOPed
    # branch inside a loop hangs; the test itself needs milliseconds, so anything
    # past a few seconds is that hang, not a slow success
    if r.returncode == 0:
        return "rejected"
    blob = r.stdout + r.stderr
    if "forged tag accepted" in blob:
        return "accepted"
    return "crashed"

# A baseline: unpatched, the test must pass.
base = run()
if base != "rejected":
    sys.exit(f"FAIL: the unpatched binary reports {base}, so nothing below is meaningful")

# The fault, per model: `nop` writes 0x90 over a byte; `bits` flips one bit of it.
accepted, crashed, untouched = [], 0, 0
offs = [off + i for off, size, _n in covered for i in range(0, size, stride)]
# This shard's slice of the offsets. Every fault is a self-contained run of the binary,
# so the shards cannot interact; the union over shards is what the sequential scan
# produced, and the caller sums the accepted sets.
offs = offs[shard::nshards]
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
    with open(binpath, "r+b") as fh:
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
        with open(binpath, "r+b") as fh:
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
with open(sys.argv[1] + ".accepted", "w") as fh:
    fh.write("\n".join(str(x) for x in accepted))
with open(sys.argv[1] + ".accepted_decision", "w") as fh:
    fh.write("\n".join(str(x) for x in accepted if "accept_or_reject" in symbol_of(x)))
with open(sys.argv[1] + ".ranges", "w") as fh:
    fh.write("\n".join(f"{n} {s}" for _a, s, n in ranges))
PY
}

scan "plain (no hardened)"  "--no-default-features"
scan "hardened (default)"   "--features hardened"
# `ultra` adds the independent second implementation, so a byte corrupted in the shared
# KDF/MAC/SIMD code no longer has to be caught by the gate alone: the crate's own answer
# stops matching the witness's, and the gate that ANDs the agreement in rejects. This row
# is where that shows up as a number -- the mechanism the accepting sites live in
# (decoder desynchronisation in shared code) is exactly the code the witness does not share.
scan "ultra"                "--features ultra"

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
#     reaching the decision at all. That is the positive control, and it is model-specific
#     for a reason worth writing down: the opt-out decision is one `test`/`je` pair, and
#     flipping the bit that turns `je` into `jne` falls through into the *accept* store.
#     Overwriting that byte with `0x90` does not do that -- the next byte then decodes as
#     part of a different instruction, and the run crashes instead of accepting -- so in
#     the `nop` model this control cannot hold and is not required. (Both models are still
#     swept in full; only the control is model-specific.)
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
  echo "      accepts. See \$WORK/*.accepted_decision for the bytes." >&2
  ok=0
fi
if [ "$MODEL" = "bits" ] && [ -z "$quick" ] && [ "$default_d" -eq 0 ]; then
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
  echo "                      quick mode samples every ${stride:-thirteenth} byte, so the"
  echo "                      opt-out control is only asserted by the full sweep (and only"
  echo "                      in the bit-flip model -- see the comment above)."
fi
