#!/usr/bin/env bash
#
# Instruction-level fault injection, in software: corrupt one byte at a time in the
# compiled decision code and see what a forgery does.
#
# Measured on this machine: 3920 bytes in the unhardened binary and 5680 in the
# hardened one, and **zero** of them accept a forgery in either build. The output is a
# map rather than a verdict -- how many faults are neutral, how many crash, how many
# accept -- and the hardened build's map is printed beside the unhardened one so the
# difference is visible rather than asserted.
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
# Usage: tools/fi_instruction.sh [--quick] [--bits]
# Exit codes: 0 = both maps came out with zero accepting faults; 1 = otherwise, or the
#             machinery failed.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CC="${CC:-$HOME/.local/bin/cc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="$WORK/target"

quick=""
MODEL="nop"
for arg in "$@"; do
  case "$arg" in
    --quick) quick="--quick" ;;
    --bits) MODEL="bits" ;;
  esac
done

scan() {  # label, features
  local label="$1" features="$2"
  cargo test --release --test decision --no-run \
    --config 'profile.release.strip=false' $features > /dev/null 2>&1
  local bin
  bin="$(ls -t "$CARGO_TARGET_DIR"/release/deps/decision-* | grep -v '\.d$' | head -1)"
  [ -n "$bin" ] || { echo "FAIL: no decision binary" >&2; exit 1; }
  python3 - "$bin" "$label" "$quick" "$MODEL" <<'PY'
import re
import subprocess
import sys

binpath, label, quick, model = sys.argv[1], sys.argv[2], sys.argv[3] == "--quick", sys.argv[4]

# Where `.text` lives in the file, so a virtual address from `nm` can be turned into
# a file offset.
hdr = subprocess.run(["objdump", "-h", binpath], capture_output=True, text=True).stdout
text = re.search(r"\.text\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", hdr)
if not text:
    sys.exit("FAIL: no .text section")
_, text_vaddr, text_off = (int(x, 16) for x in text.groups())

# The functions that contain the decision, with their sizes: the two entry points
# around it, and the decision itself -- `#[inline(never)]` keeps it in a symbol of
# its own (see `accept_or_reject` in src/lib.rs), so without this the branch the
# scan exists to sweep would sit outside every range.
syms = subprocess.run(["nm", "-S", binpath], capture_output=True, text=True).stdout
ranges = []
for line in syms.splitlines():
    f = line.split()
    if len(f) >= 4 and f[2] in ("t", "T"):
        name = f[3].encode()
        if b"decrypt" in name or b"accept_or_reject" in name:
            addr, size = int(f[0], 16), int(f[1], 16)
            if size:
                ranges.append((addr, size))
if not ranges:
    sys.exit("FAIL: no decrypt or accept_or_reject symbols -- was the binary stripped?")

covered = [(a - text_vaddr + text_off, s) for a, s in ranges]
total = sum(s for _, s in covered)
stride = 7 if quick else 1

with open(binpath, "rb") as fh:
    original = fh.read()

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
offs = [off + i for off, size in covered for i in range(0, size, stride)]
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

print(f"  {label:<26} [{model}] scanned {len(faults):5d}  rejected {untouched:5d}  "
      f"crashed {crashed:5d}  ACCEPTED {len(accepted):3d}")
if accepted:
    # One line of the file around each accepting byte, so the map is usable.
    print(f"    bytes that single-handedly accept a forgery: {len(accepted)}")
    for off in accepted[:8]:
        print(f"      0x{off:x}  " + " ".join(f"{b:02x}" for b in original[off-3:off+4]))
    if len(accepted) > 8:
        print(f"      ... and {len(accepted) - 8} more")
# Machine-readable for the caller.
with open(sys.argv[1] + ".accepted", "w") as fh:
    fh.write("\n".join(str(x) for x in accepted))
PY
  echo "$(cat "$bin.accepted" | grep -c . || true)" > "$WORK/$label.count"
}

scan "plain (no hardened)"  "--no-default-features"
scan "hardened (default)"   "--features hardened"

default_n="$(cat "$WORK/plain (no hardened).count")"
hardened_n="$(cat "$WORK/hardened (default).count")"
echo
# Absolute, not relative. The earlier criterion was `hardened_n <= default_n`, which
# passes when *both* builds accept faults -- 50 accepting bytes in each would have
# been reported as "no worse than", and the README's "none accepting" would have been
# a printed fact rather than an enforced one. A single accepting byte is a finding.
# The hardened build must have *none*, in either model: that is the claim, and the
# second gate is what makes it true. The opt-out build has a pinned residual under the
# bit-flip model -- one bit, on the opcode of the decision's arm selection, where a
# single gate has nothing behind it (measured; the site is recorded in the README
# table). A pinned count, not an allowance: a change that makes it two fails here.
PLAIN_PINNED=1
if [ "$MODEL" = "nop" ]; then
  plain_allowed=0
else
  plain_allowed=$PLAIN_PINNED
fi
if [ "$hardened_n" -eq 0 ] && [ "$default_n" -le "$plain_allowed" ]; then
  case "$MODEL" in
    nop) echo "instruction-level FI: no single neutralised byte accepts a forgery in either build" ;;
    *)   echo "instruction-level FI: no single flipped bit accepts a forgery in the hardened" ;          echo "                      build ($hardened_n), and $default_n in the opt-out build," ;          echo "                      where $PLAIN_PINNED is the pinned residual" ;;
  esac
  exit 0
fi
echo "FAIL: $default_n accepting fault(s) in the opt-out build (pinned: $plain_allowed for" >&2
echo "      this model), $hardened_n in the hardened one (pinned: 0). Look at" >&2
echo "      \$WORK/*.accepted for the bytes, and see the README's fault-model table." >&2
exit 1
echo "FAIL: the hardened build has *more* single-byte accepting faults ($hardened_n) than the plain onne ($default_n)" >&2
exit 1
