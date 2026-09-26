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
# machine code of `decrypt` and `decrypt_in_place_detached` in a built binary,
# replaces one byte at a time with `NOP`, and runs the decision test. Every run
# therefore answers the question a glitch asks: "if this byte were wrong, would a
# forgery still be rejected?" -- with no bench, on ordinary hardware.
#
# One mode: every byte of the decision code, replaced with `NOP` in turn, in both
# builds. Measured at about seven minutes, which is why it runs in the mutation job
# (once per push) and not in the fast ones -- an earlier estimate of half an hour was
# really the per-patch *timeout* being hit by branches whose NOP turns a loop into a
# spin, and a five-second timeout fixed that.
#
# What this is not: a fault model. A real glitch can flip a bit rather than replace a
# byte, can hit a register or a bus rather than the instruction stream, and can be
# timed relative to the data it is meant to disturb. Replacing a byte with `NOP` is
# the "neutralise this instruction" fault, which biases towards *rejection* (a
# neutralised comparison or branch usually fails closed); the symmetric case, a bit
# flip that turns a decision into an acceptance, is what the cheap tier's second gate
# is for and what `tools/fi_check.sh`'s `gate0-value-forced` row covers.
#
# Usage: tools/fi_instruction.sh
# Exit codes: 0 = the maps came out with the hardened build no worse than the
#             unhardened one; 1 = otherwise, or the machinery failed.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CC="${CC:-$HOME/.local/bin/cc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="$WORK/target"

quick=""
[ "${1:-}" = "--quick" ] && quick="--quick"

scan() {  # label, features
  local label="$1" features="$2"
  cargo test --release --test decision --no-run \
    --config 'profile.release.strip=false' $features > /dev/null 2>&1
  local bin
  bin="$(ls -t "$CARGO_TARGET_DIR"/release/deps/decision-* | grep -v '\.d$' | head -1)"
  [ -n "$bin" ] || { echo "FAIL: no decision binary" >&2; exit 1; }
  python3 - "$bin" "$label" "$quick" <<'PY'
import re
import subprocess
import sys

binpath, label, quick = sys.argv[1], sys.argv[2], sys.argv[3] == "--quick"

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

accepted, crashed, untouched = [], 0, 0
offs = [off + i for off, size in covered for i in range(0, size, stride)]
for off in offs:
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
        if was == 0x90:
            continue
        fh.seek(off)
        fh.write(b"\x90")
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

print(f"  {label:<26} scanned {len(offs):5d}  rejected {untouched:5d}  "
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

scan "default (no hardened)" ""
scan "hardened"             "--features hardened"

default_n="$(cat "$WORK/default (no hardened).count")"
hardened_n="$(cat "$WORK/hardened.count")"
echo
if [ "$hardened_n" -le "$default_n" ]; then
  echo "instruction-level FI: hardened is no worse than default ($hardened_n vs $default_n accepting bytes)"
  exit 0
fi
echo "FAIL: the hardened build has *more* single-byte accepting faults ($hardened_n) than the default one ($default_n)" >&2
exit 1
