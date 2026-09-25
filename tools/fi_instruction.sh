#!/usr/bin/env bash
#
# Instruction-level fault injection, in software: corrupt one byte at a time in the
# compiled decision code and see what a forgery does.
#
# Why this and not only tools/fi_check.sh: that one writes faults down as *source*
# changes, which is a model of the fault and nothing more. This walks the actual
# machine code of `decrypt` and `decrypt_in_place_detached` in a built binary,
# replaces one byte at a time with `NOP`, and runs the decision test. Every run
# therefore answers the question a glitch asks: "if this byte were wrong, would a
# forgery still be rejected?" -- with no bench, on ordinary hardware.
#
# The output is a map, not a verdict: how many bytes of the decision code can be
# single-handedly corrupted into accepting a forgery, how many merely crash, and how
# many change nothing. The hardened build's map is the interesting one -- the point of
# two gates is that a single corrupted byte is not enough -- and it is printed next to
# the unhardened build's so the difference is visible rather than asserted.
#
# What this is not: a fault model. A real glitch can flip a bit rather than a byte,
# can hit a register or a bus rather than the instruction stream, and can be timed
# relative to the data it is meant to disturb. This covers the instruction stream,
# byte-sized, one at a time -- the part a software host can reach.
#
# Usage: tools/fi_instruction.sh [--quick]
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

# The two entry points that contain the decision, with their sizes.
syms = subprocess.run(["nm", "-S", binpath], capture_output=True, text=True).stdout
ranges = []
for line in syms.splitlines():
    f = line.split()
    if len(f) >= 4 and f[2] in ("t", "T") and b"decrypt" in f[3].encode():
        addr, size = int(f[0], 16), int(f[1], 16)
        if size:
            ranges.append((addr, size))
if not ranges:
    sys.exit("FAIL: no decrypt symbols -- was the binary stripped?")

covered = [(a - text_vaddr + text_off, s) for a, s in ranges]
total = sum(s for _, s in covered)
stride = 7 if quick else 1

with open(binpath, "rb") as fh:
    original = fh.read()

def run():
    r = subprocess.run([binpath], capture_output=True, text=True, timeout=60)
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
    body = bytearray(original)
    was = body[off]
    if was == 0x90:
        continue
    body[off] = 0x90
    with open(binpath, "wb") as fh:
        fh.write(body)
    try:
        verdict = run()
    except subprocess.TimeoutExpired:
        verdict = "crashed"
    finally:
        with open(binpath, "wb") as fh:
            fh.write(original)
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
