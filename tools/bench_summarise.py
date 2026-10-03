#!/usr/bin/env python3
"""Summarise the three-pass benchmark campaign into performance.md's tables.

Reads `/home/dev123/.audit/bench/<config>-pass<N>.txt` (raw `cargo bench --bench compare`
output) and prints:
  * throughput ratio against `xchacha20-poly1305`, per config, per size, for encrypt,
    decrypt and the round trip (the 7 tabulated sizes);
  * latency in microseconds at 64 B / 16 KiB / 1 MiB for the three configs and the
    reference;
  * the `ultra`-vs-default cost table;
  * the noise floor, computed from the reference implementation's own spread.

Every figure is the median over the three passes of criterion's own median, which is the
protocol performance.md documents.
"""
import glob
import os
import re
import statistics
import sys

BENCH_DIR = os.environ.get("BENCH_DIR", "bench-out")
CONFIGS = ["hardened", "opt-out", "ultra"]
GROUPS = ["encrypt_in_place_detached", "decrypt_in_place_detached", "encrypt_then_decrypt"]
REF = "xchacha20-poly1305"
OURS = "xchacha20-blake3-siv"
ALLOC = "xchacha20-blake3-siv (allocating API)"
SIZES = [64, 256, 1024, 4096, 16384, 65536, 1048576]  # the tabulated ones

ID_RE = re.compile(r"^(encrypt_in_place_detached|decrypt_in_place_detached|encrypt_then_decrypt)/"
                   r"(.+)/(\d+)$")
TIME_RE = re.compile(r"^\s+time:\s+\[(\S+ \S+) (\S+ \S+) (\S+ \S+)\]")
UNIT = {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}


def to_seconds(text):
    num, unit = text.split()
    return float(num) * UNIT[unit]


def parse(path):
    """{(group, impl, size): seconds} — the first `time:` line after each id."""
    out = {}
    with open(path, errors="replace") as fh:
        lines = fh.read().splitlines()
    for i, line in enumerate(lines):
        m = ID_RE.match(line.strip())
        if not m:
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            t = TIME_RE.match(lines[j])
            if t and "%" not in lines[j]:
                out[(m.group(1), m.group(2), int(m.group(3)))] = to_seconds(t.group(2))
                break
    return out


def main():
    passes = {}   # config -> [parsed_pass1, pass2, pass3]
    for cfg in CONFIGS:
        got = []
        for p in (1, 2, 3):
            path = os.path.join(BENCH_DIR, f"{cfg}-pass{p}.txt")
            if not os.path.isfile(path):
                sys.exit(f"missing {path}")
            got.append(parse(path))
        passes[cfg] = got

    def cell(cfg, group, impl, size):
        vals = [p[(group, impl, size)] for p in passes[cfg] if (group, impl, size) in p]
        if not vals:
            return None
        return statistics.median(vals)

    def fmt_ratio(v):
        return f"{v:.2f}x" if v is not None else "?"

    def throughput(cfg, group, size):
        """Ratio against the reference, > 1 = this crate is faster: ref_time / ours_time."""
        ours = cell(cfg, group, OURS, size)
        ref = cell(cfg, group, REF, size)
        return (ref / ours) if ours and ref else None

    print("== throughput ratio vs xchacha20-poly1305 (median of 3 passes) ==")
    print("   (> 1 means this crate is faster)")
    hdr = "| Message | " + " | ".join(
        f"{c} {'enc' if g.startswith('encrypt_in') else 'dec'}"
        for g in GROUPS[:2] for c in CONFIGS) + " |"
    print(hdr)
    for size in SIZES:
        row = [f"{size} B" if size < 1024 else (f"{size//1024} KiB" if size < 1048576 else "1 MiB")]
        for g in GROUPS[:2]:
            for cfg in CONFIGS:
                row.append(fmt_ratio(throughput(cfg, g, size)))
        print("| " + " | ".join(row) + " |")

    print()
    print("== round trip ratio ==")
    for size in SIZES:
        vals = []
        for cfg in CONFIGS:
            vals.append(f"{cfg}={fmt_ratio(throughput(cfg, 'encrypt_then_decrypt', size))}")
        print(f"  {size:>8} B  " + "  ".join(vals))

    print()
    print("== latency (microseconds, median of 3 passes) ==")
    for size in (64, 16384, 1048576):
        for g in GROUPS[:2]:
            vals = []
            for cfg in CONFIGS:
                a = cell(cfg, g, OURS, size)
                vals.append(f"{cfg}={a*1e6:8.2f}" if a else f"{cfg}=?")
            b = cell("hardened", g, REF, size)
            vals.append(f"ref={b*1e6:8.2f}" if b else "ref=?")
            print(f"  {g.split('_')[0]:>8} {size:>8} B  " + "  ".join(vals))

    print()
    print("== ultra vs default (hardened) ==")
    print("   decrypt / encrypt are in-place; round trip in place vs allocating")
    for size in SIZES:
        vals = []
        for g, label in [(("decrypt_in_place_detached"), "dec"),
                         (("encrypt_in_place_detached"), "enc"),
                         (("encrypt_then_decrypt"), "rt")]:
            a = cell("ultra", g, OURS, size)
            b = cell("hardened", g, OURS, size)
            vals.append(f"{label}={a/b:5.2f}x" if a and b else f"{label}=?")
        a = cell("ultra", "encrypt_then_decrypt", ALLOC, size)
        b = cell("hardened", "encrypt_then_decrypt", ALLOC, size)
        vals.append(f"rt-alloc={a/b:5.2f}x" if a and b else "rt-alloc=?")
        print(f"  {size:>8} B  " + "  ".join(vals))

    print()
    print("== allocating round trip, latency (microseconds) ==")
    for size in (64, 16384, 1048576):
        vals = []
        for cfg in CONFIGS:
            a = cell(cfg, "encrypt_then_decrypt", ALLOC, size)
            vals.append(f"{cfg}={a*1e6:9.2f}" if a else f"{cfg}=?")
        print(f"  {size:>8} B  " + "  ".join(vals))

    print()
    print("== noise floor: pass-to-pass spread of the reference implementation ==")
    # The reference code is identical in all nine runs (three configurations x three
    # passes), so the spread of its own cells across *passes* is the floor -- the
    # statistic performance.md documents. One spread per (config, group, size) cell.
    pass_spreads = []
    for cfg in CONFIGS:
        for g in GROUPS:
            for size in SIZES:
                vals = [p[(g, REF, size)] for p in passes[cfg] if (g, REF, size) in p]
                if len(vals) >= 2:
                    pass_spreads.append((max(vals) - min(vals)) / statistics.median(vals))
    pass_spreads.sort()
    n = len(pass_spreads)
    print(f"  {len(CONFIGS)*3*len(GROUPS)*len(SIZES)} reference measurements; "
          f"{n} pass-to-pass cells")
    print(f"  median spread {statistics.median(pass_spreads)*100:.1f}%   "
          f"p90 {pass_spreads[min(n-1, int(0.9*n))]*100:.1f}%   "
          f"worst {pass_spreads[-1]*100:.1f}%")

    # And the spread across all nine runs of a cell (configs included), which is the
    # looser figure: it also captures cross-configuration drift.
    all_spreads = []
    for g in GROUPS:
        for size in SIZES:
            vals = [p[(g, REF, size)] for cfg in CONFIGS for p in passes[cfg]
                    if (g, REF, size) in p]
            if len(vals) >= 2:
                all_spreads.append((max(vals) - min(vals)) / statistics.median(vals))
    all_spreads.sort()
    n = len(all_spreads)
    print(f"  across all nine runs: median {statistics.median(all_spreads)*100:.1f}%   "
          f"p90 {all_spreads[min(n-1, int(0.9*n))]*100:.1f}%   "
          f"worst {all_spreads[-1]*100:.1f}%")


if __name__ == "__main__":
    main()