#!/usr/bin/env python3
"""Combine the instruction sweep's shard reports into the verdict `tools/fi_instruction.sh`
prints when it runs unsharded.

    tools/fi_instruction_verdict.py --shards 6 --model nop shard-1.json ... shard-6.json

The sweep covers every symbol-mapped byte of three configurations exactly once across N
shards (`tools/fi_instruction.sh --shard I/N --report FILE`). This script is what makes
"exactly once across N" checkable *outside* the shards, and it is the reason the scheduled
sweep could be sharded without reducing what it covers: a shard that never ran, ran twice,
swept a different slice, or described a different region fails here, and a failure here is a
failed run rather than a smaller sweep that reads as a pass.

Then it applies the tool's own cross-configuration reading:

  * no accepting fault inside the decision in `hardened` or `ultra` -- the builds that must
    not accept a forged tag at all;
  * each layer at least as good as the one below it (`ultra` <= `hardened` <= plain) in the
    total accepting faults, which is the ordering the tool prints.

Exit codes follow the repository's convention: 0 = the verdict holds, 1 = it does not (or
the reports are not a complete sweep), 3 = the reports could not be read at all.
"""

import argparse
import json
import sys

# The order the tool prints, from the weakest layering to the strongest: each entry must be
# at least as good as the one before it.
ORDER = ["plain (no hardened)", "hardened (default)", "ultra"]


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"FAIL: could not read a shard report ({path}): {exc}", file=sys.stderr)
        sys.exit(3)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--shards", type=int, required=True, help="N, the number of shards expected")
    ap.add_argument("--model", default="nop", help="the fault model every shard must have run")
    ap.add_argument("reports", nargs="+", help="the shards' JSON reports")
    args = ap.parse_args(argv)

    reports = [load(p) for p in args.reports]
    problems = []

    # Completeness first. A missing shard is a failure, not less work.
    ids = sorted(r.get("shard") for r in reports)
    if ids != list(range(1, args.shards + 1)):
        problems.append(
            f"expected one report per shard for shards 1..{args.shards}, got {ids}"
            + (" (a shard that did not run must fail the verdict, not shrink the sweep)" if len(ids) != args.shards else "")
        )

    labels = sorted(reports[0].get("configs", {})) if reports else []
    for r in reports:
        if sorted(r.get("configs", {})) != labels:
            problems.append(f"shard {r.get('shard')} reports a different configuration set")
        if r.get("model") != args.model:
            problems.append(
                f"shard {r.get('shard')} ran the {r.get('model')} model, not {args.model}"
            )
        if r.get("n") != args.shards:
            problems.append(
                f"shard {r.get('shard')} was written for {r.get('n')} shards, not {args.shards}"
            )

    for label in labels:
        totals = {
            r["configs"][label].get("covered_total")
            for r in reports
            if label in r.get("configs", {})
        }
        if len(totals) != 1 or None in totals:
            problems.append(
                f"{label}: the shards disagree about the region's size ({sorted(t or -1 for t in totals)})"
            )
            continue
        total = totals.pop()
        scanned = sum(r["configs"][label].get("scanned", 0) for r in reports)
        if scanned != total:
            hint = (
                " (a shard whose slice did not run looks exactly like this)"
                if scanned < total
                else " (slices that overlap, or a region that grew between runs)"
            )
            problems.append(f"{label}: the shards swept {scanned} of the region's {total} bytes{hint}")

    rows = {
        label: (
            sum(r["configs"][label].get("accepting_total", 0) for r in reports),
            sum(r["configs"][label].get("accepting_inside_decision", 0) for r in reports),
        )
        for label in labels
    }
    for label in ("hardened (default)", "ultra"):
        if label in rows and rows[label][1] != 0:
            problems.append(f"{label}: {rows[label][1]} accepting fault(s) inside the decision")
    present = [label for label in ORDER if label in rows]
    for lower, upper in zip(present, present[1:]):
        if rows[upper][0] > rows[lower][0]:
            problems.append(
                f"{upper} accepts more faults than {lower} ({rows[upper][0]} > {rows[lower][0]}): "
                "a layer is worse than the one below it"
            )

    print(f"shard coverage: {len(reports)} of {args.shards} report(s), {args.model} model")
    for label in present:
        total, inside = rows[label]
        print(f"  {label:24s} {total:5d} accepting total, {inside} inside the decision")
    if problems:
        print(f"FAIL: {len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"      {p}", file=sys.stderr)
        return 1
    print(
        "the sharded sweep reproduces the unsharded verdict: every slice swept exactly its "
        "share, no accepting fault in a build that must not have one, and the layers ordered"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
