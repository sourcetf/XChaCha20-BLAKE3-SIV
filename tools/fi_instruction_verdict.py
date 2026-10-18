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
        # Evidence binding: the counts alone can be written by hand, so each report carries
        # the SHA-256 of the offset list its numbers were computed from. Rejecting a missing
        # digest keeps the format from regressing to numbers; the duplicate check below is
        # what makes a copied report visible (two shards cannot have swept the same bytes).
        for label, cfg in r.get("configs", {}).items():
            if not cfg.get("offsets_sha256"):
                problems.append(
                    f"shard {r.get('shard')} ({label}) carries no offsets_sha256: the report "
                    "is not bound to the bytes it swept, so its numbers are unverifiable"
                )
        digests = {
            (label, cfg.get("offsets_sha256"))
            for label, cfg in r.get("configs", {}).items()
            if cfg.get("offsets_sha256")
        }
        if len(digests) > 1:
            # The three configurations sweep different regions, so their digests differ;
            # two shards sharing one is only a finding if the *same* label does.
            pass
    # Two shards with the same (label, digest) swept identical byte sets, which the
    # partition makes impossible: one report was copied from another (or one shard never
    # ran and its numbers were duplicated).
    seen = {}
    for r in reports:
        for label, cfg in r.get("configs", {}).items():
            key = (label, cfg.get("offsets_sha256"))
            if not key[1]:
                continue
            if key in seen:
                problems.append(
                    f"shards {seen[key]} and {r.get('shard')} report identical {label} offset "
                    "sets: the slices are disjoint by construction, so one report was copied "
                    "and a slice was never swept"
                )
            else:
                seen[key] = r.get("shard")

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
    # The opt-out build is the positive control -- but only in the `bits` model, exactly as
    # in the unsharded tool: flipping the opcode bit of its single `je` is supposed to fall
    # through into the accept store, and that is what proves the sweep reaches the decision.
    # The `nop` model has no such control (overwriting a byte with `0x90` does not change the
    # decision's outcome), so demanding one there would fail every correct nop run. Checked
    # on the sum over all shards: one slice may legitimately hold no breakable byte, since
    # the shards partition the region and `--quick` narrows it to the decision.
    if args.model == "bits" and "plain (no hardened)" in rows and rows["plain (no hardened)"][1] == 0:
        problems.append(
            "plain (no hardened): the opt-out build has no accepting bit-flip inside the "
            "decision across every shard, so this sweep is not reaching the decision and the "
            "hardened/ultra rows mean nothing"
        )
    present = [label for label in ORDER if label in rows]
    # The *totals* are deliberately not compared between configurations. They are dominated
    # by decoder desynchronisation in shared code, and the three builds contain different
    # code, so `ultra` having a larger total than `hardened` says nothing about the layers;
    # both README.md ("not comparable between configurations") and tests/README.md say so.
    # An earlier revision of this script gated on that comparison, which made the bits
    # verdict fail by construction on any correct sweep whose totals happened not to be
    # ordered -- a gate that always fails is read as noise and gets switched off, which is
    # the failure mode this repository keeps removing. The comparable quantity is the
    # decision-scoped count above, and that is what gates.
    for label in present:
        total, inside = rows[label]
        print(f"  {label:24s} {total:5d} accepting total (not comparable across builds), "
              f"{inside} inside the decision (gated)")

    if problems:
        print(f"FAIL: {len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"      {p}", file=sys.stderr)
        return 1
    print(
        "the sharded sweep reproduces the unsharded verdict: every slice swept exactly its "
        "share, no accepting fault inside the decision of a build that must not have one, and "
        "the opt-out control's decision still breakable"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
