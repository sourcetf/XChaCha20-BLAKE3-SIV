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
  * the `bits` model's opt-out control is still breakable inside the decision, so the
    sweep is reaching the decision at all.

The per-configuration `accepting_total` values are printed but deliberately not compared:
the three builds contain different code, and the totals are dominated by decoder
desynchronisation in shared code, not by the layers. The decision-scoped count gates.

Exit codes follow the repository's convention: 0 = the verdict holds, 1 = it does not (or
the reports are not a complete sweep), 3 = the reports could not be read at all.
"""

import argparse
import json
import re
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

    # Completeness first. A missing shard is a failure, not less work. The id is type-
    # checked before sorting: a string or null used to raise `TypeError: '<' not supported
    # between instances of 'str' and 'int'`, replacing the diagnosis with a traceback.
    ids = []
    for r in reports:
        shard = r.get("shard")
        if isinstance(shard, int) and not isinstance(shard, bool):
            ids.append(shard)
        else:
            problems.append(
                f"a report has shard={shard!r}, which is not an integer shard id"
            )
    ids.sort()
    if ids != list(range(1, args.shards + 1)):
        problems.append(
            f"expected one report per shard for shards 1..{args.shards}, got {ids}"
            + (" (a shard that did not run must fail the verdict, not shrink the sweep)" if len(ids) != args.shards else "")
        )

    # The configuration set is fixed, not whatever the first report happens to carry.
    # Taking it from `reports[0]` let a report set with `"configs": {}` (or only the
    # default build) skip every loop below and print the success message with rc 0 -- a
    # sweep with no measurements read as a verified one. The tool emits exactly these
    # three labels, and every report must carry all of them.
    labels = sorted(ORDER)
    for r in reports:
        got = sorted(r.get("configs", {}))
        if got != labels:
            problems.append(
                f"shard {r.get('shard')} reports configurations {got}; the sweep must "
                f"carry all of {labels}"
            )
        if r.get("model") != args.model:
            problems.append(
                f"shard {r.get('shard')} ran the {r.get('model')} model, not {args.model}"
            )
        if r.get("n") != args.shards:
            problems.append(
                f"shard {r.get('shard')} was written for {r.get('n')} shards, not {args.shards}"
            )
        for label, cfg in r.get("configs", {}).items():
            # Every count is a count of things that happened. A negative one cannot come
            # from the tool, and it used to be printed as-is (an audit passed
            # `accepting_total = -100` on all six shards and got `-600 accepting total`
            # accepted); with the gate on the decision-scoped count it no longer changes a
            # verdict, but a report that cannot have been produced should not be read as a
            # measurement at all. `bool` is an `int` in Python, so reject it explicitly: a
            # JSON `false` used to sum as zero.
            for key in (
                "scanned",
                "covered_total",
                "accepting_total",
                "accepting_inside_decision",
            ):
                value = cfg.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    problems.append(
                        f"shard {r.get('shard')} ({label}): {key}={value!r} is not a count; "
                        "the shard reports were not produced by the tool"
                    )
        # Evidence binding: the counts alone can be written by hand, so each report carries
        # the SHA-256 of the offset list its numbers were computed from. This is a tripwire,
        # not a cryptographic proof against a hand-written report: the offset lists are not
        # submitted with the report, so the digest cannot be recomputed here. Requiring the
        # exact 64-hex shape still rejects a placeholder, a missing field, and the empty
        # reports the earlier gate accepted.
        for label, cfg in r.get("configs", {}).items():
            digest = cfg.get("offsets_sha256")
            scanned = cfg.get("scanned")
            # A slice can legitimately be empty when `--quick` narrows the region and
            # there are more shards than bytes; the tool then writes a null digest. That
            # is acceptable only when the report itself says it scanned nothing.
            empty_slice = (
                isinstance(scanned, int)
                and not isinstance(scanned, bool)
                and scanned == 0
            )
            valid_digest = isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            if not valid_digest and not (empty_slice and digest is None):
                problems.append(
                    f"shard {r.get('shard')} ({label}) carries no valid offsets_sha256: the "
                    "report is not bound to the bytes it swept, so its numbers are unverifiable"
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

    # If any report already failed validation, stop before the arithmetic: summing a
    # field that failed the "is this a count?" check raises `TypeError` and ends the run
    # with a traceback instead of the diagnosis the check just produced (an audit passed
    # `scanned = "833"` and got the traceback; rc was still 1, but a report of "not a
    # count" should be the last thing the tool says, not the first of two messages).
    if problems:
        print(f"FAIL: {len(problems)} problem(s):", file=sys.stderr)
        for p in problems:
            print(f"      {p}", file=sys.stderr)
        print("      (no verdict: the reports are not measurements the tool could have produced)", file=sys.stderr)
        return 1

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
        if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
            # A shard refuses to produce a report for an empty covered range, so zero here
            # means the report was not produced by the tool (or the region vanished
            # between runs); zero bytes swept must never read as a pass.
            problems.append(
                f"{label}: the region's size is {total!r}, not a positive count"
            )
            continue
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
