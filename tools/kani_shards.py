#!/usr/bin/env python3
"""Plan Kani harness shards for CI, by reading the harnesses out of the source.

Why this exists rather than a hardcoded list in the workflow: a list in the
workflow would silently stop covering a newly added harness, and "the proofs
still pass" would quietly mean less than it used to.  Deriving the shard plan
from `src/proofs.rs` means a new `#[kani::proof]` is picked up with no change
here.

Used two ways:

    python3 tools/kani_shards.py --plan       # JSON matrix for the workflow
    python3 tools/kani_shards.py --count      # just the number of harnesses

The shard assignment is by name prefix, and the groups are deliberately unequal
in *cost* rather than in count: `hchacha20_matches_draft_vector` runs the real
ChaCha20 permutation under CBMC and is by far the most expensive harness, so it
gets a runner to itself.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROOFS = os.path.join(ROOT, "src", "proofs.rs")

# Ordered: the first prefix that matches decides the shard.  Prefixes are
# deliberately broad so a new `poly1305_*` harness lands with the other
# Poly1305 work instead of falling through to a catch-all.
SHARDS = [
    # The only harness that executes the full 20-round permutation. Measured in
    # the tens of minutes on a 16-core machine; a CI runner is far slower.
    ("permutation", ["hchacha20_"]),
    ("poly1305", ["poly1305_"]),
    ("zeroize-and-limits", ["zeroize_", "check_lengths_", "max_msg_size_"]),
    ("stream-and-commitment", ["chacha20_", "tag_", "commitment_"]),
]


def harnesses():
    """Return the names of every `#[kani::proof]` harness in src/proofs.rs.

    Deliberately not a regex over the whole file: attribute blocks can have
    comments *between* the attributes (that is exactly how
    `hchacha20_matches_draft_vector` is written), and a single regex that
    assumes `#[...]` lines are adjacent silently drops such harnesses -- which
    is the failure mode this script exists to avoid.  Instead: find a line that
    is the `kani::proof` attribute, then take the next `fn` declaration,
    skipping attribute and comment lines in between.
    """
    with open(PROOFS) as fh:
        lines = fh.read().splitlines()

    names = []
    armed = False
    for line in lines:
        stripped = line.strip()
        if stripped == "#[kani::proof]":
            armed = True
            continue
        if not armed:
            continue
        # Skip further attributes and comments.
        if stripped.startswith("#[") or stripped.startswith("//") or not stripped:
            continue
        m = re.match(r"\s*(?:pub\s+)?fn\s+([A-Za-z0-9_]+)", line)
        if m:
            names.append(m.group(1))
            armed = False
            continue
        # Anything else means the attribute was not attached to a function.
        raise SystemExit(
            f"error: #[kani::proof] not followed by a fn; got: {line!r}"
        )

    if not names:
        raise SystemExit("error: found no Kani harnesses in src/proofs.rs")
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise SystemExit(f"error: duplicate harness names: {dupes}")
    return names


def assign(names):
    """Group harness names into shards, preserving discovery order."""
    buckets = {name: [] for name, _ in SHARDS}
    unassigned = []
    for harness in names:
        for name, prefixes in SHARDS:
            if any(harness.startswith(p) for p in prefixes):
                buckets[name].append(harness)
                break
        else:
            unassigned.append(harness)

    if unassigned:
        raise SystemExit(
            "error: harness(es) match no shard; add a prefix in tools/kani_shards.py:\n"
            + "\n".join(f"  {u}" for u in unassigned)
        )
    return buckets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true", help="emit the JSON matrix")
    ap.add_argument("--count", action="store_true", help="emit the harness count")
    args = ap.parse_args()

    names = harnesses()

    if args.count:
        print(len(names))
        return

    buckets = assign(names)
    include = [
        {
            "shard": name,
            # Space-separated: consumed with a plain shell loop.
            "harnesses": " ".join(buckets[name]),
            "count": len(buckets[name]),
        }
        for name, _ in SHARDS
        if buckets[name]
    ]

    # A total that does not add up means the grouping lost or duplicated work.
    planned = sum(e["count"] for e in include)
    if planned != len(names):
        raise SystemExit(
            f"error: plan covers {planned} harnesses but source has {len(names)}"
        )

    print(json.dumps({"include": include}, separators=(",", ":")))


if __name__ == "__main__":
    sys.exit(main())
