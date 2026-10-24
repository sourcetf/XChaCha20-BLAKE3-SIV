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

# Legal spellings of the attribute: Rust permits whitespace inside the path and around
# the brackets (`#[kani :: proof]`, `# [kani::proof]`). The old parser required the exact
# `#[kani::proof]` prefix, so a harness written in one of these forms was silently absent
# from the shard plan and the count.
PROOF_ATTR = re.compile(r"#\s*\[\s*kani\s*::\s*proof\s*\]")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROOFS = os.path.join(ROOT, "src", "proofs.rs")

# Ordered: the first prefix that matches decides the shard.  Prefixes are
# deliberately broad so a new harness lands with the work it belongs to instead
# of failing the "no shard matched" check.  That check is the point: a harness
# that matched nothing would otherwise be silently unproven.
# (shard, prefix list, jobs to run in parallel inside the shard).
#
# `jobs` is per shard because the shards differ in *memory*, not in count: CBMC
# builds a formula over a symbolic key and a symbolic MAC model.  The tag shard
# used to exhaust a hosted runner -- the agent is killed, which surfaces as
#
#     ##[error]The runner has received a shutdown signal.
#
# with the other harnesses in the shard reporting SUCCESSFUL first, measured over
# four consecutive runs. The cause turned out to be in the harness rather than in
# the runner: its input shapes were a loop, so CBMC could not bound the stub's
# per-byte fold statically and unwound it to the harness's unwind bound with a
# symbolic accumulator index -- >30 GB of formula for one harness. Written as
# four separate call sites the same harness needs ~2 GB, so the tag shard can now
# run two at a time. The permutation harness stays sequential: it is the one that
# executes all 20 rounds. All of these figures are with `--extra-pointer-checks`
# on, which CI passes: the flag was never what this shard could not afford.
SHARDS = [
    # The only harness that executes the full 20-round permutation, so it is the
    # one whose cost cannot be argued away by stubbing. Its cost is host- and
    # toolchain-dependent -- 1:01 with a 1.3 GB peak (pointer checks on) is the
    # measurement recorded here, while `src/proofs.rs`'s design note re-measures
    # 37 s with Kani 0.68.0 / CBMC 6.11.0 and an audit host measured 33 s -- so
    # treat it as roughly half a minute to a minute. Sequential because it is the
    # single most expensive harness in the suite, while the others are small
    # enough to pair up.
    ("permutation", ["hchacha20_"], 1),
    # The witness anchor: a concrete cross-implementation comparison that took 3:44
    # measured on the audit host. Its own sequential shard keeps it parallel with the
    # others instead of stretching the tag shard; see the harness's doc comment.
    ("witness-anchor", ["tag_matches_the_independent_witness"], 1),
    # The four concrete tag comparisons, one per empty/non-empty AAD/message shape.
    # Their prefix must be tested before the broad `tag_` entry below. One harness per
    # shape rather than one four-shape harness: CBMC took ~17 minutes on the merged
    # version, while each single shape is a few minutes and four fit in one wave.
    # `jobs=2`, not 4: with four CBMC processes Kani 0.68.0 exited with an internal
    # "No exit code?" panic on the audit host after the first harness; two at a time
    # is the same setting the other shards use and completes reliably.
    ("tag-concrete", ["tag_matches_the_model_with_"], 2),
    # The MAC and the tag: what the keyed hash is fed, and what it returns.
    ("tag", ["tag_", "every_tag_byte", "derive_enc_", "every_aad_"], 2),
    ("zeroize-and-limits", ["zeroize_", "check_lengths_", "max_msg_size_"], 4),
    ("stream", ["chacha20_"], 2),
]


def is_cfg_attr(attr):
    """True for an attribute that can remove its item from the build."""
    return re.search(r"#\[\s*cfg\s*\(|cfg_attr\s*\(", attr) is not None


def strip_block_comments(text):
    """Blank `/* ... */` spans, nested, keeping every newline.

    A harness inside a block comment does not exist. The line scan that follows must
    not count it, and blanking rather than deleting keeps the line numbers used by
    `tools/check_kani_cfg.sh`'s cross-check intact.
    """
    out = []
    depth = 0
    i = 0
    while i < len(text):
        if depth:
            if text.startswith("/*", i):
                depth += 1
                out.append("  ")
                i += 2
            elif text.startswith("*/", i):
                depth -= 1
                out.append("  ")
                i += 2
            elif text[i] == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
        elif text.startswith("/*", i):
            depth = 1
            out.append("  ")
            i += 2
        else:
            out.append(text[i])
            i += 1
    if depth:
        raise SystemExit("error: unterminated block comment in src/proofs.rs")
    return "".join(out)


def harnesses():
    """Return the names of every `#[kani::proof]` harness in src/proofs.rs.

    Deliberately not a regex over the whole file: attribute blocks can have
    comments *between* the attributes (that is exactly how
    `hchacha20_matches_draft_vector` is written), and a single regex that
    assumes `#[...]` lines are adjacent silently drops such harnesses -- which
    is the failure mode this script exists to avoid.  Instead: find a line that
    is the `kani::proof` attribute, then take the next `fn` declaration,
    skipping attribute and comment lines in between.

    The attribute is matched as a line *prefix*, because a trailing comment on
    that line (`#[kani::proof] // why`) is valid Rust and used to drop the
    harness silently; and a count cross-check at the end turns any other shape
    this parser does not understand into a loud error rather than a harness that
    is never sharded and never proven.
    """
    with open(PROOFS) as fh:
        # A harness inside `/* ... */` is not compiled, but a line scanner sees and
        # counts it: the count floor, the shard matrix and the Formal run then agree on
        # a name Kani never builds. Strip block comments (nested, newlines preserved so
        # line-number cross-checks stay usable) before looking for harnesses.
        lines = strip_block_comments(fh.read()).splitlines()

    names = []
    armed = False
    # The attribute run directly above a harness, so a `cfg` that removes it from the
    # build cannot be counted as if it were verified (see the check below).
    attr_run = []
    for line in lines:
        stripped = line.strip()
        # Comments and blank lines between an attribute run and its item do not detach
        # the attributes. Clearing `attr_run` here was a cfg-guard bypass: a `cfg` above
        # `#[kani::proof]` followed by one comment line was counted as a live harness.
        if not stripped or stripped.startswith("//"):
            continue

        # Find the marker, accepting every legal spelling at line start (`PROOF_ATTR`)
        # and a marker after other attributes on the same line. A `kani::proof` mention
        # this parser cannot place (`cfg_attr`, a macro) is refused rather than silently
        # uncounted.
        proof = PROOF_ATTR.match(stripped)
        if proof is not None:
            prefix = ""
            marker_end = proof.end()
        else:
            marker = stripped.find("#[kani::proof]")
            if marker < 0:
                if "kani::proof" in stripped:
                    raise SystemExit(
                        "error: `kani::proof` appears in a form this parser does not "
                        f"count: {stripped!r}. Write the attribute as `#[kani::proof]` "
                        "(whitespace inside the brackets is accepted) or teach "
                        "`PROOF_ATTR` the shape."
                    )
                marker_end = None
            else:
                prefix = stripped[:marker]
                if not re.fullmatch(r"(?:\s*#\[[^\]]*\]\s*)*", prefix):
                    raise SystemExit(
                        "error: #[kani::proof] appears inside a line that is not an item: "
                        + repr(line)
                    )
                if stripped.count("#[kani::proof]") != 1:
                    raise SystemExit(
                        "error: more than one #[kani::proof] on one line: " + repr(line)
                    )
                marker_end = marker + len("#[kani::proof]")

        if marker_end is not None:
            # A `cfg` above the marker can take the harness out of the build while every
            # count here stays: an audit put `#[cfg(any())]` above twelve of the thirteen
            # and watched this parser report 13, `tools/check_kani_cfg.sh` print PASS and
            # Kani verify **one** harness. No harness in `src/proofs.rs` carries a `cfg`
            # today -- the whole module is `#[cfg(kani)]` in `lib.rs` -- so an occurrence
            # is a deliberate edit that has to change this rule, not a shape to support.
            gated = [a for a in attr_run if is_cfg_attr(a)]
            gated += [a for a in re.findall(r"#\[[^\]]*\]", prefix) if is_cfg_attr(a)]
            if gated:
                raise SystemExit(
                    "error: #[kani::proof] is preceded by "
                    + ", ".join(gated)
                    + "; a harness whose `cfg` the Kani build may not set must not be"
                    " counted as one that will be verified"
                )
            attr_run = []
            # Attributes and comments can share the line; drop them and look for the `fn`.
            tail = stripped[marker_end:]
            # A `cfg` between the marker and the `fn` is just as fatal as one above the
            # marker, and used to be invisible: the old parser only inspected the
            # attribute run *before* `#[kani::proof]`.
            gated = [
                a
                for a in re.findall(r"#\[[^\]]*\]", tail.split("//", 1)[0])
                if is_cfg_attr(a)
            ]
            if gated:
                raise SystemExit(
                    "error: #[kani::proof] is followed by "
                    + ", ".join(gated)
                    + " before its `fn`; that harness may not be compiled into the"
                    " Kani build and must not be counted"
                )
            rest = re.sub(r"#\s*\[[^\]]*\]|//.*", " ", tail)
            m = re.match(r"\s*(?:pub\s+)?fn\s+([A-Za-z0-9_]+)", rest)
            if m:
                names.append(m.group(1))
                armed = False
            else:
                armed = True
            continue

        if stripped.startswith("#[") or stripped.startswith("#!["):
            # Between `#[kani::proof]` and its `fn`, a cfg is the same bypass as one
            # above the marker; refuse it.
            if armed and is_cfg_attr(stripped):
                raise SystemExit(
                    "error: #[kani::proof] is followed by "
                    + stripped
                    + " before its `fn`; that harness may not be compiled into the"
                    " Kani build and must not be counted"
                )
            attr_run.append(stripped)
            continue
        if not armed:
            attr_run = []
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

    # The cross-check: every (non-comment) line carrying the attribute must have produced
    # a name. This is what keeps a shape the loop above does not know from disappearing
    # again -- the failure mode this parser exists to prevent, and the one a `>= 17` count
    # floor in `tools/check_kani_cfg.sh` cannot see when the harness that vanishes is a new
    # one. A `// #[kani::proof]` line is a comment, and is not counted.
    attribute_lines = sum(
        1
        for line in lines
        if not line.strip().startswith("//")
        and ("#[kani::proof]" in line or PROOF_ATTR.search(line) is not None)
    )
    if attribute_lines != len(names):
        raise SystemExit(
            f"error: {attribute_lines} line(s) start with #[kani::proof] but {len(names)} "
            f"harness name(s) were parsed -- a harness is being dropped silently"
        )
    if not names:
        raise SystemExit("error: found no Kani harnesses in src/proofs.rs")
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise SystemExit(f"error: duplicate harness names: {dupes}")
    return names


def assign(names):
    """Group harness names into shards, preserving discovery order."""
    buckets = {name: [] for name, _, _ in SHARDS}
    unassigned = []
    for harness in names:
        for name, prefixes, _ in SHARDS:
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
            "jobs": jobs,
        }
        for name, _, jobs in SHARDS
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
