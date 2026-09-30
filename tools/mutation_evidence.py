#!/usr/bin/env python3
"""Compare a fresh `cargo mutants` run against the committed evidence.

`mutants.out/` is committed on purpose (see `tests/README.md`): it is the record of the
run the CI mutation step performs, and the claim is that it describes the *current*
source. Nothing enforced that claim — the directory was refreshed when someone
remembered, and it is exactly the kind of file whose staleness is invisible: it still
parses, still says "0 missed", and still names functions that exist.

This script is the enforcement. It compares two evidence directories — the committed one
and the one the current run just produced — on the only fields that carry meaning:

    (function name, mutation genre, replacement, occurrence within that function)
        -> outcome (CaughtMutant / Unviable / MissedMutant / Timeout)

and deliberately not on the fields that move every run: line and column numbers,
durations, timestamps, host paths, log file names. Line numbers in particular shift
whenever a line is added anywhere above a mutant, so comparing them would fail on every
unrelated edit and the gate would be deleted within a week.

Usage:
    tools/mutation_evidence.py COMMITTED_DIR FRESH_DIR

Exit codes: 0 = the committed evidence describes this run; 1 = it does not (the two
directories disagree, or a mutant changed outcome); 3 = could not compare (a directory is
missing or unparseable), which is "could not run" rather than "found something".
"""
import json
import os
import sys

EXIT_COULD_NOT_RUN = 3


def load(directory):
    """`{(function, genre, replacement, index): outcome}` for one evidence directory."""
    mutants_path = os.path.join(directory, "mutants.json")
    outcomes_path = os.path.join(directory, "outcomes.json")
    for path in (mutants_path, outcomes_path):
        if not os.path.isfile(path):
            print(f"FAIL: {path} is missing -- is this a cargo-mutants output dir?", file=sys.stderr)
            sys.exit(EXIT_COULD_NOT_RUN)

    try:
        with open(mutants_path) as fh:
            mutants = json.load(fh)
        with open(outcomes_path) as fh:
            outcomes = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"FAIL: {directory} could not be parsed: {e}", file=sys.stderr)
        sys.exit(EXIT_COULD_NOT_RUN)

    # `mutants.json` carries the description of each mutant; `outcomes.json` carries the
    # verdict. Both are keyed by the mutant's `name`, which contains a line number -- so
    # the join is done on the name, and the *reporting* key below drops the line number.
    by_name = {m["name"]: m for m in mutants}
    results = {}
    seen = {}
    for outcome in outcomes.get("outcomes", []):
        scenario = outcome.get("scenario")
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            continue  # the Baseline entry
        name = scenario["Mutant"]["name"]
        mutant = by_name.get(name)
        if mutant is None:
            print(
                f"FAIL: {directory}/outcomes.json names a mutant that {directory}/mutants.json "
                f"does not describe: {name}",
                file=sys.stderr,
            )
            sys.exit(EXIT_COULD_NOT_RUN)

        function = (mutant.get("function") or {}).get("function_name", "?")
        # Occurrence index within (function, genre, replacement), ordered by line: this is
        # what disambiguates two mutations that produce identical descriptions in one
        # function (two `&` -> `^` on different lines), without depending on the line
        # number itself.
        base = (function, mutant.get("genre", "?"), mutant.get("replacement", "?"))
        index = seen.get(base, 0)
        seen[base] = index + 1
        results[base + (index,)] = outcome.get("summary", "?")
    return results, outcomes


def describe(key):
    function, genre, replacement, index = key
    return f"{function}: {genre} -> {replacement!r} (occurrence {index + 1})"


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: tools/mutation_evidence.py COMMITTED_DIR FRESH_DIR", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    committed_dir, fresh_dir = sys.argv[1], sys.argv[2]

    committed, committed_meta = load(committed_dir)
    fresh, fresh_meta = load(fresh_dir)

    problems = []
    for key in sorted(set(committed) | set(fresh), key=describe):
        old, new = committed.get(key), fresh.get(key)
        if old is None:
            problems.append(f"  new mutant not in the committed evidence: {describe(key)} -> {new}")
        elif new is None:
            problems.append(f"  mutant in the committed evidence no longer exists: {describe(key)} -> {old}")
        elif old != new:
            problems.append(f"  {describe(key)}: committed says {old}, this run says {new}")

    print(
        f"committed: {len(committed)} mutants from cargo-mutants "
        f"{committed_meta.get('cargo_mutants_version', '?')}"
    )
    print(
        f"this run:  {len(fresh)} mutants from cargo-mutants "
        f"{fresh_meta.get('cargo_mutants_version', '?')}"
    )
    if fresh_meta.get("missed"):
        print(f"this run has {fresh_meta['missed']} missed mutant(s):")
        print("\n".join(f"  {m}" for m in fresh_meta["missed"]))

    if problems:
        print()
        print("FAIL: the committed evidence does not describe this run:", file=sys.stderr)
        for line in problems:
            print(line, file=sys.stderr)
        print(
            "\n  `mutants.out/` is committed evidence that must describe the current\n"
            "  source (tests/README.md). Refresh it by running the same command the CI\n"
            "  mutation step runs, from the repository root, and committing the result:\n"
            "\n"
            "    cargo mutants --features ultra -f src/lib.rs \\\n"
            "      -F 'decrypt|accept_or_reject' -E 'replace & with \\|' \\\n"
            "      -- --test decision --test security\n",
            file=sys.stderr,
        )
        return 1

    print("PASS: the committed evidence describes this run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
