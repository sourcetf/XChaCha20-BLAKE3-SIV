#!/usr/bin/env bash
# Open a comparison PR when upstream BLAKE3 has a newer crate release than the
# fork in blake3/.
#
# The candidate PR imports upstream **unpatched** into blake3/. That is deliberate:
# applying the local patches automatically is the part most likely to conflict, and
# a conflicted tree is hard to review. Instead the branch carries three diffs under
# blake3/upstream-sync/:
#
#   local-patches.diff    our current fork vs the pristine old crate
#   upstream-changes.diff pristine old crate vs the new crate
#   combined.diff         our current fork vs the new crate (what a merge would see)
#
# A reviewer can compare the first two to see whether upstream fixed the same bug,
# and use the third to reapply/retire each local patch. The PR is opened as a draft
# and is never merged automatically.
#
# Usage:  tools/sync_blake3_upstream.sh
# Env:    INPUT_VERSION=<x.y.z>  override the crates.io latest version
#         DRY_RUN=1              print the plan and do not write/push
#         NO_PUSH=1              prepare the branch/commit locally, no push/PR
#
# Exit:   0 no update, or the PR was opened/updated
#         1 the sync could not be prepared (network/API/format)
#         3 a required tool is missing
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 3; }
command -v git >/dev/null || { echo "error: git is required" >&2; exit 3; }
command -v cargo >/dev/null || { echo "error: cargo is required" >&2; exit 3; }
command -v tar >/dev/null || { echo "error: tar is required" >&2; exit 3; }
PYTHON="python3"
if ! "$PYTHON" -c 'print(1)' >/dev/null 2>&1; then
  PYTHON="python"
fi
command -v "$PYTHON" >/dev/null || { echo "error: python3/python is required" >&2; exit 3; }

# Any relevant uncommitted work would be absent from the candidate branch and the
# three diffs, so stop before creating anything. Ignored build output is fine.
if [ -n "$(git status --porcelain --untracked-files=normal -- blake3 Cargo.toml Cargo.lock fuzz/Cargo.lock)" ]; then
  echo "error: uncommitted changes under blake3/, Cargo.toml, or the locks; commit them first" >&2
  exit 1
fi

CURRENT="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' blake3/Cargo.toml | head -1)"
if [ -z "$CURRENT" ]; then
  echo "error: could not read the version from blake3/Cargo.toml" >&2
  exit 1
fi

LATEST="${INPUT_VERSION:-}"
if [ -z "$LATEST" ]; then
  api="$(curl -fsSL --retry 3 --retry-delay 2 -A 'xsiv-blake3-sync/1' \
    https://crates.io/api/v1/crates/blake3)"
  LATEST="$(printf '%s' "$api" | "$PYTHON" -c '
import json, sys
d = json.load(sys.stdin)["crate"]
# Only stable releases: a prerelease is not a source of truth for the fork, and
# `sort -V` does not implement semver precedence for them.
print(d.get("max_stable_version") or "")
')"
fi
if [ -z "$LATEST" ]; then
  echo "error: crates.io returned no stable BLAKE3 version" >&2
  exit 1
fi
case "$LATEST" in
  *[!0-9.]*) echo "error: '$LATEST' is not a stable x.y.z version" >&2; exit 1 ;;
  *.*.*) [ "$(printf '%s' "$LATEST" | awk -F. '{print NF}')" -eq 3 ] || {
    echo "error: '$LATEST' is not x.y.z" >&2; exit 1; } ;;
  *) echo "error: '$LATEST' is not a stable x.y.z version" >&2; exit 1 ;;
esac
case "$CURRENT" in
  *[!0-9.]*) echo "error: local version '$CURRENT' is not x.y.z" >&2; exit 1 ;;
  *.*.*) [ "$(printf '%s' "$CURRENT" | awk -F. '{print NF}')" -eq 3 ] || {
    echo "error: local version '$CURRENT' is not x.y.z" >&2; exit 1; } ;;
  *) echo "error: local version '$CURRENT' is not x.y.z" >&2; exit 1 ;;
esac

highest="$(printf '%s\n%s\n' "$CURRENT" "$LATEST" | sort -V | tail -1)"
if [ "$highest" != "$LATEST" ] || [ "$LATEST" = "$CURRENT" ]; then
  echo "blake3: local $CURRENT, upstream $LATEST -- no newer upstream crate"
  exit 0
fi

BRANCH="blake3/upstream-${LATEST}"
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  # Do not silently disable the weekly alarm. A branch without a PR is the state
  # left by a failed `gh pr create`, a cancelled run, or a push that outlived its
  # job; leaving it in place would make every later run take this early exit.
  if command -v gh >/dev/null 2>&1 &&
     [ -n "$(gh pr list --state open --head "$BRANCH" --json number --jq '.[].number' 2>/dev/null)" ]; then
    echo "branch $BRANCH already has an open comparison PR; leaving it alone"
    exit 0
  fi
  echo "error: branch $BRANCH exists without an open PR; delete or inspect it before retrying" >&2
  exit 1
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "would open $BRANCH: blake3 $CURRENT -> $LATEST"
  exit 0
fi

if [ "${NO_PUSH:-0}" != "1" ]; then
  command -v gh >/dev/null || { echo "error: gh is required to open the PR (or set NO_PUSH=1)" >&2; exit 3; }
  gh auth status >/dev/null 2>&1 || { echo "error: gh is not authenticated" >&2; exit 3; }
fi

WORK="$(mktemp -d)"
TREE="$WORK/tree"
trap 'rm -rf "$WORK"' EXIT

fetch_crate() {
  local version="$1" destination="$2"
  echo "downloading blake3 $version"
  local archive="$WORK/${version}.crate"
  # Verify the archive against the checksum crates.io publishes for that version.
  # Checking only the version string inside an attacker-controlled tarball would
  # authenticate nothing, and this source runs in every later build.
  local expected_checksum
  expected_checksum="$(curl -fsSL --retry 3 --retry-delay 2 -A 'xsiv-blake3-sync/1' \
    "https://crates.io/api/v1/crates/blake3/${version}" |
    "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["version"]["checksum"])')"
  case "$expected_checksum" in
    [0-9a-f][0-9a-f]*) : ;;
    *) echo "error: crates.io returned no checksum for blake3 $version" >&2; exit 1 ;;
  esac
  curl -fsSL --retry 3 --retry-delay 2 --max-time 300 \
    --proto '=https' --proto-redir '=https' \
    -A 'xsiv-blake3-sync/1' \
    "https://crates.io/api/v1/crates/blake3/${version}/download" \
    -o "$archive"
  local actual_checksum
  actual_checksum="$(sha256sum "$archive" | cut -d' ' -f1)"
  if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "error: blake3 $version checksum mismatch: got $actual_checksum, expected $expected_checksum" >&2
    exit 1
  fi
  mkdir -p "$destination"
  tar -xzf "$archive" -C "$destination" --strip-components=1
  local found
  found="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$destination/Cargo.toml" | head -1)"
  [ "$found" = "$version" ] || {
    echo "error: downloaded crate reports version '$found', expected '$version'" >&2
    exit 1
  }
}

fetch_crate "$CURRENT" "$WORK/old-upstream"
fetch_crate "$LATEST" "$WORK/new-upstream"

# Do the import in a detached worktree, not the caller's checkout. `NO_PUSH=1` is
# documented for local runs, and `git switch -C` + `rm -rf blake3` in the live tree
# would destroy uncommitted work; this leaves the caller's branch and files untouched.
git worktree add --detach "$TREE" HEAD >/dev/null
cd "$TREE"
cleanup() {
  cd "$ROOT"
  git worktree remove --force "$TREE" >/dev/null 2>&1 || rm -rf "$TREE"
  rm -rf "$WORK"
}
trap cleanup EXIT

# The three views. `diff -N` returns 1 when it finds differences, which is the
# expected outcome; only an actual execution error (2) should stop the script.
diff_ok() {
  local rc=0
  "$@" || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "error: diff failed with status $rc" >&2
    exit 1
  fi
}

diff_ok diff -ruN --exclude=target --exclude=.git "$WORK/old-upstream" blake3 > "$WORK/local-patches.diff"
diff_ok diff -ruN --exclude=target --exclude=.git "$WORK/old-upstream" "$WORK/new-upstream" > "$WORK/upstream-changes.diff"
diff_ok diff -ruN --exclude=target --exclude=.git blake3 "$WORK/new-upstream" > "$WORK/combined.diff"

# The local patch documentation is not part of upstream; keep it in the comparison
# branch even though PATCHES.md itself is replaced with the pristine upstream tree.
cp blake3/PATCHES.md "$WORK/PATCHES.local.md"

git switch -C "$BRANCH"
find blake3 -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$WORK/new-upstream/." blake3/
mkdir -p blake3/upstream-sync
cp "$WORK/local-patches.diff" "$WORK/upstream-changes.diff" "$WORK/combined.diff" \
  "$WORK/PATCHES.local.md" blake3/upstream-sync/

# The parent declares `version + path` so cargo-deny does not classify the path
# dependency as a wildcard. Keep every such annotation in step with the imported
# crate. Edit by line, not by an exact whole-file count: a formatting change or a
# comment containing the needle must not silently produce a stale version.
"$PYTHON" - Cargo.toml "$CURRENT" "$LATEST" <<'PY'
import re
import sys

path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    lines = fh.readlines()
changed = 0
for i, line in enumerate(lines):
    if re.match(r"\s*blake3\s*=\s*\{", line) and 'path = "blake3"' in line:
        updated, n = re.subn(r'version\s*=\s*"[^"]+"', f'version = "{new}"', line, count=1)
        if n != 1:
            raise SystemExit(f"error: could not find the version in: {line.rstrip()}")
        lines[i] = updated
        changed += 1
if changed == 0:
    raise SystemExit("error: no `blake3 = { ... path = \"blake3\" ... }` line in Cargo.toml")
with open(path, "w", encoding="utf-8", newline="\n") as fh:
    fh.writelines(lines)
print(f"updated {changed} blake3 version annotation(s) in Cargo.toml")
PY

local_files="$(grep -c '^diff ' "$WORK/local-patches.diff" || true)"
upstream_files="$(grep -c '^diff ' "$WORK/upstream-changes.diff" || true)"
cat > blake3/UPSTREAM-SYNC.md <<EOF
# Upstream sync candidate: BLAKE3 $CURRENT -> $LATEST

This branch **imports upstream unpatched**. The local fork's fixes are not applied;
that is the comparison target, not a merge candidate.

| View | File |
| --- | --- |
| our current fork vs pristine old upstream | \`upstream-sync/local-patches.diff\` |
| pristine old upstream vs new upstream | \`upstream-sync/upstream-changes.diff\` |
| our current fork vs new upstream | \`upstream-sync/combined.diff\` |

Local patch diff touches $local_files file(s); upstream changes touch
$upstream_files file(s). Check each local patch in
\`upstream-sync/PATCHES.local.md\` against \`upstream-changes.diff\`: if upstream now
contains the same correction, retire the local patch; if not, port it onto this tree.
Do not merge this branch until that pass is done, and do not let its CI result stand in
for the patched tree's tests.
EOF

# Keep the path-package locks coherent with the imported version. `cargo metadata`
# resolves without compiling; the parent and fuzz locks both name the path package.
cargo metadata --format-version 1 >/dev/null
cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null

git add -A blake3 Cargo.toml Cargo.lock fuzz/Cargo.lock
git diff --cached --stat blake3 fuzz/Cargo.lock | tail -20
git -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -m "blake3: import upstream $LATEST for comparison" \
    -m "Draft comparison candidate: upstream source is unpatched; see blake3/UPSTREAM-SYNC.md and blake3/upstream-sync/ for the local-patch, upstream-change and combined diffs."

if [ "${NO_PUSH:-0}" = "1" ]; then
  echo "NO_PUSH: prepared local branch $BRANCH; not pushing or opening a PR"
  exit 0
fi

git push -u origin "$BRANCH"

cat > "$WORK/pr-body.md" <<EOF
Draft comparison candidate for upstream **BLAKE3 $LATEST** (local fork is $CURRENT).

This PR imports upstream **without re-applying the local patches**, so it is
expected to remove the fixes in \`blake3/PATCHES.md\` and may fail the guard-page /
equivalence tests until they are ported. It is not a merge candidate.

Attached on the branch:

- \`blake3/upstream-sync/local-patches.diff\` -- our current fork vs pristine $CURRENT
- \`blake3/upstream-sync/upstream-changes.diff\` -- pristine $CURRENT vs $LATEST
- \`blake3/upstream-sync/combined.diff\` -- our current fork vs $LATEST
- \`blake3/upstream-sync/PATCHES.local.md\` -- the local fork's patch notes
- \`blake3/UPSTREAM-SYNC.md\` -- the same index with counts

Use the first two to decide, for each local patch, whether upstream already fixed
it; use the third to port the remainder. Close this PR if there is nothing to adopt.
EOF

gh pr create --draft \
  --base main \
  --head "$BRANCH" \
  --title "[blake3-upstream] compare $CURRENT -> $LATEST (do not merge)" \
  --body-file "$WORK/pr-body.md"

echo "opened comparison PR for blake3 $CURRENT -> $LATEST"
