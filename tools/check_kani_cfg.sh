#!/usr/bin/env bash
# Type-check the `#[cfg(kani)]` harnesses without a Kani installation.
#
# Why this exists: `src/proofs.rs` is compiled only under `--cfg kani`, so
# `cargo test` never sees it. A signature change to any internal function the
# harnesses call therefore breaks the Formal job with **no local symptom at all** —
# which is exactly what happened to `derive_enc` (it stopped returning a tuple and
# started writing through caller slices), taking all four Kani shards down with
# `error[E0061]: this function takes 4 arguments but 2 arguments were supplied`.
#
# This does not verify anything. It substitutes no-op stand-ins for Kani's
# attributes and a zero-returning `any`, and asks the compiler whether the
# harnesses still *fit* the crate. That is the failure mode worth catching cheaply;
# the proofs themselves stay in the Formal job.
#
# Usage:  tools/check_kani_cfg.sh
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
# Some Windows hosts ship a `python3` alias that exits nonzero before running any
# code; `python` is the real interpreter there. CI's python3 satisfies the probe.
if python3 -c 'pass' >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# `mktemp -d` under Git Bash returns an MSYS path (`/tmp/...`), which a native
# Windows Python cannot open. Convert only the paths handed to Python; the shell
# and cargo keep using the MSYS forms below.
win_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

# The shim lives in the temp dir rather than in the repository, so it cannot be
# picked up as a workspace member by the real build.
mkdir -p "$WORK/shim/kani-macros/src" "$WORK/shim/kani/src"
cat > "$WORK/shim/Cargo.toml" <<'EOF'
[workspace]
members = ["kani-macros", "kani"]
resolver = "2"
EOF
cat > "$WORK/shim/kani-macros/Cargo.toml" <<'EOF'
[package]
name = "kani-macros"
version = "0.0.0"
edition = "2021"
[lib]
proc-macro = true
EOF
cat > "$WORK/shim/kani-macros/src/lib.rs" <<'EOF'
//! No-op stand-ins for Kani's attribute macros: they let `--cfg kani` code be
//! type-checked, and they prove nothing.
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn proof(_attr: TokenStream, item: TokenStream) -> TokenStream { item }
#[proc_macro_attribute]
pub fn stub(_attr: TokenStream, item: TokenStream) -> TokenStream { item }
#[proc_macro_attribute]
pub fn unwind(_attr: TokenStream, item: TokenStream) -> TokenStream { item }
EOF
cat > "$WORK/shim/kani/Cargo.toml" <<'EOF'
[package]
name = "kani"
version = "0.0.0"
edition = "2021"
[dependencies]
kani-macros = { path = "../kani-macros" }
EOF
cat > "$WORK/shim/kani/src/lib.rs" <<'EOF'
//! Facade that makes `--cfg kani` builds type-check outside Kani. Verifies nothing.
pub use kani_macros::{proof, stub, unwind};

/// Stand-in for `kani::assume`: does nothing.
#[inline]
pub fn assume(_cond: bool) {}

/// Stand-in for `kani::any`: zeroed.
///
/// Zeroed rather than uninitialised, and that matters for whether this is sound if
/// it ever does run: every type `proofs.rs` asks for is an integer, a `bool`, or an
/// array of those, and zero is a valid value for all of them.
pub fn any<T>() -> T {
    // SAFETY: only integer/array-of-integer types are requested, for which an
    // all-zero bit pattern is valid.
    unsafe { core::mem::zeroed() }
}
EOF

# A copy of the crate, pointed at the shim, so the repository's own manifest is
# never modified.
mkdir -p "$WORK/crate"
( cd "$ROOT" && tar --exclude=./target --exclude=./.git --exclude='./mutants.out*' -cf - . ) \
  | ( cd "$WORK/crate" && tar -xf - )
"$PYTHON" - "$(win_path "$WORK/crate/Cargo.toml")" "$(win_path "$WORK/shim/kani")" <<'PY'
import sys
manifest, shim = sys.argv[1], sys.argv[2]
# The path is embedded in a TOML basic string: a Windows backslash would start an
# escape (`\U` is a unicode escape), so use forward slashes. UTF-8 is explicit
# because the manifest's comments are not ASCII and Windows Python defaults to the
# locale encoding.
shim = shim.replace("\\", "/")
s = open(manifest, encoding="utf-8").read()
assert "[dependencies]" in s
s = s.replace("[dependencies]", f'[dependencies]\nkani = {{ path = "{shim}" }}', 1)
open(manifest, "w", encoding="utf-8", newline="\n").write(s)
PY

cd "$WORK/crate"
# Before the type-check, the count: cargo's exit status says the crate compiles
# *with* `--cfg kani`, and an emptied `src/proofs.rs` compiles exactly as well as a
# full one (measured: `: > src/proofs.rs` -> PASS, RC=0, with the control below
# satisfied because its plant lived in lib.rs). The count is taken from the same
# source-derived parser the Formal matrix is planned with -- `tools/kani_shards.py
# --count`, run on the copy -- rather than a second regex here, so a harness that
# parser cannot see is a failure in this gate too. 19 is the committed count; a
# change that removes harnesses has to update this number *and* the matrix.
COMMITTED_HARNESSES=19
harness_count="$("$PYTHON" tools/kani_shards.py --count 2>"$WORK/kani-count.err" || true)"
case "$harness_count" in
  ''|*[!0-9]*)
    echo "FAIL: could not count the Kani harnesses in src/proofs.rs:" >&2
    sed 's/^/      /' "$WORK/kani-count.err" >&2
    exit 1 ;;
esac
if [ "$harness_count" -ne "$COMMITTED_HARNESSES" ]; then
  echo "FAIL: src/proofs.rs contains $harness_count #[kani::proof] harness(es), not" >&2
  echo "      the $COMMITTED_HARNESSES this gate is written against. The crate" >&2
  echo "      still type-checks, and the Formal job's matrix would silently shrink, so" >&2
  echo "      a removed or added harness is judged here rather than nowhere." >&2
  exit 1
fi
echo "harness count: $harness_count (== the $COMMITTED_HARNESSES committed)"
# The count is only as trustworthy as the parser that produces it, so the parser's
# rejection rules get a control of their own. Each shape below once inflated the count
# while leaving the harness uncompiled: a cfg above or below the marker (including one
# separated by a comment), and a harness inside a block comment.
"$PYTHON" - "$ROOT/tools/kani_shards.py" <<'PY'
import os
import shutil
import subprocess
import sys
import tempfile

parser = sys.argv[1]
base = "#[kani::proof]\nfn real_one() {}\n"
cases = [
    ("an ordinary harness", base, True, "1"),
    ("two proofs on one line", "#[kani::proof] #[kani::proof]\nfn dup() {}\n", False, None),
    ("a cfg above the marker", "#[cfg(any())]\n#[kani::proof]\nfn g() {}\n", False, None),
    ("a cfg above the marker past a comment",
     "#[cfg(any())]\n// why\n#[kani::proof]\nfn g() {}\n", False, None),
    ("a cfg between the marker and the fn",
     "#[kani::proof]\n#[cfg(any())]\nfn g() {}\n", False, None),
    ("a cfg before the marker on its line",
     "#[cfg(any())] #[kani::proof]\nfn g() {}\n", False, None),
    ("a block-commented harness",
     "/* #[kani::proof]\nfn hidden() {} */\n" + base, True, "1"),
    ("a legal whitespace spelling",
     "# [ kani :: proof ]\nfn spaced() {}\n", True, "1"),
    ("a multi-line proof spelling",
     "#\n[\nkani :: proof\n]\nfn split_across_lines() {}\n", True, "1"),
    ("a proof spelling split around the path",
     "# [ kani\n :: proof ]\nfn split_path() {}\n", True, "1"),
    ("a cfg prefix across lines",
     "#[\ncfg(any())\n]\n#[kani::proof]\nfn gated_before() {}\n", False, None),
    ("an attribute before the marker",
     "#[kani::unwind(9)] #[kani::proof] fn prefixed() {}\n", True, "1"),
    ("a cfg_attr the parser cannot place",
     "#[cfg_attr(kani, kani::proof)]\nfn indirect() {}\n", False, None),
    ("a cfg on an enclosing module",
     "#[cfg(any())]\nmod h {\n#[kani::proof]\nfn f() {}\n}\n", False, None),
    ("an inner cfg",
     "#![cfg(any())]\n#[kani::proof]\nfn f() {}\n", False, None),
    ("a whitespace cfg spelling",
     "# [cfg(any())]\n#[kani::proof]\nfn f() {}\n", False, None),
    ("a multi-line cfg",
     "#[cfg(\n any()\n)]\n#[kani::proof]\nfn f() {}\n", False, None),
]
for name, source, ok, expected in cases:
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "tools"))
        os.makedirs(os.path.join(root, "src"))
        shutil.copy(parser, os.path.join(root, "tools", "kani_shards.py"))
        with open(os.path.join(root, "src", "proofs.rs"), "w") as fh:
            fh.write(source)
        proc = subprocess.run(
            [sys.executable, os.path.join(root, "tools", "kani_shards.py"), "--count"],
            capture_output=True,
            text=True,
        )
    if ok:
        if proc.returncode != 0 or proc.stdout.strip() != expected:
            sys.exit(
                f"FAIL: parser control '{name}' expected count {expected}, got rc="
                f"{proc.returncode} out={proc.stdout!r} err={proc.stderr!r}"
            )
    elif proc.returncode == 0:
        sys.exit(
            f"FAIL: parser control '{name}' was counted as a harness that Kani would "
            f"build (out={proc.stdout!r})"
        )
print("parser controls: cfg/comment shapes that hide a harness are rejected")
PY
echo "type-checking #[cfg(kani)] harnesses against a no-op Kani shim..."
# Judge by cargo's exit status, not by grepping its output. The first version of
# this script piped cargo into `grep -E "^error"` inside an `if`, and `set -o
# pipefail` made the pipeline report *cargo's* failure rather than grep's success --
# so the branch taken was the "no errors" one and the script printed PASS while
# printing the compile errors directly above it. The control in the commit message
# (reverting the fix) is what caught that.
set +e
out="$(RUSTFLAGS="--cfg kani" cargo check --release --quiet 2>&1)"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  # `|| true`: under `set -o pipefail` a `grep` with no match, or a `head` that closes
  # the pipe early (141), would abort the script here -- before the two lines below, which
  # are the diagnosis.
  printf '%s\n' "$out" | grep -E "^error|^ *-->" | head -30 >&2 || true
  echo "FAIL: the Kani harnesses do not compile against this revision of the crate." >&2
  echo "      (They are only built under --cfg kani, so nothing else would notice.)" >&2
  exit 1
fi
# ...and a control for the direction a green check cannot see. A passing type-check proves
# only that the crate compiles *with* `--cfg kani`: if the gate that pulls the harnesses in
# were removed, nothing under `#[cfg(kani)]` would be compiled and this script would still
# print PASS. An audit deleted `#[cfg(kani)] mod proofs;` from a copy and watched it stay
# green. So the check is run once more against a copy with a deliberate type error planted
# *inside* `src/proofs.rs` itself: that run must fail, which witnesses that that module's
# contents are what the type-check above compiles. (The first version of this control
# planted its error in `src/lib.rs`, next to the gate -- it proved the gate in lib.rs was
# compiled, not that anything inside proofs.rs was.)
CONTROL="$WORK/control"
mkdir -p "$CONTROL"
( cd "$WORK/crate" && tar -cf - . ) | ( cd "$CONTROL" && tar -xf - )
"$PYTHON" - "$(win_path "$CONTROL/src/proofs.rs")" <<'PLANTEOF'
import sys

p = sys.argv[1]
s = open(p, encoding="utf-8").read()
plant = s + """
// Planted by tools/check_kani_cfg.sh. This file is compiled only when lib.rs's
// `#[cfg(kani)] mod proofs;` pulls it in, so a copy that fails to compile here is
// the property the PASS above claims: the harnesses in this file are compiled.
fn _kani_compile_control() -> u8 {
    // Deliberately not a u8.
    "not a u8"
}
"""
open(p, "w", encoding="utf-8", newline="\n").write(plant)
PLANTEOF
set +e
( cd "$CONTROL" && RUSTFLAGS="--cfg kani" cargo check --release --quiet >/dev/null 2>&1 )
control_status=$?
set -e
if [ "$control_status" -eq 0 ]; then
  echo "FAIL: a deliberate type error inside a #[cfg(kani)] item did not fail the" >&2
  echo "      type-check, so the PASS above says nothing about the harnesses being" >&2
  echo "      compiled at all -- it only says the crate compiles without them." >&2
  exit 1
fi
echo "PASS: the $harness_count harnesses still fit the crate's internals (control: a"
echo "      type error planted in src/proofs.rs is caught, so that module really is"
echo "      what is compiled here)."
