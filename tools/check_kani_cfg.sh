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
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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
python3 - "$WORK/crate/Cargo.toml" "$WORK/shim/kani" <<'PY'
import sys
manifest, shim = sys.argv[1], sys.argv[2]
s = open(manifest).read()
assert "[dependencies]" in s
s = s.replace("[dependencies]", f'[dependencies]\nkani = {{ path = "{shim}" }}', 1)
open(manifest, "w").write(s)
PY

cd "$WORK/crate"
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
# *inside* a `#[cfg(kani)]` item: that run must fail.
CONTROL="$WORK/control"
mkdir -p "$CONTROL"
( cd "$WORK/crate" && tar -cf - . ) | ( cd "$CONTROL" && tar -xf - )
python3 - "$CONTROL/src/lib.rs" <<'PLANTEOF'
import sys

p = sys.argv[1]
s = open(p).read()
anchor = "#[cfg(kani)]\nmod proofs;"
if anchor not in s:
    sys.exit("the #[cfg(kani)] gate is not where this control expects it: %s" % p)
plant = anchor + """

#[cfg(kani)]
fn _kani_compile_control() -> u8 {
    // Deliberately not a u8. Compiled only when `--cfg kani` reaches this file, which is
    // the property the check above claims and can otherwise not see.
    "not a u8"
}
"""
open(p, "w").write(s.replace(anchor, plant, 1))
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
echo "PASS: the harnesses still fit the crate's internals (control: a planted"
echo "      #[cfg(kani)] type error is caught, so they really are compiled here)."
