//! Refuse to be packaged as a crates.io-style `.crate`.
//!
//! `publish = false` stops `cargo publish`, but `cargo package` rewrites the
//! `blake3 = { version = ..., path = "blake3" }` dependency to a registry
//! requirement. The resulting package would silently build against unpatched
//! crates.io BLAKE3, so this build script checks the manifest cargo actually
//! supplied to the build and fails if the path dependency is gone.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join("blake3/upstream-sync").exists() {
        panic!(
            "this is the unpatched upstream-sync comparison branch; it is not a merge              candidate and the build intentionally refuses it. Apply the documented local              patches before using this tree."
        );
    }
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap_or_default();
    if !manifest.contains("path = \"blake3\"") {
        panic!(
            "this crate is source-only and requires the vendored `blake3/` path dependency; \
             `cargo package` would rewrite it to unpatched crates.io BLAKE3. Use the git \
             checkout (or a repository archive) instead."
        );
    }
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=blake3/Cargo.toml");
}
