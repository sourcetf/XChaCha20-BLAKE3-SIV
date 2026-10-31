//! Refuse to be packaged as a crates.io-style `.crate`.
//!
//! `publish = false` stops `cargo publish`, but `cargo package` rewrites the
//! `blake3 = { version = ..., path = "blake3" }` dependency to a registry
//! requirement. The resulting package would silently build against unpatched
//! crates.io BLAKE3, so this build script requires the vendored tree itself: a
//! normative path in the manifest is not a dependency edge, and a comment or a
//! reformatted `path  =  "blake3"` can satisfy a substring check without the
//! vendored code being present.
//!
//! `cargo package --no-verify` writes the archive without running this script.
//! Nothing can prevent that locally; such an archive is untrusted, is never
//! published or attached by CI, and does not contain the vendored fix set.

use std::env;
use std::path::PathBuf;

fn main() {
    // Read the manifest directory at *run* time, not through `env!`: cargo may reuse a
    // build-script binary it compiled for another package copy (a `cargo package`
    // verification builds the same package/version in the same target dir), and the
    // compile-time `CARGO_MANIFEST_DIR` baked into that binary then points at the
    // package copy while the run-time variable points at the tree being built.
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for build scripts"),
    );
    if manifest_dir.join("blake3/upstream-sync").exists() {
        panic!(
            "this is the unpatched upstream-sync comparison branch; it is not a merge \
             candidate and the build intentionally refuses it. Apply the documented local \
             patches before using this tree."
        );
    }
    // The vendored fork's own manifest, checked by existence rather than by a substring of
    // the parent manifest: `cargo package` strips the path dependency and does not ship
    // `blake3/`, so an extracted `.crate` fails here; the git checkout has it and passes.
    if !manifest_dir.join("blake3/Cargo.toml").exists() {
        panic!(
            "this crate is source-only and requires the vendored `blake3/` tree; \
             `cargo package` would rewrite the path dependency to unpatched crates.io \
             BLAKE3. Use the git checkout (or a repository archive) instead."
        );
    }
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=blake3/Cargo.toml");
}
