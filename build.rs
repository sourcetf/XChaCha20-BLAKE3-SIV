//! Refuse to be packaged as a crates.io-style `.crate`, or to be built against a
//! `blake3` dependency edge that no longer points at the vendored tree.
//!
//! `publish = false` stops `cargo publish`, but `cargo package` rewrites the
//! `blake3 = { version = ..., path = "blake3" }` dependency to a registry
//! requirement. The resulting package would silently build against unpatched
//! crates.io BLAKE3, so this build script requires the vendored tree itself: a
//! normative path in the manifest is not a dependency edge, and a comment or a
//! reformatted `path  =  "blake3"` can satisfy a substring check without the
//! vendored code being present.
//!
//! Two checks, because they fail on different mutations and the *combination* is what
//! covers the case that was measured:
//!
//! * `blake3/Cargo.toml` must exist. `cargo package` strips the path dependency and does
//!   not ship `blake3/`, so an extracted `.crate` fails here.
//! * each `blake3` entry in a dependency section of this manifest must carry
//!   `path = "blake3"`. Existence alone does not cover a manifest edit that drops the
//!   `path` key while leaving the directory in place -- measured: `cargo build --offline`
//!   succeeds against crates.io BLAKE3 1.8.7 and only the `blake3_fork_equivalence` tests
//!   notice, which a run selecting other targets would miss.
//!
//! The second check parses the manifest rather than substring-matching it, for the reason
//! the first one exists at all: `a comment saying path = "blake3"` must not satisfy it.
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
    // The dependency edge itself. `cargo package` is caught by the existence check above;
    // this catches a source-tree manifest whose `path` key was dropped, which would compile
    // and resolve crates.io BLAKE3 while `blake3/` sits unused beside it.
    let manifest = std::fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("the parent manifest must be readable");
    check_blake3_is_a_path_dependency(&manifest);
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=blake3/Cargo.toml");
}

/// Every `blake3` entry in a dependency section of `manifest` must read `path = "blake3"`.
///
/// Panics otherwise, so a build fails rather than silently linking unpatched registry
/// BLAKE3. Mirrors `the_vendored_fork_is_wired_in_by_path` in
/// `tests/blake3_fork_equivalence.rs`, which asserts the same property from the test side;
/// the duplication is deliberate -- the test needs a test run to fire, and this fires on the
/// first `cargo build`.
fn check_blake3_is_a_path_dependency(manifest: &str) {
    let mut section = String::new();
    let mut checked = 0usize;
    // A `key = value` entry, with continuation lines while an inline table is open.
    let mut pending: Option<(String, String)> = None;
    let mut depth = 0i32;

    let finish = |section: &str, key: &str, value: &str, checked: &mut usize| {
        if key == "blake3" && is_dependency_section(section) {
            *checked += 1;
            if inline_value(value, "path").as_deref() != Some("blake3") {
                panic!(
                    "the `blake3` entry in [{section}] does not carry `path = \"blake3\"` \
                     (it is `{value}`). Without the path edge the build resolves crates.io \
                     BLAKE3 1.8.7 and none of the fixes in blake3/PATCHES.md are present. \
                     Restore the `path` key (see the distribution policy in PATCHES.md)."
                );
            }
        }
    };

    for raw in manifest.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((_key, value)) = pending.as_mut() {
            value.push(' ');
            value.push_str(line);
            depth += opening_brackets(line) - closing_brackets(line);
            if depth <= 0 {
                let (key, value) = pending.take().expect("checked above");
                finish(&section, &key, &value, &mut checked);
            }
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        depth = opening_brackets(value) - closing_brackets(value);
        if depth <= 0 {
            finish(&section, key, value, &mut checked);
        } else {
            pending = Some((key.to_string(), value.to_string()));
        }
    }
    if checked == 0 {
        // `cargo` itself rejects a manifest with no `blake3` dependency at all (it is
        // imported by `src/lib.rs`), so reaching here means the parser above stopped
        // recognising dependency entries -- which would make the check vacuous rather than
        // failing it. Refuse to build instead of pretending it passed.
        panic!(
            "no `blake3` dependency entry was found in this manifest; the dependency-edge \
             check cannot have run, so the vendored fork is unverified. This means the \
             manifest parser in build.rs no longer matches the manifest's shape."
        );
    }
}

fn is_dependency_section(name: &str) -> bool {
    name == "dependencies"
        || name == "dev-dependencies"
        || name == "build-dependencies"
        || name.ends_with(".dependencies")
        || name.ends_with(".dev-dependencies")
        || name.ends_with(".build-dependencies")
}

fn opening_brackets(s: &str) -> i32 {
    s.matches(['{', '[']).count() as i32
}

fn closing_brackets(s: &str) -> i32 {
    s.matches(['}', ']']).count() as i32
}

/// The string value of `key` in an inline table such as `{ version = "1", path = "blake3" }`.
/// The key must start at a delimiter, so `apathetic = "x"` cannot answer for `path`.
fn inline_value(table: &str, key: &str) -> Option<String> {
    let mut from = 0usize;
    while let Some(i) = table[from..].find(key) {
        let at = from + i;
        let starts_word =
            at == 0 || matches!(table.as_bytes()[at - 1], b' ' | b',' | b'{' | b'(' | b'\t');
        let rest = table[at + key.len()..].trim_start();
        if starts_word {
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('"') {
                    if let Some(end) = rest.find('"') {
                        return Some(rest[..end].to_string());
                    }
                }
            }
        }
        from = at + key.len();
    }
    None
}
