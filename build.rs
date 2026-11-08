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
//! The second check parses the manifest rather than substring-matching it -- comments are
//! stripped, *including trailing ones* (which is what `# path = "blake3"` on a dependency
//! line is), and the value has to be a `path = "…"` key in the entry -- so a comment cannot
//! satisfy it.
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
/// Whether a `path` value names the vendored fork.
///
/// Normalised rather than compared byte for byte, because the *legal* spellings of the same
/// edge were rejected as if they were a missing one: `path = './blake3'` (TOML literal
/// string), `path = "./blake3"` (cargo resolves a leading `./`) and `path = "blake3/"` (a
/// trailing separator) all point at the fork, and each panicked this check. A false refusal
/// is not a security hole -- it fails the build -- but "the manifest must be written one
/// specific way" is not what this check is for, and the earlier fix for
/// `[dependencies."blake3"]` was the same class.
fn path_is_the_vendored_fork(value: &str) -> bool {
    let v = unquote(value.trim());
    let v = v.strip_prefix("./").unwrap_or(v);
    v.trim_end_matches('/') == "blake3"
}

/// A sentence appended when the entry inherits its `path` from a workspace table this check
/// cannot see, so the failure names the real problem instead of a missing key that is not
/// missing in the manifest being read.
fn workspace_hint(value: &str) -> &'static str {
    let normalized: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.contains("workspace=true") {
        " (`workspace = true` moves the edge into a `[workspace.dependencies]` table outside \
         this manifest, which this check cannot read; keep `path = \"blake3\"` here.)"
    } else {
        ""
    }
}

fn check_blake3_is_a_path_dependency(manifest: &str) {
    let mut section = String::new();
    let mut checked = 0usize;
    // A `key = value` entry, with continuation lines while an inline table is open.
    let mut pending: Option<(String, String)> = None;
    let mut depth = 0i32;

    let finish = |section: &str, key: &str, value: &str, checked: &mut usize| {
        if unquote(key) == "blake3" && is_dependency_section(section) {
            *checked += 1;
            if !inline_value(value, "path")
                .as_deref()
                .is_some_and(path_is_the_vendored_fork)
            {
                panic!(
                    "the `blake3` entry in [{section}] does not carry a `path` pointing at \
                     the vendored fork (it is `{value}`). Without the path edge the build \
                     resolves crates.io BLAKE3 1.8.7 and none of the fixes in blake3/PATCHES.md \
                     are present. Restore the `path` key (see the distribution policy in \
                     PATCHES.md).{}",
                    workspace_hint(value)
                );
            }
        }
    };
    // The table-header form `[dependencies.blake3]`, whose keys (`version`, `path`, …) are
    // on their own lines: `(crate name, the `path` value seen so far)`. The key parser
    // above cannot see this form, which is how the decoy-section bypass worked -- the real
    // edges were moved to this form and metadata decoys satisfied the count.
    let mut table_dep: Option<(String, Option<String>)> = None;
    let finalize_table = |table_dep: &mut Option<(String, Option<String>)>, checked: &mut usize| {
        if let Some((krate, path)) = table_dep.take() {
            if krate == "blake3" {
                *checked += 1;
                if !path.as_deref().is_some_and(path_is_the_vendored_fork) {
                    panic!(
                        "the `blake3` dependency table `[*.{krate}]` does not carry a `path` \
                         pointing at the vendored fork (path is {path:?}). Without the path \
                         edge the build resolves crates.io BLAKE3 1.8.7 and none of the fixes \
                         in blake3/PATCHES.md are present. Restore the `path` key (see the \
                         distribution policy in PATCHES.md)."
                    );
                }
            }
        }
    };

    for raw in manifest.lines() {
        // Strip a trailing comment *outside string literals* before anything else: a TOML
        // comment runs to end of line, and `# path = "blake3"` appended to a dependency line
        // satisfied the previous parser without being a key at all (measured: with both real
        // `path` keys removed and that comment added, `cargo build` linked crates.io BLAKE3
        // while this check stayed quiet). A `#` inside a quoted value is data, hence the
        // string-state walk rather than `split_at('#')`.
        let raw = strip_comment(raw);
        let line = raw.trim();
        if line.is_empty() {
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
            finalize_table(&mut table_dep, &mut checked);
            section = line.trim_matches(['[', ']']).trim().to_string();
            table_dep = dep_section_crate(&section).map(|c| (c.to_string(), None));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if let Some((_, path)) = table_dep.as_mut() {
            // A line inside a `[<dep section>.<crate>]` table. Only `path` matters here;
            // the crate name is already known from the header.
            // `unquote`, not a bare comparison: `"path" = "blake3"` is the same key with a
            // quoted spelling, which TOML allows and cargo accepts.
            if unquote(key) == "path" {
                *path = Some(value.trim().to_string());
            }
            continue;
        }
        depth = opening_brackets(value) - closing_brackets(value);
        if depth <= 0 {
            finish(&section, key, value, &mut checked);
        } else {
            pending = Some((key.to_string(), value.to_string()));
        }
    }
    finalize_table(&mut table_dep, &mut checked);
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

/// Remove a TOML comment (an unquoted `#` to end of line) from `line`.
///
/// Single- and double-quoted strings are tracked, because `#` inside one is data: a
/// `path = "blake#3"` must survive. Backslash escapes inside a double-quoted string are
/// carried through so a `\"` does not close it early.
fn strip_comment(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if q == b'"' && c == b'\\' {
                    // Keep the escape and the escaped byte together.
                    out.push(c as char);
                    i += 1;
                    if i < bytes.len() {
                        out.push(bytes[i] as char);
                        i += 1;
                    }
                    continue;
                }
                if c == q {
                    quote = None;
                }
                out.push(c as char);
            }
            None => {
                if c == b'#' {
                    break;
                }
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                }
                out.push(c as char);
            }
        }
        i += 1;
    }
    out
}

/// Whether a TOML section name denotes a real dependency table.
///
/// A dot-path segment list, not a suffix: an earlier `name.ends_with(".dependencies")` also
/// matched `[package.metadata.<any>.dependencies]`, where a decoy
/// `blake3 = { path = "blake3" }` satisfied the "every blake3 entry has a path" count while
/// the *real* edge was a registry dependency in a table-header form the key parser did not
/// recognise (measured: `cargo build` linked crates.io BLAKE3). Only the three dependency
/// kinds, bare or under `target.<cfg>` / `workspace`, are real edges.
fn is_dependency_section(name: &str) -> bool {
    let (prefix, last) = match name.rsplit_once('.') {
        Some((p, l)) => (Some(p), l),
        None => (None, name),
    };
    if !matches!(
        last,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    ) {
        return false;
    }
    match prefix {
        None => true,
        Some(p) => p == "workspace" || p.starts_with("target."),
    }
}

/// A TOML bare or quoted key as its bare form: `"blake3"` -> `blake3`. Cargo accepts
/// `[dependencies."blake3"]` and `"blake3" = …`, and a parser that compared the raw text
/// missed them: a *valid* manifest spelled that way made `checked == 0` and this build
/// script panic (a false positive), and the entry was invisible to the path check
/// (measured).
fn unquote(key: &str) -> &str {
    let key = key.trim();
    if key.len() >= 2
        && ((key.starts_with('"') && key.ends_with('"'))
            || (key.starts_with('\'') && key.ends_with('\'')))
    {
        &key[1..key.len() - 1]
    } else {
        key
    }
}

/// If a section name is `<dependency section>.<crate>` (the table-header form,
/// `[dependencies.blake3]` or `[dependencies."blake3"]`), the crate name.
fn dep_section_crate(name: &str) -> Option<&str> {
    let (prefix, last) = name.rsplit_once('.')?;
    if is_dependency_section(prefix) && !last.is_empty() {
        Some(unquote(last))
    } else {
        None
    }
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
                // Both string forms: TOML's basic `"…"` and literal `'…'`, which cargo reads
                // as the same path. Accepting only the first made `path = 'blake3'` look
                // like a missing `path`.
                for quote in ['"', '\''] {
                    if let Some(rest) = rest.strip_prefix(quote) {
                        if let Some(end) = rest.find(quote) {
                            return Some(rest[..end].to_string());
                        }
                    }
                }
            }
        }
        from = at + key.len();
    }
    None
}
