//! The accept/reject decision is this crate's only secret-dependent branch, and
//! the suppression file is only allowed to cover that one function.
//!
//! `tests/ctgrind.supp` exists because SIV has to decrypt before it can verify, so
//! "does this ciphertext authenticate?" is a branch on secret-derived data that
//! cannot be removed. Valgrind suppressions match *functions* and cannot match
//! source lines, which makes the shape of the suppressed thing load-bearing: an
//! entry naming `decrypt` permits every conditional jump inside `decrypt`, and
//! that is not hypothetical — a secret-dependent branch planted inside it passed
//! the check while the entry named `decrypt` and `decrypt_in_place_detached`
//! (measured on a copy: 6 reports with no suppression file, 0 with it).
//!
//! So the decision lives in `accept_or_reject`, `#[inline(never)]`, and these
//! tests hold the two mechanical invariants that keep the permission narrow:
//!
//! * the suppression file may name nothing else, so it cannot be widened to an
//!   entry point by editing one line;
//! * the suppressed function's body contains only the branches of the decision —
//!   no loops, no `match`, no `?` — so what the entry permits stays something a
//!   reader can check at a glance instead of a 60-line function.
//!
//! `tools/ctgrind.sh` checks the first invariant again before it runs (a
//! tools-only invocation never reaches `cargo test`) and plants a
//! secret-dependent branch inside `decrypt` in a throwaway copy, requiring the
//! run to fail. These tests cover the same ground for anyone running the suite.

/// The text of `src/lib.rs`, so the assertions below are about the shipped source
/// rather than about a copy that can drift.
const LIB: &str = include_str!("../src/lib.rs");
/// The suppression file itself.
const SUPP: &str = include_str!("ctgrind.supp");

/// Locate both `accept_or_reject` definitions by name and return their full text,
/// body included, brace-matched.
///
/// There are two because the function is `#[cfg]`-selected: the default build
/// converts one `Choice`, and `--features hardened` converts two. Only one of
/// them exists in any given build, and both are in the source, so a test can
/// inspect both.
fn definitions() -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = LIB;
    while let Some(i) = rest.find("fn accept_or_reject(") {
        let after = &rest[i..];
        let open = after.find('{').expect("definition without a body");
        let mut depth = 0usize;
        let mut end = None;
        for (n, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + n);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("unbalanced braces after accept_or_reject");
        out.push(after[..=end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// Every `fun:` and error-kind line in `tests/ctgrind.supp`, comments removed.
fn suppression_lines(prefix: &str) -> Vec<String> {
    SUPP.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(prefix))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_suppression_file_names_only_the_decision() {
    let funs = suppression_lines("fun:");
    assert!(
        !funs.is_empty(),
        "tests/ctgrind.supp has no entries left: the file is the record of what \
         has been examined and permitted, and an empty file would mean the SIV \
         decision is no longer permitted anywhere -- see tools/ctgrind.sh, which \
         requires at least one entry"
    );
    for f in &funs {
        assert!(
            f.contains("accept_or_reject"),
            "tests/ctgrind.supp suppresses `{f}`. A valgrind entry permits *every* \
             conditional jump in the function it names, not just the one that was \
             reviewed, so an entry naming anything but the accept/reject decision \
             silently re-opens the hole this file documents: a secret-dependent \
             branch planted inside that function would pass the check."
        );
    }

    let kinds = suppression_lines("Memcheck:");
    assert!(!kinds.is_empty(), "entries without an error kind");
    for k in &kinds {
        assert_eq!(
            k, "Cond",
            "the decision is a conditional jump; permitting another error class \
             (`{k}`) would permit something that was not reviewed"
        );
    }
}

#[test]
fn the_suppressed_function_contains_only_the_decision() {
    let defs = definitions();
    assert_eq!(
        defs.len(),
        2,
        "expected the default and the `hardened` definitions of accept_or_reject"
    );

    for def in &defs {
        let hardened = def.contains("gate0");
        // Comments are stripped first: a future comment containing the word "for"
        // or a question mark must not read as a loop or a `?`.
        let code: String = def
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");

        for construct in ["for ", "while ", "loop ", "match "] {
            assert!(
                !code.contains(construct),
                "`{construct}` inside accept_or_reject: the whole function is \
                 suppressed, so a loop in it would be a secret-dependent branch \
                 that no check can see. Move it out, or accept that the entry is \
                 no longer a reviewable one-liner."
            );
        }
        assert!(
            !code.contains('?'),
            "`?` inside accept_or_reject propagates a `Result` through a branch on \
             a discriminant; it belongs at the call site, where ctgrind verifies \
             that the branch is on a constant"
        );

        let branches = code.matches("if ").count();
        let expected = if hardened { 2 } else { 1 };
        assert_eq!(
            branches,
            expected,
            "`accept_or_reject` has {branches} branch(es); the {} definition is \
             expected to have {expected}. The suppressed function is exactly the \
             decision, and this count is what \"exactly\" means -- if the decision \
             needs another branch, the suppression entry needs re-reviewing.",
            if hardened { "hardened" } else { "default" }
        );
        assert!(
            code.contains("bool::from"),
            "the branch must convert a `Choice`, not compare bytes directly"
        );
    }
}
