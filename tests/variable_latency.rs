//! Variable-latency operations on secrets: an inventory, because nothing else here
//! can see them.
//!
//! ctgrind reports branches and memory indices that depend on poisoned data. A
//! division (or a remainder, or a float operation) has neither: its latency varies
//! *inside* the ALU with the operand's magnitude. The timing screen cannot see it
//! either, and that is measured rather than assumed -- with a division by a
//! secret-derived byte planted inside `decrypt`, the screen reports t = 0.22 / 0.48
//! and passes, because the effect on this CPU is a few cycles against a floor of
//! about seventeen. So no tool in this repository detects that class, and the control
//! has to be a list a human maintains.
//!
//! This test enumerates every `/` and `%` in the crate's non-test source and requires
//! the set to match the table below exactly: a new one fails the test until someone
//! writes down why it is not a secret-dependent latency, and a removed one fails too
//! (so the table cannot rot). It says nothing about whether the listed operations are
//! *actually* safe -- it makes them visible, which is the part that can be automated.
//!
//! The same idea covers the crate's control flow, one section down: `CONTROL_FLOW`
//! counts `if` / `while` / `for` / `loop` / `match` in the non-test source. ctgrind
//! is the *evidence* that no branch depends on secret content -- it reports those
//! mechanically -- so that table is not evidence; it is a tripwire so a branch added
//! or removed anywhere in the crate cannot pass unnoticed while the prose in
//! `README.md` and `SECURITY.md` still claims the old count.
use std::collections::BTreeSet;

/// `(trimmed source line, why it is not a secret-dependent latency)`.
const ALLOWED: &[(&str, &str)] = &[(
    "while i < len && (ptr as usize).wrapping_add(i) % align != 0 {",
    "divides by the *alignment* of `usize`, a compile-time constant, not by anything \
     derived from a key, nonce, AAD or message",
)];

/// `(keyword, occurrences in the non-test source)`.
///
/// Read this with the caveat above: it is a tripwire, not a proof. Every branch here
/// was audited by hand to depend on a length, an alignment, a CPU feature, an enum
/// variant, or the accept/reject decision -- never on the content of a key, nonce,
/// AAD or message -- and ctgrind is what checks that mechanically. The `for` and
/// `while` counts are dominated by the fixed-trip-count loops of the ChaCha20 and
/// BLAKE3 permutations, whose trip counts come from block sizes.
///
/// When one of these numbers changes: look at the branch, decide what it depends on,
/// and update this table, `README.md` and `SECURITY.md` together.
///
/// The two `if`s added by the fail-closed decision shape (`if decision.is_ok()` in
/// each decrypt entry point) are the most recent entry: they branch on a
/// discriminant the *caller* wrote as a constant, so they depend on nothing secret
/// -- which is what makes them constant-time, and why they are listed rather than
/// suppressed.
const CONTROL_FLOW: &[(&str, usize)] = &[
    ("if", 15),
    ("while", 7),
    ("for", 27),
    ("loop", 0),
    ("match", 3),
];

/// Every `/` or `%` in `line` that is code rather than a comment or a doc comment.
fn has_division(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    let b: Vec<char> = code.chars().collect();
    for (i, c) in b.iter().enumerate() {
        if *c != '/' && *c != '%' {
            continue;
        }
        let prev = if i == 0 { ' ' } else { b[i - 1] };
        let next = if i + 1 == b.len() { ' ' } else { b[i + 1] };
        // Skip `/*`, `*/`, `/=`, and `/*` markers.
        if prev == '*' || prev == '/' || next == '*' || next == '/' || next == '=' {
            continue;
        }
        return true;
    }
    false
}

#[test]
fn variable_latency_operations_are_inventoried() {
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = &src[..cut];

    let found: BTreeSet<String> = body
        .lines()
        .filter(|l| has_division(l))
        .map(|l| l.trim().to_string())
        .collect();
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|(l, _)| l.to_string()).collect();

    let added: Vec<&String> = found.difference(&allowed).collect();
    let gone: Vec<&String> = allowed.difference(&found).collect();
    assert!(
        added.is_empty(),
        "new division-like operation(s) in non-test code, and no tool in this \
         repository can tell whether they depend on a secret: {added:?}. Add each to \
         ALLOWED with the reason, or remove it."
    );
    assert!(
        gone.is_empty(),
        "documented operation(s) no longer present: {gone:?}. Update ALLOWED."
    );
}

/// Whole-word occurrences of `kw` in code, ignoring comments and string literals.
///
/// `impl Drop for Plaintext` is not a branch, so `impl` headers are skipped.
fn count_keyword(line: &str, kw: &str) -> usize {
    let code = line.split("//").next().unwrap_or("");
    if code.trim_start().starts_with("impl ") {
        return 0;
    }

    // A `"..."` literal becomes nothing. This walks characters rather than
    // replacing the literal in place: the substitute must contain no quote at all,
    // or the search finds it again -- an empty literal `""` replaced by `""`
    // loops forever, which is how this test hung the first time it ran.
    let mut stripped = String::with_capacity(code.len());
    let mut in_literal = false;
    let mut escaped = false;
    for c in code.chars() {
        if in_literal {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_literal = false;
            }
            continue;
        }
        if c == '"' {
            in_literal = true;
        } else {
            stripped.push(c);
        }
    }

    let bytes = stripped.as_bytes();
    let mut n = 0;
    for (i, _) in stripped.match_indices(kw) {
        let before = i
            .checked_sub(1)
            .is_none_or(|j| !(bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_'));
        let after = bytes
            .get(i + kw.len())
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'));
        if before && after {
            n += 1;
        }
    }
    n
}

#[test]
fn control_flow_is_inventoried() {
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = &src[..cut];

    let mut drifted = Vec::new();
    let mut report = String::new();
    for (kw, expected) in CONTROL_FLOW {
        let found: usize = body.lines().map(|l| count_keyword(l, kw)).sum();
        report.push_str(&format!("      {kw:>5}: {found}\n"));
        if found != *expected {
            drifted.push(format!(
                "{kw}: source has {found}, CONTROL_FLOW says {expected}"
            ));
        }
    }

    assert!(
        drifted.is_empty(),
        "the crate's control flow changed: {drifted:?}\n\nfound:\n{report}\n\
         A branch was added, removed or moved. Work out what the new one depends on \
         (a length, an alignment, a CPU feature, an enum variant, or the decision -- \
         never the content of a key, nonce, AAD or message; ctgrind checks that \
         mechanically), then update CONTROL_FLOW, README.md and SECURITY.md together."
    );
}
