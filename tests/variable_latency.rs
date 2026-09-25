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
use std::collections::BTreeSet;

/// `(trimmed source line, why it is not a secret-dependent latency)`.
const ALLOWED: &[(&str, &str)] = &[(
    "while i < len && (ptr as usize).wrapping_add(i) % align != 0 {",
    "divides by the *alignment* of `usize`, a compile-time constant, not by anything \
     derived from a key, nonce, AAD or message",
)];

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
