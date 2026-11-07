//! Helpers shared by the source-shape guards in this directory.
//!
//! The scanner below lives here rather than in each target because seven targets needed
//! it and the copies drifted: `tests/security.rs`'s copy grew the whitespace / `r#test` /
//! trailing-comma handling while the six in the other targets stayed at the older
//! spelling for several rounds, which is what "seven copies" costs. A dependency report
//! confirmed the copies were byte-identical *on the day it looked*; a single definition
//! is what makes that structural instead of a fact about one revision.

/// The next `#[cfg(test)]` (or `#![cfg(test)]`) at or after `from`, as
/// `(index of the `#`, index just past the `]`, inner?)`. Whitespace is allowed between
/// the tokens, because `#[ cfg ( test ) ]` is the same attribute.
pub fn find_cfg_test_attribute(source: &str, from: usize) -> Option<(usize, usize, bool)> {
    let b = source.as_bytes();
    let mut i = from;
    while i < b.len() {
        if b[i] == b'#' {
            let mut j = i + 1;
            // `# [cfg(test)]` is the same attribute as `#[cfg(test)]`; rustc accepts
            // whitespace between every token, and a scanner that requires adjacency is
            // one space away from being evaded.
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let inner = b.get(j) == Some(&b'!');
            if inner {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
            }
            if b.get(j) == Some(&b'[') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if b[j..].starts_with(b"cfg") {
                    j += 3;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if b.get(j) == Some(&b'(') {
                        j += 1;
                        while j < b.len() && b[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        // `r#test` is the same atom as `test` (raw identifiers are
                        // accepted in cfg predicates), and `#[cfg(test,)]` is the same
                        // predicate with a trailing comma. Both were measured to evade
                        // the earlier scanner.
                        let atom = if b[j..].starts_with(b"r#test") {
                            6
                        } else if b[j..].starts_with(b"test") {
                            4
                        } else {
                            0
                        };
                        if atom != 0 {
                            let mut k = j + atom;
                            while k < b.len() && b[k].is_ascii_whitespace() {
                                k += 1;
                            }
                            if b.get(k) == Some(&b',') {
                                k += 1;
                                while k < b.len() && b[k].is_ascii_whitespace() {
                                    k += 1;
                                }
                            }
                            if b.get(k) == Some(&b')') {
                                k += 1;
                                while k < b.len() && b[k].is_ascii_whitespace() {
                                    k += 1;
                                }
                                if b.get(k) == Some(&b']') {
                                    return Some((i, k + 1, inner));
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}
