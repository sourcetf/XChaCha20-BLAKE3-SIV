//! What `ultra` claims, asserted instead of promised.
//!
//! `ultra` is the feature that turns on every defence this crate has. "Immune to every
//! attack model" is not a testable statement, so this file is the honest version of it:
//! for each model, either a test that the defence is *present and doing something*, or a
//! test that pins where the defence stops — because a mode that claims total immunity and
//! has no written limits is worse than one that states its boundaries.
//!
//! The layers, and where each is checked:
//!
//! | model | defence | checked by |
//! | --- | --- | --- |
//! | ciphertext equality / length | the construction itself; documented, not removable | `documents_what_it_cannot_defend_against` |
//! | a secret-dependent branch | constant-time comparison; the one decision suppressed, nothing else | `tools/ctgrind.sh` (its planted-leak control is the interesting half) |
//! | a single corrupted decision *value* | two slots, two serial reject-first checks | `tests/decision.rs`, `tools/fi_check.sh` |
//! | a single corrupted *instruction* | the second gate, and the fail-closed call site | `tools/fi_instruction.sh` (both models) |
//! | `computed_tag` pinned / rewritten | an independent recomputation cross-checked against both values | `dual_mac_is_wired_into_both_decrypt_paths` |
//! | key pages read out of swap or a core dump | `mlock` + `MADV_DONTDUMP` | `locked_key_is_actually_locked` (the lock); `tests/locked.rs` (`unlocking_restores_core_dump_inclusion`, `the_dump_advice_is_issued_on_the_right_range`) for the dump exclusion |
//! | a nonce reused | SIV: the tag binds the message, so reuse degrades rather than fails | `src/lib.rs`: `test_message_swap_under_a_reused_nonce_is_rejected` |
//! | remote memory exhaustion | a public bound, a pre-allocation policy check, fallible allocation | `tests/security.rs` |
//!
//! `ultra` = `hardened` + `rng` + `dual-mac` + `locked`. (`pure` is deliberately *not*
//! part of it — it is a cross-compile/perf switch that forces BLAKE3's portable backends,
//! costs 24-32% and buys no security — and `Cargo.toml` and `README.md` both say so; this
//! line used to list it, which contradicted them.) This file is compiled only when
//! `ultra` is on, and the assertions below are about the *combination*, which nothing
//! else in the suite can check.

#![cfg(feature = "ultra")]

use xchacha20_blake3_siv::{decrypt, decrypt_in_place_detached, encrypt, Error};

// `ultra` is a bundle, and this asserts the bundle is wired -- at *compile* time,
// which is the right place for a fact about which features are on. The previous
// version grepped `src/lib.rs` for the text `#[cfg(feature = "dual-mac")]`: that
// string is in the file in every configuration, so the assertion held even if
// `ultra` enabled nothing, which is how three defects in the `locked` layer
// survived a suite that claimed to test it.
const _: () = {
    // `if !.. { panic!(..) }` rather than `assert!`: clippy's
    // `assertions_on_constants` rejects `assert!` on a constant, and it is right
    // that a fact about which features are on belongs in a `const` block.
    if !cfg!(feature = "hardened") {
        panic!("`ultra` must enable `hardened`");
    }
    if !cfg!(feature = "dual-mac") {
        panic!("`ultra` must enable `dual-mac`");
    }
    if !cfg!(feature = "locked") {
        panic!("`ultra` must enable `locked`");
    }
    if !cfg!(feature = "rng") {
        panic!("`ultra` must enable `rng`");
    }
};

const KEY: [u8; 32] = [0x11u8; 32];
const NONCE: [u8; 24] = [0x22u8; 24];

/// The shipped text of `src/lib.rs`, so the assertions below are about what a user
/// compiles rather than about a copy that can drift.
const LIB: &str = include_str!("../src/lib.rs");

/// The non-test source of `LIB`: everything outside the body of its `#[cfg(test)]
/// mod tests` module, wherever that module sits in the file.
///
/// Every source-shape assertion in this file runs on this rather than on the raw file.
/// `include_str!` text makes a `matches`/`contains` satisfiable without the code: replace a
/// real statement with a comment carrying the same words and the count is unchanged. An
/// audit demonstrated exactly that for `scrub_stack();` — replaced by
/// `// scrub_stack(); (planted)` at `src/lib.rs:2495`,
/// `scrub_stack_is_called_at_every_entry_point` stayed green — and `scrub_stack` has no
/// behavioural signature, so that count is its only existence witness. The scanner is the
/// one `tests/decision_scope.rs` and `tests/counter_range.rs` use; it is copied rather than
/// shared because a test binary cannot import another test binary's items.
///
/// The obvious way to get the cut — truncate at the first `mod tests {` — hides code
/// that is textually *after* the module, because the cut is at the module's first
/// line, not at its closing brace: a production function appended below the test
/// module (legal Rust, compiled in normal builds) is skipped entirely. Measured: a
/// helper calling `zeroize_array` on a `recomputed_tag` appended after the test
/// module left this file's suite green, though
/// `dual_mac_is_wired_into_both_decrypt_paths` counts exactly those wipes. It also
/// hid a `mod tests {` *mentioned in a comment*
/// before the real one, since the old `find` ran on the raw text; stripping comments
/// and literals first removes that.
///
/// This finds the module on the stripped text, requires it to carry `#[cfg(test)]`,
/// brace-matches its body (braces inside comments and string literals are already gone,
/// so they cannot unbalance the count), and removes exactly the body and the module's own
/// `#[cfg(test)]` attribute — blanking those lines rather than deleting them, so line
/// numbers in the scans' failure messages keep pointing at the source. Everything else,
/// before *and* after the module, is what the scans read.
///
/// What the scans read is then further restricted to source a consumer's build compiles:
/// [`blank_cfg_test_items`] blanks every remaining `#[cfg(test)]`-attributed item, and
/// [`non_test_source_of`] asserts no `#[cfg(test)]` survives. That invariant falls out of
/// this function's own definition — everything left is non-test source — and it closes
/// the second-module planting: a `#[cfg(test)] mod planting { … }` beside the real test
/// module, with the real `zeroize_slice(&mut witness_ciphertext);` deleted, was measured
/// satisfying this file's count of the planted call, because the planted text lies outside
/// the one module body this cut removed.
///
/// [`non_test_source_of`] is the same cut for `src/witness.rs`, which
/// `the_witness_shares_only_the_specification_with_the_crate` scans.
fn non_test_source() -> String {
    non_test_source_of(LIB)
}

/// See [`non_test_source`]: the same cut applied to `text` rather than to `LIB`, for the
/// witness-file scan below.
fn non_test_source_of(text: &str) -> String {
    let stripped = strip_comments(text);
    let at = stripped
        .find("mod tests {")
        .expect("the scanned file's test module must exist (`mod tests {`)");
    assert_eq!(
        stripped.matches("mod tests {").count(),
        1,
        "the scanned file holds more than one `mod tests {{`: which one is the test \
         module, and what the scan cut, would be ambiguous"
    );
    let before = stripped[..at].trim_end();
    assert!(
        before.ends_with("#[cfg(test)]"),
        "the scanned `mod tests {{` is not `#[cfg(test)]`: it is production code being \
         mistaken for the test module, so the scan would skip it"
    );
    // The attribute goes with the body: it is `#[cfg(test)]`, so it is not text a
    // consumer's build compiles either, and keeping it would trip the invariant below.
    let attr_start = before.len() - "#[cfg(test)]".len();
    let open = at + "mod tests {".len() - 1;
    let mut depth = 0usize;
    let mut close = None;
    for (i, c) in stripped[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.expect("the test module's body is unterminated");
    let mut out = String::with_capacity(stripped.len());
    out.push_str(&stripped[..attr_start]);
    for _ in 0..stripped[attr_start..=close].matches('\n').count() {
        out.push('\n');
    }
    out.push_str(&stripped[close + 1..]);
    // Everything left must be non-test source. The crate's *other* `#[cfg(test)]` items
    // (`test_counters`, `extern crate std`, the `flip_byte_for_test` impl, the counter
    // call in `derive_tag`) do not ship either, and a test-gated item left in the scan is
    // exactly the planting surface.
    let out = blank_cfg_test_items(&out);
    match find_cfg_test_attribute(&out, 0) {
        None => {}
        Some((at, _, false)) => panic!(
            "a `#[cfg(test)]` at byte {at} of the cut source survived the blanking pass; \
             the cut is no longer non-test source and the counts below cannot be trusted"
        ),
        Some((at, _, true)) => panic!(
            "the scanned file carries an inner `#![cfg(test)]` at byte {at}: it gates the \
             enclosing block rather than an item, so this scanner cannot blank the right \
             span; rewrite it as `#[cfg(test)]` on the item it gates"
        ),
    }
    out
}

/// The next `#[cfg(test)]` (or `#![cfg(test)]`) at or after `from`, as
/// `(index of the `#`, index just past the `]`, inner?)`. Whitespace is allowed between
/// the tokens, because `#[ cfg ( test ) ]` is the same attribute.
fn find_cfg_test_attribute(source: &str, from: usize) -> Option<(usize, usize, bool)> {
    let b = source.as_bytes();
    let mut i = from;
    while i < b.len() {
        if b[i] == b'#' {
            let mut j = i + 1;
            let inner = b.get(j) == Some(&b'!');
            if inner {
                j += 1;
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
                        if b[j..].starts_with(b"test") {
                            let mut k = j + 4;
                            while k < b.len() && b[k].is_ascii_whitespace() {
                                k += 1;
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

/// `source` with every `#[cfg(test)]`-attributed **item** blanked to spaces (newlines
/// kept, so line numbers stay comparable): the test-only text that lies outside the one
/// `mod tests` module.
///
/// The item's extent is found by skipping any further attributes, then taking the first
/// `{` (brace-matched, so a `;` inside the item's body cannot end it) or the first `;`
/// outside parentheses and brackets. What this does **not** cover is spelled out where the
/// result is asserted: only the plain `test` predicate is matched (`all(test, …)`,
/// `cfg_attr(test, …)` are not), and the item must end in a brace block or a `;`. A shape
/// this cannot blank is not silently kept: the caller's assertion rejects any surviving
/// `#[cfg(test)]`, and an item whose extent cannot be found is a panic, not a skip.
fn blank_cfg_test_items(source: &str) -> String {
    let mut out = source.as_bytes().to_vec();
    let mut from = 0usize;
    while let Some((start, close, inner)) = find_cfg_test_attribute(source, from) {
        if inner {
            // An inner attribute gates its enclosing block, so there is no item span to
            // blank; the caller rejects the source rather than cutting the wrong thing.
            break;
        }
        let end = cfg_test_item_end(source, close);
        for byte in &mut out[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        from = end;
    }
    String::from_utf8(out).expect("blanking whole spans between ASCII tokens keeps valid UTF-8")
}

/// The byte just past the item the `#[cfg(test)]` attribute ending at `close` applies to:
/// the matching `}` of its body, or its terminating `;`.
fn cfg_test_item_end(source: &str, close: usize) -> usize {
    let mut at = close;
    // Further attributes can sit between this one and the item (`#[cfg(test)] #[inline]
    // fn …`).
    loop {
        let rest = &source[at..];
        let trimmed = rest.trim_start();
        at += rest.len() - trimmed.len();
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            let open = source[at..].find('[').map_or(at, |n| at + n + 1);
            at = source[open..].find(']').map_or(open, |n| open + n + 1);
        } else {
            break;
        }
    }
    let mut depth = 0i64;
    for (n, c) in source[at..].char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth == 0 => {
                // The item's body: brace-match it.
                let open = at + n;
                let mut inner = 0i64;
                for (m, c) in source[open..].char_indices() {
                    match c {
                        '{' => inner += 1,
                        '}' => {
                            inner -= 1;
                            if inner == 0 {
                                return open + m + 1;
                            }
                        }
                        _ => {}
                    }
                }
                panic!("the `#[cfg(test)]` item at byte {at} has an unterminated body");
            }
            ';' if depth == 0 => return at + n + 1,
            _ => {}
        }
    }
    panic!(
        "the `#[cfg(test)]` attribute ending at byte {close} has no `{{` or `;` \
         terminating the item it attributes, so this scanner cannot blank that item; a \
         test-gated item left in the scan is text a consumer's build never compiles"
    );
}

/// See [`non_test_source`]: comments and string-literal contents are removed, with newlines
/// kept so line positions stay comparable.
///
/// A small state machine rather than `find("//")`, because a `//` inside a string literal
/// used to cut the rest of the line out of the scan — which hid a real call site from a
/// count — and a `/* … */` block was scanned as code. Literal contents are dropped (the
/// quotes remain, so a literal becomes `""`), so a *string* carrying the text cannot stand
/// in for a statement either; a bare `"…"` is not an occurrence of a call.
///
/// Block comments are tracked with their **nesting depth**: Rust nests them, and a scanner
/// that exits at the first `*/` reads the rest of the comment as code. Measured before this
/// depth was tracked: `/* /* */ zeroize_slice(&mut witness_ciphertext); /* */ */` was a
/// comment to rustc and a call site to the counts here — the witness wipe could be
/// commented out of the shipped library while this file stayed green.
fn strip_comments(text: &str) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Code,
        Line,
        /// Inside a block comment, with its **nesting depth**. See the doc above.
        Block(usize),
        Str,
        /// Inside a raw string (`r"…"`, `r#"…"#`), whose contents are dropped.
        RawStr(u8),
    }
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut mode = Mode::Code;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        match mode {
            Mode::Code => {
                if c == b'/' && b.get(i + 1) == Some(&b'/') {
                    mode = Mode::Line;
                    i += 2;
                } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
                    mode = Mode::Block(1);
                    i += 2;
                } else if let Some((prefix, hashes)) = raw_string_prefix(&b[i..]) {
                    // A raw string (`r"…"`, `r#"…"#`, `br#"…"#`): its contents are
                    // dropped like any other literal's, with the prefix and the closing
                    // quotes kept. Without this the scanner re-enters code mode at the
                    // first `"` inside the string, and the text between two quotes is
                    // scanned as code — `let _ = r#"x" scrub_stack(); "x"#;` used to
                    // satisfy a `scrub_stack();` count while the real call was spelled
                    // with a space.
                    for k in 0..=prefix {
                        out.push(b[i + k] as char);
                    }
                    i += prefix + 1;
                    mode = Mode::RawStr(hashes);
                } else if c == b'\'' {
                    // A char literal is opaque, and this must come before the `"` case:
                    // `'"'` is a char literal whose *closing* quote would otherwise open
                    // `Mode::Str` and swallow the rest of the scan. A lifetime (`&'a`)
                    // and a lone apostrophe have no closing quote, so the look-ahead
                    // tests for one of the two literal shapes and otherwise treats the
                    // `'` as an ordinary byte.
                    let escaped = b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'');
                    if escaped || b.get(i + 2) == Some(&b'\'') {
                        i += if escaped { 4 } else { 3 };
                    } else {
                        out.push('\'');
                        i += 1;
                    }
                } else if c == b'"' {
                    // Keep the opening quote; the contents are dropped in `Mode::Str`
                    // and the closing quote is kept there.
                    out.push('"');
                    mode = Mode::Str;
                    i += 1;
                } else {
                    out.push(c as char);
                    i += 1;
                }
            }
            Mode::Line => {
                if c == b'\n' {
                    out.push('\n');
                    mode = Mode::Code;
                }
                i += 1;
            }
            Mode::Block(depth) => {
                if c == b'/' && b.get(i + 1) == Some(&b'*') {
                    // A nested comment: Rust counts these, so the scanner must too.
                    mode = Mode::Block(depth + 1);
                    i += 2;
                } else if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    mode = if depth == 1 {
                        Mode::Code
                    } else {
                        Mode::Block(depth - 1)
                    };
                    i += 2;
                } else {
                    if c == b'\n' {
                        out.push('\n'); // keep line numbers aligned
                    }
                    i += 1;
                }
            }
            Mode::Str => {
                if c == b'\\' {
                    i += 2; // skip the escaped byte (including `\"`)
                } else if c == b'"' {
                    out.push('"');
                    mode = Mode::Code;
                    i += 1;
                } else {
                    // Drop the contents so no byte inside a literal is scanned.
                    i += 1;
                }
            }
            Mode::RawStr(hashes) => {
                let h = hashes as usize;
                // The terminator is `"` followed by as many `#`s as opened the string;
                // until then every byte (quotes included) is contents, so it is dropped.
                // Newlines are kept so line positions stay comparable.
                if c == b'"'
                    && b.len() >= i + 1 + h
                    && b[i + 1..i + 1 + h].iter().all(|&x| x == b'#')
                {
                    out.push('"');
                    for _ in 0..h {
                        out.push('#');
                    }
                    i += 1 + h;
                    mode = Mode::Code;
                } else {
                    if c == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
        }
    }
    out
}

/// `(bytes before the opening quote, hash count)` when `b` starts a raw string literal
/// (`r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`); `None` otherwise.
///
/// A raw identifier (`r#name`) is not a string — the byte after its hashes is not a
/// quote — and a plain `"…"` is handled by `Mode::Str`.
fn raw_string_prefix(b: &[u8]) -> Option<(usize, u8)> {
    let mut i = 0usize;
    if b.get(i) == Some(&b'b') {
        if b.get(i + 1) != Some(&b'r') {
            return None;
        }
        i += 2;
    } else if b.get(i) == Some(&b'r') {
        i += 1;
    } else {
        return None;
    }
    let start = i;
    while b.get(i) == Some(&b'#') {
        i += 1;
    }
    if b.get(i) != Some(&b'"') {
        return None;
    }
    // A raw string's hash count is tiny (the compiler caps it far below 256).
    Some((i, (i - start) as u8))
}

/// Every brace-matched block in the non-test source that starts at `needle`,
/// `needle` included. The same helper as `tests/decision_scope.rs`.
fn brace_blocks(needle: &str) -> Vec<String> {
    let text = non_test_source();
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find(needle) {
        let after = &rest[i..];
        let open = after.find('{').expect("block without a body");
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
        let end = end.expect("unbalanced braces");
        out.push(after[..=end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// The independent recomputation every decrypt performs under `ultra`.
///
/// Two properties, and the second is the reason it exists: it must agree with the stored
/// value *and* with the received tag, so a fault that rewrites the stored tag to the
/// received one is caught — which the two gates cannot do, because they compare the same
/// two values and are satisfied together.
#[test]
fn dual_mac_is_wired_into_both_decrypt_paths() {
    // Comments stripped: each count below is an existence witness for a call, and a comment
    // (or a string literal) carrying the same text must not be able to stand in for it.
    let body = non_test_source();

    // `let mut`, because the result is wiped below like every other secret-derived copy.
    assert_eq!(
        body.matches("recomputed_tag = derive_tag(").count(),
        2,
        "both decrypt paths must recompute the tag independently"
    );
    // The binding is also the only write to `recomputed_tag` anywhere in the non-test
    // source.  The comparisons below name the variable, not the value that reaches them:
    // a later `recomputed_tag = computed_tag;` leaves every count in this file unchanged
    // while making the second gate compare the stored tag with itself, which is exactly
    // the rewritten-stored-tag fault the recomputation exists to catch.
    assert_eq!(
        body.matches("recomputed_tag =").count(),
        2,
        "each recomputation must be bound exactly once; a reassignment or shadowing \
         `let recomputed_tag = ...` after `derive_tag` discards the independent value \
         while every comparison below still reads a variable with the right name"
    );
    // Two, and the count is exact rather than "at least": one comparison of each kind per
    // entry point, on the single `second` line that every configuration compiles. It was
    // four when `ultra` had an arm of its own for this expression, which is the shape the
    // comment in the gate explains was removed.
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(&computed_tag)").count(),
        2,
        "the recomputation must be compared against the stored value, once per entry point"
    );
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(tag)").count(),
        2,
        "and against the received tag, which is what catches a rewritten stored value"
    );
    // The calls must actually reach the gate: keeping the comparisons but writing
    // `let second = gate_pair;` left this test green before, because it counted the calls
    // without checking that `second` used them.
    assert_eq!(
        body.matches("gate_pair & recomputed_tag.ct_eq(&computed_tag) & recomputed_tag.ct_eq(tag)")
            .count(),
        2,
        "the recomputation must be ANDed into the second gate on both entry points, not merely \
         computed"
    );
    // Under `ultra` the independent *implementation* joins the same gate: the stored tag
    // agreeing with the received one is not enough if both came from a rewritten
    // computation, so the witness's own answer is required too. It is folded into
    // `gate_pair` -- the line every configuration compiles -- rather than into a
    // `#[cfg]`-selected arm, so `cargo mutants` sees it in every run.
    assert_eq!(
        body.matches("second_gate_comparison(&computed_tag_copy, &tag_copy) & witness_ok")
            .count(),
        2,
        "`ultra`'s witness agreement must be ANDed into the second gate of both entry points"
    );
    // And the agreement must be what its block *returns*: every count above witnesses
    // that the comparison is written, none of them that its value is the one bound to
    // `witness_ok`. An audit renamed the live binding dead, returned
    // `subtle::Choice::from(1)` from both blocks, and left a witness whose tag ignores
    // the AAD -- every assertion here and in `decision_scope.rs` stayed green. Pin the
    // last non-empty line of each block, as `decision_scope.rs` does for `plain & also`.
    let witness_blocks = brace_blocks("let witness_ok: subtle::Choice = {");
    assert_eq!(
        witness_blocks.len(),
        2,
        "one witness-agreement block per decrypt entry point"
    );
    for block in &witness_blocks {
        let code = strip_comments(block);
        // `let … = { … };`: strip the trailing `;` (the `}` comes before it), then the
        // closing brace, then take the last non-empty line.
        let trimmed = code.trim_end();
        let trimmed = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
        let last = trimmed
            .strip_suffix('}')
            .expect("each witness_ok block must end in a closing brace")
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(str::trim)
            .unwrap_or("");
        assert_eq!(
            last, "agree",
            "the witness agreement must be the block's returned value rather than a \
             comparison computed and discarded with a constant returned in its place:\n{block}"
        );
    }
    // Wiped like every other secret-derived copy in the function.
    assert_eq!(
        body.matches("zeroize_array(&mut recomputed_tag)").count(),
        2,
        "the recomputed tag is secret-derived and must be wiped"
    );
    // The *witness's* copies, which none of the assertions above reach: they pin what the
    // blocks compare and return, never that the compared values were wiped. Deleting the
    // witness wipes from both decrypt blocks and from `encrypt` (three that name
    // `witness_tag`, two `witness_plaintext`, one `witness_ciphertext`) left every test in
    // this file and in `security.rs` green. Exact counts, so one deleted site is one
    // failure even though several survive.
    assert_eq!(
        body.matches("zeroize_array(&mut witness_tag)").count(),
        3,
        "the witness's tag is secret-derived and wiped at each of its call sites: the \
         `encrypt` rejection path and both decrypt entry points"
    );
    assert_eq!(
        body.matches("zeroize_slice(&mut witness_plaintext)")
            .count(),
        2,
        "the witness's recovered plaintext is secret-derived and must be wiped in both \
         decrypt entry points"
    );
    assert_eq!(
        body.matches("zeroize_slice(&mut witness_ciphertext)")
            .count(),
        1,
        "the in-place decrypt's witness ciphertext copy must be wiped with the rest"
    );
}

/// Every `scrub_stack` call site must survive.
///
/// `scrub_stack` overwrites the derivation frames that the wipes cannot name. It is
/// best-effort and has no behavioural signature, so nothing else notices if a call is
/// dropped — and dropping one leaves key material in the region it exists to clear.
/// Six sites: the two `ultra` encrypt-side rejection returns, the two success returns
/// (`encrypt`, `encrypt_in_place_detached`), and the two decrypt entry points.
#[test]
fn scrub_stack_is_called_at_every_entry_point() {
    // Comments stripped, so the injection that kept this test green — replacing a real call
    // with `// scrub_stack(); (planted)` — now reads as a *missing* call site.
    let body = non_test_source();

    /// The body of `needle`, brace-matched.
    fn body_of<'a>(src: &'a str, needle: &str) -> &'a str {
        let start = src.find(needle).unwrap_or_else(|| panic!("no {needle}"));
        assert_eq!(
            src.matches(needle).count(),
            1,
            "{needle} must appear exactly once in the non-test source"
        );
        let after = &src[start..];
        let open = after.find('{').expect("body");
        let mut depth = 0usize;
        for (n, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &after[..=open + n];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in {needle}");
    }

    // Per function, not a whole-file count: a total is unbound to position, so a call
    // moved into a helper nobody calls would keep it at six. The expected sites are
    // three in `encrypt` (the two witness-refusal returns and the success return), one
    // in `encrypt_in_place_detached` (its only encrypt-side call -- the in-place path
    // deliberately has no witness cross-check), and one in each decrypt entry point.
    let mut total = 0;
    for (name, expected) in [
        ("pub fn encrypt(", 3),
        ("pub fn encrypt_in_place_detached(", 1),
        ("pub fn decrypt(", 1),
        ("pub fn decrypt_in_place_detached(", 1),
    ] {
        let found = body_of(&body, name).matches("scrub_stack();").count();
        assert_eq!(
            found, expected,
            "{name} must contain {expected} `scrub_stack();` call sites, found {found}: a \
             dropped one leaves key material in the region it exists to clear"
        );
        total += found;
    }
    assert_eq!(total, 6, "all six scrub_stack call sites must remain");
}

/// Which entry points the witness is actually called from — all of them except one.
///
/// This exists because the documentation claimed more than the code did, and the claim was
/// believed for as long as nobody measured. The README said the witness cross-checks "on every
/// encrypt"; in fact `encrypt_in_place_detached` has no encrypt-side cross-check, only the
/// allocating `encrypt` does. It surfaced from the *benchmark*, not from reading: `ultra`'s
/// in-place encryption measured the same as the default configuration at 1 MiB while its
/// decryption measured 11.5x slower, which is only possible if the encrypt path is not
/// re-hashing the message with the scalar witness.
///
/// The asymmetry is deliberate (a fault on the encrypt side costs availability, not
/// authenticity, and the check is a full per-byte re-hash on the API a caller picks for speed),
/// so the fix was to state it and to pin it here. Both directions fail: a new witness call in
/// the in-place path means the cost warning in the README is stale, and a removed call in any of
/// the three covered entry points means a defence disappeared from a path the README promises.
#[test]
fn the_witness_is_called_from_exactly_these_entry_points() {
    // Comments stripped: the positive half of this test used to be satisfiable by *prose* —
    // the doc comment on `decrypt` names `witness::decrypt`, so deleting the real call left
    // the assertion true. That is the same guard-satisfied-by-a-comment shape the audit
    // demonstrated on `scrub_stack`.
    let body = non_test_source();

    /// The body of `needle`, brace-matched; panics if it is not found exactly once.
    fn body_of<'a>(src: &'a str, needle: &str) -> &'a str {
        let start = src.find(needle).unwrap_or_else(|| panic!("no {needle}"));
        assert_eq!(
            src.matches(needle).count(),
            1,
            "{needle} must appear once in the non-test source"
        );
        let after = &src[start..];
        let open = after.find('{').expect("body");
        let mut depth = 0usize;
        for (n, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &after[..=open + n];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in {needle}");
    }

    for entry in [
        "pub fn decrypt(",
        "pub fn decrypt_bounded(",
        "pub fn decrypt_in_place_detached(",
        "pub fn encrypt(",
    ] {
        // `body_of` reads the already comment-free `non_test_source`, so the doc comment on
        // `decrypt` that names `witness::decrypt` cannot stand in for the call.
        let b = body_of(&body, entry);
        // `decrypt_bounded` delegates to `decrypt`, so it carries no witness call of its own
        // and must not: a second one would mean the tag is computed twice on that path.
        if entry == "pub fn decrypt_bounded(" {
            assert!(
                !b.contains("witness::"),
                "decrypt_bounded delegates to decrypt; it must not cross-check again"
            );
            continue;
        }
        assert!(
            b.contains("witness::"),
            "{entry} must cross-check with the witness under ultra"
        );
    }

    let in_place_encrypt = body_of(&body, "pub fn encrypt_in_place_detached(");
    assert!(
        !in_place_encrypt.contains("witness::"),
        "if the in-place encrypt gains a witness cross-check, then it costs a full scalar \
         re-hash per byte (measured ~1.2 ms/MiB) -- update README's 'What the witness is' and \
         the fault table's witness row, which currently say this path does not carry it"
    );
}

/// Whether `XSIV_ALLOW_UNLOCKED` *affirmatively* says this host knowingly runs a
/// `locked` build with nothing locked.
///
/// Only `1`, `true` and `yes` (case-insensitive) count. `0`, `false`, `no`, the empty
/// string and an unset variable all mean "do not allow", so a kernel refusal is then a
/// *failure* — the old `is_ok()` parse made `XSIV_ALLOW_UNLOCKED=0` and an empty value
/// behave exactly like `=1`, i.e. the "refuse" setting could not be requested at all. A
/// value that is neither affirmative nor one of those recognisable denials is printed and
/// then treated as "do not allow": refusing to reinterpret a typo silently is the same
/// rule the `SKIPPED` lines below follow — a skip or an override must be recorded, never
/// inferred.
fn allow_unlocked() -> bool {
    match std::env::var("XSIV_ALLOW_UNLOCKED") {
        Ok(v)
            if ["1", "true", "yes"]
                .iter()
                .any(|a| v.eq_ignore_ascii_case(a)) =>
        {
            true
        }
        Ok(v)
            if ["0", "false", "no", ""]
                .iter()
                .any(|n| v.eq_ignore_ascii_case(n)) =>
        {
            false
        }
        Ok(v) => {
            eprintln!(
                "NOTE: XSIV_ALLOW_UNLOCKED={v:?} is neither an affirmative value \
                 (1/true/yes) nor a recognised denial (0/false/no/empty), so it is treated \
                 as *not* allowing an unlocked `locked` build: a kernel refusal will fail \
                 the tests that meet it."
            );
            false
        }
        Err(_) => false,
    }
}

/// A locking key is really locked, read back from the kernel.
///
/// The syscall numbers in `locked` are `const`s, and a wrong one would not be caught by
/// anything else: `mlock` with the wrong number either fails or does something else
/// entirely. The check that cannot be fooled is the kernel's own accounting — `VmLck`
/// must go up by at least the key's length while the lock is held — so that is what this
/// asserts. It is skipped (loudly) where locking is unsupported or the environment
/// refuses, rather than passing vacuously.
#[test]
fn locked_key_is_actually_locked() {
    use xchacha20_blake3_siv::locked::{unlock_range, LockedKey, SUPPORTED};

    // Returning early when the environment refuses to lock is indistinguishable,
    // in a test report, from having verified the lock: both say `ok`. That is the
    // vacuous shape this test exists to prevent, so a refusal is a *failure* by
    // default. `XSIV_ALLOW_UNLOCKED=1` is the explicit, recorded way to say "this
    // host cannot lock and that is not a regression" -- and setting it is a
    // decision that `ultra`'s `locked` layer is knowingly inactive here.
    let allow_unlocked = allow_unlocked();

    if !SUPPORTED {
        // `SUPPORTED == false` is a compile-time property of the target, not a failure: the
        // syscalls are wired for Linux x86_64/aarch64 only, the README says so, and
        // `cargo test --features ultra` on i686 would otherwise be red for a documented
        // platform limit. What *is* a failure is the runtime refusal below: there the target
        // should have worked and did not.
        eprintln!(
            "SKIPPED [locked_key_is_actually_locked]: memory locking is unsupported on this \
             target/architecture (`locked::SUPPORTED == false` is a compile-time property), \
             so `ultra`'s `locked` layer is inactive here (as documented). This is not a \
             pass; no environment variable can exercise it on this target."
        );
        return;
    }

    let before = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    let key = match LockedKey::new(&KEY) {
        Ok(k) => k,
        Err(e) => {
            // `ENOMEM` (12) from RLIMIT_MEMLOCK, `EPERM` (1) in a hardened container.
            assert!(
                allow_unlocked,
                "the kernel refused to lock memory (errno {}), so `ultra` promises \
                 mlock + MADV_DONTDUMP and this host is not getting it. Raise \
                 RLIMIT_MEMLOCK or grant CAP_IPC_LOCK, or set XSIV_ALLOW_UNLOCKED=1 to \
                 record that this host knowingly runs unlocked. [test: \
                 locked_key_is_actually_locked]",
                -e
            );
            // The allowed branch must be visible: a returned test reports `ok` exactly
            // like one that measured a live lock, and libtest captures this line unless
            // it is run with `--nocapture`.
            eprintln!(
                "SKIPPED [locked_key_is_actually_locked]: the kernel refused to lock memory \
                 (errno {}), so the lock was never measured. This is NOT a pass: it was \
                 reached only because XSIV_ALLOW_UNLOCKED=1 records that this host knowingly \
                 runs a `locked` build unlocked.",
                -e
            );
            return;
        }
    };
    let after = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        after >= before + 32,
        "VmLck did not account for the locked key: before {before}, after {after}. A wrong \
         syscall number or a no-op `lock_range` looks exactly like this."
    );

    // And the key still works, so the locking did not corrupt or move it.
    let (ct, tag) = encrypt(&key, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&key, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );

    // Dropping the key must unlock it. Measured *before* any manual `unlock_range`:
    // the earlier version of this test reused the pre-unlock VmLck value here, so
    // `released < held` was already implied by the live-page check below and would
    // still hold even if `Drop` never called `unlock_range` at all.
    let held = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    drop(key);
    let released = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        released < held,
        "dropping a `LockedKey` must unlock it: VmLck stayed at {released} (held {held})"
    );

    // Separately, the lock must be on the *live* key's page, not on an address the
    // value was moved away from. `mlock` is address-based, and a `LockedKey` returned by
    // value moves its 32 bytes -- so an earlier version locked a stack slot in
    // `new` and left the returned copy on an unlocked page, while VmLck (and the
    // assertion above) still looked right. Unlocking the live key's own page must
    // show up in the kernel's accounting; if it does not, the locked page is
    // somewhere else and the protection is not on the key.
    let key = match LockedKey::new(&KEY) {
        Ok(k) => k,
        Err(e) => {
            assert!(
                allow_unlocked,
                "the kernel refused the second lock (errno {}), so the live-page half of this \
                 test cannot run on this host. Raise RLIMIT_MEMLOCK or grant CAP_IPC_LOCK, or \
                 set XSIV_ALLOW_UNLOCKED=1 to record that this host knowingly runs unlocked. \
                 [test: locked_key_is_actually_locked]",
                -e
            );
            eprintln!(
                "SKIPPED [locked_key_is_actually_locked]: the kernel refused the second lock \
                 (errno {}), so the live-page half (the lock must be on the page the key is \
                 on) was not measured. This is NOT a pass: it was reached only because \
                 XSIV_ALLOW_UNLOCKED=1 records that this host knowingly runs a `locked` build \
                 unlocked.",
                -e
            );
            return;
        }
    };
    let held = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    unlock_range(key.as_bytes().as_ptr(), 32);
    let after_unlocking_live = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        after_unlocking_live < held,
        "unlocking the live key's page did not change VmLck ({held} -> {after_unlocking_live}), \
         so the page that was locked is not the page the key is on: the value was moved \
         after being locked. The key must be heap-allocated (`Box`) so its address is stable."
    );
    // The live key still answers after its page was unlocked, so the address-level
    // check did not pass by corrupting or moving it.
    let (ct, tag) = encrypt(&key, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&key, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );
}

/// The doc must state the limits, because the limits are the part a user needs.
///
/// This is a documentation assertion, which is unusual, and it is here because `ultra`
/// invites exactly the wrong reading: "everything is on, so I am safe". A debugger
/// attached to the process, a hypervisor, cold-boot remanence and a two-glitch bench are
/// all outside what any of this can do, and each one must be named where someone turning
/// the feature on will read it.
#[test]
fn documents_what_it_cannot_defend_against() {
    // Deliberately raw, and the one assertion in this file not routed through
    // `non_test_source`: its subject *is* prose. Stripping comments from `lib` would remove
    // every doc comment this test looks for and leave a README check alone, i.e. it would
    // destroy the evidence rather than harden the check. The other assertions strip
    // comments because there the words must be a statement.
    let readme = include_str!("../README.md");
    let lib = include_str!("../src/lib.rs");

    for (name, limit) in [
        ("memory-remanence", "cold boot"),
        ("core-dump scope", "core dump"),
        ("debugger", "debugger"),
        ("two-fault attack", "Two independent faults"),
        (
            "directed injection",
            "targeted fault inside the tag computation",
        ),
        ("deterministic encryption", "Deterministic encryption"),
        ("length disclosure", "Length is revealed"),
    ] {
        assert!(
            readme.contains(limit) || lib.contains(limit),
            "`ultra` claims to enable every defence; the limit `{name}` (`{limit}`) is not \
             written down anywhere a user would look, which makes the claim misleading."
        );
    }
}

/// A smoke test of the assembled `ultra` build: a round trip, a tampered-tag rejection,
/// and `rng` key/nonce generation.
///
/// It replaces a test that asserted `src/lib.rs` contains the strings
/// `#[cfg(feature = "hardened")]` and `pub mod locked` -- true in every build, so it
/// passed whether or not the layers were compiled. The name says what the body does
/// rather than "every layer answers correctly", because a per-layer *answer* is not
/// behaviourally observable from a `cargo test` target here: `dual-mac`'s recomputation,
/// the witness agreement and the derived-value wipes are pinned by
/// `dual_mac_is_wired_into_both_decrypt_paths` (and the gate's answer by
/// `the_decision_still_answers_correctly_with_every_layer_on`), `locked`'s kernel
/// behaviour by `locked_key_is_actually_locked`, and the feature bundle at compile time
/// by the `const _` assertion at the top of this file.
#[test]
fn ultra_still_round_trips_rejects_a_forgery_and_generates_keys() {
    // The body is deliberately this narrow; the doc above says where each layer's own
    // answer is checked.
    let (ct, tag) = encrypt(&KEY, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );
    let mut bad = tag;
    bad[0] ^= 1;
    assert!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &bad).is_err(),
        "a tampered tag must be rejected with every layer on"
    );

    // `locked::SUPPORTED` is a `const bool`, so asserting on it is an assertion on a
    // constant (clippy rejects it, and it would be a compile-time fact anyway). That
    // the locking module is usable is asserted where it is observable:
    // `locked_key_is_actually_locked`, which now fails -- rather than skipping when
    // the kernel refuses -- and checks the lock is on the live key's page.

    // `rng`: generating a key works here (this is the one feature `ultra` adds that
    // changes nothing about the cipher, and it is worth one assertion that it is live).
    let key = xchacha20_blake3_siv::random::generate_key().expect("OS entropy");
    let nonce = xchacha20_blake3_siv::random::generate_nonce().expect("OS entropy");
    let (ct, tag) = encrypt(&key, &nonce, b"", b"under ultra").unwrap();
    assert_eq!(
        decrypt(&key, &nonce, b"", &ct, &tag).unwrap(),
        b"under ultra"
    );
}

/// The decision is still fail-closed with every layer on, and still refuses a forgery.
///
/// `ultra` adds work *inside* the decision; this is the check that the addition did not
/// change its answer for an honest input or a forged one — including on the in-place path,
/// which has its own copy of the wiring.
#[test]
fn the_decision_still_answers_correctly_with_every_layer_on() {
    let pt: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let (ct, tag) = encrypt(&KEY, &NONCE, b"aad", &pt).unwrap();

    let mut bad = tag;
    bad[0] ^= 1;
    assert_eq!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &bad).unwrap_err(),
        Error::AuthenticationFailed
    );
    let mut buf = ct.clone();
    assert_eq!(
        decrypt_in_place_detached(&KEY, &NONCE, b"aad", &mut buf, &bad),
        Err(Error::AuthenticationFailed)
    );
    assert!(buf.iter().all(|&b| b == 0), "failure must wipe the buffer");

    // The honest pair still round-trips, so the refusals above are the forgery.
    assert_eq!(decrypt(&KEY, &NONCE, b"aad", &ct, &tag).unwrap(), pt);
    let mut buf = ct.clone();
    decrypt_in_place_detached(&KEY, &NONCE, b"aad", &mut buf, &tag).unwrap();
    assert_eq!(buf, pt);
}

/// The witness must be a *separate implementation* — and that is checked, not promised.
///
/// `ultra`'s value is that the second answer comes from code sharing nothing with the
/// first: not `derive_tag`, not the SIMD kernels, and not the `blake3` or `subtle`
/// dependencies either, because a fault in `blake3`'s compression kernel would move both
/// answers if the witness hashed through the same crate. What the two *must* share is the
/// specification — the domain strings, the nonce and tag widths — since those are the
/// construction rather than an implementation of it.
///
/// This is a source-shape test for the reason the others in this file are: a
/// "simplification" that reached for `crate::zeroize_slice`, or hashed with
/// `blake3::Hasher`, would leave every behavioural test passing. The witness would still
/// agree with the crate — it would simply have stopped being a second implementation, and
/// the fault model `ultra` exists for would quietly be single-implementation again.
#[test]
fn the_witness_shares_only_the_specification_with_the_crate() {
    let src = include_str!("../src/witness.rs");
    // Comments stripped by the same scanner as `non_test_source`, so a mention in prose
    // neither trips the check nor hides a use, and a `//` inside a string literal cannot
    // cut a line short. The cut is the brace-matched body of the witness's test module,
    // not the text before its first line: a `crate::` use appended after that module
    // would otherwise be invisible to the assertions below.
    let code = non_test_source_of(src);

    // The one permitted import: the specification's constants.
    let allowed = "use crate::{DOM_ENC, DOM_PRE, DOM_TAG, NONCE_LEN, SUBKEY_DOMAIN, TAG_LEN};";
    assert!(
        code.contains(allowed),
        "the witness must import the specification's constants explicitly, and nothing \
         else; expected to find:\n  {allowed}"
    );
    let without_imports = code.replace(allowed, "");
    // `crate::` is one spelling of "the crate's own code", and not the only one: `super::`
    // reaches it from inside this child module, the crate's own name resolves from inside
    // it too, and `use crate as other_name;` renames it without ever writing `crate::`. An
    // injected `super::blake3_keyed_multi(key, parts, out)` in the witness's `keyed_xof` --
    // the crate's own hash call, the exact shared code the fault model assumes away -- left
    // this test green while the witness stopped being a second implementation. So the
    // check is over every spelling, after the one permitted import is removed.
    for escape in ["crate", "super::", "xchacha20_blake3_siv"] {
        assert!(
            !without_imports.contains(escape),
            "the witness uses `{escape}`, which reaches the crate's own code (`crate::`, \
             `super::` from a child module, the crate name, `use crate as ...`), so it is no \
             longer a second implementation (the fault model it exists for assumes it shares \
             no *code* with the crate): {}",
            without_imports
                .lines()
                .filter(|l| l.contains(escape))
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }

    // And no use of the crate's dependencies: those are the shared code that a fault
    // could move both answers with.
    for dep in [
        "blake3::",
        "subtle::",
        "zeroize::",
        "getrandom::",
        "use blake3",
        "use subtle",
    ] {
        assert!(
            !without_imports.contains(dep),
            "the witness borrows `{dep}`, which the crate's own path also uses: a fault in \
             that shared code would move both answers, which is the one thing the second \
             implementation is there to prevent"
        );
    }

    // A sanity floor: the file must actually contain an implementation of each primitive,
    // so a future refactor cannot satisfy the assertions above by deleting the module.
    for f in [
        "fn hchacha20(",
        "fn block(",
        "fn compress(",
        "pub fn decrypt(",
        "pub fn encrypt_tag(",
    ] {
        assert!(
            code.contains(f),
            "the witness no longer defines `{f}` — these assertions would pass on an empty module"
        );
    }
}
