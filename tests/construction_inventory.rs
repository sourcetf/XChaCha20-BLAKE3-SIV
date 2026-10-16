//! The construction's primitive uses, inventoried — and the separations between them.
//!
//! `SECURITY-ANALYSIS.md` §4.10 answers "does combining ChaCha20, HChaCha20 and BLAKE3 in
//! *this* way introduce a problem none of them has alone?" with a case analysis over the
//! seven uses of the primitives and the values that flow between them. The part of that
//! argument which rots silently is its *completeness*: an eighth use (a new hash, a second
//! keystream, a re-derivation somewhere) would need the whole case analysis redone, and
//! nothing else in the suite would notice — an eighth use of a correct primitive still passes
//! every behavioural test.
//!
//! The inventory therefore also counts the one cryptographic call that is *not* part of that
//! composition — the unkeyed BLAKE3 hash behind `locked`'s key-integrity tag, which §4.10
//! argues separately — so that adding or moving *that* call is caught here too. What the count
//! pins is "the set of primitive call sites has not changed", not "these are all construction
//! uses".
//!
//! So the completeness claim is pinned here, the way `tests/variable_latency.rs` pins its
//! inventories: a change fails this file until somebody updates the analysis. The *value*
//! level half of the argument — that the two ChaCha20 uses really are at different points —
//! lives in the crate's unit tests (`mod tests`), because only those can reach the internal
//! derivation.

use xchacha20_blake3_siv::{DOM_ENC, DOM_PRE, DOM_TAG, SUBKEY_DOMAIN};

/// The non-test source of `src/lib.rs`: everything outside the body of its
/// `#[cfg(test)] mod tests` module, wherever that module sits in the file.
///
/// Every presence and count assertion in this file runs on this rather than on the raw
/// text. `include_str!` text makes a `contains`/`count` satisfiable without the code: a use
/// replaced by a comment carrying the same call, or by a dead string literal, kept its
/// count — an audit moved `head[0..8].copy_from_slice(&DOM_PRE);` behind a block comment
/// (with an equivalent `head[..8]` spelling) and all three tests here stayed green.
/// `libtest` cannot share items between test binaries, so the scanner is copied from
/// `tests/decision_scope.rs`, `tests/counter_range.rs`, `tests/ultra.rs` and
/// `tests/locked.rs` rather than imported.
///
/// The obvious way to get this — truncate at the first `mod tests {` — hides code that
/// is textually *after* the module, because the cut is at the module's first line, not
/// at its closing brace: a production function appended below the test module (legal
/// Rust, compiled in normal builds) is skipped entirely. Measured: a helper calling
/// `chacha20_keystream`, appended after the test module, left this file's suite green,
/// though `the_primitive_uses_are_the_ones_the_analysis_covers` counts exactly those
/// call sites. It also hid a `mod tests {` *mentioned in a comment* before the real
/// one, since the old `find` ran on the raw text; stripping comments and literals first
/// removes that.
///
/// This finds the module on the stripped text, requires it to carry `#[cfg(test)]`,
/// brace-matches its body (braces inside comments and string literals are already gone,
/// so they cannot unbalance the count), and removes exactly the body — blanking those
/// lines rather than deleting them, so line numbers in the scans' failure messages keep
/// pointing at the source. Everything else, before *and* after the module, is what the
/// scans read.
fn non_test_source() -> String {
    let src = include_str!("../src/lib.rs");
    let stripped = strip_comments(src);
    let at = stripped
        .find("mod tests {")
        .expect("the test module must exist (`mod tests {`)");
    assert_eq!(
        stripped.matches("mod tests {").count(),
        1,
        "src/lib.rs holds more than one `mod tests {{`: which one is the test module, and \
         what the scan cut, would be ambiguous"
    );
    assert!(
        stripped[..at].trim_end().ends_with("#[cfg(test)]"),
        "the scanned `mod tests {{` is not `#[cfg(test)]`: it is production code being \
         mistaken for the test module, so the scan would skip it"
    );
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
    out.push_str(&stripped[..at]);
    for _ in 0..stripped[at..=close].matches('\n').count() {
        out.push('\n');
    }
    out.push_str(&stripped[close + 1..]);
    out
}

/// See [`non_test_source`]: comments and string-literal contents are removed, with newlines
/// kept so line positions stay comparable.
///
/// A small state machine rather than `find("//")`, because a `//` inside a string literal
/// used to cut the rest of the line out of the scan — which hid a real call site from a
/// count — and a `/* … */` block was scanned as code. Literal contents are dropped (the
/// quotes remain, so a literal becomes `""`), so a *string* carrying the text cannot stand
/// in for a statement either.
fn strip_comments(text: &str) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Code,
        Line,
        /// Inside a block comment, with its **nesting depth**: Rust block comments
        /// nest, and a scanner that exits at the first `*/` reads the rest of the
        /// comment as code and can then be pushed into `Str` by a quote inside it,
        /// which *hides real code that follows*. Measured before this depth was
        /// tracked: `/* /* */ " */ fn f() { blake3_keyed_xof(…); } /* " */` added an
        /// eighth primitive use that this file's census could not see.
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

/// The cryptographic calls in the non-test source, with how many call sites each has.
///
/// These are the seven uses of §4.10, plus the one call outside the construction:
///
/// * `hchacha20` — U1, the subkey;
/// * `chacha20_keystream_raw` — U2, the two key-material blocks (counters 0 and 1): the
///   tag keys and the encryption seed;
/// * `blake3_keyed_multi` — U3a (the inner tag hash), U3b (the outer tag hash) and U4
///   (the per-message key, through `blake3_keyed_xof`); U3a has one call site per
///   concatenation shape *plus* the refusal fallback (all three hash the same bytes), which
///   is why this name has five sites for three uses;
/// * `chacha20_keystream` and `chacha20_apply` — U5, the data keystream, in the allocating
///   and in-place entry points;
/// * `blake3::Hasher::new` (unkeyed) — *not* a construction use: the hash behind `locked`'s
///   key-integrity tag (§4.10, "the one call outside the construction"). Counted here so a
///   change to it fails this test too, not because it is part of the composition. (It was
///   `blake3::hash` until the state-wipe fix; the explicit hasher is used so its state can be
///   zeroized, and `blake3::Hasher::new_keyed` does not match this pattern.)
///
/// A count that changes is not automatically a defect. It is a signal that §4.10's table, the
/// assumption tree in §2.1, and the L1 reductions it cites have to be re-checked for the new
/// use — which is what the failure message asks for.
const PRIMITIVE_CALLS: &[(&str, usize)] = &[
    ("hchacha20(", 1),
    ("chacha20_keystream_raw(", 2),
    ("blake3_keyed_xof(", 1),
    ("blake3_keyed_multi(", 5),
    ("chacha20_keystream(", 2),
    ("chacha20_apply(", 4),
    ("blake3::Hasher::new(", 1),
    // The single keyed-BLAKE3 seam. Counted separately because it is the *only* place that
    // may construct a keyed hasher: an audit added a second direct `new_keyed` use in the
    // non-test source and this inventory never noticed, because the name was not on the
    // list. (It does not collide with `blake3::Hasher::new(` above: after `new` comes `_`,
    // not `(`.)
    ("blake3::Hasher::new_keyed(", 1),
];

#[test]
fn the_primitive_uses_are_the_ones_the_analysis_covers() {
    // Comments and string-literal contents stripped: a use replaced by a comment (or by a
    // dead literal) carrying the same call must not keep its count.
    let body = non_test_source();

    let mut report = String::new();
    for (call, expected) in PRIMITIVE_CALLS {
        // Occurrences, not lines: a second call added to a line that already carried one
        // left the old count when this counted lines. The definition line is still
        // skipped -- it contains the name without being a call -- but only the
        // definition *of the searched name*, matched by the name that follows the
        // `fn `/`pub fn `/`unsafe fn `/`pub(crate) fn ` prefix. The old rule skipped
        // every line starting with `fn `, so a call written on a one-line definition
        // (`pub fn f(k: &[u8; 32], o: &mut [u8]) { blake3_keyed_xof(k, &[], o); }`)
        // was invisible: measured, the eighth primitive use this census exists to
        // catch stayed green.
        let bare = call.trim_end_matches('(');
        let found: usize = body
            .lines()
            .filter(|l| {
                let code = l.trim_start();
                !["fn ", "pub fn ", "unsafe fn ", "pub(crate) fn "]
                    .iter()
                    .filter_map(|prefix| code.strip_prefix(prefix))
                    .any(|rest| rest.starts_with(bare))
            })
            .map(|l| l.matches(call).count())
            .sum();
        report.push_str(&format!(
            "      {call:<28} {found} (analysis says {expected})\n"
        ));
        assert_eq!(
            found, *expected,
            "the number of call sites of `{call}` changed:\n{report}\n\
             SECURITY-ANALYSIS.md §4.10 proves the composition safe with a *complete* case \
             analysis over the uses of the primitives. A new (or removed) use means that \
             analysis, the assumption tree in §2.1 and the L1.3 reductions it cites have to be \
             re-checked before this count is updated."
        );
    }

    // The table is pinned by two equalities, not a floor. `>= 15` let a single-count row
    // be deleted silently: the row's own `assert_eq!` then never ran, and the remaining
    // rows still cleared the floor (the counts sum to 17 today, so even a two-count row
    // could go without crossing it). Removing any row now fails here, and updating these
    // numbers is the deliberate act the failure message asks for.
    let names: Vec<&str> = PRIMITIVE_CALLS.iter().map(|(name, _)| *name).collect();
    let total: usize = PRIMITIVE_CALLS.iter().map(|(_, n)| n).sum();
    assert_eq!(
        PRIMITIVE_CALLS.len(),
        8,
        "the inventory has {} rows, not the recorded 8: {names:?}",
        PRIMITIVE_CALLS.len()
    );
    assert_eq!(
        total, 17,
        "the inventory's counts sum to {total}, not the recorded 17: {names:?}"
    );
}

/// **Every counted primitive must be called, never taken as a value.**
///
/// The census above counts literal `name(` text. Obtaining the same call through a
/// function pointer preserves the original site's literal count while adding a live call
/// the census cannot see: `let f: fn(&[u8; 32], &[&[u8]], &mut [u8]) = blake3_keyed_multi;
/// f(k, parts, out);` adds an eighth use with every count unchanged (measured: the whole
/// `--features ultra` suite stayed green). `tests/counter_range.rs` rejects a `use ... as`
/// alias of a scanned name, but not `= name`, `name as fn(...)`, `&name`, or `name` passed
/// as an argument -- all of which leave the name followed by something other than `(`.
///
/// This test requires the converse for every occurrence of every counted name in the
/// non-test source: the next character is `(` -- i.e. the occurrence is a call, or a `fn`
/// definition, which is the one position the census itself already skips. Calling one of
/// these through a binding requires writing the name in some non-call position, so no
/// function-pointer call of a counted primitive can be added while this test holds.
///
/// **What this cannot close, and does not claim to:** the identifier can be *assembled*
/// rather than written (`concat_idents!`/`paste!`-style splicing, a macro that builds it),
/// or the code can come from outside this file (`include!`, a build script, a new
/// submodule -- the census reads `src/lib.rs` outside the body of its `#[cfg(test)]
/// mod tests` module and nothing else). A
/// nested `fn name(...)` that shadows the real item is textually a definition like the
/// real one, so this test cannot tell the two apart either. It closes the textual half of
/// the class -- value-taking through a written name -- and states that scope instead of
/// claiming the census now has no evasion surface.
#[test]
fn the_counted_primitives_are_never_taken_as_values() {
    let body = non_test_source();
    for (call, _) in PRIMITIVE_CALLS {
        let name = call.trim_end_matches('(');
        let path = name.contains("::");
        let mut from = 0usize;
        while let Some(rel) = body[from..].find(name) {
            let start = from + rel;
            let end = start + name.len();
            from = end;
            let after = &body[end..];
            if path {
                // `blake3::Hasher::new` is a prefix of the separately-counted
                // `blake3::Hasher::new_keyed` row; that occurrence is the longer name's.
                if after.starts_with("_keyed(") {
                    continue;
                }
            } else {
                let before = body[..start].chars().next_back();
                let next = after.chars().next();
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    || next.is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    // A substring of a longer identifier: `chacha20_keystream` inside
                    // `chacha20_keystream_raw` is not an occurrence of the shorter name.
                    continue;
                }
            }
            let line = body[..start].matches('\n').count() + 1;
            let source_line = body.split('\n').nth(line - 1).unwrap_or("").trim();
            assert!(
                after.starts_with('('),
                "`{name}` is referred to as a value, not called, at line {line} of the \
                 non-test source:\n    {source_line}\n\
                 A function pointer preserves this name's literal `{call}` count while \
                 adding a call the census above cannot see (measured: \
                 `let f: fn(&[u8; 32], &[&[u8]], &mut [u8]) = blake3_keyed_multi; \
                 f(k, parts, out);` left the whole `--features ultra` suite green with all \
                 counts unchanged), and `tests/counter_range.rs` rejects only `use ... as` \
                 aliases, not value-taking. Every reference to a counted primitive must be \
                 written as `{call}`"
            );
        }
    }
}

/// **Where the derivation blocks are consumed.** The census above counts the two
/// `chacha20_keystream_raw` calls but cannot see what their output is *used* for: an audit
/// changed `k_in.copy_from_slice(&block0[0..32]);` to read `block1` -- the wrong tag key, a real
/// KDF change -- and this file stayed green (the sibling differential and KAT tests caught it).
/// These three lines are the consumption half of U2 in §4.10's case analysis: counter 0's block
/// splits into the two tag keys, counter 1's block seeds the encryption key.
#[test]
fn the_derivation_slices_are_the_analyzed_ones() {
    let body = non_test_source();
    for (site, what) in [
        (
            "k_in.copy_from_slice(&block0[0..32]);",
            "the inner tag key must be the first half of counter 0's block",
        ),
        (
            "k_out.copy_from_slice(&block0[32..64]);",
            "the outer tag key must be the second half of counter 0's block",
        ),
        (
            "enc_seed.copy_from_slice(&block1[0..32]);",
            "the encryption seed must be the first half of counter 1's block",
        ),
    ] {
        assert_eq!(
            body.matches(site).count(),
            1,
            "the derivation slice `{site}` must be written exactly once ({what}); a \
             `block0`/`block1` or offset change here is a different key schedule, and \
             §4.10's case analysis plus the KAT values have to be re-checked"
        );
    }
}

/// **Lemma S1**: the three keyed-BLAKE3 families have disjoint input spaces.
///
/// The inner tag hash is computed over `DOM_PRE ‖ …`, the outer over `DOM_TAG ‖ X`, and the
/// per-message key over `DOM_ENC ‖ T`. For one byte string to be an input to two of them, it
/// would have to start with two different 8-byte prefixes. That is what separates the uses
/// *structurally* — i.e. even in the impossible case two of the keys coincide, where a merely
/// key-based separation would collapse.
#[test]
fn the_three_blake3_input_spaces_are_disjoint() {
    for (a, b) in [(DOM_PRE, DOM_TAG), (DOM_PRE, DOM_ENC), (DOM_TAG, DOM_ENC)] {
        assert_ne!(
            a, b,
            "two of the three BLAKE3 domains are the same string, so those two uses are \
             separated by nothing but their keys"
        );
    }
    assert_eq!(
        (DOM_PRE.len(), DOM_TAG.len(), DOM_ENC.len()),
        (8, 8, 8),
        "the prefixes must be the same width: the separation is then a byte comparison at a \
         fixed offset, which is what a reader can check by hand (a variable-length domain \
         would reintroduce exactly the ambiguity the length fields in `derive_tag` exist to \
         prevent)"
    );

    // Distinct constants are not enough: each must be written at the *right* place, or the
    // "disjoint input spaces" lemma says nothing about the bytes actually hashed. (A swap of
    // the two tag-hash prefixes is also caught by `test_tag_matches_blake3_over_the_documented_input`,
    // but pinning it here keeps this lemma self-contained rather than resting on another test.)
    //
    // Comments and literal contents stripped by `non_test_source`: a block comment carrying
    // `head[0..8].copy_from_slice(&DOM_PRE);` (behind an equivalent `head[..8]` spelling)
    // used to satisfy this.
    let body = non_test_source();
    for (site, what) in [
        (
            "head[0..8].copy_from_slice(&DOM_PRE);",
            "the inner tag hash",
        ),
        (
            "outer[0..8].copy_from_slice(&DOM_TAG);",
            "the outer tag hash",
        ),
        (
            "input[0..8].copy_from_slice(&DOM_ENC);",
            "the key derivation",
        ),
    ] {
        assert!(
            body.contains(site),
            "the domain prefix is not written where S1 needs it ({what}): {site}"
        );
    }

    // Writing the prefix is not *hashing* it: the inner hash is fed `head` either as
    // one part of the three-part call or through the contiguous buffer, and the outer
    // hash is fed `outer`. A mutant that dropped one of those -- measured with
    // `blake3_keyed_multi(k_in, &[&cat], &mut inner)` rewritten to `&[aad, msg]`, which
    // removes the prefix, the nonce and both length fields from every mid-sized
    // message's tag input -- left every assertion above, and the whole census, green.
    // These four lines are the consumption half of S1; a new call shape has to be
    // written down here before the lemma is complete again.
    for (site, expected, what) in [
        (
            "blake3_keyed_multi(k_in, &[&head, aad, msg], &mut inner)",
            2,
            "the three-part inner hash must absorb `head`, the domain-prefixed buffer \
             (once per call shape: the fallback and the `None` arm, whose lines end in \
             `;` and `,` respectively, which is why the pin stops before the `,`)",
        ),
        (
            "blake3_keyed_multi(k_in, &[&cat], &mut inner)",
            1,
            "the contiguous inner hash must absorb `cat`, the domain-prefixed copy",
        ),
        (
            "cat.extend_from_slice(&head);",
            1,
            "`cat` must begin with the domain-prefixed `head`",
        ),
        (
            "blake3_keyed_multi(k_out, &[&outer], &mut tag)",
            1,
            "the outer hash must absorb `outer`, the domain-prefixed buffer",
        ),
    ] {
        assert_eq!(
            body.matches(site).count(),
            expected,
            "the bytes S1 depends on are no longer fed to the hash ({what}): {site}"
        );
    }
}

/// **Lemma S2**, the part that is visible from outside the crate: the label sits exactly where
/// XChaCha20 leaves NUL padding, and it is not NUL.
///
/// Both schemes call `HChaCha20(K, N[0..16])` and then continue with a 12-byte nonce. The
/// draft's schemes (XChaCha20, XChaCha20-Poly1305) fill the first four bytes of that nonce with
/// zeros; this crate puts `SUBKEY_DOMAIN` there. The two nonces therefore differ in a fixed
/// byte for every input, which makes the two keystreams evaluations at *different points of
/// ChaCha20's domain* rather than a coincidence that merely has not happened yet — a structural
/// separation rather than a probabilistic one. (The unit test of the same name checks the
/// blocks themselves, using the internal derivation the crate does not export.)
#[test]
fn the_derivation_nonce_does_not_use_xchacha20s_nul_padding() {
    assert_eq!(
        SUBKEY_DOMAIN.len(),
        4,
        "the label must occupy exactly the four bytes the draft's schemes leave as padding"
    );
    assert_ne!(
        SUBKEY_DOMAIN, [0u8; 4],
        "the label is four NUL bytes, which is precisely what XChaCha20 and \
         XChaCha20-Poly1305 put there: for one (K, N) this crate would then derive the same \
         per-message key material as those schemes, and a protocol mixing them would reuse \
         keys across them"
    );
    // And the placement is in the *nonce*, not the counter: a label in the counter slot would
    // not separate this scheme from XChaCha20-Poly1305, which leaves the counter at 0.
    //
    // The test module's body is removed before searching -- brace-matched to its closing
    // brace, not cut at its first line, so production code appended below the module is
    // searched too. The searched string occurs in this file's *own* test module (the
    // nonce-reuse unit test writes the same line), so searching the whole file made the
    // assertion true even with the real write at `derive_material` deleted — a guard
    // satisfied by the test that was supposed to need it. The sibling test above already
    // read the non-test source; this one did not.
    //
    // And it now reads `non_test_source`: cutting alone left the assertions satisfiable by a
    // block comment or a dead string literal carrying the same line, which is the same
    // guard-satisfied-by-a-comment shape one level down.
    let body = non_test_source();
    assert!(
        body.contains("subkey_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);"),
        "the label is no longer written into the nonce's first four bytes"
    );
    assert!(
        body.contains("chacha20_keystream_raw(&subkey, 0, &subkey_nonce, &mut block0);"),
        "the tag-key block no longer uses counter 0 with that nonce"
    );
    assert!(
        body.contains("chacha20_keystream_raw(&subkey, 1, &subkey_nonce, &mut block1);"),
        "the encryption-seed block no longer uses counter 1 with that nonce"
    );
    // Both halves of the XChaCha20-style derivation the S2 prose depends on: the subkey
    // comes from `nonce[0..16]`, and the continuation nonce's second half from
    // `nonce[16..24]`. Without these the test held for a `nonce[8..24]` subkey input
    // (which would evaluate ChaCha20 at the same domain point XChaCha20-Poly1305 uses)
    // and for a stale second half, while its four other assertions stayed green.
    assert!(
        body.contains("let mut subkey = hchacha20(key, &nonce[0..16].try_into().unwrap());"),
        "the subkey must come from `HChaCha20(key, nonce[0..16])` -- that input slice is \
         what the different-ChaCha20-domain-point argument is about"
    );
    assert!(
        body.contains("subkey_nonce[4..12].copy_from_slice(&nonce[16..24]);"),
        "the continuation nonce's second half must come from `nonce[16..24]`"
    );
}
