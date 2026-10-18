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

/// The non-test source of `LIB`: everything outside the body of its `#[cfg(test)]
/// mod tests` module, wherever that module sits in the file.
///
/// Every presence and count assertion below runs on this, not on the raw file. Both
/// of those used to be satisfiable without the code: delete a real line and add a
/// comment (or a line inside `mod tests`) carrying the same text, and the count came
/// back to its expected value. Stripping comments and stopping at the test module
/// removes that. The scanner is a small state machine rather than `find("//")`,
/// because a `//` inside a string literal used to cut a line short — which hid a real
/// call site from the count — and a `/* … */` block was scanned as code. String
/// literal contents are dropped for the same reason (an audit kept
/// `the_hardened_second_gate_is_recomputed` green by replacing the real
/// `zeroize_array(&mut computed_tag_copy);` with a dead `let _ = "…";` carrying it),
/// raw strings included — a `r#"…"#` may contain `"`, and without handling it the
/// scanner re-entered code mode at the first one and scanned the text between two
/// quotes as code — with one exception: `#[cfg(…)]` attributes are copied through,
/// because their `"feature"` payload is itself a match target and no literal can stand
/// in for an attribute; inside those attributes the brace bytes of a literal are blanked
/// ([`without_braces`]), because braces have no meaning in a legal `cfg` predicate and the
/// brace walks that run on this text must not see a payload's (`#[cfg(feature = "{")]`
/// moved the test module's cut before that).
///
/// The obvious way to get the cut — truncate at the first `mod tests {` — hides code
/// that is textually *after* the module, because the cut is at the module's first
/// line, not at its closing brace: a production function appended below the test
/// module (legal Rust, compiled in normal builds) is skipped entirely. Measured: a
/// helper calling `accept_or_reject` appended after the test module and reached
/// through `core::hint::black_box` left this file's suite green. It also hid a
/// `mod tests {` *mentioned in a comment* before the real one, since the old `find`
/// ran on the raw text; stripping comments and literals first removes that.
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
/// this function asserts no `#[cfg(test)]` survives. That invariant falls out of the
/// function's own definition — everything left is non-test source — and it closes the
/// second-module planting: a `#[cfg(test)] mod planting { … }` beside the real test module
/// with the real statement deleted kept a count here green, because the planted text lies
/// outside the one module body this cut removed.
fn non_test_source() -> String {
    let stripped = strip_comments(LIB);
    let at = stripped
        .find("mod tests {")
        .expect("the test module must exist (`mod tests {`)");
    assert_eq!(
        stripped.matches("mod tests {").count(),
        1,
        "src/lib.rs holds more than one `mod tests {{`: which one is the test module, and \
         what the scan cut, would be ambiguous"
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

/// A brace byte is structure to the walks that run on this text no matter what it is
/// nested in; every other byte is copied through. Used inside `#[cfg(…)]` literals, whose
/// contents are otherwise kept verbatim because they are match targets.
fn without_braces(byte: u8) -> char {
    if byte == b'{' || byte == b'}' {
        ' '
    } else {
        byte as char
    }
}

/// See `non_test_source`. Public to the file so each test can build it once.
fn strip_comments(text: &str) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Code,
        Line,
        /// Inside a block comment, with its **nesting depth**: Rust block comments
        /// nest, and a scanner that exits at the first `*/` reads the rest of the
        /// comment as code (a false positive) and can then be pushed into `Str` by a
        /// quote inside it, which *hides real code that follows*. Measured before this
        /// depth was tracked: `/* /* */ " */ fn f() { <a real call> } /* " */` was
        /// invisible to every count in this file, so it could add a branch to
        /// `accept_or_reject` or a call to the crate without any assertion moving.
        Block(usize),
        Str,
        /// Inside a raw string (`r"…"`, `r#"…"#`), whose contents are dropped.
        RawStr(u8),
        /// Inside a `#[cfg(…)]` attribute, whose text is copied through: its
        /// `"feature"` payload is itself a match target below, so it cannot be blanked
        /// the way `Mode::Str` blanks a literal. What must not reach the **brace walks**
        /// that run on this text ([`non_test_source`], [`brace_blocks`], and
        /// [`statement_end`]'s bracket count) is a literal payload's braces: `{` and `}`
        /// have no meaning in a legal `cfg` predicate, and one copied through moved the
        /// test module's cut. Measured before literals were tracked here:
        /// `#[cfg(feature = "{")]` on a function inside `mod tests` made the cut report
        /// "the test module's body is unterminated" (the walk counted the payload's
        /// `{`), and the mirror `#[cfg(feature = "}")]` closed the module early, exposing
        /// the rest of `mod tests` as production text to every scan in this file. Literal
        /// contents are therefore copied through *minus the brace bytes*
        /// ([`without_braces`]), and a literal's own delimiter closes it rather than the
        /// attribute's `]`.
        Cfg,
        /// Inside a string or char literal within a `#[cfg(…)]`: contents are copied
        /// through with braces blanked to spaces (see `Mode::Cfg`), escapes are skipped,
        /// and the literal's opening delimiter — not the attribute's `]` — closes it.
        CfgLiteral(u8),
        /// Inside a raw string (`r"…"`, `r#"…"#`) within a `#[cfg(…)]`: the same
        /// brace-blanked copy, terminated by the same `"` + hashes rule as `Mode::RawStr`.
        CfgRawStr(u8),
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
                    // quotes kept. Without this, a `"` inside the raw string re-entered
                    // code mode and the text between two quotes was scanned as code.
                    for k in 0..=prefix {
                        out.push(b[i + k] as char);
                    }
                    i += prefix + 1;
                    mode = Mode::RawStr(hashes);
                } else if c == b'#' && b[i..].starts_with(b"#[cfg(") {
                    // Copy the attribute through: `feature = "hardened"` and
                    // `not(feature = "dual-mac")` are match targets below, and a string
                    // literal cannot stand in for one — reaching `Mode::Code` at all
                    // means the attribute is really written at this position. (The
                    // payload is copied through rather than blanked; everything outside
                    // a `#[cfg]` is still `Mode::Str`. Inside the attribute's literals,
                    // `Mode::CfgLiteral` blanks the brace bytes — see that variant.)
                    out.push('#');
                    mode = Mode::Cfg;
                    i += 1;
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
                    // and the closing quote is kept there, so a literal becomes `""`
                    // and cannot satisfy a match on its contents.
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
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            Mode::Cfg => {
                if c == b'"' {
                    out.push('"');
                    mode = Mode::CfgLiteral(b'"');
                    i += 1;
                } else if c == b'\'' {
                    // The same look-ahead as `Mode::Code`: `'"'` and `'\n'` are char
                    // literals; a lifetime (`&'a`) is not.
                    let escaped = b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'');
                    if escaped || b.get(i + 2) == Some(&b'\'') {
                        out.push('\'');
                        mode = Mode::CfgLiteral(b'\'');
                    } else {
                        out.push('\'');
                    }
                    i += 1;
                } else if let Some((prefix, hashes)) = raw_string_prefix(&b[i..]) {
                    for k in 0..=prefix {
                        out.push(b[i + k] as char);
                    }
                    i += prefix + 1;
                    mode = Mode::CfgRawStr(hashes);
                } else {
                    out.push(c as char);
                    i += 1;
                    if c == b']' {
                        // `#[cfg(…)]` has no bracket outside a literal (handled above);
                        // the first `]` there closes it.
                        mode = Mode::Code;
                    }
                }
            }
            Mode::CfgLiteral(delim) => {
                if c == b'\\' {
                    out.push('\\');
                    if let Some(&next) = b.get(i + 1) {
                        out.push(without_braces(next)); // even an escaped brace is structure
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else if c == delim {
                    out.push(c as char);
                    mode = Mode::Cfg;
                    i += 1;
                } else {
                    out.push(without_braces(c));
                    i += 1;
                }
            }
            Mode::CfgRawStr(hashes) => {
                let h = hashes as usize;
                if c == b'"'
                    && b.len() >= i + 1 + h
                    && b[i + 1..i + 1 + h].iter().all(|&x| x == b'#')
                {
                    out.push('"');
                    for _ in 0..h {
                        out.push('#');
                    }
                    i += 1 + h;
                    mode = Mode::Cfg;
                } else {
                    out.push(without_braces(c));
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
                    // Drop the contents so no byte inside a literal is scanned, and a
                    // literal carrying a statement's text is no longer an occurrence
                    // of it.
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

/// Count occurrences of `keyword` in `code` whose following character is not an
/// identifier character.
///
/// `code.matches("if ")` missed the same branch spelled `if(`; a keyword is a
/// keyword whatever follows it, so the boundary is what counts rather than the
/// spacing rustfmt happens to write. A keyword at the end of the text counts (there
/// is no character to make it part of a longer identifier).
fn keyword_occurrences(code: &str, keyword: &str) -> usize {
    code.match_indices(keyword)
        .filter(|(at, _)| {
            !code[at + keyword.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
        .count()
}

/// Every brace-matched block in the non-test source that starts at `needle`,
/// `needle` included.
///
/// Used to pull a block of the source out for assertions about its shape: the one
/// `accept_or_reject` definition (an earlier version of this comment said "the two",
/// which was true before the `#[cfg]`-selected bodies were merged; `definitions()`
/// asserts there is exactly one) and the two `hardened` gate blocks.
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

/// Does `code` contain `word` as a whole identifier -- not as an alphanumeric/`_`-continued
/// substring of a longer name (`plaintext` inside `witness_plaintext` is not an occurrence)?
///
/// The gaps the tests below scan are statements, not prose, so this is the boundary test
/// for "this binding was named here" without matching a longer identifier that merely
/// contains its text.
fn contains_word(code: &str, word: &str) -> bool {
    code.match_indices(word).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// The byte just past the `;` that ends the statement containing the byte `at`, counting
/// bracket depth so a `;` inside the statement's own parentheses or braces cannot end it
/// early.
///
/// The witness call's argument list is the statement `the_witness_outputs_reach_the_
/// agreement_unwritten` has to cut at. Today it holds no `;`, but a future argument (a
/// closure body) could, and a naive `find(';')` would then treat the text between there
/// and the comparison as the gap to check -- a gap that *excludes* a write inserted just
/// before the real `;`.
fn statement_end(code: &str, at: usize) -> usize {
    let mut depth = 0i64;
    for (n, c) in code[at..].char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => return at + n + 1,
            _ => {}
        }
    }
    panic!("the statement at byte {at} has no terminating `;`");
}

/// Locate `accept_or_reject` by name and return its full text, body included,
/// brace-matched.
///
/// There is exactly **one** body, with the `hardened` gates inside it rather than a
/// second `#[cfg]`-selected definition: two bodies would be two functions to a mutation
/// campaign that does not evaluate `cfg` (`cargo mutants`), and the one not compiled in a
/// given run reads there as an uncaught mutant. (An earlier version of this comment said
/// "there are two"; the source has one, and the assertion below requires it.)
fn definitions() -> Vec<String> {
    brace_blocks("fn accept_or_reject(")
}

/// Every non-comment, non-empty line of `tests/ctgrind.supp`.
fn suppression_lines() -> Vec<String> {
    SUPP.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// The `fun:` value of the one entry, if present.
fn suppression_fun() -> Option<String> {
    suppression_lines()
        .into_iter()
        .find_map(|l| l.strip_prefix("fun:").map(str::to_string))
}

#[test]
fn the_suppression_file_names_only_the_decision() {
    // The whole file, not just the `fun:` lines: `obj:`, `src:`, `Match:` and any other
    // valgrind line kind widen an entry's scope, and the earlier version of this test
    // only looked at `fun:` and `Memcheck:` lines -- everything else was unexamined.
    let lines = suppression_lines();
    let fun = suppression_fun().expect("the entry must carry a `fun:` line");
    let expected = vec![
        "{".to_string(),
        "siv-accept-or-reject-decision".to_string(),
        "Memcheck:Cond".to_string(),
        format!("fun:{fun}"),
        "}".to_string(),
    ];
    assert_eq!(
        lines, expected,
        "tests/ctgrind.supp must hold exactly one entry with exactly these five lines \
         (brace, name, Memcheck:Cond, fun:..., brace). The file's header says \"exactly \
         one entry\" and tools/ctgrind.sh refuses to run unless it names the decision, \
         so any other line kind, an extra field inside the entry or a second entry \
         needs this test updated deliberately"
    );

    // The exact function, not a name that merely contains it: `*accept_or_reject*`
    // would match `my_accept_or_reject`, and a trailing wildcard would match any
    // helper whose name starts the same way. The v0-mangled form puts the
    // identifier's length (`16`) immediately before the symbol, which is what makes
    // "ends with the symbol, preceded by its length" a check that rejects the
    // look-alikes.
    assert!(
        fun.ends_with("accept_or_reject"),
        "the suppression's `fun:` value `{fun}` must end in the decision symbol: a \
         trailing wildcard would match every function whose name starts the same way"
    );
    let before = fun.trim_end_matches("accept_or_reject");
    assert!(
        before.ends_with("16"),
        "the `fun:` value `{fun}` must be the mangled symbol of `accept_or_reject`, whose \
         v0-mangled form puts the identifier length (`16`) right before it; `{before}` \
         does not, so this entry may name a *different* function (`my_accept_or_reject`, \
         `accept_or_reject_helper`, ...) while ending in the same text"
    );
}

#[test]
fn the_suppressed_function_contains_only_the_decision() {
    let defs = definitions();
    assert_eq!(
        defs.len(),
        1,
        "exactly one definition: the `hardened` gates are compiled inside it rather \
         than selected by a second `#[cfg]`-gated definition. A second body would be \
         a second function to `cargo mutants`, which does not evaluate cfgs -- the \
         body that is not compiled in a run reads there as an uncaught mutant."
    );
    let def = &defs[0];

    // Comments are stripped first -- by the same scanner the rest of the file uses,
    // which unlike `find("//")` is not fooled by a `//` inside a string literal.
    let code = strip_comments(def);

    // `strip_comments` copies `#[cfg(…)]` payloads through *verbatim* (they are match
    // targets below), so a payload carrying a branch's text -- `#[cfg(feature =
    // "if")]` -- would count as that branch and let a real one be deleted. Only the
    // two attributes the decision really writes may appear; with those payloads
    // pinned, the keyword and spelling counts below cannot be fed by an attribute.
    let mut cfgs = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("#[cfg(") {
        let end = at
            + rest[at..]
                .find(']')
                .expect("a `#[cfg(` attribute without a closing `]`");
        cfgs.push(rest[at..=end].to_string());
        rest = &rest[end + 1..];
    }
    assert_eq!(
        cfgs,
        [
            "#[cfg(feature = \"hardened\")]".to_string(),
            "#[cfg(not(feature = \"hardened\"))]".to_string(),
        ],
        "the suppressed function must carry exactly the two cfg attributes the decision \
         needs (gate 1, and the opt-out copy). The scanner copies their payloads \
         verbatim, so any other attribute is a place branch text can hide from the \
         counts below"
    );

    for construct in ["for", "while", "loop", "match"] {
        assert!(
            keyword_occurrences(&code, construct) == 0,
            "`{construct}` inside accept_or_reject: the whole function is suppressed, \
             so a loop in it would be a secret-dependent branch that no check can \
             see. Move it out, or accept that the entry is no longer a reviewable \
             one-liner."
        );
    }
    assert!(
        !code.contains('?'),
        "`?` inside accept_or_reject propagates a `Result` through a branch on a \
         discriminant; it belongs at the call site, where ctgrind verifies that the \
         branch is on a constant"
    );
    // `?` is not the only conditional jump that is not one of the four keywords.
    // `&&` and `||` short-circuit through a branch, and a panicking macro (`assert!`,
    // `debug_assert!`, `.unwrap()`, `.expect()`, `panic!`) compiles to a branch to the
    // panic path. Inside the suppressed function either one branches on a
    // secret-derived value where no memcheck report can be seen. (Measured: both a
    // `(gate0.unwrap_u8() & 1) == 0 || { … }` line and an `assert!(…)` line were
    // accepted by the keyword counts alone.)
    for spelled in ["&&", "||", "assert", "panic", "unwrap", "expect"] {
        assert_eq!(
            code.matches(spelled).count(),
            0,
            "`{spelled}` inside accept_or_reject is a conditional jump on the \
             secret-derived gates, inside the one function `tests/ctgrind.supp` \
             covers: the body must contain only the two `if` branches"
        );
    }
    // A *method call* can branch without any of the spellings above: `Choice` converts to
    // `bool`, and `bool::then`/`then_some`/`map_or`/`and_then`/`unwrap_or*` all take a
    // closure that runs conditionally. A third-party pass injected
    // `bool::from(gate0 & gate1).then(_audit_branchy)` -- helper defined outside this body,
    // so its definition is not counted here -- measured `accept_or_reject`'s conditional
    // jumps rise from 2 to 3 in `--emit asm`, and this file stayed 7/7. Inside the
    // suppressed function the body is a fixed shape, so the honest check forbids the whole
    // family rather than tracking its members: with these names gone, no expression in
    // this body can evaluate a closure conditionally.
    for method in [
        ".then(",
        ".then_some(",
        ".map_or(",
        ".map_or_else(",
        ".and_then(",
        ".or_else(",
        ".unwrap_or(",
        ".unwrap_or_else(",
        ".unwrap_or_default(",
        ".ok_or(",
        ".ok_or_else(",
        ".filter(",
        ".is_some_and(",
        ".is_none_or(",
        ".is_ok_and(",
    ] {
        assert_eq!(
            code.matches(method).count(),
            0,
            "`{method}` inside accept_or_reject evaluates a closure or an argument \
             conditionally, which is a branch on the secret-derived gates inside the one \
             function `tests/ctgrind.supp` covers -- the keyword counts and the \
             conditional-jump count (2) do not see it, and neither does memcheck. The \
             decision's body is a fixed shape: if it needs a conditional expression, the \
             suppression entry needs re-reviewing."
        );
    }
    let branches = keyword_occurrences(&code, "if");
    assert_eq!(
        branches, 2,
        "the decision must have exactly two branches: the first gate, and the \
         `hardened` second gate. The suppressed function is exactly the decision, and \
         this count is what \"exactly\" means -- if the decision needs another branch, \
         the suppression entry needs re-reviewing:\n{def}"
    );
    // Two writes per gate -- one per arm, so the byte that lands in a slot is a
    // constant each path writes rather than a value selected from a tainted condition
    // -- plus the opt-out build's copy of slot 0 into slot 1.
    assert_eq!(
        code.matches("*out0 = ").count(),
        2,
        "gate 0 must write its slot in both arms:\n{def}"
    );
    assert_eq!(
        code.matches("*out1 = ").count(),
        3,
        "gate 1 must write its slot in both arms, plus the opt-out copy:\n{def}"
    );
    assert_eq!(
        code.matches("#[cfg(feature = \"hardened\")]").count(),
        1,
        "exactly one of the two branches is the opt-in gate:\n{def}"
    );
    assert_eq!(
        code.matches("bool::from").count(),
        2,
        "both branches must convert a `Choice`, not compare bytes directly:\n{def}"
    );
    assert!(
        !code.contains("#[cfg(not(feature = \"hardened\"))]\n    if "),
        "the default build must not have a branch of its own: it shares this body, \
         with the second gate compiled out"
    );
}

/// The `hardened` feature's second gate must be a *recomputation*.
///
/// The two gate expressions are identical, so an optimizer is entitled to
/// common-subexpression-eliminate them into one comparison — at which point a
/// single fault carries both gates and the "second" gate is decoration. `src/lib.rs`
/// forbids that with a volatile re-read, which is a guarantee the language gives
/// rather than a hope about an optimizer's choices; this test pins the mechanism in
/// the source, because a later refactor that "simplifies" the duplicated expression
/// away would otherwise look like an improvement.
///
/// The behavioural half lives in `tools/fi_check.sh`: `gate0-value-forced` must
/// still be *rejected* (the second gate recomputes), and `gates-shared` — the same
/// fault with the second gate turned into a copy — must be *accepted*, which is what
/// shows the recomputation is what does the work.
#[test]
fn the_hardened_second_gate_is_recomputed() {
    let code = non_test_source();
    let blocks = brace_blocks("let gates = {");
    assert_eq!(
        blocks.len(),
        2,
        "expected one gate block per decrypt entry point"
    );

    for block in &blocks {
        assert_eq!(
            block.matches("read_volatile").count(),
            2,
            "both operands of the second gate must be re-read through a volatile \
             read, or the comparison can be common-subexpression-eliminated into the \
             first gate's. Block was:\n{block}"
        );
        // The *sources* of the two volatile reads, not just their count. Two reads
        // that both target `computed_tag` -- `tag_copy` re-read from the stored value
        // rather than from the caller's `tag` -- make gate 1 compare a value with
        // itself, which is always true: the second gate is gone while the read count,
        // the argument names, `(first, second)` and every other count here still hold.
        // (Measured: re-pointing `tag_copy` at `&computed_tag` kept this test green.)
        for (site, what) in [
            (
                "let mut computed_tag_copy = unsafe { core::ptr::read_volatile(&computed_tag) };",
                "the second gate's computed-tag operand must be a volatile re-read of \
                 `computed_tag`",
            ),
            (
                "let mut tag_copy = unsafe { core::ptr::read_volatile(tag) };",
                "the second gate's received-tag operand must be a volatile re-read of the \
                 caller's `tag`",
            ),
        ] {
            assert_eq!(block.matches(site).count(), 1, "{what}:\n{block}");
        }
        assert!(
            block.contains("zeroize_array(&mut computed_tag_copy)"),
            "the re-read copy of the computed tag is secret-derived and must be \
             wiped like every other copy in the function:\n{block}"
        );
        assert_eq!(
            block.matches("let first =").count(),
            1,
            "the block must compute its first gate exactly once:\n{block}"
        );
        // The second gate is bound once *per configuration*, from a shared `gate_pair`: the
        // arms are `#[cfg]`-selected, so exactly one of them is compiled. Two bindings with no
        // cfg between them would be two gates over one value, which is the shape this replaced.
        // `ultra`'s witness agreement is deliberately *not* a third arm: it is folded into
        // `gate_pair` on the one line every configuration compiles, because `cargo mutants`
        // does not evaluate `cfg` and an arm that is not compiled in a given run reads there
        // as an uncaught mutant (measured: six).
        for arm in [
            "#[cfg(feature = \"dual-mac\")]",
            "#[cfg(not(feature = \"dual-mac\"))]",
        ] {
            assert!(
                block.contains(arm),
                "the second gate needs its arm for `{arm}` -- one binding per \
                 configuration, so that no build ever has two gates over one value:\n{block}"
            );
        }
        assert_eq!(
            block.matches("let second =").count(),
            2,
            "one `second` binding per arm, and no arm without one:\n{block}"
        );
        assert!(
            block.contains("& witness_ok"),
            "`ultra`'s witness agreement must join the second gate rather than becoming a \
             branch of its own -- a branch on a secret-derived comparison outside \
             `accept_or_reject` is what the suppression file forbids:\n{block}"
        );
        // The *operands*, not just the callee and the fold-in. `second_gate_comparison(
        // &computed_tag_copy, &computed_tag_copy)` makes gate 1 compare a value with
        // itself -- always true in the default build, where `witness_ok` is constant
        // true -- and every count above still holds. Only `tests/ultra.rs` caught that
        // mutation before, and only with `ultra` compiled in; this pins it per entry
        // point in every configuration that builds the gates.
        assert_eq!(
            block
                .matches("second_gate_comparison(&computed_tag_copy, &tag_copy) & witness_ok")
                .count(),
            1,
            "the second gate must compare the volatile re-read of the computed tag against \
             the volatile re-read of the received tag (each volatile read is pinned above), \
             not a value with itself:\n{block}"
        );
        assert_eq!(
            block.matches("let gate_pair =").count(),
            1,
            "the second gate must be built from one `gate_pair` computation:\n{block}"
        );
        // And the pair really is the block's *return*: the mutation this catches is
        // `(first, first)`, which reuses the first gate as the second — every count
        // above still holds under it (the `second` bindings and the `&`s remain), so a
        // fingerprint that only requires the two names to appear nearby would pass it.
        assert_eq!(
            block.matches("(first, second)").count(),
            1,
            "the gate block must return `(first, second)`, not a pair built from one gate \
             twice:\n{block}"
        );
    }

    // And the duplication is real duplication: the first gate's expression appears
    // once per entry point, so a refactor that shares one computation between both
    // decrypt paths would remove a gate from one of them.
    assert_eq!(
        code.matches("let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);")
            .count(),
        2,
        "the first gate must be computed once per decrypt entry point"
    );
}

/// The second gate compares through two *differently written* comparisons, wherever
/// the gates are built — not only under `dual-mac`.
///
/// The name used to say "in every configuration", which overclaimed: this test reads
/// source text and so also runs under `--no-default-features`, where
/// `second_gate_comparison` and `ct_eq_independent` are not compiled at all. That build
/// is the documented single-gate baseline and has no gates for this assertion to be
/// about, so the claim is scoped to the configurations that build them.
///
/// This is a boundary that was wrong once and is cheap to keep right: the differently written
/// comparison (an 8-byte fold into a `u64`, against `subtle`'s per-byte loop) used to be gated
/// on `dual-mac`, which left the *default* build with a single comparison shape — so one fault
/// that shortened that shape disarmed every gate at once, and the hand-measured result was an
/// accept after 2,573 attempts. With both shapes present the same hand-made fault produced no
/// forgery in 2,000,000 attempts, for **1.4 ns** per decryption, which is why the fold is now
/// unconditional.
///
/// The assertion is deliberately about the *shape* rather than the call site: the defence used
/// to live in a `#[cfg]`-selected arm, and a `#[cfg]` is exactly what a build configuration
/// silently drops.
#[test]
fn the_second_gate_uses_two_comparison_shapes_wherever_the_gates_are_built() {
    let _ = non_test_source(); // keep the call graph honest if this test is edited
    let body = brace_blocks("fn second_gate_comparison(");
    assert_eq!(body.len(), 1, "one `second_gate_comparison` expected");
    let body = &body[0];

    assert!(
        body.contains("a.ct_eq(b) & b.ct_eq(a)"),
        "the `subtle` comparison must stay: it is the shape the fold is independent of:\n{body}"
    );
    assert!(
        body.contains("let also = ct_eq_independent(a, b);"),
        "the fold comparison must be unconditional -- a `#[cfg]` here is how the default build \
         lost this defence before:\n{body}"
    );
    // The AND must be the function's *return expression*, not a discarded computation:
    // an earlier version of this assertion only searched for the substring `plain & also`,
    // so `let _ = plain & also; plain` — the fold computed and thrown away — passed it.
    // Compare the last non-empty line of the body (comments and the closing brace
    // removed) instead.
    let code = strip_comments(body);
    let last = code
        .trim_end()
        .strip_suffix('}')
        .expect("second_gate_comparison must end in a closing brace")
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(
        last, "plain & also",
        "the independent fold must be the returned `Choice`, not merely computed: keeping \
         the `let also = ...` line but returning `plain` alone passed this test before:\n{body}"
    );
    assert!(
        !body.contains("subtle::Choice::from(1)"),
        "the `dual-mac`-only placeholder (`Choice::from(1)`) must not come back: it is how the \
         default build ended up with a single comparison shape:\n{body}"
    );

    // The fold must be a different *shape* from `subtle`'s loop rather than a call to it, or
    // the two "comparisons" are one comparison wearing two hats. And it must *use both
    // operands*: the presence checks this replaces (`u64::from_le_bytes`, `acc |= x`,
    // `acc.ct_eq(&0u64)`) stayed green when the accumulation was made a constant
    // (`acc |= x & 0;`), which leaves `ct_eq_independent` returning constant true and
    // silently removes the single-fault defence these two shapes exist for. Pin the exact
    // fold lines instead, whitespace-flattened so rustfmt's line breaks are not the subject.
    let fold = brace_blocks("fn ct_eq_independent(");
    assert_eq!(fold.len(), 1, "one `ct_eq_independent` expected");
    let fold_code = strip_comments(&fold[0]);
    let flat = fold_code.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains(
            "let x = u64::from_le_bytes(a[i..i + 8].try_into().unwrap()) \
             ^ u64::from_le_bytes(b[i..i + 8].try_into().unwrap());"
        ),
        "the fold must XOR the *same 8-byte word position* of both tags: `a` and `b` \
         appear in that order, one `from_le_bytes` each. A copy-paste of `a` into the \
         second operand, or a swapped position, makes the comparison depend on one \
         tag twice:\n{}",
        fold[0]
    );
    assert!(
        flat.contains("acc |= x;"),
        "the word must be accumulated into the running value: `acc |= x;` is the \
         accumulation; a masked `acc |= x & 0;` is a constant and passed the substring \
         checks this test used to make:\n{}",
        fold[0]
    );
    assert!(
        flat.contains("acc |= (a[i] ^ b[i]) as u64;"),
        "the tail byte must XOR the same position of both tags into the accumulator, \
         not one of them twice:\n{}",
        fold[0]
    );
    // The accumulator comparison must be the function's *return expression*, not a
    // discarded computation followed by a constant: compare the last non-empty line of
    // the body (comments and the closing brace removed), as the `plain & also` pin above.
    let last = fold_code
        .trim_end()
        .strip_suffix('}')
        .expect("ct_eq_independent must end in a closing brace")
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(
        last, "acc.ct_eq(&0u64)",
        "the fold must return the constant-time comparison of the accumulator: a body \
         that kept the loop but returned `subtle::Choice::from(1)` passed this test \
         before:\n{}",
        fold[0]
    );
}

/// The fold's accumulator must be the value the final comparison sees.
///
/// Everything pinned about `ct_eq_independent` above is a *line*: the two `acc |= …;`
/// accumulations, the exact XOR operands, and the return `acc.ct_eq(&0u64)`. An audit kept
/// every one of those lines and inserted `let acc = 0u64;` between the tail loop and the
/// return: the OR-ed bytes are then dead, the function returns the constant
/// `0u64.ct_eq(&0u64)`, and the whole suite stays green (measured on a copy) -- the fold is
/// the second comparison *shape*, so a tautological fold silently removes the single-fault
/// defence the two shapes exist for. This test pins the *binding* instead of the lines:
/// declared `mut` exactly once, no second `let` binding of the same name anywhere (that is
/// the shadow), and no mention of `acc` between the last accumulation and the comparison
/// (which also catches `acc = 0;`, `acc &= 0;`, `acc ^= acc;` and any other statement that
/// discards the folded bits).
///
/// Narrow on purpose: it reads one function and only rejects a changed binding shape or an
/// extra mention of the accumulator, so reformatting, comment changes, or renaming an
/// unrelated local do not trip it.
#[test]
fn the_fold_accumulator_is_the_compared_value() {
    let fold = brace_blocks("fn ct_eq_independent(");
    assert_eq!(fold.len(), 1, "one `ct_eq_independent` expected");
    let code = strip_comments(&fold[0]);
    // Whitespace-flattened for the binding shapes: rustfmt's line breaks are not the
    // subject of these assertions.
    let flat = code.split_whitespace().collect::<Vec<_>>().join(" ");

    // Declared once, and `mut` -- the two `acc |= …` lines write it, and a non-`mut`
    // accumulator cannot be the one they write.
    assert_eq!(
        flat.matches("let mut acc = 0u64;").count(),
        1,
        "`ct_eq_independent` must declare `let mut acc = 0u64;` exactly once:\n{}",
        fold[0]
    );
    // And no second `let` binding of the same name: `let acc = 0u64;` shadows the
    // accumulator, so the returned comparison no longer sees the folded bytes -- every
    // line pinned above is still present under that mutation, which is why it passed.
    let binders: usize = [
        "let acc =",
        "let mut acc =",
        "let ref acc =",
        "let ref mut acc =",
    ]
    .iter()
    .map(|form| flat.matches(form).count())
    .sum();
    assert_eq!(
        binders, 1,
        "`acc` must be bound exactly once in `ct_eq_independent`: a second `let` binding of \
         the same name shadows the accumulator, discarding the OR-ed bytes before the \
         comparison (measured: an inserted `let acc = 0u64;` kept the whole suite green, \
         every pinned line intact):\n{}",
        fold[0]
    );
    // Every mention of `acc` is one of the fold's four statements: the declaration, the
    // two accumulations, the comparison. A fifth mention is a shadow binding, a
    // cancel/zero (`acc &= 0;`, `acc ^= acc;`), or a move of the compared value away from
    // the accumulator -- each leaves the fold constant or dependent on something other
    // than both tags.
    assert_eq!(
        code.match_indices("acc")
            .filter(|(at, _)| {
                let before = code[..*at].chars().next_back();
                let after = code[*at + 3..].chars().next();
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
            .count(),
        4,
        "`ct_eq_independent` must mention the accumulator exactly four times -- the \
         declaration, the two accumulations, and the final comparison. Any other mention \
         (`let acc = 0u64;`, `acc = 0;`, `acc &= 0;`, ...) is a write that discards the \
         folded bits before they are compared:\n{}",
        fold[0]
    );
    // The compared binding is the accumulator, and the comparison follows the fold. (The
    // last-line pin in the test above states the return shape for the whole function;
    // repeated here so a failure of this invariant names what it caught.)
    assert_eq!(
        code.matches("acc.ct_eq(&0u64)").count(),
        1,
        "the accumulator must be compared against zero exactly once:\n{}",
        fold[0]
    );
    let cmp_at = code
        .rfind("acc.ct_eq(&0u64)")
        .expect("asserted present above");
    let last_accum = code
        .rfind("acc |=")
        .expect("the fold must accumulate into `acc`");
    let accum_end = statement_end(&code, last_accum);
    assert!(
        accum_end <= cmp_at,
        "the comparison must follow the last accumulation:\n{}",
        fold[0]
    );
    assert!(
        !contains_word(&code[accum_end..cmp_at], "acc"),
        "`acc` must not be mentioned between the last accumulation and the comparison: any \
         statement there (`acc = 0;`, `acc &= 0;`, `acc ^= acc;`, a shadowing \
         `let acc = ...`) discards the folded bytes, and the fold then certifies any two \
         tags whose bytes the loops covered:\n{}",
        fold[0]
    );
}

/// A skipped decision call must leave a rejection standing.
///
/// The outcome is written *through* `out`, which the caller initialises before the
/// call, so a fault that never makes the call cannot accept: the caller reads the
/// rejection it wrote itself. This is not decoration — `tools/fi_instruction.sh`
/// measured six single-byte faults in `decrypt` that skipped the call and accepted a
/// forgery while the helper returned its outcome by value, because the ABI then hands
/// back whatever the return slot happened to hold. The ordering is the fix, so the
/// ordering is what is pinned here.
#[test]
fn the_decision_outcome_is_fail_closed() {
    let code = non_test_source();
    let init = "let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);\n    \
                let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);";

    // The initialisation immediately before the call, then the `hardened` call right
    // after it: the whole sequence, per entry point, is what makes the outcome
    // fail-closed. Asserted as one string so a reordering -- write the decision after
    // the call, or move one variant elsewhere -- cannot pass.
    //
    // Two slots, not one: a single corrupted outcome must not be able to accept, so
    // the caller rejects if *either* slot does and the slots are written by separate
    // gate flows (see the assertion above).
    assert_eq!(
        code.matches("let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);")
            .count(),
        3,
        "each call site must start slot 0 as a rejection: the two decrypt entry points, \
         and `encrypt`'s `ultra` cross-check, which compares the witness's tag with its \
         own and must not branch on that comparison itself (ctgrind reports it when it \
         does: measured, one report inside `encrypt`)"
    );
    assert_eq!(
        code.matches("let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);")
            .count(),
        3,
        "each call site must start slot 1 as a rejection"
    );
    // The checks sit in series, each jumping to the rejection, so accepting is the
    // fall-through of both: a single corrupted branch lands on a rejection.
    assert_eq!(
        code.matches("if decision0.is_err() {").count(),
        3,
        "one first check per call site"
    );
    assert_eq!(
        code.matches("if decision1.is_err() {").count(),
        3,
        "one second check per call site"
    );
    {
        let default_call =
            "    #[cfg(not(feature = \"hardened\"))]\n    accept_or_reject(auth_ok, \
                            auth_ok, &mut decision0, &mut decision1);";
        let hardened_call = "    #[cfg(feature = \"hardened\")]\n    accept_or_reject(gates.0, \
                             gates.1, &mut decision0, &mut decision1);";
        // Two, not one: since the decision no longer touches the buffer, both entry
        // points carry the same three lines, so one pattern covers both -- and a count
        // of 2 is what says so.
        let sequence = format!("{init}\n{default_call}\n{hardened_call}");
        assert_eq!(
            code.matches(sequence.as_str()).count(),
            2,
            "both entry points must carry the fail-closed sequence:\n{sequence}"
        );
    }

    // The default build passes the same `Choice` twice (the second gate is compiled
    // out there), which is also what keeps the signature -- and the symbol the
    // suppression names -- identical in both builds.
    assert_eq!(
        code.matches("accept_or_reject(auth_ok, auth_ok, ").count(),
        2,
        "the default build must not compute a second comparison it does not use"
    );

    // The helper must write through that pointer rather than return a value: a
    // returned value is what a skipped call loses.
    for signature in [
        "fn accept_or_reject(\n    gate0: subtle::Choice,\n    gate1: subtle::Choice,\n    \
         out0: &mut Result<(), Error>,\n    out1: &mut Result<(), Error>,\n) {",
        "    *out1 = *out0;",
    ] {
        assert!(
            code.contains(signature),
            "the decision must take the outcome by `&mut`, not return it: {signature}"
        );
    }

    // And the wipe lives in the *caller*, on the path every rejection takes -- the
    // decision function no longer touches the buffer, so a skipped call still wipes.
    // The call is `crate::zeroize_slice(` (absolute, so no `use` in the body can shadow it
    // into a no-op -- see `every_documented_wipe_has_a_witness`); the count accepts either
    // spelling so this pin is about *where* the wipe is, not how it is named.
    assert_eq!(
        code.matches("if decision0.is_err() {\n        crate::zeroize_slice(")
            .count()
            + code
                .matches("if decision1.is_err() {\n        crate::zeroize_slice(")
                .count()
            + code
                .matches("if decision0.is_err() {\n        zeroize_slice(")
                .count()
            + code
                .matches("if decision1.is_err() {\n        zeroize_slice(")
                .count(),
        4,
        "each of the four decrypt reject checks must wipe the buffer before returning"
    );
    // The third call site, `ultra`'s cross-check inside `encrypt`, wipes what it has
    // derived by then -- the MAC key and the encryption seed -- on both of its reject
    // paths. It is a different set of locals (the buffer is not written yet on that path),
    // so it is asserted separately rather than folded into the count above. As with the
    // decrypt wipes, the call is `crate::`-qualified so no `use` in the body can shadow it;
    // both spellings are counted.
    assert_eq!(
        code.matches("if decision0.is_err() {\n            crate::zeroize_array(&mut k_in);")
            .count()
            + code
                .matches("if decision1.is_err() {\n            crate::zeroize_array(&mut k_in);")
                .count()
            + code
                .matches("if decision0.is_err() {\n            zeroize_array(&mut k_in);")
                .count()
            + code
                .matches("if decision1.is_err() {\n            zeroize_array(&mut k_in);")
                .count(),
        2,
        "`encrypt`'s two reject checks must wipe the derived key material"
    );
    // There must be no conditional jump *to the accept path*: accepting is the
    // fall-through of the two reject checks, so a corrupted branch lands on a
    // rejection instead of on `Ok`. An `if <decision>.is_ok() { .. Ok(..) }` shape is
    // exactly what the two-slot rewrite removed, and it is one opcode bit from
    // accepting a forgery.
    assert_eq!(
        code.matches("if decision0.is_ok()").count() + code.matches("if decision1.is_ok()").count(),
        0,
        "the accept path must not be reached by a conditional jump"
    );
    // Both entry points, one pattern each: the second check's rejection block followed
    // immediately by the accept, which is what "fall-through" means in the source. The
    // wipe is `crate::`-qualified (see the note above), so the pattern uses that spelling.
    for (place, accept) in [
        (
            "crate::zeroize_slice(&mut plaintext);",
            "Ok(Plaintext(plaintext))",
        ),
        ("crate::zeroize_slice(buffer);", "Ok(())"),
    ] {
        let tail = [
            "    if decision1.is_err() {",
            &format!("        {place}"),
            "        return Err(Error::AuthenticationFailed);",
            "    }",
            &format!("    {accept}"),
        ]
        .join("\n");
        assert_eq!(
            code.matches(tail.as_str()).count(),
            1,
            "the accept must be the fall-through of both reject checks:\n{tail}"
        );
    }

    // The witness is a `Choice` folded into the gate, and the `encrypt` cross-check is a
    // rejection path of its own — both are asserted, because the whole point of the feature is
    // that the agreement is *required* rather than consulted.
    let non_test = non_test_source();
    // Four bindings: the witness agreement itself under `ultra`, and the constant `true`
    // that the other configurations bind instead, in each of the two entry points. The
    // constant is what keeps the gate a single expression rather than one arm per
    // configuration (see the comment in the gate).
    assert_eq!(
        non_test.matches("let witness_ok: subtle::Choice").count(),
        4,
        "two entry points, each binding the witness agreement and the constant that \
         replaces it when `ultra` is off"
    );
    assert_eq!(
        non_test.matches("& witness_ok").count(),
        2,
        "each entry point must fold that agreement into the gate"
    );
    // And the agreement must be built from the witness's own answers, not a placeholder:
    // requiring only `& witness_ok` let a `Choice::from(1)` replacement pass with the real
    // comparison deleted. These are the two operands the agreement ANDs together.
    assert_eq!(
        non_test.matches("witness_tag.ct_eq(&computed_tag)").count(),
        2,
        "each decrypt entry point must compare the witness tag against the computed tag"
    );
    // `encrypt` has no `computed_tag` in scope: its cross-check compares the witness tag
    // against the tag it just derived (`&tag`). Pinned separately, because the count above
    // is about the two decrypt paths and a `Choice::from(1)` placeholder here would not
    // change it. The comparison, not the binding's exact spelling, is what is required.
    assert_eq!(
        non_test.matches("witness_tag.ct_eq(&tag)").count(),
        1,
        "`encrypt` must build its witness agreement from the witness tag and its own tag, \
         not a placeholder"
    );
    // The two decrypt paths compare the witness plaintext against the recovered one in
    // different shapes: `decrypt` (slices) and `decrypt_in_place_detached` (a slice
    // against the caller's buffer). One of each, so a `Choice::from(1)` rewrite that
    // dropped either comparison fails here.
    assert_eq!(
        non_test
            .matches("witness_plaintext.as_slice().ct_eq(plaintext.as_slice())")
            .count(),
        1,
        "`decrypt` must compare the witness plaintext against the recovered plaintext"
    );
    assert_eq!(
        non_test.matches("witness_plaintext.ct_eq(buffer)").count(),
        1,
        "`decrypt_in_place_detached` must compare the witness plaintext against the caller's \
         buffer"
    );
    // And the agreement must be what the block *returns*: every count above is an
    // existence witness for the comparison, none of them requires the returned `Choice`
    // to be that comparison's value. An audit kept every count, left the comparison dead
    // in the block, and returned `subtle::Choice::from(1)` -- the second implementation
    // then contributes nothing while still being called. Pin the last non-empty line of
    // each block, the technique this file already uses for `plain & also`.
    let witness_blocks = brace_blocks("let witness_ok: subtle::Choice = {");
    assert_eq!(
        witness_blocks.len(),
        2,
        "one `ultra` witness-agreement block per decrypt entry point"
    );
    for block in &witness_blocks {
        let block_code = strip_comments(block);
        // `let … = { … };`: strip the trailing `;` (the closing brace comes before it),
        // then the closing brace, then take the last non-empty line -- the same shape
        // as the `plain & also` pin above, which ends in a bare `}`.
        let trimmed = block_code.trim_end();
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
            "the witness agreement must be the value its block returns rather than a \
             comparison computed and discarded with a constant returned in its place:\n{block}"
        );
        // The returned `agree` must *be* the comparison. The last line alone is
        // satisfied by `let _dead = <comparison>; let agree = Choice::from(1); agree`,
        // so pin that `agree` is bound exactly once (a second binding would shadow the
        // real one), and -- below the loop -- what each of the two bindings is.
        assert_eq!(
            block_code.matches("agree =").count(),
            1,
            "the witness block must bind `agree` exactly once, so the value it returns \
             cannot be a second binding that shadows the comparison:\n{block}"
        );
    }
    for (site, what) in [
        (
            "let agree = witness_tag.ct_eq(&computed_tag)\n            \
             & witness_plaintext.as_slice().ct_eq(plaintext.as_slice());",
            "`decrypt`",
        ),
        (
            "let agree = witness_tag.ct_eq(&computed_tag) & witness_plaintext.ct_eq(buffer);",
            "`decrypt_in_place_detached`",
        ),
    ] {
        assert_eq!(
            non_test.matches(site).count(),
            1,
            "the witness agreement in {what} must be bound to `agree` by the comparison \
             itself; an existence count elsewhere in the function let the comparison be \
             bound to a dead name and `agree` be a constant:\n{site}"
        );
    }
    assert_eq!(
        non_test.matches("witness::decrypt(").count(),
        2,
        "each decrypt entry point must run the independent implementation"
    );
    assert_eq!(
        non_test.matches("witness::encrypt_tag(").count(),
        1,
        "`encrypt` must cross-check the tag with the independent implementation"
    );
    // The declaration is `#[cfg(feature = "ultra")] mod witness;`: a bare
    // `LIB.contains("mod witness;")` held in every build while proving nothing about the
    // `ultra` build (and would also hold if the module were compiled into the opt-out
    // baseline, changing the documented feature set). Pin the gated declaration, which is
    // the text the `ultra` build compiles. Read through `non_test`, not `LIB`: the raw
    // file let an ungated `mod witness;` sit beside a block comment carrying the old
    // attribute, so the gate could be deleted while this stayed green.
    assert!(
        non_test.contains("#[cfg(feature = \"ultra\")]\nmod witness;"),
        "the independent implementation must be declared as the `ultra`-gated module \
         `witness`: a bare `mod witness;` would compile it into every build, and a missing \
         gate would silently move the feature boundary"
    );
    // `encrypt`'s cross-check goes through the same function rather than comparing and
    // branching at its own call site: as an `if !bool::from(..ct_eq(..))` it is a branch on
    // the tag, which no suppression entry covers (valgrind reported it: one report inside
    // `encrypt`, `tools/ctgrind.sh --features ultra`). One call, both slots from the same
    // `Choice`, so the decision has exactly one definition in the crate.
    assert_eq!(
        non_test.matches("accept_or_reject(agree, agree,").count(),
        1,
        "`ultra`'s encrypt-side cross-check must go through the one suppressed decision"
    );
    assert!(
        !non_test.contains("bool::from(witness::"),
        "the witness agreement must not be branched on at the call site, in any spelling: \
         `bool::from` on a witness result is a branch on the tag, which no suppression entry \
         covers (valgrind reported it: one report inside `encrypt`, `tools/ctgrind.sh \
         --features ultra`)"
    );
}

/// The witness's own outputs must reach the agreement unwritten.
///
/// `ultra`'s headline property is that the accept decision requires the independent
/// implementation to agree, and the two comparisons in each `witness_ok` block are that
/// requirement's only statement. They are worth their names only if the compared values are
/// what `witness::decrypt` produced: an inserted
/// `witness_tag.copy_from_slice(&computed_tag);` immediately before the `let agree = ...`
/// line makes the tag comparison a value against itself, leaves every substring this file
/// pins elsewhere intact, and kept the whole `--features ultra` suite green at 128 passed /
/// 0 failed / 7 ignored (measured on a copy). The same insertion on the other operands is
/// the same defeat and was measured green too: `computed_tag.copy_from_slice(&witness_tag);`
/// empties the tag agreement from the other side, and
/// `witness_plaintext.copy_from_slice(...);` empties the plaintext agreement.
///
/// So the gap between the witness call's `;` and the comparison is pinned to name *none* of
/// the four operands: a write of any spelling (`=`, `copy_from_slice`, `copy_from`,
/// `copy_within`, `fill`, `swap`, `&mut`, a raw-pointer store) has to name its target, so
/// "not named at all" is the deterministic form of "never written". The tag comparison's two
/// operands are pinned here as well, and the exact-text `let agree = ...` pins in
/// `the_decision_outcome_is_fail_closed` hold the rest of the agreement line, so a write
/// hiding *inside* the comparison expression breaks those.
///
/// `encrypt`'s cross-check is the same agreement outside a `witness_ok` block -- the witness
/// tag against the tag `encrypt` is about to return, turned into a rejection path through
/// `accept_or_reject` -- and it carries the same rule: an inserted
/// `witness_tag.copy_from_slice(&tag);` there was measured green at the same 128 passed / 0
/// failed / 7 ignored.
#[test]
fn the_witness_outputs_reach_the_agreement_unwritten() {
    let blocks = brace_blocks("let witness_ok: subtle::Choice = {");
    assert_eq!(
        blocks.len(),
        2,
        "one `ultra` witness-agreement block per decrypt entry point"
    );
    for block in &blocks {
        let code = strip_comments(block);

        // The main path's recovered plaintext, the plaintext comparison's other operand:
        // `plaintext` in `decrypt` (a slice, against the witness's slice), the caller's
        // `buffer` in `decrypt_in_place_detached`. Derived from the block rather than
        // assumed by position, so the two blocks cannot be swapped under this check.
        let recovered = if code.contains("witness_plaintext.as_slice().ct_eq(plaintext.as_slice())")
        {
            "plaintext"
        } else if code.contains("witness_plaintext.ct_eq(buffer)") {
            "buffer"
        } else {
            panic!(
                "the witness block's plaintext comparison is neither known shape, so this \
                 test cannot tell what its operands are:\n{block}"
            );
        };

        // The witness's tag is received by one `let mut witness_tag =` binding, directly
        // from the call.
        assert_eq!(
            code.matches("let mut witness_tag =").count(),
            1,
            "the witness tag must be received by exactly one `let mut witness_tag =` binding \
             (a second binding of the name would shadow the first):\n{block}"
        );
        let decl_at = code
            .find("let mut witness_tag =")
            .expect("asserted present above");
        let call_at = decl_at
            + code[decl_at..]
                .find("witness::decrypt(")
                .expect("the binding must be initialised from the witness call");
        assert!(
            code[decl_at + "let mut witness_tag =".len()..call_at]
                .trim()
                .is_empty(),
            "`witness_tag` must be bound *directly* from `witness::decrypt(...)`, with no \
             other expression in between:\n{block}"
        );

        let stmt_end = statement_end(&code, call_at);
        let agree_at = code
            .find("let agree =")
            .expect("the witness block must bind `agree`");
        assert!(
            agree_at > stmt_end,
            "the agreement must follow the witness call:\n{block}"
        );

        // The gap: comments are already stripped, so any mention here is code, and every
        // write to one of these names is a mention of it.
        let gap = &code[stmt_end..agree_at];
        for name in [
            "witness_tag",
            "witness_plaintext",
            "computed_tag",
            recovered,
        ] {
            assert!(
                !contains_word(gap, name),
                "`{name}` must not be mentioned between the `witness::decrypt(...)` call and \
                 the `let agree = ...` comparison. A write of any spelling here -- an \
                 assignment, `copy_from_slice`, `copy_from`, `fill`, `swap`, `&mut` -- has to \
                 name its target, so \"mentioned nowhere\" is the deterministic form of \
                 \"never written\": a mention is either a write to `{name}` or an expression \
                 that moves `{name}`'s value somewhere else, and both make one half of the \
                 agreement compare a value with itself (measured: \
                 `witness_tag.copy_from_slice(&computed_tag);`, \
                 `computed_tag.copy_from_slice(&witness_tag);` and \
                 `witness_plaintext.copy_from_slice(...);` each left the whole \
                 `--features ultra` suite green at 128 passed / 0 failed / 7 ignored).\n\
                 Gap was:\n{gap}"
            );
        }

        // The tag comparison's operands are that binding and the computed tag, and the
        // comparison is the `agree` binding's initialiser rather than a dropped one.
        assert_eq!(
            code.matches("witness_tag.ct_eq(&computed_tag)").count(),
            1,
            "the agreement must compare the witness tag against the computed tag exactly \
             once:\n{block}"
        );
        let cmp_at = code
            .find("witness_tag.ct_eq(&computed_tag)")
            .expect("asserted present above");
        assert!(
            cmp_at > agree_at,
            "the tag comparison must be the `agree` binding's initialiser, not an earlier \
             comparison whose result is dropped:\n{block}"
        );
        assert_eq!(
            code.matches("witness_tag.ct_eq(").count(),
            1,
            "the witness tag must be compared exactly once in the block:\n{block}"
        );
    }

    // `encrypt`'s cross-check is the same agreement outside a `witness_ok` block: the
    // witness tag against the tag `encrypt` is about to return, turned into a rejection
    // path through `accept_or_reject` (see `the_decision_outcome_is_fail_closed`). Same
    // defeat, same rule. It has no `let witness_ok` to find a block by, so it is pinned
    // here rather than in the loop above.
    let non_test = non_test_source();
    let decl = "let mut witness_tag = witness::encrypt_tag(";
    assert_eq!(
        non_test.matches(decl).count(),
        1,
        "`encrypt` must receive the witness tag into one `let mut witness_tag =` binding"
    );
    let decl_at = non_test.find(decl).expect("asserted present above");
    let call_at = decl_at + "let mut witness_tag = ".len();
    let stmt_end = statement_end(&non_test, call_at);
    let agree_line = "let agree: subtle::Choice = witness_tag.ct_eq(&tag);";
    assert_eq!(
        non_test.matches(agree_line).count(),
        1,
        "`encrypt`'s witness agreement must be the `witness_tag.ct_eq(&tag)` comparison"
    );
    let agree_at = non_test.find(agree_line).expect("asserted present above");
    assert!(
        agree_at > stmt_end,
        "`encrypt`'s agreement must follow the witness call"
    );
    let gap = &non_test[stmt_end..agree_at];
    for name in ["witness_tag", "tag"] {
        assert!(
            !contains_word(gap, name),
            "`{name}` must not be touched between `encrypt`'s `witness::encrypt_tag(...)` \
             call and its `let agree = ...` comparison: the same one-line write that empties \
             a decrypt-path agreement empties this one, and it was measured green at 128 \
             passed / 0 failed / 7 ignored as well.\nGap was:\n{gap}"
        );
    }
}
