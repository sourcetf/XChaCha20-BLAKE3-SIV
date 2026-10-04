//! The ChaCha20 block counter's range, and the one property that keeps a message
//! inside it.
//!
//! `MAX_MSG_SIZE` is 2^38 bytes, which is 2^32 blocks of 64 — exactly the number of
//! values a `u32` counter has, `0 ..= u32::MAX`, with no margin. Every keystream path
//! increments with `ctr.wrapping_add(1)`, the scalar one and both SIMD ones, so if the
//! limit were raised the counter would wrap to 0 *inside a single message* and reuse
//! keystream from the start of that message: silent, and catastrophic.
//!
//! That is bound twice, deliberately:
//!
//! * a `const` assertion in `src/lib.rs`, which makes raising the limit a **build**
//!   failure rather than a test failure (`MAX_MSG_SIZE = (1 << 38) + 64` does not
//!   compile — measured, not assumed), and
//! * this file: the same arithmetic at run time, on every target including the 32-bit
//!   ones where `usize` cannot express the limit at all, plus the property that makes
//!   the reachable range `0 ..= blocks - 1` for *any* admitted message — every call
//!   site starts the counter at zero.
//!
//! The counter range is a property of the whole call graph, not of one function, which
//! is why the second test reads the source instead of calling anything: a future
//! streaming or multi-part API would have to start the counter somewhere else, and that
//! is exactly the change that must not pass unnoticed.
//!
//! The scan is textual, so it has an evasion surface as well as a false-positive
//! surface, and both are handled rather than assumed away: comments and string
//! literals are stripped first (a `//` inside a string used to cut a line short, and a
//! `/* … */` block was scanned as code), calls may be spelled with whitespace before
//! the `(` and may span lines, `use … as …` aliases of a scanned name are rejected
//! outright, and the call count is asserted **exactly** rather than as a floor — a
//! floor let a renamed `chacha20_block` drop the count from 13 to 11 and still pass.

use xchacha20_blake3_siv::MAX_MSG_SIZE;

/// The ChaCha20 block size, restated here on purpose: this is the *format's*
/// arithmetic, so it must not take its own constants from the crate under test.
const BLOCK: u64 = 64;

/// The keystream call sites the scan below looks for, and the exact number of
/// hits each name must have in the non-test source. `(name, expected)`: the sum is
/// asserted too, so a name added to or removed from the source without this table
/// following fails here.
///
/// The list used to be the first two names only, so a call routed through
/// `chacha20_keystream_raw`, a SIMD kernel or the scalar `chacha20_block` was
/// invisible while a lower floor still passed.
const CALL_SITES: &[(&str, usize)] = &[
    ("chacha20_keystream(", 2),
    ("chacha20_apply(", 4),
    ("chacha20_keystream_raw(", 2),
    ("x86_simd::blocks4(", 1),
    ("x86_simd::blocks8(", 1),
    ("aarch64_simd::blocks4(", 1),
    // Not currently called: the zero is a tripwire, so the day a wide aarch64 path
    // starts using it this test asks for the counter argument to be reviewed.
    ("aarch64_simd::blocks8(", 0),
    // The scalar block primitive the kernels' tails fall through to. It was absent
    // from this list, so a call routed through it was invisible: an audit added
    // `chacha20_block(key, 7, nonce)` and this test stayed green. Both real call
    // sites advance a `ctr` the caller owns, so it belongs here.
    ("chacha20_block(", 2),
];

#[test]
fn the_limit_is_exactly_the_block_counters_capacity() {
    let capacity = u32::MAX as u64 + 1;

    assert_eq!(
        MAX_MSG_SIZE % BLOCK,
        0,
        "the limit must be a whole number of blocks"
    );
    assert_eq!(
        MAX_MSG_SIZE / BLOCK,
        capacity,
        "the limit must be exactly the counter's capacity: fewer blocks wastes range, \
         more wraps the counter inside one message"
    );
    // The tighter "one block more would not fit" used to be asserted here as
    // `MAX_MSG_SIZE / BLOCK + 1 > capacity`; that is implied by the equality above
    // (m/64 == c ⇒ m/64 + 1 > c), so it could not fail on its own and was removed
    // rather than left as an assertion that reads like independent evidence.
}

/// Both keystream entry points take `(key, counter, nonce, ...)`: the counter is the
/// second parameter, which is what the call-site check below assumes.
#[test]
fn the_counter_is_the_second_parameter() {
    let src = include_str!("../src/lib.rs");
    for (name, signature) in [
        ("chacha20_keystream", "fn chacha20_keystream("),
        ("chacha20_apply", "fn chacha20_apply("),
    ] {
        let at = src.find(signature).unwrap_or_else(|| {
            panic!("{name} is gone: the counter check below would be checking nothing")
        });
        let open = at + signature.len() - 1;
        let (first, second) = first_two_parameters(src, open);
        assert!(
            second.contains("counter: u32") || second.contains("ctr: u32"),
            "{name}'s second parameter is no longer the counter, so the call-site check \
             below is checking the wrong argument:\n  first:  {first}\n  second: {second}"
        );
    }
}

/// Every call site either starts the counter at zero or passes its own through.
///
/// The entry points start at zero; the internal dispatch passes the counter it was
/// given to the SIMD or scalar implementation. Both keep the reachable range at
/// `0 ..= blocks - 1`, which with the length bound above is `0 ..= u32::MAX`. A future
/// multi-part or streaming API would have to start somewhere else — or *compute* a
/// counter rather than forwarding one — and this fails then, deliberately.
///
/// One exception, and it is scoped by **position** rather than by name: `derive_material`
/// takes one block at counter 0 (the two tag keys) and one at counter 1 (the encryption
/// seed), both single blocks under the *derivation* key. That range is `{0, 1}`, it is
/// fixed, and it shares no key with any message keystream (Theorem 3), so it cannot
/// repeat a counter inside a message. A literal `1` is accepted only for a
/// `chacha20_keystream_raw` call that lies **inside `derive_material`'s body**, and there
/// must be exactly one — so a new helper cannot inherit the allowance by being named like
/// the derivation primitive, and a message-keystream call (where starting at 1 would push
/// the last block to counter `2^32` and wrap) is still rejected.
#[test]
fn every_keystream_call_site_starts_the_counter_at_zero() {
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = strip_comments(&src[..cut]);

    // The line range of `derive_material`'s body, so the one literal-1 allowance can be
    // scoped to it. Brace-matched; a missing function is itself a failure, because the
    // allowance would then have nothing to scope to.
    let derive_lines = {
        let at = body
            .find("fn derive_material(")
            .expect("derive_material is gone: the literal-1 allowance has nothing to scope to");
        let open = at + body[at..].find('{').expect("derive_material has no body");
        let start_line = body[..at].matches('\n').count();
        let mut depth = 0usize;
        let mut end_line = None;
        for (i, c) in body[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_line = Some(body[..open + i].matches('\n').count());
                        break;
                    }
                }
                _ => {}
            }
        }
        start_line..=end_line.expect("derive_material's body is unterminated")
    };

    // An alias would hide every call site below under a new name.
    for (name, _) in CALL_SITES {
        let bare = name.trim_end_matches('(');
        assert!(
            !body.contains(&format!("{bare} as ")),
            "`{bare}` is aliased in the non-test source, which hides its call sites from \
             this scan: the alias is a new name this file does not know"
        );
    }

    let mut seen = vec![0usize; CALL_SITES.len()];
    let mut literal_one = 0;
    for (idx, (name, _)) in CALL_SITES.iter().enumerate() {
        let bare = name.trim_end_matches('(');
        let mut from = 0usize;
        while let Some(rel) = body[from..].find(bare) {
            let at = from + rel;
            from = at + bare.len();
            // The call's `(`, allowing whitespace between the name and it.
            let after = &body[at + bare.len()..];
            let open = at + bare.len() + after.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            if body.as_bytes().get(open) != Some(&b'(') {
                continue; // a mention, not a call (e.g. a `use` or a doc reference)
            }
            let line_start = body[..at].rfind('\n').map_or(0, |i| i + 1);
            let line = body[line_start..].lines().next().unwrap_or("");
            let line_no = body[..at].matches('\n').count() + 1;
            // The definition itself contains the name being searched for.
            let before_on_line = &body[line_start..at];
            if before_on_line.contains("fn ") || before_on_line.trim_start().starts_with("fn ") {
                continue;
            }
            seen[idx] += 1;
            let (first, second) = first_two_arguments(&body, open);
            let arg = second.trim();
            let is_literal_one = arg == "1";
            if is_literal_one {
                literal_one += 1;
            }
            let allowed = arg == "0"
                || arg == "counter"
                || arg == "ctr"
                || (is_literal_one
                    && *name == "chacha20_keystream_raw("
                    && derive_lines.contains(&line_no));
            assert!(
                allowed,
                "src/lib.rs:{line_no} calls `{name}` with a counter that is neither zero nor \
                 the caller's own (so it could be anywhere in the range): {line}"
            );
            // And the counter really is the *second*: the first argument must not be a
            // numeric literal, which is what it would be if a signature reordering moved
            // the counter to position 1 and this loop silently inspected the key instead.
            let first = first.trim();
            assert!(
                !first.is_empty() && !first.chars().next().is_some_and(|c| c.is_ascii_digit()),
                "src/lib.rs:{line_no} passes `{name}` a numeric first argument, so the counter \
                 may no longer be the second parameter and the check above is inspecting the \
                 wrong one: {line}"
            );
        }
    }

    let observed: Vec<(&str, usize, usize)> = CALL_SITES
        .iter()
        .enumerate()
        .map(|(i, (name, expected))| (*name, seen[i], *expected))
        .collect();
    assert!(
        observed.iter().all(|(_, got, want)| got == want),
        "the keystream call-site census moved ({observed:?} as name/got/want): update \
         CALL_SITES deliberately when the construction gains or loses a keystream call \
         (a floor was not enough — a renamed `chacha20_block` slipped under it)"
    );
    assert_eq!(
        literal_one, 1,
        "expected exactly one literal-1 keystream call (the derivation's counter-1 block), \
         found {literal_one}: a second one is either a new derivation block or a message \
         keystream starting at 1, and the latter wraps the counter"
    );
}

/// `text` with `//` line comments and `/* … */` block comments removed, and string
/// literals left as empty `""` so their contents cannot be mistaken for code.
///
/// A plain `line.split("//")` let a string literal containing `//` cut the rest of
/// its line out of the scan (hiding a real call), and never removed block comments
/// (so commented-out code counted as a call site).
fn strip_comments(text: &str) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Code,
        Line,
        Block,
        Str,
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
                    mode = Mode::Block;
                    i += 2;
                } else if c == b'"' {
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
            Mode::Block => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    mode = Mode::Code;
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
                    // Replace the contents so no byte inside a literal is scanned.
                    i += 1;
                }
            }
        }
    }
    out
}

/// The first two top-level comma-separated arguments of the call whose `(` is at
/// `open`, with nesting respected and newlines allowed. Both are empty when the
/// call's `)` closes before a second argument.
fn first_two_arguments(text: &str, open: usize) -> (String, String) {
    let mut depth = 0i32;
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in text[open + 1..].chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' if depth == 0 => {
                args.push(cur);
                break;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur));
                if args.len() == 2 {
                    break;
                }
            }
            _ => cur.push(c),
        }
    }
    while args.len() < 2 {
        args.push(String::new());
    }
    (args[0].clone(), args[1].clone())
}

/// The first two parameters of the signature whose `(` is at `open`.
fn first_two_parameters(text: &str, open: usize) -> (String, String) {
    let (a, b) = first_two_arguments(text, open);
    (a, b)
}
