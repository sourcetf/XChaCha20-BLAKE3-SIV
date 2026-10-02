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

use xchacha20_blake3_siv::MAX_MSG_SIZE;

/// The ChaCha20 block size, restated here on purpose: this is the *format's*
/// arithmetic, so it must not take its own constants from the crate under test.
const BLOCK: u64 = 64;

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
    // Tight in the other direction as well: one block more would not fit.
    assert!(
        MAX_MSG_SIZE / BLOCK + 1 > capacity,
        "the limit must not leave room for a block the counter cannot address"
    );
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
        let head: String = src[at..].chars().take(160).collect();
        assert!(
            head.contains("counter: u32") || head.contains("ctr: u32"),
            "{name}'s second parameter is no longer the counter, so the call-site check \
             below is checking the wrong argument:\n{head}"
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
    let body = &src[..cut];

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

    let mut calls = 0;
    let mut literal_one = 0;
    for (n, line) in body.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        // The definitions themselves contain the names being searched for.
        if code.trim_start().starts_with("fn ") || code.trim_start().starts_with("pub fn ") {
            continue;
        }
        // Every keystream entry point, including the raw (no-XOR) one the derivation
        // path uses and the SIMD kernels. The list used to be the first two, so a call
        // routed through `chacha20_keystream_raw` or `x86_simd::blocks8` would have been
        // invisible here while a lower floor still passed.
        for f in [
            "chacha20_keystream(",
            "chacha20_apply(",
            "chacha20_keystream_raw(",
            "x86_simd::blocks4(",
            "x86_simd::blocks8(",
            "aarch64_simd::blocks4(",
        ] {
            let Some(i) = code.find(f) else { continue };
            calls += 1;
            // `chacha20_keystream(&key, 0, &nonce, ...)`: after the first comma the
            // argument must be a literal zero.  The one literal 1 is the derivation's
            // second block, and only inside `derive_material`.
            let after_key = code[i + f.len()..].split_once(',').map_or("", |(_, a)| a);
            let arg = after_key.trim_start();
            let is_literal_one = arg.starts_with("1,");
            if is_literal_one {
                literal_one += 1;
            }
            let allowed = arg.starts_with("0,")
                || arg.starts_with("counter,")
                || arg.starts_with("ctr,")
                || (is_literal_one && f == "chacha20_keystream_raw(" && derive_lines.contains(&n));
            assert!(
                allowed,
                "src/lib.rs:{} calls `{f}` with a counter that is neither zero nor the \
                 caller's own (so it could be anywhere in the range): {}",
                n + 1,
                line.trim()
            );
            // And the counter really is the *second*: the first argument must not be a
            // numeric literal, which is what it would be if a signature reordering moved
            // the counter to position 1 and this loop silently inspected the key instead.
            let first = code[i + f.len()..].split_once(',').map_or("", |(a, _)| a);
            let first = first.trim();
            assert!(
                !first.is_empty() && !first.chars().next().is_some_and(|c| c.is_ascii_digit()),
                "src/lib.rs:{} passes `{f}` a numeric first argument, so the counter may \
                 no longer be the second parameter and the check above is inspecting the \
                 wrong one: {}",
                n + 1,
                line.trim()
            );
        }
    }
    assert_eq!(
        literal_one, 1,
        "expected exactly one literal-1 keystream call (the derivation's counter-1 block), \
         found {literal_one}: a second one is either a new derivation block or a message \
         keystream starting at 1, and the latter wraps the counter"
    );
    assert!(
        calls >= 11,
        "expected at least eleven keystream call sites in the non-test source, found \
         {calls}: this check is vacuous if the calls moved or were renamed out of the list"
    );
}
