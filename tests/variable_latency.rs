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
//! This test enumerates every `/` and `%` in the always-compiled non-test source --
//! `src/lib.rs` and `src/witness.rs` -- and requires the set to match the table below
//! exactly: a new one fails the test until someone writes down why it is not a
//! secret-dependent latency, and a removed one fails too (so the table cannot rot). It
//! does not read `src/proofs.rs`, which is `#[cfg(kani)]` and compiled out of every run
//! of this suite; its divisions are bounded-model-checking scaffolding. (An earlier
//! header claimed "the crate's non-test source" while reading only `src/lib.rs`, and
//! did not name `src/proofs.rs` as the exclusion.) It says nothing about whether the
//! listed operations are *actually* safe -- it makes them visible, which is the part
//! that can be automated.
//!
//! The same idea covers the crate's control flow, one section down: `CONTROL_FLOW`
//! counts `if` / `while` / `for` / `loop` / `match` in the non-test source. ctgrind
//! is the *evidence* that no branch depends on secret content -- it reports those
//! mechanically -- so that table is not evidence; it is a tripwire so a branch added
//! or removed anywhere in the crate cannot pass unnoticed while the prose in
//! `README.md` and `SECURITY.md` still claims the old count.
use std::collections::BTreeSet;

/// `(trimmed source line, why it is not a secret-dependent latency)`.
const ALLOWED: &[(&str, &str)] = &[
    (
        "while i < len && (ptr as usize).wrapping_add(i) % align != 0 {",
        "divides by the *alignment* of `usize`, a compile-time constant, not by anything \
         derived from a key, nonce, AAD or message",
    ),
    (
        "MAX_MSG_SIZE % CHACHA20_BLOCK as u64 == 0,",
        "both operands are constants: this is the build-time binding between the length \
         limit and the ChaCha20 block counter, evaluated by the compiler inside a `const` \
         assertion, so no run-time value -- secret or otherwise -- reaches it",
    ),
    (
        "MAX_MSG_SIZE / CHACHA20_BLOCK as u64 <= u32::MAX as u64 + 1,",
        "the same binding, same reason: `const` context, constant operands, no run-time \
         division at all",
    ),
];

/// `(keyword, occurrences in the non-test source)` — `src/lib.rs`.
///
/// Read this with the caveat above: it is a tripwire, not a proof. Every branch here
/// was audited by hand to depend on a length, an alignment, a CPU feature, an enum
/// variant, or the accept/reject decision -- never on the content of a key, nonce,
/// AAD or message -- and ctgrind is what checks that mechanically. The `for` and
/// `while` counts are dominated by the fixed-trip-count loops of the ChaCha20 and
/// BLAKE3 permutations, whose trip counts come from block sizes.
///
/// When one of these numbers changes: look at the branch, decide what it depends on,
/// and update this table, `README.md`, `SECURITY.md` and `tests/README.md` together.
///
/// What the numbers are made of, so a change can be read against this list:
///
/// * the decision function itself: two gate branches, no loops, no `match` (see
///   `tests/decision_scope.rs`, which holds that shape);
/// * six `if decision*.is_err()` checks: the fail-closed shape, on all three call sites --
///   the two decrypt entry points and, under `ultra`, `encrypt`'s cross-check of its own tag
///   against the witness. These *do* depend on the secret-derived accept/reject decision;
///   what makes them constant-time is that each arm writes a *constant* discriminant into
///   the slot rather than a value selected from the condition, so memcheck sees no taint on
///   the branch and the outcome bit they reveal is the one the mode is designed to reveal
///   anyway. They are listed rather than suppressed because they are a branch on that bit;
/// * `decrypt_bounded`'s length check, `decrypt_in_place_detached`'s (which wipes the
///   caller's buffer before returning — see that function's docs), and the `MAX_MSG_SIZE`
///   checks in `derive_tag`: lengths, which are public;
/// * the `locked` module: `Page` allocation, `LockedKey::new`, `lock_range`'s
///   alignment, and `page_size()`'s auxv walk. Every branch there tests a public fact
///   -- a `/proc` open, a full auxv entry, `AT_PAGESZ`, a plausible page size, a
///   syscall result -- and none is reached with secret data in hand (the arithmetic is
///   on addresses, which are not secret);
/// * `random::fill` (branches on whether the OS entropy source succeeded, a public fact
///   about the environment, and its arms are what zero the buffer on the error path);
/// * the `derive_tag` window `match`, on the public message/AAD lengths;
/// * `soft_impl`/`x86_simd` CPU-feature detection: a CPU fact, and `usize` width;
/// * the fallible-allocation and slice-copy helpers, on lengths.
///
/// History, because this tripwire has moved repeatedly and been right each time. The
/// early moves (15 -> 14 when the two `#[cfg]`-selected `accept_or_reject` definitions
/// were merged into one body, back to 15 when `decrypt_bounded`'s bound check was
/// added, 15 -> 17 when the caller's accept branch became two serial reject-first
/// checks) are in `git log` on this file. The most recent moves: the `locked` module and
/// the `ultra` witness took it to 34; moving the witness into its own file --
/// `src/witness.rs`, inventoried on its own below -- while folding its agreement into
/// the existing gate took it back to 30; and 30 -> 31 when `encrypt`'s cross-check
/// against the witness stopped being a comparison-then-branch at the call site and went
/// through `accept_or_reject` like the decrypt side (-1 for that `if`, +2 for the
/// fail-closed checks that replace it, which is the count now).
///
/// `for` moved 28 -> 26 without a loop changing: the scanner was counting the `for` in
/// `unsafe impl Send for LockedKey` and in `impl<const N: usize> PartialEq<…> for Plaintext`
/// as keywords, because its skip test was `starts_with("impl ")`. Both are impl headers, not
/// loops; [`is_impl_header`] now recognises all three spellings, and the four phantom counts
/// are gone.
///
/// `if` moved 31 -> 34 when `locked` gained `deny_debugging`/`is_dumpable`: two `if !ok(…)`
/// returns and one `if !ok(v) { … } else { … }`, every one of them branching on a **syscall
/// return value** (an errno, a public fact about the environment) and never on key, nonce,
/// AAD or message content — the same class as `random::fill`'s error branch above.
///
/// `if` 34 -> 35 when `LockedKey` gained its integrity check: one branch on the result of a
/// **constant-time comparison** of the page's stored tag against a recomputed one. Its outcome
/// is a property of the *page* — whether the hardware corrupted it — and not of any key, nonce,
/// AAD or message, which is the same publicness argument as the decision itself.
///
/// `if` 35 -> 36 and `match` 5 -> 7 when the allocation-failure paths changed: `derive_tag`
/// tries its contiguous buffer with `try_reserve_exact` and falls back to the three-part hash
/// when the allocator refuses (one `if`), and `decrypt_in_place_detached` matches each of
/// `ultra`'s two allocations so the failure arm can zeroize the caller's buffer before
/// returning `Err(AllocationFailed)` (two `match`es). Every one of the three branches tests
/// **whether the allocator could satisfy a request this call just made** — a public fact about
/// the process's memory, never key, nonce, AAD or message content — the same class as
/// `random::fill`'s errno branch above.
///
/// `if` 36 -> 37 when `unlock_range` stopped restoring `MADV_DODUMP` on a refused `munlock`:
/// the new branch is the **return value of the `munlock` syscall**, the same public class as
/// the errno branches above (and the reason it exists: restoring the advice after a refused
/// unlock left a page locked *and* dumpable, which an audit reproduced under a syscall
/// filter).
const CONTROL_FLOW: &[(&str, usize)] = &[
    ("if", 38),
    ("while", 10),
    ("for", 26),
    ("loop", 0),
    ("match", 7),
];

/// The same table for `src/witness.rs`, the `ultra` build's independent second
/// implementation.
///
/// Separate because the file is separate, and because the *reason* the counts are safe
/// is different in kind: this file is a from-scratch ChaCha20/BLAKE3 written to be
/// checked against the crate's, so what it must not do is branch on key, nonce, AAD or
/// message *content*. Its loops run over block indices and chunk boundaries (lengths,
/// hence public) and its branches are length and boundary tests:
///
/// * `if` 3: `ChunkState::start_flag` (is this the chunk's first block -- a counter),
///   `ChunkState::update` (is the block buffer full) and `Hasher::update` (is the chunk
///   buffer full). Counters and lengths;
/// * `while` 5 / `for` 21: `keystream_xor`'s block loop, `ChunkState::update`,
///   `Hasher::add_chunk_cv`'s carry loop, `Hasher::update` and `finalize_xof`'s squeeze
///   loop; and the `for` loops of the ChaCha20 permutation (10 double-rounds), the
///   key/nonce word unpacking, the BLAKE3 round function (7 rounds), the message
///   permutation, the chaining-value extraction and the byte loops of the tag
///   comparison. Trip counts come from `CHACHA20_BLOCK`, `BLAKE3_BLOCK`, `CHUNK_LEN`,
///   `TAG_LEN` and the 8 words of a chaining value, all compile-time constants or
///   public lengths; `add_chunk_cv`'s carry loop runs once per finalised chunk, which
///   is `len / 1024`.
///
/// The one thing to check when this changes: an early return or a `match` on a *byte of
/// state* rather than on a boundary. There is none today.
const WITNESS_CONTROL_FLOW: &[(&str, usize)] = &[
    ("if", 3),
    ("while", 5),
    ("for", 21),
    ("loop", 0),
    ("match", 0),
];

/// Replace every `"..."` literal with nothing, so a `/` inside one is not counted.
fn strip_string_literals(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
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
            out.push(c);
        }
    }
    out
}

/// Every `/` or `%` in `line` that is code rather than a comment or a doc comment.
fn has_division(line: &str) -> bool {
    // String literals are removed *first*: `b"/proc/self/status\0"` is a path, not a
    // division, and a `//` inside a literal would otherwise cut the rest of the line at
    // the comment marker and hide a real `/` written after it.
    let code = strip_string_literals(line);
    let code = code.split("//").next().unwrap_or("");
    let b: Vec<char> = code.chars().collect();
    for (i, c) in b.iter().enumerate() {
        if *c != '/' && *c != '%' {
            continue;
        }
        let prev = if i == 0 { ' ' } else { b[i - 1] };
        let next = if i + 1 == b.len() { ' ' } else { b[i + 1] };
        // Skip comment markers. `next == '='` used to be in this list, which meant a
        // *compound assignment* (`x /= n`, `x %= n`) was invisible to the inventory --
        // and `/=` divides just as much as `/` does. The marker case that matters is
        // `//` and `/*`, handled by `prev`.
        if prev == '*' || prev == '/' || next == '*' || next == '/' {
            continue;
        }
        return true;
    }
    false
}

#[test]
fn variable_latency_operations_are_inventoried() {
    // Both always-compiled source files, so a division added to the independent
    // implementation is inventoried too (`src/proofs.rs` is `#[cfg(kani)]`; see the
    // module header).
    let sources = [
        ("src/lib.rs", include_str!("../src/lib.rs")),
        ("src/witness.rs", include_str!("../src/witness.rs")),
    ];
    let found: BTreeSet<String> = sources
        .iter()
        .flat_map(|(_, src)| {
            let cut = src.find("mod tests {").unwrap_or(src.len());
            src[..cut].lines()
        })
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

/// Whether a line is an `impl` header, in any of the three spellings.
///
/// This function exists because the first version of the skip was `starts_with("impl ")`,
/// which misses `impl<const N: usize> PartialEq<[u8; N]> for Plaintext` (no space after
/// `impl`) and `unsafe impl Send for LockedKey` (an `unsafe` prefix) — so the `for` in
/// those headers was counted as a loop, and the table carried phantom `for`s. It was
/// found by adding two `unsafe impl` lines and watching the `for` count move by two while
/// adding no loop: a tripwire that fires on a false positive is a tripwire people learn to
/// update without reading, which is the failure mode this test exists to avoid.
fn is_impl_header(code: &str) -> bool {
    let trimmed = code.trim_start();
    let after_unsafe = trimmed.strip_prefix("unsafe ").unwrap_or(trimmed);
    match after_unsafe.strip_prefix("impl") {
        Some(rest) => rest.starts_with(' ') || rest.starts_with('<'),
        None => false,
    }
}

/// Whole-word occurrences of `kw` in code, ignoring comments and string literals.
///
/// `impl Drop for Plaintext` is not a branch, so `impl` headers are skipped — see
/// [`is_impl_header`] for why that test is not just `starts_with("impl ")`.
fn count_keyword(line: &str, kw: &str) -> usize {
    // String literals are removed *before* the comment split, for the same reason as in
    // `has_division`: a `"http://"` literal would otherwise truncate the line at the
    // `//` inside it and hide any keyword after it. A `"..."` literal becomes nothing.
    // This walks characters rather than replacing the literal in place: the substitute
    // must contain no quote at all, or the search finds it again -- an empty literal
    // `""` replaced by `""` loops forever, which is how this test hung the first time it
    // ran.
    let mut stripped = String::with_capacity(line.len());
    let mut in_literal = false;
    let mut escaped = false;
    for c in line.chars() {
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
    let code = stripped.split("//").next().unwrap_or("");
    if is_impl_header(code) {
        return 0;
    }

    let bytes = code.as_bytes();
    let mut n = 0;
    for (i, _) in code.match_indices(kw) {
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
    let lib = include_str!("../src/lib.rs");
    let witness = include_str!("../src/witness.rs");

    // Every file of the crate that has branches is listed here, so "the crate's control
    // flow is inventoried" stays true when a file is added rather than quietly covering
    // part of the crate. `src/proofs.rs` is deliberately not listed: it is
    // `#[cfg(kani)]`, compiled out of every build this suite runs in, and its loops are
    // bounded-model-checking scaffolding rather than shipped code -- Kani's own harnesses
    // state what they must hold.
    // Every keyword must have a row. The loop below only checks the rows the table
    // carries, so deleting one (say `("match", 5)`) would silently stop counting that
    // keyword while every remaining row still matches -- the division table is protected
    // by its added/gone diff, this one needs the row list itself pinned.
    const KEYWORDS: [&str; 5] = ["if", "while", "for", "loop", "match"];
    for (name, src, table) in [
        ("src/lib.rs", lib, CONTROL_FLOW),
        ("src/witness.rs", witness, WITNESS_CONTROL_FLOW),
    ] {
        let keys: Vec<&str> = table.iter().map(|(kw, _)| *kw).collect();
        assert_eq!(
            keys, KEYWORDS,
            "{name}'s control-flow table must carry exactly the {KEYWORDS:?} rows, in that \
             order: a missing row is a keyword nothing counts"
        );
        let cut = src.find("mod tests {").unwrap_or(src.len());
        let body = &src[..cut];

        let mut drifted = Vec::new();
        let mut report = String::new();
        for (kw, expected) in table {
            let found: usize = body.lines().map(|l| count_keyword(l, kw)).sum();
            report.push_str(&format!("      {kw:>5}: {found}\n"));
            if found != *expected {
                drifted.push(format!(
                    "{kw}: source has {found}, the table says {expected}"
                ));
            }
        }

        assert!(
            drifted.is_empty(),
            "{name}'s control flow changed: {drifted:?}\n\nfound:\n{report}\n\
             A branch was added, removed or moved. Work out what the new one depends on \
             (a length, an alignment, a CPU feature, an enum variant, or the decision -- \
             never the content of a key, nonce, AAD or message; ctgrind checks that \
             mechanically), then update the table for that file, README.md, SECURITY.md \
             and tests/README.md together."
        );
    }
}
