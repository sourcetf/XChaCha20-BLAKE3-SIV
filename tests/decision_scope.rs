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

/// `LIB` with comments removed and string-literal contents blanked, cut at `mod tests {`.
///
/// Every presence and count assertion below runs on this, not on the raw file. Both
/// of those used to be satisfiable without the code: delete a real line and add a
/// comment (or a line inside `mod tests`) carrying the same text, and the count came
/// back to its expected value. Stripping comments and stopping at the test module
/// removes that. The scanner is a small state machine rather than `find("//")`,
/// because a `//` inside a string literal used to cut a line short — which hid a real
/// call site from the count — and a `/* … */` block was scanned as code.
fn non_test_source() -> String {
    let cut = LIB.find("mod tests {").expect("the test module must exist");
    strip_comments(&LIB[..cut])
}

/// See `non_test_source`. Public to the file so each test can build it once.
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
            Mode::Block => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    mode = Mode::Code;
                    i += 2;
                } else {
                    if c == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            Mode::Str => {
                // String literals are copied through unchanged. They are recognised so
                // that a `//` inside one is not read as a comment (which cut the rest
                // of the line out of the scan); their contents are still *code* for
                // the assertions below (`#[cfg(feature = "hardened")]` is a match on
                // one), so blanking them would break the checks instead of hardening
                // them.
                if c == b'\\' {
                    out.push(c as char);
                    if let Some(n) = b.get(i + 1) {
                        out.push(*n as char);
                    }
                    i += 2;
                } else if c == b'"' {
                    out.push('"');
                    mode = Mode::Code;
                    i += 1;
                } else {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
    }
    out
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

    for construct in ["for ", "while ", "loop ", "match "] {
        assert!(
            !code.contains(construct),
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

    // Keywords are matched with their trailing space. A spelling without one (`if(`,
    // `while(`) would slip past this scan, which is a known limit of reading source: the
    // mechanical evidence is ctgrind, which sees the compiled form, and `cargo fmt
    // --check` is a CI gate whose rustfmt always writes the space.
    let branches = code.matches("if ").count();
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
    // the two "comparisons" are one comparison wearing two hats.
    let fold = brace_blocks("fn ct_eq_independent(");
    assert_eq!(fold.len(), 1, "one `ct_eq_independent` expected");
    assert!(
        fold[0].contains("u64::from_le_bytes") && fold[0].contains("acc |= x"),
        "the fold must accumulate 8-byte words into one comparison:\n{}",
        fold[0]
    );
    assert!(
        fold[0].contains("acc.ct_eq(&0u64)"),
        "the fold must end in a constant-time comparison of the accumulator: a body that kept \
         the loop but returned `subtle::Choice::from(1)` passed this test before:\n{}",
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
    assert_eq!(
        code.matches("if decision0.is_err() {\n        zeroize_slice(")
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
    // so it is asserted separately rather than folded into the count above.
    assert_eq!(
        code.matches("if decision0.is_err() {\n            zeroize_array(&mut k_in);")
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
    // immediately by the accept, which is what "fall-through" means in the source.
    for (place, accept) in [
        ("zeroize_slice(&mut plaintext);", "Ok(Plaintext(plaintext))"),
        ("zeroize_slice(buffer);", "Ok(())"),
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
    // the text the `ultra` build compiles.
    assert!(
        LIB.contains("#[cfg(feature = \"ultra\")]\nmod witness;"),
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
