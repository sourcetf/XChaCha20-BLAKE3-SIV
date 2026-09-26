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

/// Every brace-matched block in `LIB` that starts at `needle`, `needle` included.
///
/// Used to pull a block of the source out for assertions about its shape: the two
/// `accept_or_reject` definitions, and the two `hardened` gate blocks.
fn brace_blocks(needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = LIB;
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

/// Locate both `accept_or_reject` definitions by name and return their full text,
/// body included, brace-matched.
///
/// There are two because the function is `#[cfg]`-selected: the default build
/// converts one `Choice`, and `--features hardened` converts two. Only one of them
/// exists in any given build, and both are in the source, so a test can inspect
/// both.
fn definitions() -> Vec<String> {
    brace_blocks("fn accept_or_reject(")
}

/// Every `fun:` and error-kind line in `tests/ctgrind.supp`, comments removed.
fn suppression_lines(prefix: &str) -> Vec<String> {
    SUPP.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(prefix))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_suppression_file_names_only_the_decision() {
    let funs = suppression_lines("fun:");
    assert!(
        !funs.is_empty(),
        "tests/ctgrind.supp has no entries left: the file is the record of what \
         has been examined and permitted, and an empty file would mean the SIV \
         decision is no longer permitted anywhere -- see tools/ctgrind.sh, which \
         requires at least one entry"
    );
    for f in &funs {
        assert!(
            f.contains("accept_or_reject"),
            "tests/ctgrind.supp suppresses `{f}`. A valgrind entry permits *every* \
             conditional jump in the function it names, not just the one that was \
             reviewed, so an entry naming anything but the accept/reject decision \
             silently re-opens the hole this file documents: a secret-dependent \
             branch planted inside that function would pass the check."
        );
    }

    let kinds = suppression_lines("Memcheck:");
    assert!(!kinds.is_empty(), "entries without an error kind");
    for k in &kinds {
        assert_eq!(
            k, "Cond",
            "the decision is a conditional jump; permitting another error class \
             (`{k}`) would permit something that was not reviewed"
        );
    }
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

    // Comments are stripped first: a future comment containing the word "for" or a
    // question mark must not read as a loop or a `?`.
    let code: String = def
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

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
        assert_eq!(
            block.matches("let second =").count(),
            1,
            "the block must compute its second gate exactly once -- two `if`s over \
             one shared value is one gate with two branches:\n{block}"
        );
    }

    // And the duplication is real duplication: the first gate's expression appears
    // once per entry point, so a refactor that shares one computation between both
    // decrypt paths would remove a gate from one of them.
    assert_eq!(
        LIB.matches("let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);")
            .count(),
        2,
        "the first gate must be computed once per decrypt entry point"
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
        LIB.matches("let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);")
            .count(),
        2,
        "each entry point must start slot 0 as a rejection"
    );
    assert_eq!(
        LIB.matches("let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);")
            .count(),
        2,
        "each entry point must start slot 1 as a rejection"
    );
    // The two checks sit in series, each jumping to the rejection, so accepting is the
    // fall-through of both: a single corrupted branch lands on a rejection.
    assert_eq!(
        LIB.matches("if decision0.is_err() {").count(),
        2,
        "one first check per entry point"
    );
    assert_eq!(
        LIB.matches("if decision1.is_err() {").count(),
        2,
        "one second check per entry point"
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
            LIB.matches(sequence.as_str()).count(),
            2,
            "both entry points must carry the fail-closed sequence:\n{sequence}"
        );
    }

    // The default build passes the same `Choice` twice (the second gate is compiled
    // out there), which is also what keeps the signature -- and the symbol the
    // suppression names -- identical in both builds.
    assert_eq!(
        LIB.matches("accept_or_reject(auth_ok, auth_ok, ").count(),
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
            LIB.contains(signature),
            "the decision must take the outcome by `&mut`, not return it: {signature}"
        );
    }

    // And the wipe lives in the *caller*, on the path every rejection takes -- the
    // decision function no longer touches the buffer, so a skipped call still wipes.
    assert_eq!(
        LIB.matches("if decision0.is_err() {\n        zeroize_slice(")
            .count()
            + LIB
                .matches("if decision1.is_err() {\n        zeroize_slice(")
                .count(),
        4,
        "each of the four reject checks must wipe before returning"
    );
    // There must be no conditional jump *to the accept path*: accepting is the
    // fall-through of the two reject checks, so a corrupted branch lands on a
    // rejection instead of on `Ok`. An `if <decision>.is_ok() { .. Ok(..) }` shape is
    // exactly what the two-slot rewrite removed, and it is one opcode bit from
    // accepting a forgery.
    assert_eq!(
        LIB.matches("if decision0.is_ok()").count() + LIB.matches("if decision1.is_ok()").count(),
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
            LIB.matches(tail.as_str()).count(),
            1,
            "the accept must be the fall-through of both reject checks:\n{tail}"
        );
    }
}
