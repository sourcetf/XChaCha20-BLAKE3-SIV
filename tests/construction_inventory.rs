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
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = &src[..cut];

    let mut report = String::new();
    for (call, expected) in PRIMITIVE_CALLS {
        let found = body
            .lines()
            .filter(|l| {
                let code = l.split("//").next().unwrap_or("");
                // The definitions themselves are not call sites.
                !code.trim_start().starts_with("fn ")
                    && !code.trim_start().starts_with("pub fn ")
                    && !code.trim_start().starts_with("unsafe fn ")
                    && code.contains(call)
            })
            .count();
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
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = &src[..cut];
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
    // Cut at `mod tests {` before searching. The searched string occurs in this file's *own*
    // test module too (the nonce-reuse unit test writes the same line), so searching the whole
    // file made the assertion true even with the real write at `derive_material` deleted — a
    // guard satisfied by the test that was supposed to need it. The sibling test above already
    // cuts at `mod tests {`; this one did not.
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("the test module must exist");
    let body = &src[..cut];
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
