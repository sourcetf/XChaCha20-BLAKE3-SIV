//! The construction's primitive uses, inventoried — and the separations between them.
//!
//! `SECURITY-ANALYSIS.md` §4.10 answers "does combining ChaCha20, HChaCha20 and BLAKE3 in
//! *this* way introduce a problem none of them has alone?" with a case analysis over the
//! five uses of the primitives and the six values that flow between them. The part of that
//! argument which rots silently is its *completeness*: a sixth use (a new hash, a second
//! keystream, a re-derivation somewhere) would need the whole case analysis redone, and
//! nothing else in the suite would notice — a sixth use of a correct primitive still passes
//! every behavioural test.
//!
//! The inventory therefore also counts the one cryptographic call that is *not* part of that
//! composition — the unkeyed `blake3::hash` behind `locked`'s key-integrity tag, which §4.10
//! argues separately — so that adding or moving *that* call is caught here too. What the count
//! pins is "the set of primitive call sites has not changed", not "these are all construction
//! uses".
//!
//! So the completeness claim is pinned here, the way `tests/variable_latency.rs` pins its
//! inventories: a change fails this file until somebody updates the analysis. The *value*
//! level half of the argument — that the two ChaCha20 uses really are at different points —
//! lives in the crate's unit tests (`mod tests`), because only those can reach the internal
//! derivation.

use xchacha20_blake3_siv::{DOM_ENC, DOM_TAG, SUBKEY_DOMAIN};

/// The cryptographic calls in the non-test source, with how many call sites each has.
///
/// These are the five uses of §4.10, plus the one call outside the construction:
///
/// * `hchacha20` — U1, the subkey;
/// * `chacha20_keystream_raw` — U2, the 64-byte key-material block (counter 0);
/// * `blake3_keyed_xof` — U4, the per-message key; U3 (the tag) goes through
///   `blake3_keyed_multi` from `derive_tag`, which also has the two concatenation shapes;
/// * `chacha20_keystream` and `chacha20_apply` — U5, the data keystream, in the allocating
///   and in-place entry points;
/// * `blake3::hash` — *not* a construction use: the unkeyed hash behind `locked`'s
///   key-integrity tag (§4.10, "the one call outside the construction"). Counted here so a
///   change to it fails this test too, not because it is part of the composition.
///
/// A count that changes is not automatically a defect. It is a signal that §4.10's table, the
/// assumption tree in §2.1, and the L1 reductions it cites have to be re-checked for the new
/// use — which is what the failure message asks for.
const PRIMITIVE_CALLS: &[(&str, usize)] = &[
    ("hchacha20(", 1),
    ("chacha20_keystream_raw(", 1),
    ("blake3_keyed_xof(", 1),
    ("blake3_keyed_multi(", 3),
    ("chacha20_keystream(", 2),
    ("chacha20_apply(", 4),
    ("blake3::hash(", 1),
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

    // A floor, so deleting the functions cannot make the assertions above vacuous.
    let total: usize = PRIMITIVE_CALLS.iter().map(|(_, n)| n).sum();
    assert!(total >= 13, "the inventory itself shrank: {total}");
}

/// **Lemma S1**: the two keyed-BLAKE3 families have disjoint input spaces.
///
/// The tag is computed over `DOM_TAG ‖ …` and the per-message key over `DOM_ENC ‖ T`. For one
/// byte string to be an input to both, it would have to start with two different 8-byte
/// prefixes. That is what separates the two uses *structurally* — i.e. even in the impossible
/// case `mac_key = enc_seed`, where a merely key-based separation would collapse.
#[test]
fn the_two_blake3_input_spaces_are_disjoint() {
    assert_ne!(
        DOM_TAG, DOM_ENC,
        "the tag domain and the key-derivation domain are the same string, so those two uses \
         of keyed BLAKE3 are separated by nothing but their keys"
    );
    assert_eq!(
        DOM_TAG.len(),
        DOM_ENC.len(),
        "the prefixes must be the same width: the separation is then a byte comparison at a \
         fixed offset, which is what a reader can check by hand"
    );
    assert_eq!(
        DOM_TAG.len(),
        8,
        "a variable-length domain would reintroduce exactly the ambiguity the length fields in \
         `derive_tag` exist to prevent"
    );
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
    let src = include_str!("../src/lib.rs");
    assert!(
        src.contains("subkey_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);"),
        "the label is no longer written into the nonce's first four bytes"
    );
    assert!(
        src.contains("chacha20_keystream_raw(&subkey, 0, &subkey_nonce, &mut material);"),
        "the key-material block no longer uses counter 0 with that nonce"
    );
}
