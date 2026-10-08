//! Security tests: property-based and fuzz. (The statistical timing screen is
//! *not* here — it lives in `tests/timing.rs`, as the paragraph below says; this
//! header used to list "statistical-timing" among this file's contents, which was
//! stale, and `ci.yml`'s qemu step still carries a now-vestigial `--skip timing`
//! for `security-*` on that assumption.)
//!
//! These cover the classes of defect that a fixed known-answer vector cannot:
//! statements quantified over *all* inputs (property tests) and statements
//! about *arbitrary bytes* (a fuzz loop). The KATs pin the construction; these
//! pin its security properties. (An audit caught the second paragraph still
//! listing "statements about *time*" after the first paragraph had been corrected
//! to say the timing screen lives elsewhere.)
//!
//! Tooling note: `cargo-fuzz`/libFuzzer and `ctgrind` are wired up (see
//! `.github/workflows/deep.yml` and `tools/ctgrind.sh`), but the fuzz loop here
//! stays as it is, because it runs in a plain `cargo test` with no extra tooling
//! and no nightly: the deterministic seeded fuzz loop is the regression net that
//! catches a failure without libFuzzer's corpus. The statistical timing screen
//! lives in `tests/timing.rs`, because it is only meaningful on an optimized
//! build. It is a *screen* — it can flag a leak, but passing it is not proof of
//! constant-time behaviour; `tools/ctgrind.sh` is the mechanical check. See
//! `tests/README.md`.

use proptest::prelude::*;
use xchacha20_blake3_siv::{
    decrypt, decrypt_bounded, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, Error,
    KEY_LEN, NONCE_LEN, TAG_LEN,
};

// ── Generators ────────────────────────────────────────────────────────

fn key_strategy() -> impl Strategy<Value = [u8; KEY_LEN]> {
    any::<[u8; KEY_LEN]>()
}

fn nonce_strategy() -> impl Strategy<Value = [u8; NONCE_LEN]> {
    any::<[u8; NONCE_LEN]>()
}

/// Byte vectors, capped well below `MAX_MSG_SIZE` so the tests stay fast.
fn bytes_strategy(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// The same, but never empty. Tests that cannot do anything with an empty input
/// used to filter it with `prop_assume!`, which proptest counts as a *global
/// reject*: at the default 256 cases the ~6% reject rate is invisible, but a run
/// with `PROPTEST_CASES=20000` aborts with "Too many global rejects" long before
/// it finishes the cases it was asked for.
fn nonempty_bytes_strategy(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..max)
}

/// Lengths chosen to straddle every internal boundary: ChaCha20 blocks, the
/// SIMD widths, and BLAKE3's chunk boundary.
const BOUNDARY_LENS: &[usize] = &[
    0, 1, 63, 64, 65, 127, 128, 255, 256, 511, 512, 1023, 1024, 2048,
];

// ── Property: round-trip ──────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `decrypt(encrypt(m)) == m` for every key, nonce, AAD and message.
    #[test]
    fn prop_roundtrip(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in bytes_strategy(300),
        pt in bytes_strategy(2000),
    ) {
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        prop_assert_eq!(ct.len(), pt.len());
        let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        prop_assert_eq!(back.as_slice(), pt.as_slice());
    }

    /// The detached API must agree with the allocating one, byte for byte.
    #[test]
    fn prop_detached_matches_allocating(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in bytes_strategy(200),
        pt in bytes_strategy(1200),
    ) {
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let mut buf = pt.clone();
        let tag2 = encrypt_in_place_detached(&key, &nonce, &aad, &mut buf).unwrap();
        prop_assert_eq!(&buf, &ct);
        prop_assert_eq!(tag2, tag);
        decrypt_in_place_detached(&key, &nonce, &aad, &mut buf, &tag).unwrap();
        prop_assert_eq!(buf, pt);
    }

    /// Flipping a bit of the ciphertext must be rejected.
    ///
    /// This is the property that a truncated-MAC or prefix-comparing
    /// implementation would violate.  Note what this test does and does not do:
    /// `proptest` draws a *single* `(pos, bit)` per case and varies the inputs
    /// across cases, so the coverage over tag positions is statistical, not
    /// exhaustive.  (This comment claimed it was "quantified over every position
    /// rather than sampled", which is not what the strategy does.)  The exhaustive
    /// sweeps are `tests/decision.rs`, which walks all 65 tag bytes for a fixed
    /// vector, and `tests/differential_reference.rs`, which sweeps every position
    /// of a corpus.
    #[test]
    fn prop_ciphertext_bit_flip_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in bytes_strategy(64),
        pt in nonempty_bytes_strategy(64),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let (mut ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let i = pos.index(ct.len());
        ct[i] ^= 1u8 << bit;
        prop_assert_eq!(
            decrypt(&key, &nonce, &aad, &ct, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// Flipping **any** single bit of the tag must be rejected.
    ///
    /// The strategy draws one byte position per case, so this is *sampled*, not a
    /// sweep over all 65 positions (with the default 256 cases, a run leaves at
    /// least one tag byte untried about 71% of the time). The exhaustive
    /// per-position sweeps live in `tests/decision.rs` and
    /// `tests/differential_reference.rs`.
    #[test]
    fn prop_tag_bit_flip_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in bytes_strategy(64),
        pt in bytes_strategy(64),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let (ct, mut tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let i = pos.index(TAG_LEN);
        tag[i] ^= 1u8 << bit;
        prop_assert_eq!(
            decrypt(&key, &nonce, &aad, &ct, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// Flipping any single bit of the AAD must be rejected.
    #[test]
    fn prop_aad_bit_flip_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in nonempty_bytes_strategy(64),
        pt in bytes_strategy(64),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let mut bad = aad.clone();
        let i = pos.index(bad.len());
        bad[i] ^= 1u8 << bit;
        prop_assert_eq!(
            decrypt(&key, &nonce, &bad, &ct, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// A wrong key or a wrong nonce must be rejected. The flipped byte's *position* is
    /// sampled, not fixed at index 0: an implementation that ignored `key[1..]` or
    /// `nonce[1..]` passed while only the first byte was ever disturbed.
    #[test]
    fn prop_wrong_key_or_nonce_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        pt in bytes_strategy(64),
        kpos in any::<prop::sample::Index>(),
        npos in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let (ct, tag) = encrypt(&key, &nonce, b"", &pt).unwrap();

        let mut k2 = key;
        k2[kpos.index(k2.len())] ^= delta;
        prop_assert!(decrypt(&k2, &nonce, b"", &ct, &tag).is_err());

        let mut n2 = nonce;
        n2[npos.index(n2.len())] ^= delta;
        prop_assert!(decrypt(&key, &n2, b"", &ct, &tag).is_err());
    }

    /// **Nonce reuse semantics.** With `(key, nonce)` fixed:
    ///
    ///   * identical `(aad, msg)` gives byte-identical output (the scheme is
    ///     deterministic — that is what makes the KATs meaningful);
    ///   * different `(aad, msg)` gives a different tag, which is what SIV
    ///     promises on nonce reuse (the *ciphertexts* are not promised to differ —
    ///     see the note in the body);
    ///   * and both still decrypt.
    ///
    /// The second point is the reason this construction is usable with a random
    /// nonce: reuse degrades confidentiality but not authenticity.
    #[test]
    fn prop_nonce_reuse_behavior(
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in bytes_strategy(32),
        pt in bytes_strategy(128),
        other in bytes_strategy(128),
    ) {
        let (ct1, tag1) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let (ct1b, tag1b) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        prop_assert_eq!(&ct1, &ct1b);
        prop_assert_eq!(tag1, tag1b);

        // A different message under the same nonce: different **tag**, and each still
        // authenticates under its own tag.
        //
        // The *ciphertexts* are deliberately not asserted to differ. SIV guarantees the tag
        // differs (`2^-520`), and the ciphertext is `M ⊕ KS(tag)`, so `ct1 == ct2` would need
        // `KS₁ ⊕ KS₂ == M₁ ⊕ M₂` — a `2^-8·|M|` event, not a contradiction. With 1-byte
        // messages that is `2^-8`, so an earlier version of this test carried a
        // `prop_assert_ne!(&ct1, &ct2)` that failed spuriously roughly once in 16,000 runs
        // (and, once the corpus grows, more often than that). It asserted something SIV does
        // not promise; the property that *is* promised — distinct tags — is the line above.
        prop_assume!(other != pt);
        let (ct2, tag2) = encrypt(&key, &nonce, &aad, &other).unwrap();
        prop_assert_ne!(tag1, tag2);

        let back1 = decrypt(&key, &nonce, &aad, &ct1, &tag1).unwrap();
        prop_assert_eq!(back1.as_slice(), pt.as_slice());
        let back2 = decrypt(&key, &nonce, &aad, &ct2, &tag2).unwrap();
        prop_assert_eq!(back2.as_slice(), other.as_slice());

        // And the tags are not interchangeable.
        prop_assert!(decrypt(&key, &nonce, &aad, &ct1, &tag2).is_err());
        prop_assert!(decrypt(&key, &nonce, &aad, &ct2, &tag1).is_err());
    }

    /// The AAD/message split must be unambiguous: `(aad, msg)` and a different
    /// split of the same bytes must not authenticate under one another.
    #[test]
    fn prop_aad_message_split_is_bound(
        key in key_strategy(),
        nonce in nonce_strategy(),
        a in nonempty_bytes_strategy(32),
        b in nonempty_bytes_strategy(32),
    ) {
        // Move one byte from the AAD into the message: the concatenation is
        // unchanged, only the split differs.
        let mut a2 = a.clone();
        let moved = a2.pop().unwrap();
        let mut b2 = b.clone();
        b2.insert(0, moved);

        // The tags must differ, because the two lengths are encoded. Under an
        // ambiguous encoding these would be equal and one ciphertext would
        // authenticate under the other's context.
        //
        // As above, the ciphertexts are not asserted to differ: here the plaintext bytes are
        // *identical* (`a ‖ b == a2 ‖ b2`), so `ct1 == ct2` reduces to `KS₁ == KS₂`, a
        // `2^-8·len` event that the two distinct tags do not rule out. The property that
        // matters — the two contexts are not interchangeable — is the pair of decryptions
        // below, not a byte comparison of the ciphertexts.
        let (ct1, tag1) = encrypt(&key, &nonce, &a, &b).unwrap();
        let (ct2, tag2) = encrypt(&key, &nonce, &a2, &b2).unwrap();
        prop_assert_ne!(tag1, tag2);

        // Concretely: a ciphertext authenticated under (a2, b2) must not verify
        // when presented with aad = a.
        prop_assert!(decrypt(&key, &nonce, &a, &ct2, &tag2).is_err());
        prop_assert!(decrypt(&key, &nonce, &a2, &ct1, &tag1).is_err());
    }

    /// Empty inputs at every length boundary must round-trip, so an
    /// off-by-one in the padding or length encoding shows up.
    #[test]
    fn prop_boundary_lengths(
        key in key_strategy(),
        nonce in nonce_strategy(),
        idx in any::<prop::sample::Index>(),
    ) {
        let n = BOUNDARY_LENS[idx.index(BOUNDARY_LENS.len())];
        let pt = vec![0xA5u8; n];
        let aad = vec![0x5Au8; n];
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        prop_assert_eq!(ct.len(), n);
        let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        prop_assert_eq!(back.as_slice(), pt.as_slice());
    }

    /// A tag of all zeros must not be accepted (a MAC that degenerated to
    /// "compare against zero" would accept it).
    #[test]
    fn prop_zero_tag_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        pt in bytes_strategy(64),
    ) {
        let (ct, _) = encrypt(&key, &nonce, b"", &pt).unwrap();
        prop_assert!(decrypt(&key, &nonce, b"", &ct, &[0u8; TAG_LEN]).is_err());
    }
}

/// Fuzzing `decrypt` with arbitrary bytes must never panic and never return
/// plaintext.
///
/// `cargo-fuzz`/libFuzzer is unavailable here, so this is a deterministic
/// replacement: a fixed-seed PRNG drives structured and unstructured inputs, so
/// any failure is reproducible from the seed. It explores far less of the input
/// space than coverage-guided fuzzing, but it does exercise the paths an
/// attacker controls — length, key, nonce, AAD and ciphertext bytes, plus the
/// tag — and the `no_std` crate has no allocator-related panic paths beyond the
/// vector allocations themselves.
#[test]
fn fuzz_decrypt_never_panics_and_never_returns_plaintext() {
    // xorshift64*, so the whole test is reproducible without a dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 33) as u8
        }
        fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next() % n as u64) as usize
            }
        }
    }

    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    for round in 0..20_000u32 {
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        for b in key.iter_mut() {
            *b = rng.byte();
        }
        for b in nonce.iter_mut() {
            *b = rng.byte();
        }

        // Bias toward tiny inputs (where length handling bugs live) and toward
        // boundary lengths, but allow anything up to 1 KiB.
        let ct_len = match round % 4 {
            0 => rng.below(8),
            1 => BOUNDARY_LENS[rng.below(BOUNDARY_LENS.len())],
            _ => rng.below(1024),
        };
        let aad_len = rng.below(64);

        let ct: Vec<u8> = (0..ct_len).map(|_| rng.byte()).collect();
        let aad: Vec<u8> = (0..aad_len).map(|_| rng.byte()).collect();
        let mut tag = [0u8; TAG_LEN];
        for b in tag.iter_mut() {
            *b = rng.byte();
        }

        // The in-place contract, on the structured round's own inputs: the in-place
        // variant used to be exercised only in the unstructured rounds below, so the
        // "valid tag but corrupted input" cases — the ones this round exists for —
        // never reached `decrypt_in_place_detached` at all. `Ok` here is legitimate
        // only when the round left the input intact, and then the buffer must be the
        // plaintext that was encrypted; a failure must zero the caller's buffer.
        macro_rules! in_place_contract {
            ($buf_src:expr, $aad:expr, $tag:expr) => {{
                let mut buf = $buf_src.clone();
                match decrypt_in_place_detached(&key, &nonce, $aad, &mut buf, &$tag) {
                    Ok(()) => assert_eq!(
                        buf, ct,
                        "round {round}: the in-place path accepted but wrote different bytes"
                    ),
                    Err(e) => {
                        assert_eq!(e, Error::AuthenticationFailed);
                        assert!(
                            buf.iter().all(|&b| b == 0),
                            "round {round}: failed in-place decrypt left data in the buffer"
                        );
                    }
                }
            }};
        }

        // Round half the cases through a genuine encrypt, then corrupt, so the
        // "valid tag but corrupted input" path is reached too rather than only
        // the "random tag" path.
        if round % 2 == 0 {
            let (real_ct, real_tag) = encrypt(&key, &nonce, &aad, &ct).unwrap();
            let mut t = real_tag;
            if round % 4 == 0 {
                // Corrupt exactly one thing.
                match rng.below(3) {
                    0 if !real_ct.is_empty() => {
                        let i = rng.below(real_ct.len());
                        let mut c = real_ct.clone();
                        c[i] ^= 1;
                        assert!(decrypt(&key, &nonce, &aad, &c, &t).is_err());
                        in_place_contract!(c, &aad, t);
                        continue;
                    }
                    1 => {
                        let i = rng.below(TAG_LEN);
                        t[i] ^= 1;
                    }
                    _ => {
                        if !aad.is_empty() {
                            let i = rng.below(aad.len());
                            let mut a = aad.clone();
                            a[i] ^= 1;
                            assert!(decrypt(&key, &nonce, &a, &real_ct, &t).is_err());
                            in_place_contract!(real_ct, &a, t);
                            continue;
                        }
                    }
                }
            }
            // Whatever happened, the call must return rather than panic, and
            // must never hand back the plaintext when the tag does not match. "Never
            // returns plaintext" is asserted rather than assumed: an `Ok` here is
            // legitimate only when this round left the input intact (the empty-AAD
            // branch above can), and then it has to be exactly the plaintext that was
            // encrypted -- a wrong plaintext under a matching tag would be a far
            // worse finding than a panic.
            match decrypt(&key, &nonce, &aad, &real_ct, &t) {
                Ok(pt) => assert_eq!(
                    pt.as_slice(),
                    ct.as_slice(),
                    "round {round}: decrypt returned a plaintext that was never encrypted"
                ),
                Err(e) => assert_eq!(e, Error::AuthenticationFailed),
            }
            in_place_contract!(real_ct, &aad, t);
            continue;
        }

        // Unstructured: arbitrary bytes, including the key and nonce, so the tag is
        // a random 520-bit value under a key that was never used to make it. `Ok` is
        // impossible -- it would take a 2^-520 coincidence -- so it is asserted away
        // rather than ignored: an "Ok(_) => {}" here is how a check that never fires
        // reads as a check that passes.
        match decrypt(&key, &nonce, &aad, &ct, &tag) {
            Ok(_) => panic!("round {round}: a random tag authenticated"),
            Err(e) => assert_eq!(e, Error::AuthenticationFailed),
        }

        // The in-place variants must not panic either, and on failure they must
        // leave the caller's buffer zeroed (never the "plaintext").
        let mut buf = ct.clone();
        match decrypt_in_place_detached(&key, &nonce, &aad, &mut buf, &tag) {
            // As above: the same random tag cannot authenticate. The failure path's
            // wipe is asserted because it is the caller's buffer.
            Ok(()) => panic!("round {round}: a random tag authenticated (in place)"),
            Err(e) => {
                assert_eq!(e, Error::AuthenticationFailed);
                assert!(
                    buf.iter().all(|&b| b == 0),
                    "round {round}: failed in-place decrypt left data in the buffer"
                );
            }
        }

        let mut buf2 = ct.clone();
        let _ = encrypt_in_place_detached(&key, &nonce, &aad, &mut buf2);
    }
}
// ── KAT regression lock ───────────────────────────────────────────────
//
// A deliberately duplicated copy of the in-crate KATs. The point is that a
// change to the construction which silently alters the wire format fails here
// even if someone "fixes" the in-crate expectation to match. These values come
// from tools/ref_impl.py, which is anchored to the published RFC 8439, HChaCha20
// and official-BLAKE3 vectors — not from this crate.
//
// That independence is bounded at the *construction* layer, and `ref_impl.py`'s own
// docstring (and `tests/README.md`) says where: the primitives are anchored to vectors
// published by others, but the construction glue — domain strings, counter placement,
// field order and widths, the two-level split — is a transcription of the same design,
// with no external anchor. So this lock (like the differential fixture) catches a
// *divergence* between the crate and the reference, not a shared misreading of the
// specification. It is a lock on the bytes, not a correctness proof.

#[test]
fn kat_regression_lock() {
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    let key: [u8; 32] = hx("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .try_into()
        .unwrap();
    let nonce: [u8; 24] = hx("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .unwrap();
    let aad = hx("50515253c0c1c2c3c4c5c6c7");
    let pt = hx(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
         73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
         6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
         637265656e20776f756c642062652069742e",
    );
    let want_ct = hx(
        "ce8797ab2f9545a09a64c160940cdf2d96fdb7093232db8701d252ac7d897c5c\
        4da16707fb7859c5dcd7c0f6f3f03475ef304270c9eb38b355f08856b293bebb\
        0b0a67c771acb395f6408bec5f27706ca4a251756586f85c925f65ed6d2be08b\
        b759e59368f2125c40babb535377b778b898",
    );
    let want_tag = hx("252fcc32463a1d94bcd0e058d5338d1ca87a026e7974acdf1803d27b7cf68466a4c6180a866b2f4f8712f4a8f0e4bfbad7eabe689a276c86e70c03c68f7dc22f29");

    let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
    assert_eq!(
        ct, want_ct,
        "ciphertext changed: the wire format is no longer what \
                             tools/ref_impl.py generates"
    );
    assert_eq!(tag.as_slice(), want_tag.as_slice(), "tag changed");

    // The empty case pins the empty-AAD and empty-message paths.
    let key2: [u8; 32] = hx("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .try_into()
        .unwrap();
    let (ct2, tag2) = encrypt(&key2, &nonce, b"", b"").unwrap();
    assert!(ct2.is_empty());
    assert_eq!(
        tag2.as_slice(),
        hx("b2834c5164b63c132bbffb4940fb36ead01cf0d90f6352f002775e7e26baa1a0a58e5243f05d27f87a50d45c40e01362b9260bd2d7e04378d7162f671045b785ce").as_slice()
    );
}

// ── Caller-visible limits ───────────────────────────────────────────────

/// `MAX_MSG_SIZE` is public, and that is the half of the memory-exhaustion story a
/// caller can act on.
///
/// `decrypt` allocates a buffer as large as its ciphertext argument, so a service
/// that trusts a length field off the wire has to reject over the limit *before*
/// reading the body — the crate cannot do that on the caller's behalf. This test
/// exists mostly for its compile-time half: it only builds if the constant really
/// is reachable from outside the crate, and it fails if the limit moves without
/// anyone deciding to move it (the format's maximum is 2^38, exactly 2^32 ChaCha20
/// blocks; see `max_msg_size_fits_in_the_block_counter`).
#[test]
fn max_msg_size_is_public_and_is_the_documented_limit() {
    assert_eq!(xchacha20_blake3_siv::MAX_MSG_SIZE, 1u64 << 38);

    // On a 64-bit target the limit is a length a slice could have; on a 32-bit one it
    // is *above* `usize::MAX`, so the guard cannot fire there and a length can never
    // be rejected as too long (the crate's own `test_length_guard_cannot_fire_on_32_bit`
    // records the same asymmetry). Getting this backwards is a compile-time-valid
    // assertion that fails only on the target the tests are least often run on, which
    // is how the first version of this test passed here and failed in the i686 job.
    #[cfg(target_pointer_width = "64")]
    assert!(
        xchacha20_blake3_siv::MAX_MSG_SIZE <= usize::MAX as u64,
        "on 64-bit the limit must be expressible as a length"
    );
    #[cfg(target_pointer_width = "32")]
    assert!(
        xchacha20_blake3_siv::MAX_MSG_SIZE > usize::MAX as u64,
        "on 32-bit the format's limit is above every possible length"
    );
}

/// `decrypt_bounded` refuses an over-long ciphertext *before* allocating.
///
/// The bound is the caller's, not the format's, and this is the entry point for a
/// service whose message length came off the wire: `decrypt` would allocate the
/// buffer first and check nothing, so the limit has to be enforced by a call that
/// cannot be forgotten. The test asserts the refusal, the boundary (equal to the
/// length is allowed), and that the bound does not disturb a normal round trip.
#[test]
fn decrypt_bounded_enforces_the_callers_limit() {
    let key = [0x36u8; 32];
    let nonce = [0x63u8; NONCE_LEN];
    let message = b"a message whose length is known to the test";
    let (ciphertext, tag) = encrypt(&key, &nonce, b"aad", message).unwrap();

    // Under the limit: refused, and nothing is allocated first. (`matches!` because the
    // `Err` variant is the half this test is about; an earlier version of this comment
    // said `Plaintext` could not be compared against another `Plaintext` -- that was true
    // once, and `impl PartialEq<Plaintext> for Plaintext` plus `Debug` exist now, so
    // `assert_eq!` on the `Result` would work too.)
    for max_len in [0, message.len() - 1] {
        assert!(
            matches!(
                decrypt_bounded(&key, &nonce, b"aad", &ciphertext, &tag, max_len),
                Err(Error::MessageTooLong)
            ),
            "a {max_len}-byte limit must refuse a {}-byte ciphertext",
            ciphertext.len()
        );
    }

    // At the limit and above: accepted, and the plaintext is what was encrypted.
    for max_len in [message.len(), message.len() + 1, usize::MAX] {
        assert_eq!(
            decrypt_bounded(&key, &nonce, b"aad", &ciphertext, &tag, max_len).unwrap(),
            message,
            "a {max_len}-byte limit should accept a {}-byte ciphertext",
            ciphertext.len()
        );
    }

    // A bound cannot widen the format's own limit: that check still runs inside, so
    // the two entry points agree whenever the bound itself admits the input.
    assert_eq!(
        decrypt_bounded(&key, &nonce, b"aad", &ciphertext, &tag, usize::MAX)
            .unwrap()
            .as_slice(),
        decrypt(&key, &nonce, b"aad", &ciphertext, &tag)
            .unwrap()
            .as_slice()
    );
}

/// The fallible step in every entry point runs **before** any key material exists.
///
/// `alloc_zeroed` returns `Error::AllocationFailed` instead of aborting, and the
/// `?` that carries it out of the function also skips every `zeroize_array` below —
/// so an allocation taken *after* a derivation returns through live key material.
/// That was a real defect (`encrypt` derived first, and an `AllocationFailed` left
/// `k_in`, `k_out`, `enc_seed`, `enc_key` and `enc_nonce` in the frame), and it came back
/// when `ultra`'s witness buffers were added to `decrypt_in_place_detached` where
/// they are used rather than at the top.
///
/// This is a source-shape assertion, which is unusual here, and it is one because the
/// property is not observable from outside: the failure needs an allocator refusal,
/// and what it leaves behind is stack memory no test can reach. The same reasoning as
/// `tests/decision_scope.rs` applies — the ordering is the fix, so the ordering is
/// what is pinned.
#[test]
fn every_allocation_happens_before_any_derivation() {
    const LIB: &str = include_str!("../src/lib.rs");

    /// The body of `fn name(`, brace-matched.
    fn body(name: &str) -> String {
        let start = LIB
            .find(&format!("pub fn {name}("))
            .unwrap_or_else(|| panic!("{name} not found"));
        let after = &LIB[start..];
        let open = after.find('{').expect("block without a body");
        let mut depth = 0usize;
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return after[..=open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in {name}");
    }

    // All three allocating entry points: the allocation must exist (deleting it would
    // make the ordering assertion below vacuous) and precede the first derivation.
    for name in ["encrypt", "decrypt", "decrypt_in_place_detached"] {
        let body = body(name);
        assert!(
            body.contains("alloc_zeroed("),
            "{name} has no allocation at all -- is it still there?"
        );
    }

    // Every entry point, including the in-place encryptor that allocates nothing today:
    // *each* allocation must precede the first derivation. Comparing only the first
    // `alloc_zeroed(` with the first derivation was the hole -- the historical defect
    // (an allocation added at its use site, after `derive_tag`) passed as long as the
    // original early allocation stayed, and a new allocation in a function the list did
    // not name was never looked at. A late allocation is the one whose `?` returns
    // through live key material.
    for name in [
        "encrypt",
        "encrypt_in_place_detached",
        "decrypt",
        "decrypt_in_place_detached",
    ] {
        let body = body(name);
        let derive = body
            .find("derive_material(")
            .unwrap_or_else(|| panic!("{name} derives no key material"));
        for (alloc, _) in body.match_indices("alloc_zeroed(") {
            assert!(
                alloc < derive,
                "{name} allocates at byte {alloc}, after deriving key material at byte \
                 {derive}: an `AllocationFailed` from that `?` returns through live key \
                 material without wiping it. Move the allocation above the first derivation \
                 (and say why in a comment, because it looks like it can go anywhere)."
            );
        }
    }

    // And `ultra` adds its own buffers, which is how this came back: the witness writes
    // into caller slices, so those allocations are in the entry points too -- and all of
    // them must be on the early side of the same line.
    let in_place = body("decrypt_in_place_detached");
    for buffer in ["witness_ciphertext", "witness_plaintext"] {
        let site = in_place
            .find(&format!("let mut {buffer} = match alloc_zeroed("))
            .unwrap_or_else(|| {
                panic!(
                    "`ultra`'s {buffer} is no longer a `match` on a fallible allocation: an \
                     infallible one aborts the process on refusal (worse), and a plain `?` \
                     returns without the wipe the doc promises"
                )
            });
        assert!(
            site < in_place.find("derive_material(").unwrap(),
            "`ultra`'s {buffer} is allocated after the derivations"
        );
    }
    // The failure arm of each match must wipe the caller's buffer before returning: the
    // doc says "on failure the buffer is zeroized", and an audit measured the `?` version
    // returning `Err(AllocationFailed)` with the caller's ciphertext still in place.
    assert_eq!(
        in_place
            .matches("zeroize_slice(buffer);\n            return Err(e);")
            .count(),
        2,
        "both `ultra` allocation failures must zeroize the caller's buffer before returning"
    );
}
