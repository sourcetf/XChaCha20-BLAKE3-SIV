//! Security tests: property-based, statistical-timing, and fuzz.
//!
//! These cover the classes of defect that a fixed known-answer vector cannot:
//! statements quantified over *all* inputs (property tests), statements about
//! *time* (a dudect-style test), and statements about *arbitrary bytes* (a fuzz
//! loop). The KATs pin the construction; these pin its security properties.
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

    /// Flipping **any** single bit of the ciphertext must be rejected.
    ///
    /// This is the property that a truncated-MAC or prefix-comparing
    /// implementation would violate, and it is quantified over every position
    /// rather than sampled.
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

    /// Flipping **any** single bit of the tag must be rejected, at every one of
    /// the 65 byte positions.
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

    /// A wrong key or a wrong nonce must be rejected.
    #[test]
    fn prop_wrong_key_or_nonce_rejected(
        key in key_strategy(),
        nonce in nonce_strategy(),
        pt in bytes_strategy(64),
        delta in 1u8..=255,
    ) {
        let (ct, tag) = encrypt(&key, &nonce, b"", &pt).unwrap();

        let mut k2 = key;
        k2[0] ^= delta;
        prop_assert!(decrypt(&k2, &nonce, b"", &ct, &tag).is_err());

        let mut n2 = nonce;
        n2[0] ^= delta;
        prop_assert!(decrypt(&key, &n2, b"", &ct, &tag).is_err());
    }

    /// **Nonce reuse semantics.** With `(key, nonce)` fixed:
    ///
    ///   * identical `(aad, msg)` gives byte-identical output (the scheme is
    ///     deterministic — that is what makes the KATs meaningful);
    ///   * different `(aad, msg)` gives a different tag *and* different
    ///     ciphertext, which is what SIV promises on nonce reuse;
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

        // A different message under the same nonce: different tag, different
        // ciphertext, and each still authenticates under its own tag.
        prop_assume!(other != pt);
        let (ct2, tag2) = encrypt(&key, &nonce, &aad, &other).unwrap();
        prop_assert_ne!(tag1, tag2);
        prop_assert_ne!(&ct1, &ct2);

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
        let (ct1, tag1) = encrypt(&key, &nonce, &a, &b).unwrap();
        let (ct2, tag2) = encrypt(&key, &nonce, &a2, &b2).unwrap();
        prop_assert_ne!(tag1, tag2);
        prop_assert_ne!(&ct1, &ct2);

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
                            continue;
                        }
                    }
                }
            }
            // Whatever happened, the call must return rather than panic, and
            // must never hand back the plaintext when the tag does not match.
            match decrypt(&key, &nonce, &aad, &real_ct, &t) {
                Ok(_) => {}
                Err(e) => assert_eq!(e, Error::AuthenticationFailed),
            }
            continue;
        }

        // Unstructured: arbitrary bytes.
        match decrypt(&key, &nonce, &aad, &ct, &tag) {
            Ok(_) => {}
            Err(e) => assert_eq!(e, Error::AuthenticationFailed),
        }

        // The in-place variants must not panic either, and on failure they must
        // leave the caller's buffer zeroed (never the "plaintext").
        let mut buf = ct.clone();
        match decrypt_in_place_detached(&key, &nonce, &aad, &mut buf, &tag) {
            Ok(()) => {}
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
        "39d8c2bc507e147e719d79975b5cf999f0313790d98f7b523f3f4d738116822b\
        3b582ecf7b448d43b3074761cf5c6c2af92faabaf04c779c5f5fe8aa3d3b2a65\
        88137488b453d3728452341483725c9ba1b5ee36d2cf9c743da4df8c4f602385\
        2db6a85e82fcf58636d38768d88c881d56e5",
    );
    let want_tag = hx("6f463e1fb35a5c7727a73bc194a826a4607a7a885b6bdc4622a8a118e673f786800e0fbff12d3d6db861042eb88bda44ca69a9f222417ecea36525ebb9390bb2b6");

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
        hx("1db104f0e59673b1426fc2febf34b719273295bc5d04f7accd04a1181aa5495af53f3924cc55cbf08d17d640ad8af582b49fa64eafb82856f927b3ff173f75996e").as_slice()
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

    // Under the limit: refused, and nothing is allocated first. (`matches!` rather
    // than `assert_eq!`: `Plaintext` compares against byte slices, not against
    // another `Plaintext`, deliberately — see its `PartialEq` impls.)
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
