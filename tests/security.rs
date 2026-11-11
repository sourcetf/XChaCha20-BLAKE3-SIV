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

mod common;

use proptest::prelude::*;
use xchacha20_blake3_siv::{
    decrypt, decrypt_bounded, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, Error,
    KEY_LEN, NONCE_LEN, TAG_LEN,
};

// ── Allocation counting ───────────────────────────────────────────────
//
// `decrypt_bounded`'s contract is that the caller's bound is checked *before* the buffer
// is allocated, and the `MessageTooLong` variant alone cannot witness that: a check moved
// below `decrypt` returns the same variant after allocating (and then zeroizing) the
// plaintext. This allocator makes the ordering observable. The count is per-thread, so the
// proptest cases running on other threads of the same binary cannot move it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocator calls made on this thread so far.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Counts allocator calls, then defers to the system allocator.
struct CountingAllocator;

#[global_allocator]
static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

/// One allocator call seen on the calling thread. `try_with` so an allocation made while a
/// thread's TLS is being torn down cannot recurse into a panic here.
fn count_alloc() {
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
}

/// Allocator calls made on the calling thread so far.
fn allocations_on_this_thread() -> u64 {
    ALLOCATIONS.with(|n| n.get())
}

// SAFETY: every method forwards to `System` with the same arguments and returns its
// result; the only addition is a thread-local `Cell<u64>` increment, which allocates
// nothing and cannot recurse into the allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_alloc();
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_alloc();
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_alloc();
        System.alloc_zeroed(layout)
    }
}

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
    0, 1, 63, 64, 65, 127, 128, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2048,
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
        prop_assert_eq!(
            decrypt(&k2, &nonce, b"", &ct, &tag),
            Err(Error::AuthenticationFailed)
        );

        let mut n2 = nonce;
        n2[npos.index(n2.len())] ^= delta;
        prop_assert_eq!(
            decrypt(&key, &n2, b"", &ct, &tag),
            Err(Error::AuthenticationFailed)
        );
    }

    /// **Nonce reuse semantics.** With `(key, nonce)` fixed:
    ///
    ///   * identical `(aad, msg)` gives byte-identical output (the scheme is
    ///     deterministic — that is what makes the KATs meaningful);
    ///   * a different message under the same key, nonce and AAD gives a different tag,
    ///     which is what SIV promises on nonce reuse (the *ciphertexts* are not promised
    ///     to differ — see the note in the body);
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
        prop_assert_eq!(
            decrypt(&key, &nonce, &aad, &ct1, &tag2),
            Err(Error::AuthenticationFailed)
        );
        prop_assert_eq!(
            decrypt(&key, &nonce, &aad, &ct2, &tag1),
            Err(Error::AuthenticationFailed)
        );
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
        prop_assert_eq!(
            decrypt(&key, &nonce, &a, &ct2, &tag2),
            Err(Error::AuthenticationFailed)
        );
        prop_assert_eq!(
            decrypt(&key, &nonce, &a2, &ct1, &tag1),
            Err(Error::AuthenticationFailed)
        );
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
        prop_assert_eq!(
            decrypt(&key, &nonce, b"", &ct, &[0u8; TAG_LEN]),
            Err(Error::AuthenticationFailed)
        );
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
            ($buf_src:expr, $aad:expr, $tag:expr, $must_reject:expr) => {{
                let mut buf = $buf_src.clone();
                match decrypt_in_place_detached(&key, &nonce, $aad, &mut buf, &$tag) {
                    Ok(()) => {
                        // `$must_reject` is true when this round corrupted the ciphertext,
                        // the AAD or the tag. Asserting only `buf == ct` let a tampered
                        // tag through: an implementation that ignored one tag bit would
                        // return the correct plaintext and this arm would call it a pass.
                        assert!(
                            !$must_reject,
                            "round {round}: the in-place path accepted a corrupted input"
                        );
                        assert_eq!(
                            buf, ct,
                            "round {round}: the in-place path accepted but wrote different bytes"
                        );
                    }
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
            let mut tag_tampered = false;
            if round % 4 == 0 {
                // Corrupt exactly one thing.
                match rng.below(3) {
                    0 if !real_ct.is_empty() => {
                        let i = rng.below(real_ct.len());
                        let mut c = real_ct.clone();
                        c[i] ^= 1;
                        assert!(decrypt(&key, &nonce, &aad, &c, &t).is_err());
                        in_place_contract!(c, &aad, t, true);
                        continue;
                    }
                    1 => {
                        let i = rng.below(TAG_LEN);
                        t[i] ^= 1;
                        tag_tampered = true;
                    }
                    _ => {
                        if !aad.is_empty() {
                            let i = rng.below(aad.len());
                            let mut a = aad.clone();
                            a[i] ^= 1;
                            assert!(decrypt(&key, &nonce, &a, &real_ct, &t).is_err());
                            in_place_contract!(real_ct, &a, t, true);
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
            // worse finding than a panic. When the tag was the thing corrupted, `Ok` is
            // never legitimate: without this arm the test accepted a correct-looking
            // plaintext under a flipped tag bit, so an implementation that ignored that
            // bit passed.
            match decrypt(&key, &nonce, &aad, &real_ct, &t) {
                Ok(pt) => {
                    assert!(
                        !tag_tampered,
                        "round {round}: decrypt accepted a tag with one flipped bit"
                    );
                    assert_eq!(
                        pt.as_slice(),
                        ct.as_slice(),
                        "round {round}: decrypt returned a plaintext that was never encrypted"
                    );
                }
                Err(e) => assert_eq!(e, Error::AuthenticationFailed),
            }
            in_place_contract!(real_ct, &aad, t, tag_tampered);
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

        // The in-place encrypt must produce the same wire output as the allocating
        // one; `let _ = ...` only checked that it did not panic, so a wrong returned
        // tag or an unmodified buffer went unnoticed here.
        let (expected_ct, expected_tag) = encrypt(&key, &nonce, &aad, &ct).unwrap();
        let mut buf2 = ct.clone();
        let tag2 = encrypt_in_place_detached(&key, &nonce, &aad, &mut buf2).unwrap();
        assert_eq!(
            buf2, expected_ct,
            "round {round}: in-place encryption wrote different ciphertext"
        );
        assert_eq!(
            tag2, expected_tag,
            "round {round}: in-place encryption returned a different tag"
        );
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
        let before = allocations_on_this_thread();
        let refused = decrypt_bounded(&key, &nonce, b"aad", &ciphertext, &tag, max_len);
        let after = allocations_on_this_thread();
        assert!(
            matches!(refused, Err(Error::MessageTooLong)),
            "a {max_len}-byte limit must refuse a {}-byte ciphertext",
            ciphertext.len()
        );
        // And the refusal must not have allocated the plaintext it refuses to produce. The
        // variant cannot see the difference on its own: an injected copy that checked the
        // bound *after* `decrypt` still returned `MessageTooLong` -- having allocated and
        // dropped the plaintext -- and this test stayed green until the counter existed.
        assert_eq!(
            after,
            before,
            "the refusal at max_len={max_len} allocated {} time(s) before returning \
             MessageTooLong: the bound must be checked before `decrypt`, or an over-long \
             request costs exactly the allocation the bound exists to avoid",
            after - before
        );
    }

    // At the limit and above: accepted, and the plaintext is what was encrypted.
    for max_len in [message.len(), message.len() + 1, usize::MAX] {
        let before = allocations_on_this_thread();
        let accepted = decrypt_bounded(&key, &nonce, b"aad", &ciphertext, &tag, max_len).unwrap();
        let after = allocations_on_this_thread();
        assert_eq!(
            accepted,
            message,
            "a {max_len}-byte limit should accept a {}-byte ciphertext",
            ciphertext.len()
        );
        // The counter is live: an accepted call does allocate its plaintext buffer and the
        // witness copy under `ultra`. Without this, the zero-delta assertions above would
        // also hold for a counter that never fires.
        assert!(
            after > before,
            "the allocation counter saw no allocation on the accepted path, so its \
             zero-delta assertion on the refused path is vacuous"
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
/// what is pinned — and the same hardening applies too: the searched text comes from
/// `non_test_source()`, with comments and string-literal contents removed, so a comment
/// or a dead literal cannot stand in for an allocation or an ordering.
/// The shipped text of `src/lib.rs`, for the one source-shape test below.
const LIB: &str = include_str!("../src/lib.rs");

/// The non-test source of `LIB`: everything outside the body of its `#[cfg(test)]
/// mod tests` module, wherever that module sits in the file.
///
/// Every text search in `every_allocation_happens_before_any_derivation` runs on this.
/// The raw text made `body.contains("alloc_zeroed(")` and the ordering matches satisfiable
/// by a comment or a dead string literal: an audit moved `encrypt`'s allocation below
/// `derive_material` — the historical defect that test exists for, which returns through
/// live key material on `AllocationFailed` — spelled it `alloc_zeroed (` with a space, and
/// left the old call in a comment; the test stayed green with no allocation before the
/// first derivation. `libtest` cannot share items between test binaries, so the scanner is
/// copied from `tests/decision_scope.rs`, `tests/counter_range.rs`, `tests/ultra.rs` and
/// `tests/locked.rs` rather than imported.
///
/// The obvious way to get the cut — truncate at the first `mod tests {` — hides code
/// that is textually *after* the module, because the cut is at the module's first
/// line, not at its closing brace: a production function appended below the test
/// module (legal Rust, compiled in normal builds) is skipped entirely. Measured: a
/// helper carrying a `#[cfg(any())]` and a `zeroize_slice` call appended after the
/// test module left this file's suite green, although
/// `no_constant_cfg_attribute_can_deaden_the_crypto_source` exists to reject exactly
/// that attribute. It also hid a `mod tests {` *mentioned in a comment* before the
/// real one, since the old `find` ran on the raw text; stripping comments and
/// literals first removes that.
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
/// [`non_test_source_of`] asserts no `#[cfg(test)]` survives. That is the invariant that
/// falls out of this function's own name — everything left outside the one test module is
/// non-test source — and it is what closes the second-module planting: a
/// `#[cfg(test)] mod planting { … }` beside the real test module satisfied a count here
/// (and in `tests/ultra.rs`, measured) while the real statement was deleted, because the
/// planted text lies outside the module body this cut removed.
///
/// [`non_test_source_of`] is the same cut for `src/witness.rs`, the other file
/// `no_constant_cfg_attribute_can_deaden_the_crypto_source` scans.
fn non_test_source() -> String {
    non_test_source_of(LIB)
}

/// The total number of `crate::zeroize_array(` / `zeroize_slice(` / `zeroize_raw(` calls
/// in the non-test source, the backstop [`every_documented_wipe_has_a_witness`] pins. The
/// qualified form is required by the same file's shadow check, so counting it counts every
/// wipe primitive the crate calls.
fn full_wipe_calls() -> usize {
    let source = non_test_source();
    [
        "crate::zeroize_array(",
        "crate::zeroize_slice(",
        "crate::zeroize_raw(",
    ]
    .iter()
    .map(|p| source.matches(p).count())
    .sum()
}

/// See [`non_test_source`]: the same cut applied to `text` rather than to `LIB`, for
/// the two files `no_constant_cfg_attribute_can_deaden_the_crypto_source` scans.
fn non_test_source_of(text: &str) -> String {
    non_test_source_of_impl(text, true)
}

/// The same cut with **string-literal contents kept**.
///
/// `strip_comments` blanks every literal, which is right for the counts (a `zeroize_array(`
/// inside a string is not a call) and wrong for the `cfg` scan: it erases the feature names
/// a predicate's atoms are made of, so `all(feature = "a", not(feature = "b"))` reads as one
/// atom repeated and looks constant. The blanket guard evaluates predicates on this cut and
/// keeps only the attributes the blanked cut also sees, so a `#[cfg(…)]` written inside a
/// string literal is still not an attribute.
fn non_test_source_of_keeping_literals(text: &str) -> String {
    non_test_source_of_impl(text, false)
}

fn non_test_source_of_impl(text: &str, blank_literals: bool) -> String {
    let stripped = strip_comments_impl(text, blank_literals);
    let at = stripped
        .find("mod tests {")
        .expect("the scanned file's test module must exist (`mod tests {`)");
    assert_eq!(
        stripped.matches("mod tests {").count(),
        1,
        "the scanned file holds more than one `mod tests {{`: which one is the test \
         module, and what the scan cut, would be ambiguous"
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
    // exactly the planting surface: its text can stand in for code a consumer's build
    // never compiles.
    let out = blank_cfg_test_items(&out);
    match crate::common::find_cfg_test_attribute(&out, 0) {
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

/// `source` with every `#[cfg(test)]`-attributed **item** blanked to spaces (newlines
/// kept, so line numbers stay comparable): the test-only text that lies outside the one
/// `mod tests` module.
///
/// The item's extent is found by skipping any further attributes, then taking the first
/// `{` (brace-matched, so a `;` inside the item's body cannot end it) or the first `;`
/// outside parentheses and brackets. Local variables cannot tell the two apart from
/// modifiers, so a `pub(crate) mod`, an `impl`, and a `let` statement all work; what this
/// does **not** cover is spelled out where the result is asserted — only the plain `test`
/// predicate is matched (`all(test, …)`, `cfg_attr(test, …)` are not), and the item must
/// end in a brace block or a `;`, which attributes on struct fields, match arms or
/// expressions do not. A shape this cannot blank is not silently kept: the caller's
/// assertion rejects any surviving `#[cfg(test)]`, and an item whose extent cannot be
/// found is a panic, not a skip.
fn blank_cfg_test_items(source: &str) -> String {
    let mut out = source.as_bytes().to_vec();
    let mut from = 0usize;
    while let Some((start, close, inner)) = crate::common::find_cfg_test_attribute(source, from) {
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
        if is_attribute_line(trimmed) {
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

/// See [`non_test_source`]: comments and string-literal contents are removed, with newlines
/// kept so line positions stay comparable.
///
/// Block comments are tracked with their **nesting depth**: Rust nests them, and a scanner
/// that exits at the first `*/` reads the rest of the comment as code. Measured before this
/// depth was tracked, `/* /* */ zeroize_array(&mut enc_key); /* */ */` was discarded by
/// rustc but counted here — every wipe in the table below could be commented out of the
/// library a consumer builds while the counts stayed green.
fn strip_comments(text: &str) -> String {
    strip_comments_impl(text, true)
}

fn strip_comments_impl(text: &str, blank_literals: bool) -> String {
    #[derive(PartialEq)]
    enum Mode {
        Code,
        Line,
        /// Inside a block comment, with its **nesting depth**. See the doc above: a
        /// single-depth scanner reports the text between a nested comment's inner `*/`
        /// and the outer one as code.
        Block(usize),
        Str,
        /// Inside a raw string (`r"…"`, `r#"…"#`), whose contents are dropped.
        RawStr(u8),
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
                    // quotes kept. Without this the scanner re-enters code mode at the
                    // first `"` inside the string, and the text between two quotes is
                    // scanned as code — `let _ = r#"x" scrub_stack(); "x"#;` used to
                    // satisfy a `scrub_stack();` count while the real call was spelled
                    // with a space.
                    for k in 0..=prefix {
                        out.push(b[i + k] as char);
                    }
                    i += prefix + 1;
                    mode = Mode::RawStr(hashes);
                } else if c == b'\'' {
                    // A char literal is opaque, and this must come before the `"` case:
                    // `'"'` is a char literal whose *closing* quote would otherwise open
                    // `Mode::Str` and swallow the rest of the scan. A lifetime (`&'a`)
                    // and a lone apostrophe have no closing quote, so the look-ahead
                    // tests for one of the two literal shapes and otherwise treats the
                    // `'` as an ordinary byte.
                    let escaped = b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'');
                    if escaped || b.get(i + 2) == Some(&b'\'') {
                        let len = if escaped { 4 } else { 3 };
                        if !blank_literals {
                            for k in 0..len {
                                out.push(b[i + k] as char);
                            }
                        }
                        i += len;
                    } else {
                        out.push('\'');
                        i += 1;
                    }
                } else if c == b'"' {
                    // Keep the opening quote; the contents are dropped in `Mode::Str`
                    // and the closing quote is kept there.
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
                        out.push('\n'); // keep line numbers aligned
                    }
                    i += 1;
                }
            }
            Mode::Str => {
                if c == b'\\' {
                    // Skip the escaped byte (including `\"`). A newline escaped this way
                    // still ends a raw source line, so it is emitted: dropping it made
                    // this function's output have fewer lines than its input, which
                    // `raw_cfg_predicate_at` (in the guards below) relies on not
                    // happening — it reads a raw line back by line number.
                    if b.get(i + 1) == Some(&b'\n') {
                        out.push('\n');
                    } else if !blank_literals {
                        // Keeping literals means keeping the escape as written.
                        out.push('\\');
                        if let Some(&next) = b.get(i + 1) {
                            out.push(next as char);
                        }
                    }
                    i += 2;
                } else if c == b'"' {
                    out.push('"');
                    mode = Mode::Code;
                    i += 1;
                } else if !blank_literals {
                    // Literal-intact mode: the contents are the scanned text (a `cfg`
                    // predicate's atoms are its feature names).
                    out.push(c as char);
                    i += 1;
                } else {
                    // Drop the contents so no byte inside a literal is scanned. A
                    // newline is the exception, as everywhere else in this function: it
                    // is structure, not contents, and keeping it holds line numbers
                    // comparable.
                    if c == b'\n' {
                        out.push('\n');
                    }
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
                } else if !blank_literals {
                    out.push(c as char);
                    i += 1;
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

/// `pred` evaluated **as a constant** if it is one, ignoring the actual configuration:
/// `Some(b)` means the predicate is `b` in every configuration; `None` means it depends on
/// the configuration. `any` / `all` / `not` are interpreted, plus three leaf constants;
/// every other token is a configuration atom (`feature = "…"`, `target_arch = "…"`,
/// `kani`, …).
///
/// The leaves that are constants here:
///
/// * `true` / `false`, the boolean literals `cfg` predicates accept (rustc 1.88+). This
///   crate's MSRV is 1.85, so `#[cfg(not(true))]` does not compile on every supported
///   toolchain — rejecting it is defence in depth rather than the closing of a live hole;
/// * `test`, which is set only while the crate is compiled by its own test harness. In
///   every build a consumer makes it is `false`, so `#[cfg(test)]` on a counted wipe is
///   `#[cfg(any())]` spelled differently: the text this file counts is unchanged and the
///   wipe is not in the library a consumer links. The crate's legitimate test-only items
///   (`test_counters`, `extern crate std`, the `flip_byte_for_test` impl, …) never reach
///   this parser: [`non_test_source_of`] removes every `#[cfg(test)]`-attributed item and
///   asserts no `#[cfg(test)]` remains, so this leaf only fires on a `cfg(test)` that
///   survived in what must be production source. One deliberate over-rejection falls out:
///   `#[cfg(not(test))]` evaluates to `Some(true)` and is rejected too, although it
///   compiles its scope *into* every consumer build. No such attribute exists in the
///   scanned files, and rejecting a legitimate spelling is fail-closed; if one is ever
///   wanted, the guard has to learn the difference between "false for a consumer" and
///   "constant", rather than silently accepting it here.
///
/// What this does *not* interpret: other always-off-in-a-consumer's-build atoms (`kani`,
/// `miri`, `doc`, `doctest`, `fuzzing`) stay atoms, and so does everything inside a
/// `cfg_attr`, which [`attribute_finding`] evaluates separately.
///
/// This is what makes the blanket rejection below honest rather than a list of spellings:
/// `any()`, `all()`, `not(any())`, `not(all())` and any nesting of them (`any(all())`)
/// evaluate to a definite value, and a predicate that is definite is not a configuration
/// gate — it compiles its scope in or out everywhere. Whitespace is normalised away first,
/// because `#[ cfg ( any ( ) ) ]` is the same attribute written to evade a byte scan.
/// Three-valued evaluation of a `cfg` predicate in `pred`'s **whitespace-free** form, plus a
/// direct polarity conflict at every conjunction/disjunction node.
///
/// Kleene logic answers most predicates exactly at linear cost: an operand that cannot change
/// the result absorbs the node (`all(false, unknown)` is false, `any(true, unknown)` is true,
/// `all()` is true, `any()` is false). On top of that, a node holding both `X` and `not(X)`
/// among its direct operands is constant by inspection -- `all(X, not(X))` is false and
/// `any(X, not(X))` is true, whatever the atom is -- which is how a predicate of any length is
/// decided without enumerating it. `None` means "not decided here", and the caller falls back
/// to the enumeration and then to the literal folding.
///
/// This is not a SAT solver: a tautology that needs reasoning *across* atoms
/// (`all(any(a, b), any(not(a), not(b)))`-shaped) is left undecided, and a predicate with more
/// atoms than the enumeration bound and no polarity conflict is then reported as undecidable
/// rather than passed.
fn cfg_three_valued(normalized: &str) -> Option<bool> {
    let p = normalized.trim().trim_end_matches(',');
    let mut parsed = None;
    for name in ["all", "any", "not"] {
        if let Some(inner) = p
            .strip_prefix(name)
            .and_then(|s| s.strip_prefix('('))
            .and_then(|s| s.strip_suffix(')'))
        {
            parsed = Some((name, inner));
            break;
        }
    }
    let (name, inner) = parsed?;
    if name == "not" {
        return cfg_three_valued(inner).map(|value| !value);
    }
    let args = split_cfg_args(inner);
    if args.is_empty() {
        return Some(name == "all");
    }
    let mut positive: Vec<&str> = Vec::new();
    let mut negative: Vec<&str> = Vec::new();
    let mut unknown = false;
    for arg in &args {
        let arg = arg.trim();
        let (atom, flipped) = match arg.strip_prefix("not(").and_then(|s| s.strip_suffix(')')) {
            Some(inner) => (inner.trim(), true),
            None => (arg, false),
        };
        if flipped {
            negative.push(atom);
        } else {
            positive.push(atom);
        }
        match cfg_three_valued(arg) {
            // A decided operand decides the node when it is the absorbing value.
            Some(false) if name == "all" => return Some(false),
            Some(true) if name == "any" => return Some(true),
            Some(_) => {}
            None => unknown = true,
        }
    }
    if positive.iter().any(|atom| negative.contains(atom)) {
        return Some(name == "any");
    }
    if unknown {
        None
    } else {
        Some(name == "all")
    }
}

/// The number of distinct atoms [`constant_cfg_value`] enumerates. Past it the three-valued
/// pass is still tried (it decides a contradiction of any length) and the caller reports the
/// predicate as undecidable rather than passing it.
const CFG_ATOM_ENUMERATION_LIMIT: usize = 16;

fn constant_cfg_value(pred: &str) -> Option<bool> {
    // A predicate that names a configuration atom *twice* can still be definite:
    // `all(feature = "x", not(feature = "x"))` is false under every assignment of
    // `feature = "x"`, and `not(any(feature = "x", not(feature = "x")))` is true. The
    // literal rules below only fold constants, so both came back `None` -- "unknown atom"
    // -- and the blanket guard let them through: a dependency report measured
    // `#[cfg(all(feature = "ultra", not(feature = "ultra")))]` on `decrypt`'s
    // `check_lengths(...)?` compiling the input-length bound out of every build with the
    // whole suite green.
    //
    // A `cfg` predicate is a Boolean formula over its distinct atoms, so with few enough of
    // them it can be decided exactly by evaluating it under every assignment. The bound (12
    // atoms) keeps this cheap -- the crate's predicates name one to three -- and a
    // predicate that varies under *some* assignment is not a gate that is constant, which
    // is the only thing this function is asked.
    //
    // The atom text has to be real for this: a source put through `strip_comments` has
    // every string literal blanked, so `feature = "a"` and `feature = "b"` both read
    // `feature = ""` and the formula `all(feature = "a", not(feature = "b"))` would be
    // "decided" false. A predicate naming a blanked literal is therefore left to the
    // literal rules (no enumeration) -- conservative -- and the callers that want this
    // class detected pass the literal-intact cut.
    //
    // The atom *identity* is whitespace-insensitive, so both the atom list and the
    // evaluation are computed from a whitespace-free copy: `feature="x"` and
    // `feature = "x"` are one atom to rustc, and comparing the raw text made them two --
    // a dependency report measured `all(feature="x", not(feature = "x"))` walking past the
    // first version of this enumeration for exactly that reason.
    let normalized: String = pred.chars().filter(|c| !c.is_whitespace()).collect();
    // A formula whose constancy does not need its atoms enumerated is decided first, at any
    // length: `all(p0 … p16, not(p0))` is false by inspection, and it was measured deadening
    // `check_lengths(...)?` in every consumer build while this guard stayed silent (the
    // enumeration below used to stop at sixteen atoms).
    if let Some(value) = cfg_three_valued(&normalized) {
        return Some(value);
    }
    let atoms = cfg_atoms(&normalized);
    // Sixteen atoms is 65 536 evaluations of a predicate whose nodes number in the tens --
    // microseconds, and far past anything a hand-written gate uses. Beyond it the answer is
    // the literal folding's (usually `None`, i.e. not reported): a *conservative* boundary,
    // stated rather than implied. A predicate that names a **blanked** literal is also left
    // to the folding: `strip_comments` erases literal contents, so `feature = ""` may stand
    // for any feature name and folding two of them into one atom could call a real gate
    // constant. Callers that need the names pass the literal-intact cut.
    if !atoms.is_empty()
        && atoms.len() <= CFG_ATOM_ENUMERATION_LIMIT
        && !atoms.iter().any(|a| a.contains("\"\""))
    {
        let mut seen_true = false;
        let mut seen_false = false;
        let mut malformed = false;
        for mask in 0u32..(1u32 << atoms.len()) {
            match eval_cfg_under(&normalized, &atoms, mask) {
                Some(true) => seen_true = true,
                Some(false) => seen_false = true,
                None => {
                    malformed = true;
                    break;
                }
            }
            if seen_true && seen_false {
                break;
            }
        }
        if !malformed && !(seen_true && seen_false) {
            return Some(seen_true);
        }
    }
    constant_cfg_value_literal(pred)
}

/// The finding for a `cfg` predicate, or `None` when it is a configuration.
///
/// [`constant_cfg_value`] answers "is this formula constant" for predicates it can decide; a
/// predicate it *cannot* decide -- more distinct atoms than the enumeration bound and no
/// polarity conflict the three-valued pass can see -- is reported rather than passed. Fail
/// closed, because "cannot decide" is exactly where a constant gate hides: the 17-atom
/// `all(p0 ... p16, not(p0))` that walked past the sixteen-atom enumeration was measured
/// deadening `check_lengths(...)?` in every consumer build with the whole suite green.
fn constant_cfg_finding(pred: &str) -> Option<String> {
    if let Some(value) = constant_cfg_value(pred) {
        return Some(format!("its predicate is constant ({value})"));
    }
    let normalized: String = pred.chars().filter(|c| !c.is_whitespace()).collect();
    let atoms = cfg_atoms(&normalized);
    if atoms.len() > CFG_ATOM_ENUMERATION_LIMIT && !atoms.iter().any(|a| a.contains("\"\"")) {
        return Some(format!(
            "its predicate names {} distinct atoms, more than the {CFG_ATOM_ENUMERATION_LIMIT} \
             this guard decides, so it cannot be shown to be a configuration rather than a \
             constant gate",
            atoms.len()
        ));
    }
    None
}

/// The literal folding: combinators over constants, and the three predicates this crate
/// treats as fixed (`test`, `true`, `false`). Anything else is an atom and unknown *here* —
/// [`constant_cfg_value`] is what decides whether a formula over atoms is still definite.
fn constant_cfg_value_literal(pred: &str) -> Option<bool> {
    let normalized: String = pred.chars().filter(|c| !c.is_whitespace()).collect();
    // `#[cfg(any(),)]` / `#[cfg(test,)]`: a trailing comma is the same predicate. Strip
    // it at every recursion level before matching, or the recursive calls below receive
    // `any(),` and fall through to the unknown-atom branch.
    let p = normalized.trim_end_matches(',');
    if let Some(inner) = p.strip_prefix("any(").and_then(|s| s.strip_suffix(')')) {
        let args = split_cfg_args(inner);
        if args.is_empty() {
            return Some(false); // `any()` matches nothing
        }
        let mut unknown = false;
        for a in &args {
            match constant_cfg_value(a) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => unknown = true,
            }
        }
        return if unknown { None } else { Some(false) };
    }
    if let Some(inner) = p.strip_prefix("all(").and_then(|s| s.strip_suffix(')')) {
        let args = split_cfg_args(inner);
        if args.is_empty() {
            return Some(true); // `all()` matches everything
        }
        let mut unknown = false;
        for a in &args {
            match constant_cfg_value(a) {
                Some(false) => return Some(false),
                Some(true) => {}
                None => unknown = true,
            }
        }
        return if unknown { None } else { Some(true) };
    }
    if let Some(inner) = p.strip_prefix("not(").and_then(|s| s.strip_suffix(')')) {
        return constant_cfg_value(inner).map(|b| !b);
    }
    match p {
        "test" | "r#test" => Some(false), // set only by the crate's own test harness
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// The distinct atoms of a `cfg` predicate, in first-appearance order.
///
/// An atom is a bare identifier (`unix`) or a key/value pair (`feature = "x"`); the
/// `any`/`all`/`not` combinators are structure, not atoms.
fn cfg_atoms(pred: &str) -> Vec<String> {
    let p = pred.trim().trim_end_matches(',');
    for name in ["any", "all", "not"] {
        if let Some(inner) = p.strip_prefix(name).and_then(|s| s.strip_prefix('(')) {
            if let Some(inner) = inner.strip_suffix(')') {
                let mut out: Vec<String> = Vec::new();
                for a in split_cfg_args(inner) {
                    for atom in cfg_atoms(a) {
                        if !out.contains(&atom) {
                            out.push(atom);
                        }
                    }
                }
                return out;
            }
        }
    }
    if p.is_empty() {
        Vec::new()
    } else {
        vec![p.to_string()]
    }
}

/// Evaluate a `cfg` predicate with every atom assigned by `mask` (`None` if the predicate
/// is malformed, which leaves the caller on its conservative answer).
fn eval_cfg_under(pred: &str, atoms: &[String], mask: u32) -> Option<bool> {
    let p = pred.trim().trim_end_matches(',');
    for name in ["any", "all"] {
        if let Some(inner) = p.strip_prefix(name).and_then(|s| s.strip_prefix('(')) {
            if let Some(inner) = inner.strip_suffix(')') {
                let args = split_cfg_args(inner);
                if name == "any" {
                    let mut any_true = false;
                    for a in &args {
                        if eval_cfg_under(a, atoms, mask)? {
                            any_true = true;
                        }
                    }
                    return Some(any_true);
                }
                let mut all_true = true;
                for a in &args {
                    if !eval_cfg_under(a, atoms, mask)? {
                        all_true = false;
                    }
                }
                return Some(all_true);
            }
        }
    }
    if let Some(inner) = p.strip_prefix("not").and_then(|s| s.strip_prefix('(')) {
        if let Some(inner) = inner.strip_suffix(')') {
            return Some(!eval_cfg_under(inner, atoms, mask)?);
        }
    }
    match p {
        "true" => Some(true),
        "false" => Some(false),
        atom => {
            let bit = atoms.iter().position(|a| a == atom)?;
            Some(mask >> bit & 1 == 1)
        }
    }
}

/// `inner` split at its **top-level** commas (`all(a, any(b, c))` -> `["a", "any(b, c)"]`).
///
/// Empty arguments are dropped: `any(test,)` and `any(any(),)` are legal Rust and evaluate
/// exactly like `any(test)` / `any(any())`. Keeping the empty slice made
/// [`constant_cfg_value`] see an unknown atom and return `None`, which was a measured
/// bypass of the constant-gate check.
fn split_cfg_args(inner: &str) -> Vec<&str> {
    let b = inner.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        // Separators inside a string literal are data (`feature = "a,b"` is one argument),
        // so the walk skips whole literals rather than counting their punctuation.
        if b[i] == b'"' || b[i] == b'\'' {
            i = end_of_string_literal(b, i);
            continue;
        }
        match b[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let arg = &inner[start..i];
                if !arg.trim().is_empty() {
                    out.push(arg);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = &inner[start..];
    if !last.trim().is_empty() {
        out.push(last);
    }
    out
}

/// Which `cfg`-family attribute [`find_cfg_attribute`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CfgAttribute {
    /// `#[cfg(predicate)]`: the predicate is the gate.
    Cfg,
    /// `#[cfg_attr(condition, attributes…)]`: the condition gates whether the listed
    /// attributes apply, not the scope directly.
    CfgAttr,
}

/// The next `#[cfg(…)]` / `#![cfg(…)]` / `#[cfg_attr(…)]` attribute at or after `from`,
/// as `(index of the `#`, index of the `(` after the name, kind)`.
///
/// Whitespace is allowed between the tokens — `#[ cfg (any())]` is the same attribute, and
/// a scanner that requires the literal `#[cfg(` is one space away from being evaded. Two
/// shapes beyond the plain outer `#[cfg(` are matched because they are the same deadening
/// spelled differently:
///
/// * the inner form `#![cfg(…)]`, which gates the enclosing block:
///   `{ #![cfg(any())] zeroize_array(&mut enc_key); }` compiled the wipe out while a scan
///   that only looked for `#[cfg(` saw no attribute at all;
/// * `cfg_attr`, which is not skipped as a non-match but carried as its own kind, because
///   `#[cfg_attr(all(), cfg(any()))]` has no constant predicate *directly* — its condition
///   is constant (so it gates nothing) and the attribute it applies is the always-false
///   `cfg(any())`. [`attribute_finding`] evaluates that shape.
fn find_cfg_attribute(source: &str, from: usize) -> Option<(usize, usize, CfgAttribute)> {
    let b = source.as_bytes();
    let mut i = from;
    while i < b.len() {
        if b[i] == b'#' {
            let mut j = i + 1;
            // Whitespace is legal between every token: `# [cfg(any())]` and
            // `# ! [cfg(any())]` are the same attributes, and rustc accepts them.
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if b.get(j) == Some(&b'!') {
                j += 1; // the inner form `#![…]`
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
            }
            if b.get(j) == Some(&b'[') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if b[j..].starts_with(b"cfg") {
                    let mut k = j + 3;
                    while k < b.len() && b[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if b.get(k) == Some(&b'(') {
                        return Some((i, k, CfgAttribute::Cfg));
                    }
                    if b[k..].starts_with(b"_attr") {
                        let mut m = k + 5;
                        while m < b.len() && b[m].is_ascii_whitespace() {
                            m += 1;
                        }
                        if b.get(m) == Some(&b'(') {
                            return Some((i, m, CfgAttribute::CfgAttr));
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// The predicate of the attribute that opens at `open` (the `(` after `cfg`), bracket
/// matched, and where it closes.
/// The index just past the string literal starting at `at` (`b[at]` is the opening quote).
///
/// Both quote forms, escapes included; an unterminated literal ends at the end of the
/// input, which leaves the caller's walk conservative (it stops rather than guesses).
fn end_of_string_literal(b: &[u8], at: usize) -> usize {
    let quote = b[at];
    let mut i = at + 1;
    while i < b.len() && b[i] != quote {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    i.saturating_add(1)
}

fn cfg_predicate_at(source: &str, open: usize) -> (String, usize) {
    let b = source.as_bytes();
    let mut depth = 0usize;
    let mut close = None;
    let mut at = open;
    while at < b.len() {
        if b[at] == b'"' || b[at] == b'\'' {
            // A literal's contents are not structure: a `)` or `#[cfg(` inside one must not
            // close the attribute or open a nested one. Without this, a `#[cfg(…)]` written
            // inside a string made the scan report an "unbalanced `cfg(`" panic (fail-closed,
            // but a panic on legal source).
            at = end_of_string_literal(b, at);
            continue;
        }
        match b[at] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(at);
                    break;
                }
            }
            _ => {}
        }
        at += 1;
    }
    let close = close.expect("unbalanced `cfg(` in the source");
    (source[open + 1..close].to_string(), close)
}

/// Every `cfg`-family attribute in `source` whose gating is constant, as
/// `(line number, attribute text with the reason it is constant)`.
///
/// `source` must be comment-free — the callers use `strip_comments_impl` through
/// [`non_test_source_of`] or [`non_test_source_of_keeping_literals`] — so a `#[cfg(any())]`
/// written only in prose is not a finding. It should **keep string literals**: `strip_comments` blanks them, and a
/// blanked predicate loses the feature names its atoms are made of, so
/// `all(feature = "a", not(feature = "b"))` would read as one atom repeated and be called
/// constant. [`constant_cfg_value`] refuses to enumerate a predicate that names a blanked
/// literal, so a blanked source is merely conservative; the blanket guard passes the
/// literal-intact cut.
fn constant_cfg_attributes(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some((start, open, kind)) = find_cfg_attribute(source, from) {
        let (args, close) = cfg_predicate_at(source, open);
        if let Some(finding) = attribute_finding_for(kind, &args) {
            let line = source[..start].matches('\n').count() + 1;
            let end = source[close..]
                .find(']')
                .map_or(close + 1, |n| close + n + 1);
            out.push((line, format!("{} {finding}", &source[start..end])));
        }
        from = close + 1;
    }
    out
}

/// The 1-based lines of every `cfg`-family attribute in `source`, whatever its predicate.
///
/// Used to keep the literal-intact scan honest: an attribute text that survives only
/// because a string literal's contents were kept — `#[cfg(any())]` written *inside* a
/// string — is not an attribute, and the blanked cut is what removes it.
fn cfg_attribute_lines(source: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some((start, open, _kind)) = find_cfg_attribute(source, from) {
        out.push(source[..start].matches('\n').count() + 1);
        let (_, close) = cfg_predicate_at(source, open);
        from = close + 1;
    }
    out
}

/// The attribute texts **directly above** byte `at` in `body`, nearest first, stopping at
/// the first line that is not an attribute or blank. Blank lines are skipped rather than
/// ending the run: Rust attaches an attribute to the next item across blank lines, so
/// `#[cfg(feature = "pure")]` followed by one blank line still deadens the wipe (measured).
/// An attribute that belongs to an earlier statement is separated from this one by that
/// statement, not by whitespace, so it is not attributed here. The same-line form
/// (`#[cfg(any())] zeroize_array(…);`) is seen because the text before `at` then ends with
/// the attribute itself.
///
/// Two further spellings are seen, because each is the same deadening with the statement
/// dressed differently:
///
/// * a line starting with the inner form `#![cfg(…)]`, which `starts_with("#[")` missed;
/// * a line that *ends* with an attribute rather than starting it — `{ #![cfg(any())]
///   zeroize_array(&mut enc_key); }` — found by [`attribute_suffix`]. Both were measured
///   to deaden a wipe with this per-site check silent (the blanket scan in
///   [`no_constant_cfg_attribute_can_deaden_the_crypto_source`] did catch them, but the
///   per-site message is the one that names the wipe).
///
/// Each entry is `(0-based line number within `body`, trimmed line)` rather than a bare
/// text: the line number is what lets [`assert_wipes_are_not_deadened`] read a
/// predicate's *string contents* back from the raw `src/lib.rs`, where the scan text
/// has them blanked.
fn preceding_attributes(body: &str, at: usize) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut end = body[..at].trim_end().len();
    loop {
        let start = body[..end].rfind('\n').map_or(0, |n| n + 1);
        let line = body[start..end].trim();
        let line_no = body[..start].matches('\n').count();
        // Blank lines do not end the attribute run. Rust attaches an attribute to the
        // next item regardless of blank lines between them, so treating a blank line as
        // the end let `#[cfg(feature = "pure")]` followed by one blank line deaden a
        // counted wipe while this scan saw no attribute at all (measured).
        if line.is_empty() {
            if start == 0 {
                break;
            }
            end = start - 1;
            continue;
        }
        // An attribute above a block opener applies to the whole block. Walk through the
        // opener so `#[cfg(feature = "pure")] { wipe }` is seen; that multi-line form was
        // a measured bypass of the earlier scan, which stopped at the `{` line. The
        // attribute branches come first: a line can be both an attribute and an opener
        // (`#[cfg(feature = "pure")] {`), and skipping it as an opener would lose the
        // attribute this scan exists to see.
        if is_attribute_line(line) {
            out.push((line_no, line));
            if start == 0 {
                break;
            }
            end = start - 1;
        } else if let Some(attr) = attribute_suffix(line) {
            out.push((line_no, attr));
            break;
        } else if line.ends_with('{') {
            if start == 0 {
                break;
            }
            end = start - 1;
            continue;
        } else if let Some((attr_start, attr, attr_line)) = attribute_ending_at(body, end) {
            // A **multi-line** attribute: the statement's line begins with `)]` (or the
            // predicate's last line does), so the line-based test above sees neither a
            // `#` nor a trailing `]`. Measured: `#[cfg(feature = "pure"\n)]` above
            // `derive_material`'s `subkey` wipe left this scan with no attribute at all and
            // the whole suite green, while the single-line spelling was caught -- the
            // newline was the entire difference.
            out.push((attr_line, attr));
            if attr_start == 0 {
                break;
            }
            end = body[..attr_start].trim_end().len();
        } else {
            break;
        }
    }
    out
}

/// The balanced `#[…]` / `#![…]` group that **ends exactly at `end`**, as
/// `(byte offset of the `#`, text, 0-based line of the `#`), or `None`.
///
/// `end` is an exclusive offset into `body` with no trailing whitespace before it. The scan
/// walks backwards over `]`/`[` (and `)`/`(` for good measure, though only the outermost
/// bracket matters) and then requires the `#` that opens the group, so a line that merely
/// ends in `)` -- the last line of a multi-line attribute -- is recognised as the *end* of
/// an attribute rather than as the statement's first line.
fn attribute_ending_at(body: &str, end: usize) -> Option<(usize, &str, usize)> {
    let bytes = body.as_bytes();
    if end == 0 || bytes.get(end - 1) != Some(&b']') {
        return None;
    }
    let mut depth = 0i64;
    let mut i = end;
    let mut hash_at = None;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    // Skip whitespace backwards, then an optional `!`, then whitespace,
                    // then require the `#`.
                    let mut k = i;
                    while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                        k -= 1;
                    }
                    if k > 0 && bytes[k - 1] == b'!' {
                        k -= 1;
                        while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                            k -= 1;
                        }
                    }
                    if k > 0 && bytes[k - 1] == b'#' {
                        hash_at = Some(k - 1);
                    }
                    break;
                }
            }
            // A `#` inside the group is not the opener; nothing to do.
            _ => {}
        }
    }
    let hash_at = hash_at?;
    let text = body[hash_at..end].trim();
    // Only a real attribute: it must start with `#[` or `#![` after the whitespace the
    // backwards walk skipped (that whitespace is inside the text only if it was between
    // `#` and `[`, which the walk already allowed for).
    if !(text.starts_with("#[") || text.starts_with("#![")) {
        return None;
    }
    let line = body[..hash_at].matches('\n').count();
    Some((hash_at, text, line))
}

/// The `#[…]` / `#![…]` attribute that *ends* `line` (`{ #![cfg(any())]` becomes
/// `#![cfg(any())]`), or `None` when the line does not end with a balanced one.
///
/// This exists for the block-wrapped form: `{ #![cfg(any())] zeroize_array(&mut enc_key); }`
/// is `#[cfg(any())] zeroize_array(&mut enc_key);` with the statement's own block around
/// it, and the leading `{` keeps the line from starting with `#[`, so
/// [`preceding_attributes`] could not see it.
fn attribute_suffix(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.last() != Some(&b']') {
        return None;
    }
    let mut depth = 0i64;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    // `# [ … ]` / `# ! [ … ]` are the same attributes with whitespace;
                    // skip it backwards before looking for the `#`/`!`.
                    let mut k = i;
                    while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                        k -= 1;
                    }
                    if k > 0 && bytes[k - 1] == b'!' {
                        k -= 1;
                        while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                            k -= 1;
                        }
                    }
                    if k > 0 && bytes[k - 1] == b'#' {
                        return Some(&line[k - 1..]);
                    }
                    return None; // the `[` is not part of an attribute
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether `line`, after leading whitespace, begins an outer or inner attribute.
///
/// Unlike `starts_with("#[")`, this accepts whitespace between `#`, `!` and `[`:
/// `# [cfg(any())]` is a legal, always-false attribute that the earlier scanners missed.
fn is_attribute_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix('!') {
        Some(rest) => rest.trim_start(),
        None => rest,
    };
    rest.starts_with('[')
}

/// The cfg scanners must recognise the spellings rustc accepts but a literal `#[cfg(`
/// byte scan does not: whitespace between `#`/`!`/`[`, a trailing comma, empty arguments,
/// and the raw identifier `r#test`. Each was a measured bypass of an earlier scanner.
#[test]
fn cfg_scanners_recognise_whitespace_and_trailing_comma_spellings() {
    for predicate in ["any(),", "test,", "any(any(),)", "any(test,)", "r#test"] {
        assert_eq!(
            constant_cfg_value(predicate),
            Some(false),
            "`{predicate}` is an always-false cfg predicate and must be recognised"
        );
    }
    for attribute in [
        "#[cfg(test,)] fn t() {}",
        "# [cfg(test)] fn t() {}",
        "# ! [cfg(r#test)] fn t() {}",
    ] {
        assert!(
            crate::common::find_cfg_test_attribute(attribute, 0).is_some(),
            "the test-item blanker must see {attribute}"
        );
    }
    for attribute in [
        "#[cfg(any())] wipe();",
        "# [cfg(any())] wipe();",
        "# ! [cfg(any(),)] wipe();",
    ] {
        assert!(
            find_cfg_attribute(attribute, 0).is_some(),
            "the constant-gate scan must see {attribute}"
        );
    }
    let line = "{ # [cfg(any())]";
    assert_eq!(
        attribute_suffix(line).map(str::trim_start),
        Some("# [cfg(any())]"),
        "the suffix scan must see a whitespace-separated attribute ending a line"
    );
}

/// The reason the attribute of `kind` with argument list `args` is constant-gated, if it
/// is.
///
/// `cfg(predicate)` is constant when the predicate is ([`constant_cfg_value`]).
/// `cfg_attr(condition, attributes…)` is constant when the condition is — the listed
/// attributes then apply in every configuration or in none — or when one of the listed
/// attributes is itself a constant `cfg`. `#[cfg_attr(all(), cfg(any()))]` is the
/// measured evasion this closes (constant-true condition, always-false inner attribute);
/// `#[cfg_attr(feature = "x", cfg(any()))]` is the same wipe compiled out in every
/// configuration where `x` is on. Nested `cfg_attr`s are walked.
fn attribute_finding_for(kind: CfgAttribute, args: &str) -> Option<String> {
    match kind {
        CfgAttribute::Cfg => constant_cfg_finding(args),
        CfgAttribute::CfgAttr => {
            let parts = split_cfg_args(args);
            let (condition, attributes) = parts.split_first()?;
            if let Some(finding) = constant_cfg_finding(condition) {
                return Some(format!(
                    "its condition `{condition}` {finding}, so the attributes it lists always \
                     apply or never do"
                ));
            }
            for attribute in attributes {
                if let Some(finding) = bare_attribute_finding(attribute) {
                    return Some(format!(
                        "it applies `{attribute}`, whose own gating is constant: {finding}"
                    ));
                }
            }
            None
        }
    }
}

/// The finding for a bare attribute body — `cfg(…)` or `cfg_attr(…)`, without a leading
/// `#[`: the spelling an attribute has inside a `cfg_attr` list — if it is constant-gated.
fn bare_attribute_finding(text: &str) -> Option<String> {
    let text = text.trim_start();
    let (kind, rest) = match text.strip_prefix("cfg_attr") {
        Some(rest) => (CfgAttribute::CfgAttr, rest),
        // `cfg` is the shorter prefix and has to be tried second, hence the `?` rather
        // than a second `if let`: anything else is not this function's business.
        None => (CfgAttribute::Cfg, text.strip_prefix("cfg")?),
    };
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    let (args, _) = cfg_predicate_at(rest, 0);
    attribute_finding_for(kind, &args)
}

/// The finding for the attribute at the start of `attr` (`#[cfg(…)]`, `#![cfg(…)]`,
/// `#[cfg_attr(…)]`), if its gating is constant.
fn attribute_finding(attr: &str) -> Option<String> {
    let (_, open, kind) = find_cfg_attribute(attr, 0)?;
    let (args, _) = cfg_predicate_at(attr, open);
    attribute_finding_for(kind, &args)
}

/// Whether the attribute text `attr` is a `cfg`-family attribute (`#[cfg(…)]`,
/// `#![cfg(…)]`, `#[cfg_attr(…)]`).
fn is_cfg_attribute(attr: &str) -> bool {
    find_cfg_attribute(attr, 0).is_some()
}

/// The predicate of the `cfg`-family attribute on **line `line` (1-based) of
/// `src/lib.rs`**, whitespace normalised away, read from the raw file.
///
/// The predicate has to come from the raw line rather than from the stripped scan
/// text, and that is the whole reason this function exists: [`strip_comments`] blanks
/// every string literal's contents (it must, or a literal could stand in for code in
/// this file's counts), so `feature = "dual-mac"` and `feature = "pure"` both read as
/// `feature = ""` in the scan text — and a feature *name* is exactly what the
/// allow-list compares. A predicate this function cannot read is a panic, not a pass:
/// waving through a line whose gating could not be determined is the fail-open shape
/// the guard exists to prevent.
///
/// The line numbers line up because the cut and the stripper preserve every newline —
/// asserted by the caller before this is reached, see
/// [`assert_wipes_are_not_deadened`].
fn raw_cfg_predicate_at(line: usize) -> String {
    // The attribute may span several lines (`#[cfg(all(\n    feature = "pure",\n))]`), so
    // the raw read is the *rest of the file from `line`*, not a single line: reading one
    // line made the multi-line spelling panic with "unbalanced `cfg(`" -- fail-closed, but
    // a panic on legal Rust, and the panic's line was the attribute's first line rather
    // than the statement that carries it.
    static REST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    let rest = REST.get_or_init(|| LIB.lines().collect());
    let start = line
        .checked_sub(1)
        .unwrap_or_else(|| panic!("`src/lib.rs` line numbers are 1-based, got {line}"));
    let raw: String = rest[start..].join("\n");
    let (_, open, _) = find_cfg_attribute(&raw, 0).unwrap_or_else(|| {
        panic!(
            "line {line} of `src/lib.rs` is an attribute in the stripped scan text but \
             carries no `cfg`-family attribute when read raw (`{}`); the predicate \
             cannot be checked, and passing it would be fail-open",
            rest.get(start).copied().unwrap_or("")
        )
    });
    let (args, _) = cfg_predicate_at(&raw, open);
    args.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The raw text of `src/lib.rs` line `line` (1-based), for reading back what
/// [`strip_comments`] blanked (string contents) or dropped (a trailing comment).
fn raw_lib_line(line: usize) -> &'static str {
    LIB.lines().nth(line - 1).unwrap_or_else(|| {
        panic!("`src/lib.rs` has no line {line}, so a `cfg` predicate cannot be read back")
    })
}

/// The wipe sites the counts below rely on must not be deadened by a `cfg` attribute.
///
/// `#[cfg(any())] { zeroize_array(&mut enc_key); }` keeps the wipe's text — and therefore
/// every count in this file — exactly as it was while compiling the statement out. An
/// auditor measured that form surviving the whole default suite (96/96, the `encrypt`
/// success-path wipe) and the same attribute wrapping `zeroize_array(&mut tag)` surviving
/// the whole `ultra` suite (128/128): a count cannot tell a wiped frame from a compiled-out
/// one. Each occurrence is checked against the attributes directly above it, including the
/// same-line and block-wrapped spellings [`preceding_attributes`] now sees.
///
/// Two shapes are rejected, because a `cfg` can deaden a counted wipe in two ways:
///
/// * **constant gating** (`#[cfg(any())]`, `#[cfg(test)]`, a `cfg_attr` whose condition
///   or listed attribute is constant): the wipe is compiled out in *every* build.
///   [`attribute_finding`] is the check, and it predates the second shape;
/// * **a non-constant predicate the table does not count the wipe in** (`allowed_cfg`):
///   a *plausible feature name* compiles the wipe out of every build that feature is
///   off in. This half was missing when an auditor planted `#[cfg(feature = "pure")]`
///   on `encrypt`'s `zeroize_array(&mut enc_key);`: the default and `ultra` builds
///   then contained no wipe, while the text — and every count in this file — was
///   unchanged, so the whole suite stayed green (16/16 in `--release --features
///   ultra`, and the constant-`cfg` blanket scan saw nothing, because `pure` is not
///   constant). Each counted wipe therefore carries **the set of predicates the table
///   enumerates as configurations it counts that wipe in**, and the set is empty for
///   every wipe that exists in every build — so a `cfg` no one wrote down as counted
///   is, by default, not counted, whatever its feature name.
///
///   The one non-empty entry is `recomputed_tag`, which only exists under `dual-mac`
///   (its declaration is gated the same way), so `feature="dual-mac"` is allowed there
///   and nothing else is. The predicate is read from the raw source by line number:
///   the scan text this file builds has string literals blanked, so every feature
///   predicate reads there as `feature=""` — indistinguishable from any other — and an
///   allow-list matched against that would accept `pure` at a `dual-mac` site.
///
/// `body_line` is the 1-based line of `src/lib.rs` that `body`'s first line is, so the
/// raw read can find the attribute the stripped line describes.
/// The brace-nesting depth at byte `at` in `body`: the number of `{` opened and not yet
/// closed before it. A statement at a function's top level is depth 1. `body` comes from
/// [`non_test_source`], whose literal contents are blanked and comments removed, so no
/// brace inside a string or comment can move the count.
fn brace_depth_at(body: &str, at: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in body.char_indices() {
        if i >= at {
            break;
        }
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

/// Occurrences of `needle` in `body` that are direct statements of the outer block
/// (depth 1), not nested in an `if`/`match`/loop, a local function, or a *closure body*.
///
/// The closure exclusion is not decorative: a closure body is also one brace deep, so
/// `let _dead = || { wipe };` counts as a top-level statement of the enclosing function
/// while never running. The old version compared the brace depth alone and accepted it
/// (measured: the whole suite stayed green with `derive_material`'s four wipes moved into
/// such a closure).
fn top_level_count(body: &str, needle: &str) -> usize {
    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(i) = body[from..].find(needle) {
        let at = from + i;
        if brace_depth_at(body, at) == 1
            && !inside_closure_body(body, at)
            && brace_less_closure_head(body, at).is_none()
        {
            count += 1;
        }
        from = at + needle.len();
    }
    count
}

/// Attributes that gate a block *enclosing* byte `at`, not only those directly above it.
///
/// `preceding_attributes` stops at the first non-attribute line in the same statement
/// position, so a `#[cfg(feature = "rng")] { let _ = 0; wipe }` hides the gate behind the
/// leading `let`. Walking the enclosing brace stack and asking the same question at each
/// opener recovers it.
fn enclosing_block_attributes(body: &str, at: usize) -> Vec<(usize, &str)> {
    let mut opens = Vec::new();
    for (i, c) in body.char_indices() {
        if i >= at {
            break;
        }
        match c {
            '{' => opens.push(i),
            '}' => {
                opens.pop();
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for open in opens {
        out.extend(preceding_attributes(body, open));
    }
    out
}

/// The head (text between the previous delimiter and the `{`) of any enclosing block that
/// is a constant-false wrapper. A wipe moved inside `if black_box(false) { … }` keeps
/// every text count while never executing; the table cannot afford to reject `match`,
/// `if decision.is_err()` or a `while` loop, which are legitimate enclosing shapes in this
/// crate, so only the constant-false forms are rejected.
fn constant_false_enclosing_block(body: &str, at: usize) -> Option<String> {
    if let Some(head) = brace_less_closure_head(body, at) {
        return Some(format!(
            "{head}  [a binding or assignment whose right-hand side is a brace-less \
             closure; this crate writes every wipe as a plain statement]"
        ));
    }
    for (open, head) in enclosing_block_heads(body, at) {
        if let Some(reason) = deadening_head(body, open, &head) {
            return Some(format!("{head}  [{reason}]"));
        }
    }
    None
}

/// The head text of every `{` block that encloses byte `at`, innermost last.
///
/// A head is the text between the block's opening `{` and the previous delimiter
/// (`\n`, `;`, `{`, `}`), trimmed — that is, the `if …`/`match …`/`fn …`/`let x = …`
/// fragment the block belongs to. Callers use it to judge the *shape* of the enclosing
/// statement rather than the spelling of any particular condition.
fn enclosing_block_heads(body: &str, at: usize) -> Vec<(usize, String)> {
    let mut opens = Vec::new();
    for (i, c) in body.char_indices() {
        if i >= at {
            break;
        }
        match c {
            '{' => opens.push(i),
            '}' => {
                opens.pop();
            }
            _ => {}
        }
    }
    opens
        .into_iter()
        .map(|open| {
            // The head is the text back to the previous statement/block boundary. A
            // newline is normally that boundary, but the `{` may sit on its own line
            // (`if false\n{`), where the last newline is just the line break before the
            // block and the head would come out empty -- making every head-based rule
            // (constant condition, closure, else-chain) miss. When the plain extraction is
            // empty, re-scan without `\n` as a boundary so the condition on the line above
            // is captured. A genuinely empty head (a block that follows `;`/`}`/`)`) stays
            // empty, because those delimiters are still boundaries.
            let head = |dels: &[char]| -> String {
                let head_start = body[..open].rfind(dels).map_or(0, |i| i + 1);
                body[head_start..open].trim().to_string()
            };
            let mut h = head(&['\n', ';', '{', '}']);
            if h.is_empty() {
                h = head(&[';', '{', '}']);
            }
            (open, h)
        })
        .collect()
}

/// The `if` condition that selects the *other* branch of an enclosing `else` block at
/// `open`, if the block really is an `else`/`else if` and the condition can be recovered.
///
/// Walking back is what makes the `else` half of the constant-condition class checkable:
/// the wipe in `if true { … } else { wipe }` is not enclosed by the `if` at all, so the
/// condition has to be reached through the then-branch's closing brace. `else if c { … }`
/// heads are handled by `deadening_head` directly (they are `if`s).
fn else_branch_condition(body: &str, open: usize) -> Option<Vec<&str>> {
    /// The opening `{` of the block that ends at the `}` immediately before `end`.
    fn block_open_before(body: &str, end: usize) -> Option<usize> {
        let bytes = body.as_bytes();
        let mut i = end;
        let mut depth = 0i32;
        loop {
            match bytes[i] {
                b'}' => depth += 1,
                b'{' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
            if i == 0 {
                return None;
            }
            i -= 1;
        }
    }

    // The `else` keyword must sit on the line above the `{`; when the `{` is on its own
    // line (`if true { } else\n{`) the newline before it is not a statement boundary, so
    // the plain scan lands on it and leaves `before` ending in `else` instead of `}` --
    // and the whole chain is skipped (measured: `if true { } else\n{ wipe }` stayed
    // green). Re-scan without `\n` when the text between the last newline and `{` is
    // blank, mirroring `enclosing_block_heads`.
    let head_start_newline = body[..open]
        .rfind(['\n', ';', '{', '}'])
        .map_or(0, |i| i + 1);
    let head_start = if body[head_start_newline..open].trim().is_empty() {
        body[..open].rfind([';', '{', '}']).map_or(0, |i| i + 1)
    } else {
        head_start_newline
    };
    let before = body[..head_start].trim_end();
    if !before.ends_with('}') {
        return None;
    }
    // Walk the whole `else if` chain, not just to the nearest `if`. For
    // `if A { } else if B { } else { wipe }` the nearest preceding `if` is B, but the wipe
    // runs only when A *and* B are false -- so a constant-true A kills the branch even when
    // B is not constant. The previous version stopped at B and accepted the case (measured:
    // `if true { } else if <non-const> { } else { wipe }` stayed green). Every condition in
    // the chain is needed, so all of them are returned.
    let mut conds: Vec<&str> = Vec::new();
    let mut cursor = before.len(); // one past the most recent `}`
    loop {
        let close = cursor - 1; // the `}` that ends this block
        let open_at = block_open_before(body, close)?;
        let hs = body[..open_at]
            .rfind(['\n', ';', '{', '}'])
            .map_or(0, |i| i + 1);
        let head = body[hs..open_at].trim();
        let Some(pos) = head.rfind("if ") else {
            // Not an `if` (a plain `else` has no condition of its own): keep walking.
            let prefix_end = hs;
            cursor = prefix_end;
            if cursor == 0 {
                return Some(conds);
            }
            continue;
        };
        conds.push(head[pos + 3..].trim());
        // Is this `else if`? Then another block precedes it and the walk continues.
        let before_this = body[..hs].trim_end();
        if before_this.ends_with('}') {
            cursor = before_this.len();
            continue;
        }
        return Some(conds);
    }
}

/// Why the block with head `head` cannot execute the statement it encloses, if it cannot.
///
/// This is deliberately a *reachability* judgement, not a list of spellings. The earlier
/// version matched `if false`, `while false` and `black_box(false)` literally, so five
/// equivalent formulations walked straight past it while the whole six-configuration
/// matrix, `cargo fmt --check` and `cargo clippy -D warnings` stayed green (measured on
/// the enclosing wipes of `derive_material`, `scrub_stack` and `encrypt`):
///
/// * `if 1u8 == 2u8 { … }`            — a constant comparison, not the `false` literal;
/// * `match 0u8 { 1 => { … }, _ => {} }` — a constant scrutinee, so the arm is unreachable;
/// * `for _ in 0..0u8 { … }`          — an empty range;
/// * `let _dead = || { … };`, `… black_box(&_dead);` and the brace-less
///   `let _dead = || crate::zeroize_array(&mut enc_key);` — a closure that is never
///   called. The brace-less form has no `{` to find, so it is judged from the statement
///   head instead (see [`brace_less_closure_head`]).
///
/// What this does **not** catch, measured on this tree and deliberately left as a documented
/// limit rather than chased with more spellings (which is the trap the first version fell
/// into): a deadening condition built from an *expression* over literals -- `1 + 1 == 3`,
/// `0u8 as u32 == 1`, `1.0 == 2.0` -- because `literal_value` requires one literal per
/// operand; `b'a' == b'b'`, which the char/string blanking turns into the non-literal
/// `b == b`; a comparison of two *string* literals (`"" == "x"` becomes `"" == ""`); and an
/// empty iterator that is not a literal range (`for _ in v.iter()` with `v: [u8; 0]`). Each
/// of those needs the *raw* line to decide, and the scan runs on `strip_comments`'s output
/// for the reason its own docs give. The structural half -- a wipe inside a constant
/// condition, a constant `match`, an empty range, a `let`-bound closure, a constant-selected
/// `else` -- is what this file actually pins.
///
/// The first three are decided from the *condition* (via [`constant_condition_value`] and
/// the literal/empty-range helpers); the fourth is decided from the head ending in `|`,
/// which is what every closure parameter list does (`||`, `|x|`, `move |x|`, `…for_each(|x|`).
/// `cfg!(…)`-guarded `if`s are included because `cfg!` is an expression, so an attribute
/// check alone would miss `if cfg!(any()) { … }`.
///
/// Residual limits found by a round-10 adversarial pass, left as limits because each is
/// caught elsewhere in the suite rather than only here: `loop { break; wipe }`,
/// `while true { break; wipe }` and `if true { return; wipe }` (unreachable code after a
/// diverge) are caught by `clippy -D warnings` in CI and `verify.sh`; a `<0`-spaced
/// `let _=if false { … }` is caught by `cargo fmt --check`; `for _ in [0u8; 0] { … }` and
/// `for _ in Vec::<u8>::new() { … }` (empty non-range iterators) are not caught at all --
/// the same class as the documented `for _ in v.iter()` limit above; and the `if 'a' ==
/// 'a'` over-rejection below is accepted as the conservative cost of rejecting the whole
/// blanked-comparison class.
fn deadening_head(body: &str, open: usize, head: &str) -> Option<&'static str> {
    // A string-level backstop for the closure shape. The authoritative closure guard is
    // `no_counted_wipe_is_inside_a_closure` (below), which parses `src/lib.rs` and rejects
    // a wipe inside *any* `ExprClosure`; the crate's convention is that every wipe is a
    // plain statement. This branch is a subset kept for a message that names the enclosing
    // block, and it fires on a `let`-bound closure head.
    if head.starts_with("let ") && head.contains('|') {
        return Some(
            "the enclosing block is a closure body bound with `let`; this crate writes every \
             wipe as a plain statement, so hoist it out (see \
             `no_counted_wipe_is_inside_a_closure`)",
        );
    }
    if let Some(cond) = if_condition_of(head) {
        if constant_condition_value(cond) == Some(false) {
            return Some(
                "the enclosing block's condition is a constant false, so its body never runs",
            );
        }
        // `if let <pat> = <constant> { wipe }` / `while let …`: a pattern match on a
        // constant scrutinee the pattern cannot agree with is dead. `if let Some(_x) =
        // None::<u8>` was measured green; only the *literal/`None`* RHS forms are
        // rejected, so a live `if let Some(x) = opt` (RHS a binding or a call) is not.
        if cond.starts_with("let ") {
            if let Some((pat, rhs)) = cond.split_once(" = ") {
                if dead_if_let_rhs(rhs) && pat.trim() != "let None" {
                    return Some(
                        "the enclosing `if let`/`while let` matches a constant scrutinee the \
                         pattern cannot agree with, so its body never runs",
                    );
                }
            }
        }
    }
    // `if { false } { wipe }`: the condition is a block expression, so it is not an
    // enclosing block of the wipe (it closed before the wipe's own block opened) and the
    // head is empty. Read the `if`/`while` and its `{ … }` from just before the block.
    if head.is_empty() {
        if let Some(cond) = block_condition_before(body, open) {
            if constant_condition_value(cond) == Some(false) {
                return Some(
                    "the enclosing block's `{ … }` condition is a constant false, so its body \
                     never runs",
                );
            }
        }
    }
    // `else` and `else if` need the whole preceding chain, not just one condition:
    // `if true { } else if <non-const> { wipe }` is dead because the outer `if` is constant
    // true -- the `else if` branch is never reached even though its own condition is not
    // constant. Conversely `else if false { wipe }` is dead because its *own* condition is
    // constant false. The chain walk (see `else_branch_condition`) is what makes both
    // forms checkable, and it is what the previous version missed (measured: both stayed
    // green under an injection that put the wipe behind one of these).
    if head == "else" {
        if let Some(conds) = else_branch_condition(body, open) {
            if conds
                .iter()
                .any(|cond| constant_condition_value(cond) == Some(true))
            {
                return Some(
                    "the enclosing `else` branch is reached only when all of its `if` conditions \
                     are false, and one of them is a constant true, so the branch never runs",
                );
            }
        }
    }
    if let Some(inner) = head.strip_prefix("else if ") {
        // The branch itself: unreachable when its own condition is a constant false.
        if constant_condition_value(inner) == Some(false) {
            return Some(
                "the enclosing `else if` condition is a constant false, so the branch is never \
                 reached",
            );
        }
        // ...and unreachable when any condition *before* it in the chain is constant true.
        if let Some(conds) = else_branch_condition(body, open) {
            if conds
                .iter()
                .any(|cond| constant_condition_value(cond) == Some(true))
            {
                return Some(
                    "an `if` condition preceding this `else if` is a constant true, so the \
                     branch is never reached",
                );
            }
        }
    }
    // A match *arm* guard: `_ if false => { … }` is an arm whose guard never matches, and its
    // body is dead. The outer `match` may have a non-constant scrutinee, so the scrutinee
    // check below does not see it; a guard is a separate condition and is checked here.
    if head.contains("=>") {
        if let Some(guard) = arm_guard_condition(head) {
            if constant_condition_value(guard) == Some(false) {
                return Some(
                    "the enclosing `match` arm has a guard that is a constant false, so the \
                     arm is never matched",
                );
            }
            // Same blanked-literal class as the `if`/`while` heads: F4 extended
            // `both_comparison_operands_blanked` to the ordering operators but the arm
            // guard was not routed through it, so `_ if 'a' == 'b' =>` stayed green
            // (measured).
            if both_comparison_operands_blanked(guard) {
                return Some(
                    "the enclosing `match` arm's guard compares two literals that were \
                     blanked out of the scanned text, so the guard is constant and the arm \
                     is decided at compile time",
                );
            }
        }
    }
    // The scanned text is `strip_comments`'s output, and that stripper removes a char
    // literal (`'a'`) entirely while blanking a string literal's contents. So a condition
    // like `'a' == 'b'` reaches here as `if  == ` — no operand at all. That shape cannot
    // come from valid Rust, so it means a literal was blanked and the condition's value is
    // unknown: reject it rather than assume the branch is live.
    if both_comparison_operands_blanked(head) {
        return Some(
            "both operands of this block's comparison were blanked out of the scanned text \
             (char or string literals: `'a' == 'b'` reaches here as `== `), so the condition \
             is constant and its body never runs",
        );
    }
    // A `match` with no scrutinee is the same shape: `match 'a' { … }` loses the literal and
    // the head arrives as just `match` (the trim in `enclosing_block_heads` removes the
    // space that `strip_prefix("match ")` would need).
    if head == "match" {
        return Some(
            "this `match`'s scrutinee was blanked out of the scanned text (a char or string \
             literal), so its arms are decided at compile time",
        );
    }
    // A `match` arm: whether it can be *selected* depends on the scrutinee, not on the
    // arm alone. Rejecting every arm of a constant-scrutinee `match` was over-broad --
    // `match 5u8 { 5 => { wipe }, _ => {} }` runs the `5` arm and its wipe is live
    // (measured). Only a *literal arm pattern the constant scrutinee cannot equal* is
    // dead; a wildcard or binding pattern is reachable and is not rejected.
    if let Some(pat) = arm_pattern(head) {
        let scrutinee = enclosing_block_heads(body, open)
            .iter()
            .find_map(|(_, h)| h.strip_prefix("match "))
            .and_then(|s| literal_value(strip_outer_parens(s.trim())));
        if let Some(scrut) = scrutinee {
            if arm_pattern_may_match(pat, scrut) == Some(false) {
                return Some(
                    "the enclosing `match` has a constant scrutinee that this arm's pattern \
                     (literals, `|` alternatives and ranges) cannot match, so the arm never \
                     runs",
                );
            }
        }
    }
    if let Some(rest) = head.strip_prefix("for ") {
        // Whitespace-normalise the header: `for _ in\t0..0u8 {` is the same loop as
        // `for _ in 0..0u8 {`, but `split_once(" in ")` required single spaces and the
        // tab spelling slipped (measured).
        let normalized: String = rest.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some((_, iter)) = normalized.split_once(" in ") {
            if empty_range(iter.trim()) {
                return Some("the enclosing `for` iterates an empty range, so its body never runs");
            }
        }
    }
    None
}

/// Whether a comparison in `head` lost *both* operands to `strip_comments`'s char/string
/// literal blanking, i.e. the condition was two literals (`'a' == 'b'` reaches here as
/// `== `) and is therefore constant.
///
/// Both sides, not either: `let c = 'a'; if c == 'a' { … }` blanks only the right-hand
/// literal, and that condition is *live* -- an earlier version of this helper rejected it,
/// which would have failed the build for a correct edit.
///
/// Every comparison operator, not only `==`/`!=`: `'b' < 'a'` blanks to `if  < ` and
/// deadens the wipe the same way (measured). All six are undecidable once blanked --
/// `'a' == 'a'`, `'a' != 'b'`, `'a' < 'b'` are the live halves of the same shapes -- so the
/// guard rejects the whole class rather than guess; a wash that responds to the rejection
/// by rewriting a comparison of two literals in a wipe gate is the outcome the guard wants.
fn both_comparison_operands_blanked(head: &str) -> bool {
    let cond = if_condition_of(head).unwrap_or(head);
    // `<=`/`>=` before `<`/`>`: splitting `a <= b` on `<` leaves a non-empty `= b`.
    for op in ["==", "!=", "<=", ">=", "<", ">"] {
        if let Some((left, right)) = cond.split_once(op) {
            if left.trim().is_empty() && right.trim().is_empty() {
                return true;
            }
        }
    }
    false
}

/// The truth value of `cond` when it is a compile-time constant, `None` when it is not.
///
/// Handles, in binding order (`||` loosest, then `&&`, then comparisons, then `!`):
/// the boolean literals, `black_box(false)` in any path spelling, `cfg!(…)` with a constant
/// predicate, `!`-negation, `==`/`!=`, the ordering operators, and `&&`/`||` where one
/// operands forces the result (`false && x` is false whatever `x` is). Everything else — a
/// call, a field access, a comparison against a non-literal — is `None`, which the caller
/// reads as "not a known-constant gate" and does not reject: this crate legitimately guards
/// counted wipes with `if decision0.is_err()`, `if off < n` and
/// `while off + CHACHA20_BLOCK <= n`.
///
/// The `&&`/`||` and ordering cases are here because the first version decided only
/// `==`/`!=`: an adversarial pass on this very guard showed `if false && x { wipe }` and
/// `while 1 > 2 { wipe }` both walked past it. (`literal_value` was also too lax — it read
/// the leading digits of `1 > 2` as the literal `1` — so it now requires the whole string to
/// be a literal plus an integer suffix.)
fn constant_condition_value(cond: &str) -> Option<bool> {
    let cond = strip_outer_parens(cond.trim());
    let peeled = peel_black_box(cond);
    if peeled != cond {
        // `black_box` is the compiler barrier an adversarial edit uses to keep a constant
        // condition from being folded; its argument is the real condition.
        return constant_condition_value(peeled);
    }
    if let Some(pred) = cond.strip_prefix("cfg!(").and_then(|s| s.strip_suffix(')')) {
        return constant_cfg_value(pred);
    }
    // `||` before `&&` before the comparisons: that is Rust's own precedence, and the
    // recursive calls below re-enter here so `false && (1 == 2)` is decided too.
    if let Some((left, right)) = split_at_top_level_op(cond, "||") {
        return match (
            constant_condition_value(left),
            constant_condition_value(right),
        ) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), other) => other,
            (other, Some(false)) => other,
            _ => None,
        };
    }
    if let Some((left, right)) = split_at_top_level_op(cond, "&&") {
        return match (
            constant_condition_value(left),
            constant_condition_value(right),
        ) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), other) => other,
            (other, Some(true)) => other,
            _ => None,
        };
    }
    if let Some(inner) = cond.strip_prefix('!') {
        return constant_condition_value(inner).map(|v| !v);
    }
    for (op, eq_when) in [("==", true), ("!=", false)] {
        if let Some((left, right)) = split_at_top_level_op(cond, op) {
            let (l, r) = (literal_operand(left)?, literal_operand(right)?);
            return Some(if eq_when { l == r } else { l != r });
        }
    }
    // `>=`/`<=` before `>`/`<` so a two-character operator is found before its
    // one-character prefix (`split_at_top_level_op` also refuses to match `>` inside
    // `>=`). Each operator is evaluated directly: an earlier version drove both from a
    // shared `ordered = l >= r`/`l > r` and negated for the `<` side, which swapped
    // `<` with `<=` -- `if 1u8 <= 1u8 { wipe }` (a live wipe) was reported dead, and
    // `if 1u8 < 1u8 { wipe }` (a dead wipe) was not reported at all (measured).
    for op in [">=", "<=", ">", "<"] {
        if let Some((left, right)) = split_at_top_level_op(cond, op) {
            let (l, r) = (literal_operand(left)?, literal_operand(right)?);
            return Some(match op {
                ">=" => l >= r,
                "<=" => l <= r,
                ">" => l > r,
                _ => l < r,
            });
        }
    }
    literal_value(cond).map(|v| v != 0)
}

/// [`literal_value`] after peeling a balanced outer `( … )` pair from the operand.
///
/// The comparison branches above use this, not `literal_value` directly: `if (1u8) ==
/// (2u8) { wipe }` is a constant false that deadens the wipe, but `literal_value("(1u8)")`
/// is `None`, so the whole condition was undecidable and the wipe passed (measured).
fn literal_operand(text: &str) -> Option<i128> {
    literal_value(strip_outer_parens(text.trim()))
}

/// Remove one balanced outer `( … )` pair, if the whole string is wrapped in one.
fn strip_outer_parens(s: &str) -> &str {
    // To a fixpoint: `(((false)))` is a constant too, and peeling one layer per call left
    // `((false))` unreadable (measured as a bypass).
    let mut t = s.trim();
    while t.starts_with('(') && t.ends_with(')') && balanced_inside(t) {
        t = t[1..t.len() - 1].trim();
    }
    t
}

/// Whether the parentheses around `t` (which starts with `(` and ends with `)`) are one
/// matched pair, i.e. the leading `(` closes only at the end.
fn balanced_inside(t: &str) -> bool {
    let mut depth = 0i32;
    for (i, c) in t.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i == t.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// If `s` is exactly a `black_box(<expr>)` call, the `<expr>`; otherwise `s` unchanged.
///
/// `if black_box(false)` was matched as a substring before, which missed
/// `black_box(1u8 == 2u8)`, `black_box( false )` and any path-qualified spelling.
fn peel_black_box(s: &str) -> &str {
    let t = s.trim();
    let Some(pos) = t.find("black_box") else {
        return t;
    };
    // Rust accepts whitespace between a path's last segment and its `(`:
    // `core::hint::black_box (false)` is legal and the compiler folds it like
    // `black_box(false)`, but a matcher that required the literal `black_box(` evaded it
    // (measured: `black_box (false)` deadened a counted wipe with the suite green). Skip
    // the whitespace before requiring `(`.
    let rest = &t[pos + "black_box".len()..];
    let ws = rest.len() - rest.trim_start().len();
    let open = pos + "black_box".len() + ws;
    // Only when the call is the whole condition and its paren closes it.
    if !t[open..].starts_with('(') || !t[open..].ends_with(')') {
        return t;
    }
    let inner = &t[open + 1..t.len() - 1];
    if balanced_inside(&format!("({inner})")) {
        inner.trim()
    } else {
        t
    }
}

/// Split `expr` at the first top-level occurrence of `op` (not inside parentheses), when the
/// operator is not part of a longer one (`>=`/`<=` are not `=`).
fn split_at_top_level_op<'a>(expr: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0i32;
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    while i + op.len() <= bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && expr[i..].starts_with(op) {
            let after = bytes.get(i + op.len());
            // `=` immediately after `!`/`=` would make `!=`/`==` part of a longer token; a
            // third `=` is not a comparison this crate writes.
            if after == Some(&b'=') {
                return None;
            }
            return Some((&expr[..i], &expr[i + op.len()..]));
        }
        i += 1;
    }
    None
}

/// The integer value of a Rust literal, or `None` when `text` is not *exactly* one literal.
///
/// `true`/`false` map to 1/0, so boolean comparisons are decided too. Anything after the
/// digits must be a recognised integer suffix: the whole string is the literal, which is what stops `1 > 2` from parsing
/// as `1` (a bug in the first version that made `while 1 > 2 { … }` look like a constant
/// *true* condition and therefore acceptable).
fn literal_value(text: &str) -> Option<i128> {
    let t: String = text.trim().chars().filter(|c| *c != '_').collect();
    let t = t.trim();
    match t {
        "true" => return Some(1),
        "false" => return Some(0),
        _ => {}
    }
    // `1u8`, `0xFFu32`, `0b1010_u8`, `0o17i32`: split the prefix, the digits, and the
    // suffix, and require the suffix to be one this language allows.
    let (radix, rest) = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (16u32, h)
    } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        (2, b)
    } else if let Some(o) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        (8, o)
    } else {
        (10, t)
    };
    let digits: String = match radix {
        16 => rest.chars().take_while(char::is_ascii_hexdigit).collect(),
        2 => rest
            .chars()
            .take_while(|c| matches!(c, '0' | '1'))
            .collect(),
        8 => rest
            .chars()
            .take_while(|c| matches!(c, '0'..='7'))
            .collect(),
        _ => rest.chars().take_while(char::is_ascii_digit).collect(),
    };
    if digits.is_empty() || !is_integer_suffix(&rest[digits.len()..]) {
        return None;
    }
    i128::from_str_radix(&digits, radix).ok()
}

/// Whether `suffix` is an integer literal suffix (or empty). `f32`/`f64` are included so a
/// float comparison is not silently treated as an integer one.
fn is_integer_suffix(suffix: &str) -> bool {
    matches!(
        suffix,
        "" | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "f32"
            | "f64"
    )
}

/// Whether `iter` is a range literal that is empty by construction (`0..0`, `3..0u8`).
/// `..=` is excluded: `0..=0` has one element and is not an empty loop.
fn empty_range(iter: &str) -> bool {
    let iter = strip_outer_parens(iter.trim());
    if iter.contains("..=") {
        return false;
    }
    let Some((lo, hi)) = iter.split_once("..") else {
        return false;
    };
    // Each bound may itself be parenthesized: `0..(0)` is the same empty range as `0..0`,
    // and `literal_value("(0)")` was `None`, so the loop slipped (measured).
    match (literal_operand(lo), literal_operand(hi)) {
        (Some(lo), Some(hi)) => lo >= hi,
        _ => false,
    }
}

/// A binding or assignment whose RHS is a brace-less closure whose body is this statement:
/// `let _dead = || crate::zeroize_array(&mut enc_key);`, `_ = || wipe;`.
///
/// There is no `{` for [`enclosing_block_heads`] to find, and the statement still sits at
/// brace depth 1, so the wipe reads as a top-level statement of the function while never
/// running. Measured on this tree: the whole six-configuration matrix, `fmt` and `clippy`
/// stayed green with `encrypt`'s success-path `enc_key` wipe moved here. The authoritative
/// closure guard is now `no_counted_wipe_is_inside_a_closure` (a `syn` walk); this string
/// rule is a subset kept for a message that quotes the statement head.
fn brace_less_closure_head(body: &str, at: usize) -> Option<String> {
    let head_start = body[..at].rfind(['\n', ';', '{', '}']).map_or(0, |i| i + 1);
    let head = body[head_start..at].trim();
    if head.contains('{') {
        return None;
    }
    // A closure parameter list always ends with `|` (`||`, `|x|`, `move |x|`); a bitwise
    // `a | b` ends with an operand, not a pipe. Requiring two pipes excludes a lone `|`.
    if !head.ends_with('|') || head.matches('|').count() < 2 {
        return None;
    }
    // The closure must be the statement's *value*, not an argument to an eager call:
    // `v.iter().for_each(|_| wipe)` runs its closure, so it is not dead. A binding
    // (`let x = …`) or an assignment (`_ = …`, `x = …`) stores the closure without
    // calling it. The `let`-only version of this rule left `_ = || wipe;` (a discard
    // assignment) unflagged (measured: `fmt`, `--test security` and `--all-features` all
    // green with `encrypt`'s `enc_key` wipe moved there).
    let before_pipes = head[..head.len() - 1].trim_end_matches('|').trim_end();
    let before_pipes = before_pipes
        .strip_suffix("move")
        .map_or(before_pipes, str::trim_end);
    if head.starts_with("let ") || before_pipes.ends_with('=') {
        return Some(head.to_string());
    }
    None
}

/// True when `at` sits inside a closure body, which nothing guarantees is ever called.
fn inside_closure_body(body: &str, at: usize) -> bool {
    enclosing_block_heads(body, at)
        .iter()
        .any(|(_, head)| head.ends_with('|'))
}

/// The condition of an `if`/`while` head that may carry a keyword prefix.
///
/// `enclosing_block_heads` builds the head as all text back to the previous
/// `\n`/`;`/`{`/`}`, so a keyword prefix stays attached: `let _ = if false { wipe };` and
/// `return if false { wipe };` both reach the guard with a head that does *not* start with
/// `if `, and `strip_prefix` alone missed them (measured: both deadened a counted wipe with
/// the suite green). Strip a leading `let … = ` or `return ` before re-reading the keyword.
fn if_condition_of(head: &str) -> Option<&str> {
    if let Some(c) = head
        .strip_prefix("if ")
        .or_else(|| head.strip_prefix("while "))
    {
        return Some(c);
    }
    for prefix in ["let ", "return "] {
        if let Some(rest) = head.strip_prefix(prefix) {
            let rest = rest.trim();
            let rhs = rest.rsplit_once(" = ").map_or(rest, |(_, rhs)| rhs.trim());
            if let Some(c) = rhs
                .strip_prefix("if ")
                .or_else(|| rhs.strip_prefix("while "))
            {
                return Some(c);
            }
        }
    }
    None
}

/// Whether the scrutinee of an `if let`/`while let` is a constant a non-`None` pattern
/// cannot agree with (`None`, `None::<T>`, or a literal). A live `if let` matches a
/// binding or a call, so this rejects only the constant forms.
fn dead_if_let_rhs(rhs: &str) -> bool {
    let rhs = strip_outer_parens(rhs.trim());
    if literal_value(rhs).is_some() {
        return true;
    }
    rhs == "None" || rhs.starts_with("None::") || rhs.starts_with("None.")
}

/// The pattern of a `match` arm head (`5 =>`, `_ =>`, `Some(x) if c =>`), with any
/// ` if <guard>` removed. `None` when `head` is not an arm (does not end in `=>`).
fn arm_pattern(head: &str) -> Option<&str> {
    let arm = head.strip_suffix("=>")?;
    let pat = arm.split_once(" if ").map_or(arm, |(p, _)| p);
    Some(pat.trim())
}

/// Whether `pat` *might* match the constant `scrut`.
///
/// `Some(false)` only when every alternative is a literal or a literal range and none
/// contains `scrut` -- the dead-arm case. A wildcard, a binding, a path pattern
/// (`Some(_)`, `Foo::Bar`) or an unparseable part is "may match" (`Some(true)`), because
/// the guard must not reject a live arm. This covers the `6 | 7` and `6..=9` patterns the
/// plain `literal_value(pat)` comparison missed.
fn arm_pattern_may_match(pat: &str, scrut: i128) -> Option<bool> {
    let mut saw_decidable = false;
    for alt in split_top_level(pat, '|') {
        let alt = strip_outer_parens(alt.trim());
        if alt == "_" || alt.is_empty() {
            return Some(true);
        }
        if let Some((lo, hi, inclusive)) = split_range(alt) {
            let (Some(lo), Some(hi)) = (literal_operand(lo), literal_operand(hi)) else {
                return Some(true);
            };
            saw_decidable = true;
            let in_range = if inclusive {
                scrut >= lo && scrut <= hi
            } else {
                scrut >= lo && scrut < hi
            };
            if in_range {
                return Some(true);
            }
            continue;
        }
        match literal_operand(alt) {
            Some(v) => {
                saw_decidable = true;
                if v == scrut {
                    return Some(true);
                }
            }
            // A non-literal part (a binding, `Some(_)`, a path): may match.
            None => return Some(true),
        }
    }
    if saw_decidable {
        Some(false)
    } else {
        Some(true)
    }
}

/// Split `s` on top-level occurrences of `sep` (not inside `()`, `[]`, `{}`).
fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// `a..=b` / `a..b` split into `(a, b, inclusive)`, if `s` is a range.
fn split_range(s: &str) -> Option<(&str, &str, bool)> {
    if let Some((lo, hi)) = s.split_once("..=") {
        return Some((lo, hi, true));
    }
    let (lo, hi) = s.split_once("..")?;
    Some((lo, hi, false))
}

/// The `{ … }` condition of an `if { … }` / `while { … }` whose keyword sits immediately
/// before the block opening at `open` (the wipe block for `if { false } { wipe }`).
fn block_condition_before(body: &str, open: usize) -> Option<&str> {
    let before = body[..open].trim_end();
    if !before.ends_with('}') {
        return None;
    }
    let close = before.len() - 1;
    // The matching `{` of that `}`.
    let mut depth = 0i32;
    let mut content_open = None;
    for (i, c) in body[..=close].char_indices().rev() {
        match c {
            '}' => depth += 1,
            '{' => {
                depth -= 1;
                if depth == 0 {
                    content_open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let content_open = content_open?;
    let kw = body[..content_open].trim_end();
    if kw.ends_with("while") || kw.ends_with("if") {
        let start = if kw.ends_with("while") {
            kw.len() - "while".len()
        } else {
            kw.len() - "if".len()
        };
        // The keyword must be a whole word (`elif`/`iff` are not it).
        let boundary_ok = start == 0
            || !kw[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if boundary_ok {
            return Some(&body[content_open + 1..close]);
        }
    }
    None
}

fn assert_wipes_are_not_deadened(
    name: &str,
    body: &str,
    body_line: usize,
    wipe: &str,
    allowed_cfg: &[&str],
    ungated_success_path: bool,
) {
    // The raw read below turns a line number in `body` into a line of `src/lib.rs`.
    // That mapping holds because every stage of the cut blanks spans and comments while
    // keeping every newline (`strip_comments` keeps them inside line comments, block
    // comments and raw strings; the one shape it can drop is a `\`-continued ordinary
    // string literal, which no longer matches the raw file). Asserted, not assumed: a
    // future edit that breaks it would make the read land on the wrong line, and the
    // wrong line is a predicate this guard did not check.
    assert_eq!(
        non_test_source().lines().count(),
        LIB.lines().count(),
        "the stripped scan text and `src/lib.rs` have different line counts (a \
         `\\`-continued string literal drops its newline in `strip_comments`), so a raw \
         `cfg` predicate cannot be read back by line number; fix the stripper rather \
         than reading the wrong line"
    );
    let mut base = 0usize;
    while let Some(i) = body[base..].find(wipe) {
        let at = base + i;
        // The table spells the call without its qualifier, but the source writes
        // `crate::zeroize_array(...)`. Starting the attribute scan at the `zeroize_array`
        // token reads a prefix that ends in `crate::`, so an attribute on the line *above
        // the statement* looks like a non-attribute line and the wipe passes. Back up over
        // the qualifier to make the whole statement the subject of the scan.
        let mut stmt_at = at;
        for qualifier in ["crate::", "self::", "super::"] {
            if body[..stmt_at].ends_with(qualifier) {
                stmt_at -= qualifier.len();
                break;
            }
        }
        if let Some(head) = constant_false_enclosing_block(body, stmt_at) {
            panic!(
                "`{name}`'s wipe `{wipe}` is deadened by an enclosing block that cannot run: \
                 `{head}`. The text this file counts is unchanged while the wipe never \
                 executes. Delete the wrapper."
            );
        }
        let mut attrs = preceding_attributes(body, stmt_at);
        for candidate in enclosing_block_attributes(body, stmt_at) {
            if !attrs
                .iter()
                .any(|(line, attr)| *line == candidate.0 && *attr == candidate.1)
            {
                attrs.push(candidate);
            }
        }
        for (line_no, attr) in attrs {
            if let Some(finding) = attribute_finding(attr) {
                panic!(
                    "`{name}`'s wipe `{wipe}` is directly preceded by `{attr}`: {finding}. An \
                     attribute whose gating is constant compiles the wipe out while leaving \
                     the text this file counts unchanged, and `#[cfg(any())] {{ {wipe} }}` \
                     survived the whole suite before this check existed. Delete the \
                     attribute — a constant gate is not a configuration."
                );
            }
            if is_cfg_attribute(attr) {
                let line = body_line + line_no;
                let predicate = raw_cfg_predicate_at(line);
                // The allow-list is per wipe, but a wipe can occur several times in one
                // body (encrypt's `k_in`/`k_out`/`enc_seed` occur twice inside the
                // `#[cfg(feature = "ultra")]` witness block and once on the unconditional
                // success path). Passing one list for all of them let
                // `#[cfg(feature = "ultra")]` sit on the success-path wipe, compiling it
                // out of the default build while the suite stayed green (measured). When
                // the caller marks the success path as required-ungated, a depth-1
                // occurrence (a direct statement of the function body -- the path every
                // build takes) may carry no `cfg` at all, whatever the allow-list says.
                // The `sites` table, whose rows may name a genuinely feature-gated wipe
                // (`decrypt`'s `recomputed_tag` exists only to be compared under
                // `dual-mac`), passes `false` and keeps the per-wipe list.
                let effective_allowed: &[&str] =
                    if ungated_success_path && brace_depth_at(body, stmt_at) <= 1 {
                        &[]
                    } else {
                        allowed_cfg
                    };
                assert!(
                    effective_allowed.contains(&predicate.as_str()),
                    "`{name}`'s wipe `{wipe}` is directly preceded by `{}` (line {line}), \
                     whose predicate `{predicate}` is not one of the configurations this \
                     wipe's occurrence may be gated by ({effective_allowed:?}). A `cfg` on a \
                     counted wipe compiles the wipe out of every build the predicate is false \
                     in while leaving the counted text unchanged: `#[cfg(feature = \"pure\")]` \
                     on `encrypt`'s `enc_key` wipe was measured taking the wipe out of the \
                     default and `ultra` builds with the whole suite green, and the same \
                     predicate is not allowed on the unconditional success path even though \
                     the ultra witness block is enumerated for it. Delete the attribute, or \
                     add the predicate to the table deliberately, with the reason the wipe is \
                     not counted in the configurations it excludes.",
                    raw_lib_line(line).trim()
                );
            }
        }
        base = at + wipe.len();
    }
}

/// No `cfg`-family attribute whose gating is constant may appear anywhere in the crypto
/// source.
///
/// This is the blanket half of [`assert_wipes_are_not_deadened`]: the per-site check only
/// covers the wipes named in the table below, and the attribute form can deaden anything
/// (a `scrub_stack()` call, an integrity check). A constant gate has no legitimate use —
/// it compiles its scope in or out in *every* configuration (or, for a `cfg_attr` with a
/// constant condition, applies its attributes unconditionally or never) — so the rejection
/// is the whole shape rather than a list of spellings. Checked before this guard was
/// written: `src/lib.rs` and `src/witness.rs` contain no `cfg(any())`, `cfg(all())`,
/// `cfg(not(any()))` or `cfg(not(all()))` anywhere, so there is nothing to carve out; the
/// scan is what keeps that true. (The `if cfg!(any())` form is not an attribute; it is
/// already caught by `tests/variable_latency.rs`'s control-flow inventory, because it is
/// an `if`.)
///
/// The shapes this covers, each of which was measured surviving an earlier version: the
/// outer `#[cfg(…)`]` with a constant predicate, including `not(true)` and `not(false)`
/// (rustc 1.88+ boolean literals; rejecting them is defence in depth while the MSRV is
/// 1.85); the inner `#![cfg(…)]` form, which used to match nothing; and `#[cfg_attr(…)]`,
/// whose condition (or whose listed `cfg` attribute) can be constant. What it does not
/// cover: a `cfg_attr` nested deeper than the walk recurses (it recurses without a depth
/// bound, so this is only stack depth), attributes in files other than the two scanned
/// here, and always-off-in-a-consumer's-build atoms other than `test` (`kani`, `miri`,
/// `doc`, `doctest`), which stay configuration atoms.
#[test]
fn no_constant_cfg_attribute_can_deaden_the_crypto_source() {
    for (name, src) in [
        ("src/lib.rs", LIB),
        ("src/witness.rs", include_str!("../src/witness.rs")),
    ] {
        // The brace-matched cut, not `src.find("mod tests {")`: production code appended
        // after either file's test module is scanned here too (a constant `#[cfg(…)]`
        // appended below `mod tests` in `src/lib.rs` left this test green).
        let body = non_test_source_of(src);
        // The known leading-statement bypass used a `pure` cfg on a block. There is no
        // legitimate `pure` cfg in the crate source: the feature is forwarded to the
        // BLAKE3 dependency in Cargo.toml, never tested in Rust cfg. The check reads the
        // *raw* source, not `body`: `strip_comments` blanks string-literal contents, so
        // `cfg(feature = "pure")` becomes `cfg(feature = "")` there and the assertion
        // could never fire.
        assert!(
            !src.contains("cfg(feature = \"pure\")"),
            "`{name}` contains a `pure` cfg attribute; the known deadening bypass uses one, \
             and no production code needs it"
        );
        let found = {
            // The predicate is evaluated on the **literal-intact** cut, so a feature name
            // is a name and `all(feature = "a", not(feature = "b"))` is the two-atom
            // formula it is. An attribute text that exists only there — a `#[cfg(…)]`
            // inside a string literal — is dropped by the line filter, because the blanked
            // cut is the one that knows what is code.
            let seen_in_code = cfg_attribute_lines(&body);
            constant_cfg_attributes(&non_test_source_of_keeping_literals(src))
                .into_iter()
                .filter(|(line, _)| seen_in_code.contains(line))
                .collect::<Vec<_>>()
        };
        assert!(
            found.is_empty(),
            "{name} carries constant `cfg` attribute(s) {found:?}. `#[cfg(any())]` compiles \
             its scope *out* while leaving the text intact — a wipe protects nothing if it \
             is never executed, and no text count in this file can see the difference — \
             and `all()` / `not(any())` / `not(all())` / `not(true)` / `#[cfg(test)]` are \
             the same shape with the other constant value, as is a `cfg_attr` whose \
             condition or listed attribute is constant. Write a real predicate or delete \
             the code."
        );
    }
}

/// The body of the item whose header starts with `marker` — `"pub fn encrypt("`,
/// `"fn derive_tag("`, `"impl Drop for Plaintext {"` — brace-matched, on the
/// comment-free non-test source, so a comment or a dead literal cannot stand in for
/// the item the count below wants.
///
/// This generalises the `body` helper inside `every_allocation_happens_before_any_derivation`,
/// which only finds `pub fn`: roughly half the wipes the crate's documentation promises
/// live in `impl Drop` bodies and in private helpers, and pinning a *call site* there
/// witnesses nothing — `derive_material`, `derive_tag`, `derive_enc` and
/// `blake3_keyed_multi` are `#[inline]`-able and are reached from several entry points,
/// so the wipe has to be counted where it is written.
///
/// Returns the body **and the 1-based line of `src/lib.rs` its first line is**, which
/// [`assert_wipes_are_not_deadened`] needs to read a `cfg` predicate's string contents
/// back from the raw source (the scan text has them blanked). Line numbers survive the
/// cut and the stripper; the guard asserts that before it relies on it.
fn body_of(marker: &str) -> (String, usize) {
    let source = non_test_source();
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("`{marker}` not found in src/lib.rs"));
    let line = source[..start].matches('\n').count() + 1;
    let after = &source[start..];
    let open = after.find('{').expect("block without a body");
    let mut depth = 0usize;
    for (i, c) in after[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return (after[..=open + i].to_string(), line);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in `{marker}`");
}

#[test]
fn every_allocation_happens_before_any_derivation() {
    /// The body of `pub fn name(`: [`body_of`] with the marker spelled for an entry
    /// point, kept because every call in this test names an entry point. (The wipe
    /// loop below needs the line as well, so it calls `body_of` directly.)
    fn body(name: &str) -> String {
        body_of(&format!("pub fn {name}(")).0
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

    // The ordering above recognizes one *spelling* of "allocation". A second allocation
    // added at its use site under another name -- `vec![…]`, `Vec::with_capacity`,
    // `try_reserve`, `.to_vec()`, `Box::new` -- is the same defect (its `?`/abort path
    // returns through live key material) and every `alloc_zeroed(` match above is blind to
    // it: an injected `Vec::<u8>::with_capacity(1)` after `derive_enc` in
    // `decrypt_in_place_detached` left this test green (a first version of this list named
    // `Vec::with_capacity`, which the turbofish walked past). Pin the other spellings so a
    // new one has to be added deliberately, at a decided position, rather than slipping past
    // the ordering.
    //
    // Iterator adapters and the owned-conversion constructors are the same class, and the
    // list was measured incomplete: a later pass inserted
    // `let _late: Vec<u8> = (0..4u8).collect();` immediately after `derive_material(` in
    // `decrypt_in_place_detached` -- an allocation whose `try_reserve` failure aborts
    // *after* the derivation, exactly the defect this loop exists for -- and this test, and
    // the whole suite, stayed green. `.collect(`, `.to_owned(`, `String::`, `Rc::` and
    // `Arc::` are pinned for that reason; `Vec::from` is named as well even though the bare
    // `Vec::` above already subsumes it, because the list is a checklist of the class rather
    // than a minimal set. It remains a spelling list, not a proof: a helper of the crate's
    // own that allocates (there is one, `alloc_zeroed`) or a macro that expands to an
    // allocation elsewhere would not be caught here, so an ordering assertion over the
    // alloc_zeroed sites is still the primary check.
    for name in [
        "encrypt",
        "encrypt_in_place_detached",
        "decrypt",
        "decrypt_in_place_detached",
    ] {
        let body = body(name);
        for spelling in [
            "vec![",
            "vec! [",
            // The bare path form, so the turbofish spelling `Vec::<u8>::with_capacity` is
            // caught too: an injected `Vec::<u8>::with_capacity(1)` after `derive_enc`
            // walked straight past a `Vec::with_capacity` match. `Box::` and `vec!` catch
            // the turbofish and the space-before-bracket spellings.
            "Vec::",
            "Vec::from",
            "with_capacity",
            "try_reserve",
            ".to_vec()",
            ".to_owned(",
            ".collect(",
            "Box::",
            "String::",
            "Rc::",
            "Arc::",
            "alloc::alloc::alloc",
        ] {
            assert!(
                !body.contains(spelling),
                "{name} allocates through `{spelling}`, which the ordering above cannot \
                 place relative to the first derivation; route it through the fallible \
                 `alloc_zeroed` helper before the derivation, or add this spelling to the \
                 list deliberately and order it too"
            );
        }
        // A function item alias (`let f = alloc_zeroed;`) puts an unbanned call spelling
        // after the derivation while the early allocation goes through the alias; reject
        // the binding shape rather than trying to follow it.
        for alias in ["= alloc_zeroed;", "= derive_material;"] {
            assert!(
                !body.contains(alias),
                "{name} binds `{alias}` as a function item; a call through the alias escapes \
                 both this spelling list and the ordering check above"
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
    // The third failure arm with the same promise is the length refusal. It returns
    // before anything is written, and its input (more than `MAX_MSG_SIZE` bytes) cannot
    // be built in a test, so a *source* shape is the only witness: deleting this wipe
    // leaves every behavioural test green while the documented "on failure the buffer is
    // zeroized" contract becomes false for this arm.
    let length_arm = [
        "    if let Err(e) = check_lengths(buffer.len(), aad.len()) {",
        "        crate::zeroize_slice(buffer);",
        "        return Err(e);",
        "    }",
    ]
    .join("\n");
    assert_eq!(
        in_place.matches(length_arm.as_str()).count(),
        1,
        "the length-refusal arm must zeroize the caller's buffer before returning; the \
         contract is unconditional and this arm has no behavioural route:\n{length_arm}"
    );

    // Every named secret buffer must actually be wiped, per entry point. The ordering
    // assertions above only compare *positions*: an audit deleted `encrypt`'s
    // `zeroize_array(&mut enc_key);` -- one key left in the frame on the success path --
    // and this file, the three sibling source-shape files and all 50 crate unit tests
    // stayed green. The counts are exact, so deleting a wipe of a buffer that has more
    // than one site (`encrypt`'s three `k_in` wipes) fails too rather than being covered
    // by a surviving site.
    //
    // `tag` is the `ultra`-only pair: `encrypt`'s two witness-rejection returns wipe the
    // computed tag before returning. Those two lines are counted as *text* here (this test
    // runs in every configuration), which is the point -- deleting either one leaves the
    // secret-derived KDF input in the frame, and no behavioural test can reach the
    // rejection path because reaching it needs a witness disagreement.
    let buffer_table = [
        (
            "encrypt",
            &[
                ("k_in", 3),
                ("k_out", 3),
                ("enc_seed", 3),
                ("enc_key", 1),
                ("enc_nonce", 1),
                ("tag", 2),
            ][..],
        ),
        (
            "encrypt_in_place_detached",
            &[
                ("k_in", 1),
                ("k_out", 1),
                ("enc_seed", 1),
                ("enc_key", 1),
                ("enc_nonce", 1),
            ][..],
        ),
        (
            "decrypt",
            &[
                ("k_in", 1),
                ("k_out", 1),
                ("enc_seed", 1),
                ("enc_key", 1),
                ("enc_nonce", 1),
                ("computed_tag", 1),
            ][..],
        ),
        (
            "decrypt_in_place_detached",
            &[
                ("k_in", 1),
                ("k_out", 1),
                ("enc_seed", 1),
                ("enc_key", 1),
                ("enc_nonce", 1),
                ("computed_tag", 1),
            ][..],
        ),
    ];
    // The table's own size is pinned: deleting a whole entry-point row (and its wipes)
    // would otherwise leave the per-row counts above true for the rows that remain.
    assert_eq!(
        buffer_table.len(),
        4,
        "the entry-point wipe table must keep all four rows"
    );
    for (name, buffers) in buffer_table {
        let expected_buffers = match name {
            "encrypt" => 6,
            "encrypt_in_place_detached" => 5,
            "decrypt" => 6,
            "decrypt_in_place_detached" => 6,
            other => panic!("unexpected entry-point table row `{other}`"),
        };
        assert_eq!(
            buffers.len(),
            expected_buffers,
            "`{name}`'s buffer list has {} entries, expected {expected_buffers}: a deleted \
             row must be a deliberate change to this count",
            buffers.len()
        );
        let (body, body_line) = body_of(&format!("pub fn {name}("));
        for (buffer, expected) in buffers {
            let wipe = format!("zeroize_array(&mut {buffer});");
            let found = body.matches(wipe.as_str()).count();
            assert_eq!(
                found, *expected,
                "`{name}` wipes `{buffer}` {found} times, not {expected}: a deleted (or \
                 added) wipe changes what survives on the stack, and the ordering \
                 assertion above cannot see it -- it compares the position of the first \
                 derivation with each allocation, never the wipes"
            );
            // The count is text, and text survives being compiled out: the same wipe
            // wrapped in `#[cfg(any())] { … }` (or prefixed with `#[cfg(any())]`, or with
            // `#[cfg(feature = "…")]`) is counted exactly as before while never running.
            // Pin the live shape at each site the count just found. `encrypt`'s rejection
            // arms live inside its `#[cfg(feature = "ultra")]` block, so that predicate is
            // the one legitimate enclosing gate; every other site must have none.
            let allowed: &[&str] = if name == "encrypt" {
                &["feature=\"ultra\""]
            } else {
                &[]
            };
            assert_wipes_are_not_deadened(name, &body, body_line, &wipe, allowed, true);
            // The per-wipe check above pins the shapes around the *counted* rows. This one
            // also covers the wipes those rows do not name -- `encrypt`'s and `decrypt`'s
            // `crate::scrub_stack()` calls among them, whose deadening the suite used to
            // leave entirely to `tools/stack_residue.sh`.
            assert_no_deadened_wipe(name, &body);
            // The count alone cannot see a wipe moved into an existing rejection branch:
            // every entry point's success-path wipe is a direct statement of the function
            // body (depth 1). `encrypt`'s `tag` is the one exception -- the tag is
            // returned, not wiped on success -- so it has no depth-1 site by design.
            if !(name == "encrypt" && *buffer == "tag") {
                let top = top_level_count(&body, &wipe);
                assert!(
                    top >= 1,
                    "`{name}` has no top-level `{wipe}`: a copy of the wipe inside an \
                     `if`/`match`/loop keeps the count while the success path stops wiping; \
                     `top_level_count` found {top}"
                );
            }
        }
    }
}

/// Every wipe the crate's own documentation promises, witnessed by an exact
/// source-shape count **in the body that promises it**.
///
/// `every_allocation_happens_before_any_derivation`'s table counts the secret locals
/// of the four entry points. The wipes those functions rely on live one level down —
/// in `derive_material`, `derive_tag`, `derive_enc`, the `Drop` impls, `locked`'s page
/// and BLAKE3's own state — and an adversarial pass deleted **twelve** of them with
/// `cargo test --all-features` still green: `Plaintext::drop`'s `zeroize_slice`,
/// `Page::drop` and `LockedKey::drop`, `derive_material`'s four, `derive_tag`'s
/// `cat`/`inner`/`outer` and `derive_enc`'s `material`/`input`. A wipe of a stack local
/// has no behavioural signature, so a text count is the only witness it can have; the
/// counts are exact, so a buffer with more than one site (the two BLAKE3-state pairs)
/// fails on a single deleted call rather than being covered by the survivor.
///
/// `tag_copy` is here with the opposite history: it was counted nowhere *and* the code
/// called it "secret-derived", which an audit pointed out is false — it is a copy of
/// the **received** tag, which is public. The wipe stays (the pair is read out as one
/// comparison's operands, and the table should cover both), the rationale where the
/// wipe lives is corrected, and the count here is what makes the wipe survive an edit.
///
/// The one deliberate **absence** is the two `zeroize_slice(&mut ciphertext);`
/// statements that used to sit in `encrypt`'s `ultra` witness-rejection arms. They
/// cleared a buffer that `alloc_zeroed` had just filled with zeros and the keystream
/// had not touched yet — `O(plaintext.len())` volatile stores on a should-never-happen
/// path, protecting nothing — so they are deleted rather than counted, and the `0`
/// assertion at the end of this test pins the deletion.
///
/// Wipes this table deliberately does **not** duplicate, because another test already
/// pins the same statement (with a stronger, call-site-specific check) and a second
/// count would only be a second thing to keep in step:
///
/// * `LockedKey::new`'s `crate::zeroize_array(&mut tag);` and
///   `check_integrity`'s `crate::zeroize_array(&mut expected);` — `tests/locked.rs`'s
///   `the_integrity_tag_is_wiped_in_both_callers` pins both, their position relative to
///   the fallible `lock_range` / the branch, and that each is an unconditional
///   top-level statement rather than a nested or attribute-deadened one;
/// * `ultra`'s witness copies (`witness_tag`, `witness_plaintext`,
///   `witness_ciphertext`) — exact counts in `tests/ultra.rs`
///   (`dual_mac_is_wired_into_both_decrypt_paths`'s wipe assertions: 3/2/1);
/// * `decrypt`'s `zeroize_slice(&mut plaintext);` and the in-place entry point's
///   `zeroize_slice(buffer);` rejection wipes — `tests/decision_scope.rs` pins the
///   `if decisionN.is_err() { <wipe>; return … }` shape at all four sites and the
///   accept-fall-through, and this file's allocation table pins the two
///   `zeroize_slice(buffer);\n return Err(e);` allocation-failure arms.
///
/// Each row carries the item `marker` its body is extracted by and the `cfg`
/// predicates the table counts each wipe under (empty for every wipe that exists in
/// every build; see [`assert_wipes_are_not_deadened`]). That second half is what
/// catches a *plausible feature name*: an auditor planted
/// `#[cfg(feature = "pure")]` on `encrypt`'s `zeroize_array(&mut enc_key);` and the
/// default and `ultra` builds lost the wipe while every test stayed green.
#[test]
fn every_documented_wipe_has_a_witness() {
    /// One item, its body located by `marker`, and every wipe that body owes.
    struct Site {
        label: &'static str,
        marker: &'static str,
        /// `(wipe text, exact count, the `cfg` predicates this wipe is counted in)`.
        wipes: &'static [(&'static str, usize, &'static [&'static str])],
    }

    let sites = [
        Site {
            label: "Plaintext::drop",
            marker: "impl Drop for Plaintext {",
            // The buffer is the recovered plaintext: the one wipe a caller of `decrypt`
            // never sees and cannot do for the crate. The second row is the capacity tail:
            // it is conditional today (`alloc_zeroed` reserves exactly `len`, so the
            // branch does not run), but the comment there promises it for a future
            // constructor that grows the buffer, and the raw-pointer form is the *only*
            // way to clear bytes past `len` that no reference may cover.
            wipes: &[
                ("zeroize_slice(self.0.as_mut_slice());", 1, &[]),
                (
                    "zeroize_raw(self.0.as_mut_ptr().add(len), cap - len)",
                    1,
                    &[],
                ),
            ],
        },
        Site {
            label: "Key::zeroize",
            marker: "impl Zeroize for Key {",
            // `Key::drop` goes through this impl, so the wipe the `Key` docs promise is
            // one statement in one body; the `Drop` row below pins the call into it.
            wipes: &[("zeroize_array(&mut self.0);", 1, &[])],
        },
        Site {
            label: "Key::drop",
            marker: "impl Drop for Key {",
            // Fully qualified on purpose: `self.zeroize()` resolved to an inherent method
            // if one were added, silently turning the drop wipe into a no-op (A1/L-40 in
            // the external report). This row pins the qualified spelling.
            wipes: &[("<Key as zeroize::Zeroize>::zeroize(self);", 1, &[])],
        },
        Site {
            label: "Page::drop (locked)",
            marker: "impl Drop for Page {",
            // `LockedKey::new`'s early returns and any unwind drop the page directly; the
            // key is written after the fallible `lock_range`, so the current refusal path
            // drops an all-zero page. This wipe is the unwinding-path and future-early-return
            // cover, not the `lock_range` refusal (which has nothing to wipe yet).
            wipes: &[("crate::zeroize_slice(self.bytes_mut());", 1, &[])],
        },
        Site {
            label: "LockedKey::drop (locked)",
            marker: "impl Drop for LockedKey {",
            // Wipes the whole page *before* unlocking it: `munlock` opens the swap window
            // this wipe exists to close.
            wipes: &[("crate::zeroize_slice(self.0.bytes_mut());", 1, &[])],
        },
        Site {
            label: "derive_material",
            marker: "fn derive_material(",
            wipes: &[
                ("zeroize_array(&mut subkey);", 1, &[]),
                ("zeroize_array(&mut subkey_nonce);", 1, &[]),
                ("zeroize_array(&mut block0);", 1, &[]),
                ("zeroize_array(&mut block1);", 1, &[]),
            ],
        },
        Site {
            label: "derive_tag",
            marker: "fn derive_tag(",
            wipes: &[
                // The one allocation in the two-level tag: the concatenated inner-hash
                // input, wiped before it is freed.
                ("zeroize_slice(&mut cat);", 1, &[]),
                // The inner digest is a PRF output under `k_in`; the outer input is that
                // digest under a domain word.
                ("zeroize_array(&mut inner);", 1, &[]),
                ("zeroize_array(&mut outer);", 1, &[]),
            ],
        },
        Site {
            label: "derive_enc",
            marker: "fn derive_enc(",
            wipes: &[
                ("zeroize_array(&mut material);", 1, &[]),
                ("zeroize_array(&mut input);", 1, &[]),
            ],
        },
        Site {
            label: "blake3_keyed_multi (keyed seam)",
            marker: "fn blake3_keyed_multi(",
            wipes: &[("reader.zeroize();", 1, &[]), ("hasher.zeroize();", 1, &[])],
        },
        Site {
            label: "integrity_tag (locked's unkeyed seam)",
            marker: "fn integrity_tag(",
            wipes: &[("reader.zeroize();", 1, &[]), ("hasher.zeroize();", 1, &[])],
        },
        Site {
            label: "random::fill_from",
            marker: "fn fill_from(",
            // `getrandom` guarantees nothing about `dest` on failure, so a partial fill
            // is wiped rather than left for a caller that ignores the `Result`.
            wipes: &[("crate::zeroize_slice(dest);", 1, &[])],
        },
        Site {
            label: "decrypt",
            marker: "pub fn decrypt(",
            wipes: &[
                // Secret-derived: the computed MAC. (Previously uncounted here; the
                // existence check in `tests/decision_scope.rs` did not pin the count.)
                ("zeroize_array(&mut computed_tag_copy);", 1, &[]),
                // A copy of the *received* tag: public, wiped as one operand of the pair
                // rather than because it is a secret. See the comment at the wipe.
                ("zeroize_array(&mut tag_copy);", 1, &[]),
                // Only exists under `dual-mac`, which is why this is the table's one
                // non-empty allow-list.
                (
                    "zeroize_array(&mut recomputed_tag);",
                    1,
                    &["feature=\"dual-mac\""],
                ),
            ],
        },
        Site {
            label: "decrypt_in_place_detached",
            marker: "pub fn decrypt_in_place_detached(",
            wipes: &[
                ("zeroize_array(&mut computed_tag_copy);", 1, &[]),
                ("zeroize_array(&mut tag_copy);", 1, &[]),
                (
                    "zeroize_array(&mut recomputed_tag);",
                    1,
                    &["feature=\"dual-mac\""],
                ),
            ],
        },
    ];

    // The table must not be able to shrink silently: deleting a `Site` or one of its wipe
    // entries (together with the source line it names) would otherwise leave every label
    // check true while the wipe it witnessed is gone. These two counts are the literal
    // size of the table, so a deletion has to edit them too and the diff says why.
    assert_eq!(
        sites.len(),
        13,
        "the wipe table has {} sites, expected 13: a deleted Site must be a deliberate \
         change to this count",
        sites.len()
    );
    let wipe_entries: usize = sites.iter().map(|s| s.wipes.len()).sum();
    assert_eq!(
        wipe_entries, 26,
        "the wipe table has {wipe_entries} entries, expected 26: a deleted entry must be a \
         deliberate change to this count"
    );
    // The table witnesses the wipes it *names*; it cannot see a wipe added in a function
    // that is not listed, so a new wipe-bearing function would ship unwitnessed. Pin the
    // total number of `crate::zeroize_*` calls in the non-test source as an independent
    // backstop: a new one -- or a deleted one outside a listed site -- changes the total
    // and has to update this number in the same change (measured: adding a
    // `fn new_secret_helper() { … crate::zeroize_array(&mut secret); }` left the suite
    // green until this count existed).
    let wipe_calls = full_wipe_calls();
    assert_eq!(
        wipe_calls, 81,
        "the non-test source contains {wipe_calls} `crate::zeroize_*` call(s), expected 81. \
         This count is the backstop the per-site table cannot provide: a wipe added in a \
         function the table does not list would otherwise be unwitnessed. Count it, add the \
         site, or record why the new wipe is not listed."
    );
    // And every marker must still be a single definition, driven from the table rather
    // than a hand-kept list that can drift: `body_of` takes the *first* match, so a decoy
    // with the same marker would otherwise satisfy the counts for a deleted real wipe.
    let full = non_test_source();
    for site in &sites {
        assert_eq!(
            full.matches(site.marker).count(),
            1,
            "`{}`'s marker `{}` has more than one definition in the non-test source; \
             `body_of` takes the first, so a decoy can stand in for the real item",
            site.label,
            site.marker
        );
    }

    for site in &sites {
        let (body, body_line) = body_of(site.marker);
        for (wipe, expected, allowed_cfg) in site.wipes {
            let found = body.matches(wipe).count();
            assert_eq!(
                found, *expected,
                "`{}`'s wipe `{wipe}` appears {found} times in its body, not {expected}: a \
                 deleted (or added) wipe of a local no test can name has no behavioural \
                 signature -- twelve of them were deleted with the whole suite green -- so \
                 this count is the witness. The live shape at each found site is pinned \
                 separately, below.",
                site.label
            );
            assert_wipes_are_not_deadened(site.label, &body, body_line, wipe, allowed_cfg, false);
        }
        // Same second pass as the entry-point table: every wipe primitive in the site's
        // body must be reachable, not only the rows listed above.
        assert_no_deadened_wipe(site.label, &body);
    }

    // The BLAKE3-state pair, counted as a total across its two call sites: `Cargo.toml`
    // enables `blake3/zeroize` for exactly these calls, and the key lives inside
    // `blake3::Hasher` where no `zeroize_array` of this crate can reach it. The pair is
    // `2` together -- `reader.zeroize(); hasher.zeroize();` at the keyed seam and at
    // `locked`'s unkeyed one -- and the per-site rows above make each of the four
    // statements individually counted, so deleting one half of one pair fails twice
    // over. Half a pair is not a wipe: a `reader`-only call would leave the hasher's
    // `CVWords` (the key, for the keyed seam) in the dependency's frame.
    let pairs: usize = ["fn blake3_keyed_multi(", "fn integrity_tag("]
        .iter()
        .map(|marker| {
            let body = body_of(marker).0;
            let reader = body.matches("reader.zeroize();").count();
            let hasher = body.matches("hasher.zeroize();").count();
            assert_eq!(
                reader, hasher,
                "`{marker}` has {reader} `reader.zeroize();` and {hasher} \
                 `hasher.zeroize();`: the two calls are one wipe (BLAKE3's XOF reader \
                 carries key-derived output state, the hasher holds the key), so a pair \
                 that lost one half is not a wipe"
            );
            reader
        })
        .sum();
    assert_eq!(
        pairs, 2,
        "the `reader.zeroize(); hasher.zeroize();` pair must survive at both keyed-BLAKE3 \
         seams (`blake3_keyed_multi` and `locked`'s `integrity_tag`); `Cargo.toml`'s \
         `zeroize`-feature note cites exactly these calls, and nothing else in this crate \
         can reach BLAKE3's internal key state"
    );

    // The one deliberate absence: `encrypt` no longer wipes its all-zero ciphertext
    // buffer on the `ultra` witness-rejection arms. `0` is the recorded decision, not a
    // witness to a wipe: the buffer comes from `alloc_zeroed` and the keystream has not
    // run yet, so the wipe was `O(plaintext.len())` volatile stores on a path that must
    // never be taken. If a wipe is wanted there after all, delete this assertion
    // deliberately and say what it protects.
    assert_eq!(
        body_of("pub fn encrypt(")
            .0
            .matches("zeroize_slice(&mut ciphertext)")
            .count(),
        0,
        "`encrypt`'s witness-rejection arms must not wipe `ciphertext`: it is still all \
         zeros there (`alloc_zeroed`, keystream below), and the wipe of an all-zero \
         buffer is `O(msg)` work on a should-never-happen path, protecting nothing. \
         Re-adding one is a decision, not a hygiene fix -- make it here."
    );

    // The counts above are text, and text does not resolve names: a local
    // `fn zeroize_array<T>(_: &mut T) {}` at the top of a function leaves every counted
    // occurrence in place while every call resolves to the empty local (a third-party pass
    // measured all thirteen dead in an entry point and `security` still 17/17). Rust has no
    // overloading to hide behind, so the direct check is enough: no function item inside a
    // wipe-bearing body may be named after a wipe it performs.
    //
    // **The markers come from the same table as the counts.** An earlier revision drove
    // this check from a hand-written list of five entry points while the `Site` table above
    // already knew about thirteen -- so `derive_material`, `derive_tag`, `derive_enc`,
    // `blake3_keyed_multi` and `random::fill_from` (the core derivation chain, and the only
    // place `stack_residue.sh` cannot reach) could each carry a shadowing no-op and stay
    // green (found by a later pass and reproduced here). Two lists that describe the same
    // set drift; one list cannot.
    //
    // A *`use` import* does the same thing without declaring anything in the body: a
    // crate-level `mod dummy { pub fn zeroize_array<T>(_: &mut T) {} }` plus
    // `use crate::dummy::zeroize_array;` made all thirteen calls no-ops while `security`,
    // `fmt`, `clippy -D warnings` and every suite stayed green. Both the import spelling and
    // the bare-call spelling are rejected below, in every one of the table's sites.
    for site in &sites {
        let marker = site.marker;
        let body = body_of(marker).0;
        for name in [
            "zeroize_array",
            "zeroize_slice",
            "zeroize_raw",
            "scrub_stack",
        ] {
            for decl in [format!("fn {name}"), format!("fn {name}<")] {
                assert!(
                    !body.contains(&decl),
                    "`{marker}` declares its own `{name}`: every occurrence of that name in \
                     the body then resolves to the local item, so the wipe counts above stay \
                     green while the wipes do nothing (measured: the text counts are \
                     unchanged and the whole suite passes). Delete the local item, or route \
                     the wipe through `crate::{name}` and teach the counts that spelling -- \
                     but do not leave a name that shadows a wipe."
                );
            }
            // `use …::{name};` / `use …::{name} as …;` / `use {name};` inside the body
            // import a different item under the wipe's name. There is no legitimate reason
            // for a wipe-bearing body to import one of these four names: they resolve
            // through the crate root already.
            for import in [
                format!("use {name}"),
                format!("use crate::{name}"),
                format!("use super::{name}"),
            ] {
                assert!(
                    !body.contains(&import),
                    "`{marker}` imports `{name}` (`{import}`): in a function body that \
                     `use` shadows the crate-level item, so every wipe call in this body \
                     resolves to whatever was imported -- a no-op carrying the right name \
                     passes all of the counts above and the whole suite. Wipes resolve \
                     through the crate root; write `crate::{name}(…)` if a local import is \
                     ever tempting."
                );
            }
            // And the *general* import shape: `use <any path>::{name};` inside the body.
            // Matching only the three prefixes above misses the form a real bypass used --
            // a crate-level `mod dummy { pub fn zeroize_array<T>(_: &mut T) {} }` plus
            // `use crate::dummy::zeroize_array;` in the body (a later pass measured all
            // thirteen calls dead and `security` 17/17). Any `use` that ends with one of
            // the four wipe names is rejected, whatever path precedes it.
            for line in body.lines() {
                let t = line.trim();
                if !t.starts_with("use ") || !t.ends_with(&format!("{name};")) {
                    continue;
                }
                panic!(
                    "`{marker}` imports `{name}` (`{t}`): a `use` that brings a different \
                     item in under a wipe's name makes every call to that name resolve to \
                     it, so the wipes silently do nothing while every count above stays \
                     green (measured: a crate-level no-op plus this import left 17/17 and \
                     `clippy -D warnings` clean). Delete the import, and write the call as \
                     `crate::{name}(…)`."
                );
            }
        }
        // And the calls themselves must not be shadowable in the first place: with
        // `-D warnings` a genuinely unused `use` would be caught, but one that *is* used
        // (by rewriting the call) is not. Requiring the absolute form here means a body
        // that calls the bare name is a failing test before any shadowing is attempted --
        // the counting table above matches both spellings, so this is a naming rule, not a
        // coverage change.
        for name in [
            "zeroize_array",
            "zeroize_slice",
            "zeroize_raw",
            "scrub_stack",
        ] {
            let bare = format!(" {name}(");
            let path = format!("crate::{name}(");
            let bare_calls = body.matches(&bare).count();
            let path_calls = body.matches(&path).count();
            assert_eq!(
                bare_calls, 0,
                "`{marker}` calls `{name}(` without the `crate::` prefix ({bare_calls} \
                 occurrence(s)): a bare name is shadowable by a `use` in the same body, and \
                 then the wipe silently does nothing while every count stays. Write \
                 `crate::{name}(…)`. ({path_calls} call(s) in this body already do.)"
            );
        }
    }

    // Whole-file fallback: every wipe call in the crate is `crate::`-qualified. The loop
    // above covers the table's entries; this covers anything the table does not name --
    // a helper added later, a call moved out of a site's body -- so a bare `zeroize_array(`
    // anywhere in non-test source fails here regardless of which function it is in.
    //
    // It scans all three source files, not just `lib.rs`: `src/witness.rs` has no wipe
    // calls today, and `src/proofs.rs`'s two (inside Kani harnesses) are qualified below,
    // but a comment claiming "the whole crate" while reading one file is exactly the kind
    // of scope mismatch this file exists to catch (a later pass pointed that out).
    let stripped_witness = strip_comments(include_str!("../src/witness.rs"));
    let witness_source = {
        // Cut the module body if there is one; `witness.rs` has one, but stay robust.
        match stripped_witness.find("mod tests {") {
            Some(at) => {
                let mut depth = 0usize;
                let mut close = None;
                for (i, c) in stripped_witness[at..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                close = Some(at + i);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let close = close.expect("unterminated `mod tests` in witness.rs");
                format!(
                    "{}\n{}",
                    &stripped_witness[..at],
                    &stripped_witness[close + 1..]
                )
            }
            None => stripped_witness,
        }
    };
    let proofs_source = strip_comments(include_str!("../src/proofs.rs"));
    let source = format!(
        "{}\n{}\n{}",
        non_test_source(),
        witness_source,
        proofs_source
    );
    for n in [
        "zeroize_array",
        "zeroize_slice",
        "zeroize_raw",
        "scrub_stack",
    ] {
        let mut from = 0usize;
        while let Some(rel) = source[from..].find(&format!("{n}(")) {
            let at = from + rel;
            from = at + n.len();
            let before = &source[..at];
            // Skip the definition itself and anything already `crate::`-qualified.
            if before.ends_with("crate::") {
                continue;
            }
            let line_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &source[line_start..];
            if line.trim_start().starts_with("fn ")
                || line.trim_start().starts_with("pub fn ")
                || line.trim_start().starts_with("pub(crate) fn ")
                || line.trim_start().starts_with("unsafe fn ")
            {
                continue;
            }
            let line_no = before.matches('\n').count() + 1;
            panic!(
                "`{n}(` is called without the `crate::` prefix at line {line_no}: a bare name \
                 is shadowable by a local `fn` or a `use` in the same body, which turns the \
                 wipe into a no-op while every count stays green. Write `crate::{n}(…)`. \
                 (This check covers `lib.rs`, `witness.rs` and `proofs.rs`; the per-site \
                 loop above covers the table's entries.)"
            );
        }
    }

    // The one list must not be able to shrink. The count and the shadow check are driven
    // by `sites` now, so a deleted entry takes *both* its witness and its shadow check with
    // it: delete `derive_enc`'s entry and its two wipes and every gate stays green (a later
    // pass measured exactly that). The literal below is the list the table must be.
    let expected_labels = [
        "Plaintext::drop",
        "Key::zeroize",
        "Key::drop",
        "Page::drop (locked)",
        "LockedKey::drop (locked)",
        "derive_material",
        "derive_tag",
        "derive_enc",
        "blake3_keyed_multi (keyed seam)",
        "integrity_tag (locked's unkeyed seam)",
        "random::fill_from",
        "decrypt",
        "decrypt_in_place_detached",
    ];
    let mut actual: Vec<&str> = sites.iter().map(|s| s.label).collect();
    let mut expected: Vec<&str> = expected_labels.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "the `Site` table is the crate's one list of wipe-bearing sites: the count and the \
         shadow check both read it, so a deleted entry removes its own witness and its own \
         shadow check at once and nothing fails (measured: deleting `derive_enc`'s entry and \
         its two wipes left `security` 17/17 and every other gate green). This literal is \
         the list; adding a site means adding it here in the same change, and removing one \
         means saying so deliberately rather than by deleting a row."
    );
}

/// The attribute scan must see an attribute through its block opener, including the
/// same-line form where the opener and attribute share a line. The earlier scan stopped
/// at `{`, so `#[cfg(feature = "pure")] { wipe }` compiled the wipe out while every
/// count stayed green.
#[test]
fn block_attributes_are_seen_through_their_opener() {
    for body in [
        "#[cfg(any())]\n{\n    zeroize_array(&mut x);\n}\n",
        "#[cfg(any())] {\n    zeroize_array(&mut x);\n}\n",
        "#[cfg(feature = \"pure\")]\n\n{\n    zeroize_array(&mut x);\n}\n",
    ] {
        let at = body.find("zeroize_array").expect("fixture holds the wipe");
        let attrs = preceding_attributes(body, at);
        assert!(
            attrs.iter().any(|(_, attr)| attr.contains("cfg")),
            "the scan did not see the block's attribute:\n{body}"
        );
    }
}

/// A wipe hidden in a `macro_rules!` definition is never expanded, but a text scan still
/// counts it. This was a measured bypass: putting `derive_material`'s wipes (or
/// `Plaintext::drop`'s) in an unused macro left every count and `-D warnings` green.
fn macro_bodies(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("macro_rules") {
        let after = &rest[start..];
        // `macro_rules ! m { … }` is the same definition with whitespace between the
        // tokens (rustc accepts it); a literal `macro_rules!` search missed it.
        let name_at = "macro_rules".len();
        let Some(tail) = after.get(name_at..) else {
            break;
        };
        let trimmed = tail.trim_start();
        if !trimmed.starts_with('!') {
            rest = &after[name_at..];
            continue;
        }
        let Some(open) = trimmed.find('{') else {
            break;
        };
        let open = after.len() - trimmed.len() + open;
        let mut depth = 0usize;
        let mut end = None;
        for (offset, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            break;
        };
        out.push(after[..=end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// The names of every `macro_rules!` defined in `source`.
fn macro_names(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("macro_rules") {
        let after = &rest[start..];
        let tail = after.get("macro_rules".len()..).unwrap_or("");
        let trimmed = tail.trim_start();
        if let Some(after_bang) = trimmed.strip_prefix('!') {
            let name: String = after_bang
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push(name);
            }
        }
        rest = &after["macro_rules".len()..];
    }
    out
}

/// The byte index of the delimiter matching the one at `open` (same-delimiter counting:
/// Rust requires balanced delimiters, so the matching close is the one that returns the
/// count to zero).
fn matching_delim(source: &str, open: usize, open_ch: char, close_ch: char) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in source[open..].char_indices() {
        if c == open_ch {
            depth += 1;
        } else if c == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(open + i);
            }
        }
    }
    None
}

/// Every invocation of a `macro_rules!` *defined in this source*, as the token text from
/// the opening delimiter through its match.
///
/// [`macro_bodies`] catches a wipe inside a macro that is never expanded. It cannot see
/// the other half: a macro that takes the wipe as a token-tree argument and discards it --
/// `macro_rules! run_dead { ($($t:tt)*) => {{ let _ = 0u8; }} }` invoked as
/// `run_dead!(crate::zeroize_array(&mut enc_key);)` -- removes a live wipe while the count
/// still sees the text and `fmt`, `clippy -D warnings`, the default suite and
/// `--all-features` all stay green (measured). Scanning the invocations of locally defined
/// macros closes it.
fn macro_invocations(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in macro_names(source) {
        let bytes = source.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = source[from..].find(&name) {
            let at = from + rel;
            from = at + name.len();
            // Word boundary before the name (`notqr128` is not `qr128`).
            let before_ok = at == 0
                || !source[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let after = &source[at + name.len()..];
            let trimmed = after.trim_start();
            if !before_ok {
                continue;
            }
            let Some(after_bang) = trimmed.strip_prefix('!') else {
                continue;
            };
            let arg = after_bang.trim_start();
            let Some(open_ch) = arg.chars().next() else {
                continue;
            };
            let close_ch = match open_ch {
                '(' => ')',
                '[' => ']',
                '{' => '}',
                _ => continue,
            };
            let open = source.len() - arg.len();
            debug_assert_eq!(bytes[open], open_ch as u8);
            if let Some(end) = matching_delim(source, open, open_ch, close_ch) {
                out.push(source[open..=end].to_string());
            }
        }
    }
    out
}

/// `src/lib.rs`, parsed. Every structural check below reads the AST rather than the text.
/// Whether `func` is a call target named like one of the crate's wipe primitives.
///
/// `wipe`/`wipe_words` are the vendored witness's own helpers; they are as much a wipe
/// as `crate::zeroize_array`.
fn is_wipe_path(func: &syn::Expr) -> bool {
    let syn::Expr::Path(p) = func else {
        return false;
    };
    p.path.segments.last().is_some_and(|seg| {
        matches!(
            seg.ident.to_string().as_str(),
            "zeroize_array"
                | "zeroize_slice"
                | "zeroize_raw"
                | "scrub_stack"
                | "wipe"
                | "wipe_words"
        )
    })
}

/// Whether a method call is a wipe: `.zeroize()` on the BLAKE3 `Hasher`/`XofReader` at the
/// keyed seam (`src/lib.rs:2267-2268` in `blake3_keyed`, `:2879-2880` in `blake3_keyed_multi`)
/// is the *only* clearing of the MAC key
/// state, and a method call is not an `ExprCall`, so the path test above never saw it.
fn is_wipe_method(m: &syn::ExprMethodCall) -> bool {
    matches!(
        m.method.to_string().as_str(),
        "zeroize" | "wipe" | "wipe_words"
    )
}

/// Whether a `use` tree binds `Choice` under a different name (`use subtle::Choice as C;`),
/// which would let `C::from(2)` reach the guard's blind side. A glob, or `Choice` imported
/// under its own name, is fine: the call still says `Choice`.
fn use_tree_renames_choice(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(p) => use_tree_renames_choice(&p.tree),
        syn::UseTree::Group(g) => g.items.iter().any(use_tree_renames_choice),
        syn::UseTree::Rename(r) => r.ident == "Choice",
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

/// Whether a type names `Choice` in its path (`Choice`, `subtle::Choice`).
fn type_names_choice(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(tp) => tp.path.segments.iter().any(|s| s.ident == "Choice"),
        _ => false,
    }
}

/// Whether a call target is `<something naming Choice>::from`: the plain path
/// (`subtle::Choice::from`), the same path written with whitespace around `::` (the parser
/// normalises it away), or the fully qualified form `<subtle::Choice as From<u8>>::from`,
/// whose type lives in the expression path's `qself` rather than in a segment.
fn path_is_choice_from(func: &syn::Expr) -> bool {
    let syn::Expr::Path(p) = func else {
        return false;
    };
    if !p.path.segments.last().is_some_and(|s| s.ident == "from") {
        return false;
    }
    p.path.segments.iter().any(|s| s.ident == "Choice")
        || p.qself.as_ref().is_some_and(|q| type_names_choice(&q.ty))
}

/// What the `Choice` guard finds in one source.
struct ChoiceFindings {
    /// The banned identifier names (`conditional_select`, `ConditionallySelectable`,
    /// `CtOption`) with the lines they appear on.
    banned: Vec<(String, usize)>,
    /// The renamings that would put a `Choice` call out of the guard's sight, with their lines.
    hidden: Vec<(String, usize)>,
    /// Every `Choice`-naming `from` call as `(line, argument-is-a-literal-0/1?)`.
    froms: Vec<(usize, bool)>,
}

impl ChoiceFindings {
    /// The banned identifiers in a `macro_rules!` body.
    ///
    /// A macro's body is a token stream, not an expression tree, so the `syn` walk above does
    /// not descend into it: measured, a macro expanding to
    /// `u8::conditional_select(a, b, c)` (with its `use ... as _` inside the same body) left
    /// this guard's three rules and `froms` exactly as they were. The tokens are matched as
    /// text, which for a *ban* is strictly stronger than resolving names -- an alias cannot
    /// hide the token `conditional_select`, only a different call could, and that is what the
    /// AST rules above are for.
    fn scan_macro_tokens(&mut self, tokens: &proc_macro2::TokenStream) {
        use syn::spanned::Spanned;

        let text = tokens.to_string();
        let line = tokens.span().start().line;
        for banned in ["conditional_select", "ConditionallySelectable", "CtOption"] {
            if contains_identifier(&text, banned) {
                self.banned
                    .push((format!("{banned} (in a macro body)"), line));
            }
        }
        if contains_identifier(&text, "Choice") {
            self.hidden
                .push(("Choice named inside a macro body".to_string(), line));
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for ChoiceFindings {
    fn visit_ident(&mut self, i: &'ast proc_macro2::Ident) {
        // `Ident::span` is inherent; the `Spanned` trait is what the item/expression
        // methods below need, so this one does not import it.
        let name = i.to_string();
        if matches!(
            name.as_str(),
            "conditional_select" | "ConditionallySelectable" | "CtOption"
        ) {
            self.banned.push((name, i.span().start().line));
        }
        syn::visit::visit_ident(self, i);
    }
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        use syn::spanned::Spanned;

        if use_tree_renames_choice(&u.tree) {
            self.hidden
                .push(("use ... Choice as ...".to_string(), u.span().start().line));
        }
        syn::visit::visit_item_use(self, u);
    }
    // One override, not two: an `item macro!` is visited through its inner `syn::Macro` as
    // well, and reporting both put every hit in the message twice.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.scan_macro_tokens(&m.tokens);
        syn::visit::visit_macro(self, m);
    }
    fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
        use syn::spanned::Spanned;

        if type_names_choice(&t.ty) {
            self.hidden.push((
                format!("type {} = ... Choice ...", t.ident),
                t.span().start().line,
            ));
        }
        syn::visit::visit_item_type(self, t);
    }
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        use syn::spanned::Spanned;

        if path_is_choice_from(&c.func) {
            let literal = matches!(
                c.args.first(),
                Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(i),
                    ..
                })) if matches!(i.base10_digits(), "0" | "1")
            );
            self.froms.push((c.span().start().line, literal));
        }
        syn::visit::visit_expr_call(self, c);
    }
}

/// Run the rules over one source.
///
/// Separate from the test so they can be pointed at *synthetic* sources: a guard whose only
/// input is the crate itself cannot show that it would notice anything, and this one's
/// predecessor was measured to miss three spellings of the same construction.
fn choice_guard_findings(src: &str) -> ChoiceFindings {
    let file = syn::parse_file(src).expect("the scanned source must parse as a Rust file");
    let mut found = ChoiceFindings {
        banned: Vec::new(),
        hidden: Vec::new(),
        froms: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut found, &file);
    found
}

/// The seven copies of `strip_comments` are one implementation, or a *declared* variant.
///
/// This file's scanner is the canonical one (it takes a `blank_literals` flag, so the `cfg`
/// scan can read literals and the counts can ignore them). The other six targets carry
/// their own copy — `decision_scope.rs`'s adds `Mode::Cfg` tracking of `#[cfg(…)]`
/// payloads because its counts match on them — and until this guard existed nothing kept
/// them in step: five of the six had silently lost the two newline pushes that keep a
/// literal's newlines in the output, so every failure message those scans print named a
/// source line *earlier* than the code it described (measured: `src/lib.rs:3239` for a call
/// at `3253`). Behaviour is the thing being pinned, and behaviour here is text: the five
/// copies must be identical, `decision_scope`'s must carry the same line-preserving arm,
/// and all six must keep the pushes. A future edit to one copy fails this test rather than
/// half of the diagnostics.
#[test]
fn the_strip_comments_copies_are_one_implementation_or_a_declared_variant() {
    // The one declared variant, with why: `decision_scope.rs` matches on `#[cfg(…)]`
    // predicate text, so its scanner copies attribute payloads through instead of blanking
    // them (see that file's `Mode::Cfg` doc).
    const DECLARED_VARIANT: &str = "decision_scope.rs";
    let copies = [
        ("locked.rs", include_str!("locked.rs")),
        ("counter_range.rs", include_str!("counter_range.rs")),
        (DECLARED_VARIANT, include_str!("decision_scope.rs")),
        (
            "construction_inventory.rs",
            include_str!("construction_inventory.rs"),
        ),
        ("variable_latency.rs", include_str!("variable_latency.rs")),
        ("ultra.rs", include_str!("ultra.rs")),
    ];
    let canonical = include_str!("security.rs");
    // Line-based: the function starts at `fn <name>(` and ends at the first line whose
    // closing brace sits in column 0 (rustfmt indents every brace inside a top-level
    // function), so braces inside char literals and doc comments cannot confuse this.
    let body_of = |text: &str, name: &str| -> String {
        let mut lines = text
            .lines()
            .skip_while(|l| !l.starts_with(&format!("fn {name}(")));
        assert!(
            lines.clone().next().is_some(),
            "`{name}` is gone from the file"
        );
        let body: Vec<&str> = lines.by_ref().take_while(|l| !l.starts_with('}')).collect();
        body.join("\n")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let preserve = "if b.get(i + 1) == Some(&b'\\n') { out.push('\\n'); }"
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut identical: Vec<(&str, String)> = Vec::new();
    for (name, text) in copies {
        let body = body_of(text, "strip_comments");
        assert!(
            body.contains(&preserve),
            "{name}'s `strip_comments` does not keep an escaped newline in its output, so \
             every source line its scans report is wrong from that point on (and its own \
             doc says the opposite). Copy the canonical arm from this file."
        );
        if name != DECLARED_VARIANT {
            identical.push((name, body));
        }
    }
    for window in identical.windows(2) {
        assert_eq!(
            window[0].1, window[1].1,
            "`{}` and `{}` have drifted apart: these copies must stay one implementation \
             (a divergence in the middle of the list is the drift this test exists for)",
            window[0].0, window[1].0
        );
    }
    // The canonical copy is the reference; assert it keeps the arm too, so a fix applied
    // only there cannot silently be the odd one out.
    assert!(
        body_of(canonical, "strip_comments_impl").contains(&preserve),
        "this file's canonical `strip_comments_impl` lost the escaped-newline arm"
    );
}

/// Whether `text` contains `name` as a whole Rust identifier (not as a substring of a longer
/// one: `my_conditional_select` is not `conditional_select`).
fn contains_identifier(text: &str, name: &str) -> bool {
    let mut from = 0usize;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Whether `expr` contains a call to a wipe primitive anywhere inside it.
fn contains_wipe_call(expr: &syn::Expr) -> bool {
    struct V {
        hit: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if is_wipe_path(&c.func) {
                self.hit = true;
            }
            syn::visit::visit_expr_call(self, c);
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if is_wipe_method(m) {
                self.hit = true;
            }
            syn::visit::visit_expr_method_call(self, m);
        }
    }
    let mut v = V { hit: false };
    syn::visit::Visit::visit_expr(&mut v, expr);
    v.hit
}

/// The line numbers of every wipe call in `source` (path calls and `.zeroize()` methods),
/// outside the `tests` module.
fn wipe_call_lines(source: &str) -> Vec<usize> {
    use syn::spanned::Spanned;
    struct V {
        lines: Vec<usize>,
    }
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if is_wipe_path(&c.func) {
                self.lines.push(c.span().start().line);
            }
            syn::visit::visit_expr_call(self, c);
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if is_wipe_method(m) {
                self.lines.push(m.span().start().line);
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
            if m.ident == "tests" {
                return;
            }
            syn::visit::visit_item_mod(self, m);
        }
    }
    let file = syn::parse_file(source).expect("the source must parse as a Rust file");
    let mut v = V { lines: Vec::new() };
    syn::visit::Visit::visit_file(&mut v, &file);
    v.lines.sort_unstable();
    v.lines
}

/// The witness's own wipe calls are local helpers (`wipe`, `wipe_words`) and a `.zeroize()`
/// on the keyed seam, none of which the table-driven count in
/// `every_documented_wipe_has_a_witness` names (it lists `crate::zeroize_*` sites in
/// `src/lib.rs`). Pin the witness's total so a deleted witness wipe is caught rather than
/// silently surviving the whole suite.
#[test]
fn witness_wipe_sites_are_pinned() {
    let lines = wipe_call_lines(include_str!("../src/witness.rs"));
    assert_eq!(
        lines.len(),
        42,
        "src/witness.rs has {} wipe call(s) at line(s) {lines:?}, not the 42 this count \
         pins: a deleted witness wipe would leave derived material in the frames it runs \
         in, and no other guard counts these (the table in \
         `every_documented_wipe_has_a_witness` names only `src/lib.rs`'s `crate::zeroize_*` \
         sites). Update this number deliberately.",
        lines.len()
    );
}

/// No counted wipe may sit inside a closure body -- of any kind.
///
/// This is the `syn`-based structural check that closes the class the string-scanning
/// rules could not, after six consecutive audit rounds each found a new spelling they
/// missed: `let`-bound (`let f = || wipe;`), assignment RHS (`_ = || wipe;`),
/// braced/brace-less, `move`, parameterised (`_ = |x: u8| wipe;`), and nested in a block
/// (`let _d = { || wipe };`). The parser cannot be fooled by a spelling.
///
/// It is a *convention* check, not a reachability one: the crate writes every wipe as a
/// plain statement in a function body, and requiring that lets the guard stop reasoning
/// about whether a closure runs. A stored closure never runs it; a `for_each` may run it
/// zero times; an immediately-invoked closure does run it -- but a wipe hidden in a
/// closure is the shape every bypass used, and "is this wipe a plain statement?" is the
/// question the other guards are built around. A wipe an author wants counted is hoisted
/// to a statement; the syn rule then holds for all of them at once.
#[test]
fn no_counted_wipe_is_inside_a_closure() {
    use syn::spanned::Spanned;

    struct V {
        lines: Vec<usize>,
    }
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
            if contains_wipe_call(&c.body) {
                self.lines.push(c.span().start().line);
            }
            syn::visit::visit_expr_closure(self, c);
        }
        // The test module is not the crate's code; its closures are not the subject.
        fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
            if m.ident == "tests" {
                return;
            }
            syn::visit::visit_item_mod(self, m);
        }
    }
    // Both production sources: `src/lib.rs` and the vendored witness (which the ultra
    // configuration runs and whose `wipe`/`wipe_words`/`.zeroize()` calls are wipes too).
    for (name, source) in [
        ("src/lib.rs", LIB),
        ("src/witness.rs", include_str!("../src/witness.rs")),
    ] {
        let file = syn::parse_file(source)
            .unwrap_or_else(|e| panic!("{name} must parse as a Rust file: {e}"));
        let mut v = V { lines: Vec::new() };
        syn::visit::Visit::visit_file(&mut v, &file);
        assert!(
            v.lines.is_empty(),
            "{name}: a counted wipe sits inside a closure body (closure begins at line(s) \
             {:?}). This crate's convention is that every wipe is a plain statement in a \
             function body; a wipe inside a closure -- stored, `move`, parameterised, \
             passed to an iterator adapter, or even immediately invoked -- is not written \
             that way here, and the guard requires the convention so it never has to reason \
             about whether a closure runs. Hoist the wipe to a plain statement.",
            v.lines
        );
    }
}

#[test]
fn no_wipe_is_hidden_in_an_unexpanded_macro() {
    for (name, source) in [
        ("src/lib.rs", non_test_source()),
        (
            "src/witness.rs",
            // The same cut as `src/lib.rs`: a wipe inside the witness's own `mod tests` is
            // test code, and scanning it made this guard stricter for `src/witness.rs` than
            // for `src/lib.rs` (a dependency report measured the asymmetry). `src/proofs.rs`
            // has no test module -- it is the `#[cfg(kani)]` file -- so it is scanned whole.
            non_test_source_of(include_str!("../src/witness.rs")),
        ),
        (
            "src/proofs.rs",
            strip_comments(include_str!("../src/proofs.rs")),
        ),
    ] {
        for body in macro_bodies(&source)
            .into_iter()
            .chain(macro_invocations(&source))
        {
            for marker in [
                "zeroize_array(",
                "zeroize_slice(",
                "zeroize_raw(",
                "scrub_stack(",
                // The keyed seam's method wipes and the witness's local helpers: the same
                // clearing as the path calls above, and just as hideable in a macro.
                "zeroize(",
                "wipe(",
                "wipe_words(",
            ] {
                assert!(
                    !body.contains(marker),
                    "`{name}` hides `{marker}` inside an unexpanded `macro_rules!` or an \
                     invocation of a locally defined macro; the wipe count sees the text but \
                     no build necessarily executes it (a macro may discard a token-tree \
                     argument). Inline the calls or make the wipe part of the counted \
                     path:\n{body}"
                );
            }
        }
    }
}

/// The scanners identify a function or `Drop` impl by a literal marker and read the first
/// match. A decoy with the same marker earlier in the file can therefore satisfy every
/// count while the real function's wipe is deleted. Each counted definition must be
/// unique in the non-test source.
#[test]
fn counted_definitions_are_unique() {
    let code = non_test_source();
    for marker in [
        "fn derive_material(",
        "fn derive_tag(",
        "fn derive_enc(",
        "fn zeroize_raw(",
        "fn accept_or_reject(",
        "impl Drop for Plaintext {",
        "impl Drop for Key {",
        "pub fn encrypt(",
        "pub fn encrypt_in_place_detached(",
        "pub fn decrypt(",
        "pub fn decrypt_bounded(",
        "pub fn decrypt_in_place_detached(",
    ] {
        assert_eq!(
            code.matches(marker).count(),
            1,
            "`{marker}` has more than one definition in the non-test source; a decoy \
             earlier in the file can satisfy the wipe counts while the real definition's \
             wipe is removed. Keep one definition, or teach the scanner to select it."
        );
    }
}

/// The primitive-level wipes the entry-point table does not count: `scrub_stack`'s own
/// buffer, the scalar ChaCha20/HChaCha20 state, and the per-block keystream scratch.
///
/// These functions are documented as wiping key-derived state, but no behavioural test
/// sees a volatile store, and `tools/stack_residue.sh` scans entry points rather than
/// these frames. Source-shape counts are the guard. `chacha20_apply` has five `ks` wipes
/// (one per dispatch arm and the scalar tail); a deleted one leaves a keystream block in
/// the frame.
#[test]
fn primitive_wipe_sites_have_a_witness() {
    for (marker, call, expected) in [
        ("fn scrub_stack(", "crate::zeroize_array(&mut buf);", 1usize),
        (
            "fn chacha20_block_into(",
            "crate::zeroize_array(&mut s);",
            1,
        ),
        (
            "fn chacha20_block_into(",
            "crate::zeroize_array(&mut orig);",
            1,
        ),
        ("fn hchacha20_into(", "crate::zeroize_array(&mut s);", 1),
        ("fn chacha20_apply(", "crate::zeroize_array(&mut ks);", 5),
    ] {
        let (body, _) = body_of(marker);
        assert_eq!(
            body.matches(call).count(),
            expected,
            "`{marker}` must contain `{call}` {expected} time(s): the state holds key words \
             or key-derived keystream, and no behavioural test can see a volatile store:\n{body}"
        );
        assert_no_deadened_wipe(marker, &body);
    }
}

/// Every wipe call in `body` must be reachable: not inside a constant-false condition, a
/// constant `match`, an empty `for`, or a closure body that is never called.
///
/// This is the *shape* judgement the two-string check used to stand in for. That check only
/// recognised `black_box(false)` and `if false`, so `if 1u8 == 2u8 { wipe }` and
/// `let _dead = || { wipe };` were called "reachable" while the count above stayed exact and
/// the whole six-configuration matrix, `cargo fmt --check` and `cargo clippy -D warnings`
/// passed (measured).
fn assert_no_deadened_wipe(label: &str, body: &str) {
    for primitive in [
        "zeroize_array(",
        "zeroize_slice(",
        "zeroize_raw(",
        "zeroize_xmm(",
        "zeroize_ymm(",
        "zeroize_neon(",
        "scrub_stack(",
    ] {
        for (at, _) in body.match_indices(primitive) {
            if let Some(shape) = constant_false_enclosing_block(body, at) {
                panic!(
                    "`{label}`'s `{primitive}…` call is deadened: {shape}. The text survives \
                     compilation exactly as it is written, so every count stays correct while \
                     the wipe never runs. Delete the wrapper."
                );
            }
        }
    }
}

/// Every SIMD kernel that keeps the key words in vector registers must wipe its named
/// state arrays before returning.
///
/// `zeroize_xmm`/`zeroize_ymm`/`zeroize_neon` are residue measures, not behaviour: deleting
/// a call leaves every ciphertext identical, and the committed stack-residue tool only
/// exercises 64-byte messages, below the 256/512-byte SIMD threshold. These source-shape
/// counts are the only guard against a dropped wipe. They are scoped to the kernel bodies,
/// not the whole file, and reject a `black_box(false)` wrapper that would keep the text but
/// never execute it.
#[test]
fn simd_kernels_wipe_their_key_state() {
    // Markers must not contain a string literal: `non_test_source` blanks literal
    // contents, so a marker like `#[target_feature(enable = "sse2")]` is not findable.
    for (module, calls) in [
        (
            "mod x86_simd {",
            &[
                ("zeroize_xmm(&mut x);", 1usize),
                ("zeroize_xmm(&mut orig);", 1),
                ("zeroize_ymm(&mut x);", 1),
                ("crate::zeroize_array(&mut s);", 2),
            ][..],
        ),
        (
            "mod aarch64_simd {",
            &[
                ("zeroize_neon(&mut x);", 1usize),
                ("zeroize_neon(&mut orig);", 1),
                ("crate::zeroize_array(&mut w);", 1),
                ("crate::zeroize_array(&mut s);", 1),
            ][..],
        ),
    ] {
        let (body, _) = body_of(module);
        for (call, expected) in calls {
            assert_eq!(
                body.matches(call).count(),
                *expected,
                "`{module}` must contain `{call}` {expected} time(s): the SIMD state holds \
                 the per-message key words, and no behavioural test or stack-residue case \
                 reaches this path:\n{body}"
            );
        }
        assert_no_deadened_wipe(module, &body);
    }
}

/// No local definition may provide its own `ct_eq`, which would shadow `subtle`'s
/// constant-time comparison inside a scanned body while every text pin around the call
/// stays true.
///
/// `witness_tag.ct_eq(&computed_tag)` is text, and text is satisfied by any method named
/// `ct_eq` in scope: a trait (or an inherent impl) whose `ct_eq` returns `Choice::from(1)`
/// makes `ultra`'s witness agreement a constant true, silently dropping the gate operand.
/// The audit that raised this named exactly that shape, and nothing here rejected it --
/// `tests/decision_scope.rs` pins the *bindings and lines* of the decision, not the
/// resolution of the method name. The crate defines no such method (its own fold is
/// `ct_eq_independent`, whose name does not match `fn ct_eq(`) and implements no
/// `ConstantTimeEq`, so the rejection has nothing to carve out.
#[test]
fn no_local_method_can_shadow_the_constant_time_comparison() {
    for (name, src) in [
        ("src/lib.rs", non_test_source()),
        (
            "src/witness.rs",
            strip_comments(include_str!("../src/witness.rs")),
        ),
    ] {
        for shape in [
            "fn ct_eq(",
            "impl ConstantTimeEq",
            "impl subtle::ConstantTimeEq",
            "impl core::cmp::PartialEq",
        ] {
            assert_eq!(
                src.matches(shape).count(),
                0,
                "`{name}` contains `{shape}`: a definition in the crate's own sources can \
                 shadow or replace a constant-time comparison at its call site -- an \
                 always-true `ct_eq` for `[u8; TAG_LEN]` turns `ultra`'s witness agreement \
                 into a constant while every text pin around the call stays true. Use \
                 `subtle`'s implementations (imported, not reimplemented)."
            );
        }
    }
}

/// `subtle::Choice`'s 0/1 invariant is a `debug_assert!`, so a release build accepts any
/// `u8` in `Choice::from(x)` and `conditional_select` then returns neither operand (the
/// dependency report measured `u8::conditional_select(1, 2, Choice::from(2)) == 3`);
/// upstream's open soundness issue puts the same hazard on `Ordering::conditional_select`,
/// where the result is an invalid enum discriminant. This crate compares with `ct_eq` and
/// folds the result, so it is correct by construction today -- and `subtle` is the one
/// dependency-report item that *is* in the shipped closure, which is what makes that
/// construction worth holding: a future `Choice::from(flag as u8)` or a `conditional_select`
/// call would move a gate onto an operand nothing checks.
///
/// Structural, not textual. The first revision of this guard counted the substring
/// `Choice::from(` and sliced its argument out of the text, and a dependency report walked
/// past it three ways: `use subtle::Choice as C; C::from(2)`, the fully qualified
/// `<subtle::Choice as From<u8>>::from(2)`, and `Choice :: from(2)` -- every spelling that
/// stops those thirteen characters being adjacent made the site disappear from the count.
/// The AST cannot be fooled by spelling, so the rules are now: no identifier anywhere in
/// the non-test sources may be `conditional_select`, `ConditionallySelectable` or
/// `CtOption`; every call whose path (or whose qualified type) *names* `Choice` must take a
/// literal `0`/`1`; and no `use ... Choice as <other>` or `type <X> = ...Choice...` may
/// rename it out of sight.
///
/// `syn` does not resolve names, so two residuals are documented rather than claimed
/// closed: an alias of an alias (`type R = subtle::Choice; type C = R;`) and a conversion
/// whose type is inferred at the call (`let z: Choice = From::from(2);`). Both are
/// deliberate obfuscation; the direct spellings an author actually reaches for are
/// covered, and each of the three measured bypasses is a case in `tests/security.rs`'s own
/// history now.
#[test]
fn the_constant_time_selection_api_is_absent_and_choice_constants_are_literal() {
    let lib = non_test_source();
    let witness = non_test_source_of(include_str!("../src/witness.rs"));
    for (name, src, expected) in [
        ("src/lib.rs", lib.as_str(), 2usize),
        ("src/witness.rs", witness.as_str(), 0usize),
    ] {
        let ChoiceFindings {
            banned,
            hidden,
            froms,
        } = choice_guard_findings(src);
        assert!(
            banned.is_empty() && hidden.is_empty(),
            "`{name}` reaches the constant-time *selection* API the `subtle` 0/1 invariant \
             cannot protect (idents {banned:?}, renamings {hidden:?}). `Choice`'s invariant \
             is a `debug_assert!`, so a release build accepts any `u8` and the selection \
             returns neither operand -- or, through `Ordering`, an invalid enum discriminant \
             (upstream's open issue). This crate compares with `ct_eq` and folds the result; \
             it must not select, and it must not rename `Choice` out of this guard's sight.",
        );
        assert_eq!(
            froms.len(),
            expected,
            "`{name}` has {} `Choice`-naming `from` call(s) at line(s) {:?}, expected \
             {expected}: every constant `Choice` in this crate is `Choice::from(1)` \
             (`src/lib.rs:3598` in `decrypt`, `src/lib.rs:3882` in `decrypt_in_place_detached`, the two \
             `ultra`-off witness-gate operands), and this count is what makes a *new* \
             site a deliberate change -- the guard's other rules already reject a \
             non-literal argument at any site it can see.",
            froms.len(),
            froms.iter().map(|(l, _)| *l).collect::<Vec<_>>()
        );
        for (line, literal) in &froms {
            assert!(
                *literal,
                "`{name}:{line}` calls `Choice::from` with something other than a literal \
                 `0`/`1`. The release build does not check that argument, and a computed one \
                 is exactly how `subtle`'s 0/1 invariant stops holding."
            );
        }
    }
}

/// Every spelling a dependency report measured against this guard, pointed at the AST rules.
///
/// The guard's predecessor matched text, and the report walked past it with an alias import,
/// a qualified conversion and whitespace around `::` -- each leaving the whole suite green.
/// A guard whose only input is the crate cannot show that it would notice anything, so the
/// six shapes are asserted here: the clean one must stay clean, and the other five (the
/// report's three, plus the computed argument and the selection API the text version already
/// caught) must each be **visible**. A refactor that loses sensitivity fails in this suite
/// rather than in the next report.
#[test]
fn the_choice_guard_sees_every_spelling_measured_against_it() {
    let ChoiceFindings {
        banned,
        hidden,
        froms,
    } = choice_guard_findings("fn f() -> u8 { let c: Choice = Choice::from(1); c.unwrap_u8() }");
    assert!(
        banned.is_empty() && hidden.is_empty() && froms == vec![(1, true)],
        "the shape the guard allows -- a literal `1` through a path naming `Choice` -- must \
         produce exactly one hit and nothing else: {banned:?} {hidden:?} {froms:?}"
    );

    for (what, src) in [
        (
            "an alias import",
            "use subtle::Choice as C;\nfn f() -> u8 { let z: C = C::from(2); z.unwrap_u8() }",
        ),
        (
            "a qualified conversion",
            "fn f() -> u8 { let z: subtle::Choice = <subtle::Choice as From<u8>>::from(2); \
             z.unwrap_u8() }",
        ),
        (
            "whitespace around `::`",
            "fn f() -> u8 { let z: subtle::Choice = subtle::Choice :: from(2); z.unwrap_u8() }",
        ),
        (
            "a type alias",
            "type C = subtle::Choice;\nfn f() -> u8 { let z: C = C::from(2); z.unwrap_u8() }",
        ),
        (
            "an argument the release build does not check",
            "fn f() -> u8 { let z: Choice = Choice::from(u8::from(true)); z.unwrap_u8() }",
        ),
        (
            "the selection API",
            "use subtle::ConditionallySelectable as _;\n\
             fn f(c: Choice, a: u8, b: u8) -> u8 { a.conditional_select(b, c) }",
        ),
        // A macro body is a token stream, not an expression tree, so `syn`'s default walk
        // never descends into it. Measured: this exact shape -- the `use ... as _` and the
        // `conditional_select` call both inside the body -- left the AST rules and `froms`
        // exactly as they were, with a reachable selection API in the crate.
        (
            "a macro body",
            "macro_rules! _sel { ($a:expr, $b:expr, $c:expr) => {{\n\
                 use subtle::ConditionallySelectable as _;\n\
                 u8::conditional_select(&$a, &$b, $c)\n\
             }}; }\n\
             pub fn f(a: u8, b: u8, c: Choice) -> u8 { _sel!(a, b, c) }",
        ),
    ] {
        let ChoiceFindings {
            banned,
            hidden,
            froms,
        } = choice_guard_findings(src);
        let caught =
            !banned.is_empty() || !hidden.is_empty() || froms.iter().any(|(_, literal)| !literal);
        assert!(
            caught,
            "{what} was invisible to the AST rules: idents {banned:?}, renamings {hidden:?}, \
             `Choice`-naming `from` calls {froms:?}. Every one of these was either a measured \
             bypass of the text version or one of its negative controls; if a refactor loses \
             one, the guard is back to being satisfiable by a spelling."
        );
    }
}

/// The constant-`cfg` scan, pointed at synthetic sources.
///
/// The blanket guard above is the only thing that catches a constant `cfg` on a statement
/// no per-site table names (`decrypt`'s `check_lengths(...)?`, say), so its *sensitivity* is
/// worth a test of its own rather than a comment about a past measurement: a refactor that
/// made `constant_cfg_attributes` return nothing would leave every other test green. Each
/// shape here is either a measurement from an audit round or the control for one.
#[test]
fn the_constant_cfg_scan_fires_on_constant_predicates_and_only_those() {
    let finding =
        |attr: &str| !constant_cfg_attributes(&format!("{attr}\nfn _probe() {{}}")).is_empty();

    // Fires: the shapes a constant gate is written in. The last two carry a configuration
    // atom *twice*, which the literal folding alone cannot decide — the case a dependency
    // report measured compiling an input-length check out of every build with the whole
    // suite green.
    for constant in [
        "#[cfg(any())]",
        "#[cfg(all())]",
        "#[cfg(not(any()))]",
        "#[cfg(test)]",
        "#[cfg(all(feature = \"x\", not(feature = \"x\")))]",
        // The same predicate with the two occurrences spelled differently: rustc sees one
        // atom, and the first version of this enumeration saw two (measured by a report).
        "#[cfg(all(feature=\"x\", not(feature = \"x\")))]",
        "#[cfg(not(any(unix, not(unix))))]",
    ] {
        assert!(
            finding(constant),
            "`{constant}` is constant and must be reported"
        );
    }

    // Does not fire: real gates, including ones whose atoms share a prefix and one that
    // `strip_comments` would blank into a repeated atom (`feature = ""`), which is why the
    // caller passes the literal-intact cut.
    for gate in [
        "#[cfg(feature = \"hardened\")]",
        "#[cfg(all(any(feature = \"dual-mac\", feature = \"ultra\"), not(feature = \"hardened\")))]",
        "#[cfg(all(not(feature = \"ultra\"), feature = \"hardened\"))]",
        "#[cfg(all(unix, not(feature = \"pure\")))]",
    ] {
        assert!(!finding(gate), "`{gate}` is a real gate and must not be reported");
    }

    // A predicate over more atoms than the enumeration bound is still decided when it
    // contradicts itself: seventeen distinct atoms, jointly unsatisfiable
    // (`all(p0 ... p16, not(p0))` is false under every assignment). This walked past the
    // enumeration for as long as the bound was the only decision procedure -- measured
    // deadening `check_lengths(...)?` in every consumer build with the whole suite green --
    // so the boundary is asserted rather than implied: it must be *reported* now.
    let mut pred = String::from("all(");
    for i in 0..17 {
        pred.push_str(&format!("feature = \"p{i}\", "));
    }
    pred.push_str("not(feature = \"p0\"))");
    assert_eq!(
        cfg_atoms(&pred).len(),
        17,
        "the boundary control must actually exceed the sixteen-atom bound"
    );
    assert_eq!(
        constant_cfg_value(&pred),
        Some(false),
        "seventeen atoms is past the enumeration bound, so this predicate has to be decided by \
         the three-valued pass; if it is `None` again, that pass was removed and a constant \
         gate of arbitrary length is invisible to this guard once more"
    );
    assert!(
        finding(&format!("#[cfg({pred})]")),
        "the seventeen-atom contradiction must be reported"
    );

    // Past the bound *and* free of any contradiction the three-valued pass can see, the
    // predicate is undecidable here -- and undecidable is reported, not passed, because
    // that is where a constant gate hides. `all(p0 ... p16)` alone is a real gate, so this
    // control is deliberately one atom more than the guard can enumerate.
    let mut wide = String::from("all(");
    for i in 0..17 {
        wide.push_str(&format!("feature = \"p{i}\", "));
    }
    wide.pop();
    wide.pop();
    wide.push(')');
    assert_eq!(
        wide.matches("feature = ").count(),
        17,
        "the undecidable control needs seventeen distinct atoms"
    );
    assert_eq!(
        constant_cfg_value(&wide),
        None,
        "a satisfiable 17-atom predicate is a real gate and must not be reported as constant"
    );
    assert!(
        finding(&format!("#[cfg({wide})]")),
        "a predicate this guard cannot decide must be reported as undecidable rather than \
         passed: fail-closed is the whole point of the bound being a bound"
    );

    // An attribute *inside a string literal* is not an attribute: the guard's line filter
    // (against the blanked cut) drops it.
    let body = "const _S: &str = \"#[cfg(any())]\";\nfn _probe() {}";
    assert!(
        constant_cfg_attributes(&strip_comments(body)).is_empty(),
        "a `cfg` attribute inside a string literal must not be reported"
    );
    assert_eq!(
        cfg_attribute_lines(&strip_comments(body)),
        Vec::<usize>::new(),
        "the blanked cut is what proves the text is inside a literal"
    );
}

/// A source file under `src/` that this scanner does not know about can hold a
/// wipe-bearing function with no witness at all. The list is literal; adding a file must
/// be a deliberate change to the scanner, not a silent gap.
#[test]
fn every_source_file_is_accounted_for() {
    fn collect(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src/ must be readable") {
            let path = entry.expect("src/ entry must be readable").path();
            if path.is_dir() {
                collect(&path, base, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let relative = path
                    .strip_prefix(base)
                    .expect("walked paths must stay under src/");
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    const SOURCES: &[&str] = &["lib.rs", "proofs.rs", "witness.rs"];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    collect(&dir, &dir, &mut found);
    found.sort();
    let mut listed: Vec<String> = SOURCES.iter().map(|s| (*s).to_string()).collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "`src/` has {found:?} but this scanner accounts for {listed:?}. A new source file \
         (including `src/<subdir>/mod.rs`, which a non-recursive scan misses) can hold \
         wipes or call sites that none of the guards read; add it to the scanner or \
         explain why it holds no secret-bearing code."
    );
}

/// The `if <expr>` guard of a `match` arm: `_ if a < b => { … }` yields `"a < b"`,
/// `_ => { … }` yields None. Only the guard text between the first `if ` and the `=>`
/// is read; a pattern like `Some(x) if a < b` also yields `"a < b"`, which is fine
/// because [`constant_condition_value`] only decides on literals and known-constant
/// expressions -- `Some(x) if a < b` with non-literal `a`, `b` yields None and the arm
/// is treated as reachable.
fn arm_guard_condition(head: &str) -> Option<&str> {
    // Everything from the start of the arm to `=>`.
    let arm = head.split_once("=>").map(|(a, _)| a)?.trim();
    let guard = arm.split_once("if ").map(|(_, g)| g)?;
    Some(guard.trim())
}

// ---------------------------------------------------------------------------
// Expression-position wipes
//
// Every other wipe guard in this file reads *statements*: a count of the call text, the
// `crate::` qualifier requirement, `preceding_attributes`, `enclosing_block_attributes`,
// `constant_false_enclosing_block` and `no_counted_wipe_is_inside_a_closure`. All of them
// keep their verdict when the wipe is moved into an expression that need not run, because
// none of them is a statement: measured on this tree, replacing `derive_material`'s
//     crate::zeroize_array(&mut subkey);
// with
//     let dead = core::hint::black_box(false);
//     let _ = dead && { crate::zeroize_array(&mut subkey); true };
// left `cargo test --all-features` (every target, 74 lib tests included) and
// `cargo clippy --all-features --all-targets -- -D warnings` green, while the wipe never
// executed. The same holds for a plain `false` (no `black_box`), for `||`, for a closure
// that is stored and maybe called, and for a `?`-guarded argument. A short-circuit operand
// is not a block with a condition that can be folded, so `constant_false_enclosing_block`
// cannot see it either.
//
// The property is structural, so the check is too: a counted wipe must be a statement of a
// function body, or a statement of an `if`/`match`/`loop`/`unsafe`/`async`/`try` block
// reached from one. Anywhere else -- an operand of `&&`/`||`, a closure body, a call
// argument, an assignment or `return` value, a `let` initialiser that is not itself a
// branch -- it is an expression, and the guards above keep reading text that may never run.

/// The wipe primitives whose calls this file counts.
const WIPE_CALLS: [&str; 3] = ["zeroize_array", "zeroize_slice", "zeroize_raw"];

/// Whether `expr` is a call to one of [`WIPE_CALLS`] (`crate::zeroize_array(…)`).
fn is_wipe_call(expr: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expr else {
        return false;
    };
    let syn::Expr::Path(path) = &*call.func else {
        return false;
    };
    let name = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    WIPE_CALLS.contains(&name.as_str())
}

/// Every wipe call anywhere inside `expr`, with the line the callee's path starts on.
struct WipeCallFinder(Vec<(usize, String)>);

impl<'ast> syn::visit::Visit<'ast> for WipeCallFinder {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let last = path.path.segments.last();
            let name = last
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if WIPE_CALLS.contains(&name.as_str()) {
                let line = last
                    .map(|segment| segment.ident.span().start().line)
                    .unwrap_or(0);
                self.0.push((line, name));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Every wipe call anywhere inside `expr` -- used on the sub-expressions that are *not*
/// statement-shaped, where any hit is a finding.
fn wipe_calls_within(expr: &syn::Expr) -> Vec<(usize, String)> {
    let mut finder = WipeCallFinder(Vec::new());
    syn::visit::Visit::visit_expr(&mut finder, expr);
    finder.0
}

/// [`wipe_calls_within`] tagged as an expression operand, which is what a hit there is.
fn operand_wipes(expr: &syn::Expr) -> Vec<(usize, String, &'static str)> {
    wipe_calls_within(expr)
        .into_iter()
        .map(|(line, name)| (line, name, "an expression operand"))
        .collect()
}

/// The wipe calls in `src`'s item tree that are not in statement position, as
/// `(line, name, why)`. `why` distinguishes an expression operand from a definition nested
/// inside a function body: both leave the crate's site tables satisfied while the wipe leaves
/// the enclosing function's flow.
fn expression_position_wipes(source: &str) -> Vec<(usize, String, &'static str)> {
    let file = syn::parse_file(source).expect("the scanned source must parse as a Rust file");
    let mut found = Vec::new();
    scan_items_for_expression_wipes(&file.items, &mut found);
    found
}

/// The wipes a statement *item* defines. A `fn` (or `impl`/`trait`) declared inside a function
/// body is not part of that body's statement flow: deleting `derive_material`'s
/// `crate::zeroize_array(&mut subkey);` and leaving
/// `fn _never_called() { let mut subkey = [0u8; 32]; crate::zeroize_array(&mut subkey); }`
/// behind keeps every count in this file at the same number -- measured green across the whole
/// suite -- while the derived subkey is never cleared.
fn nested_item_wipe_calls(item: &syn::Item) -> Vec<(usize, String)> {
    let mut finder = WipeCallFinder(Vec::new());
    syn::visit::Visit::visit_item(&mut finder, item);
    finder.0
}

fn scan_items_for_expression_wipes(
    items: &[syn::Item],
    out: &mut Vec<(usize, String, &'static str)>,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) => scan_block_for_expression_wipes(&function.block, out),
            syn::Item::Impl(block) => {
                for item in &block.items {
                    if let syn::ImplItem::Fn(function) = item {
                        scan_block_for_expression_wipes(&function.block, out);
                    }
                }
            }
            syn::Item::Trait(block) => {
                for item in &block.items {
                    if let syn::TraitItem::Fn(function) = item {
                        if let Some(body) = &function.default {
                            scan_block_for_expression_wipes(body, out);
                        }
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    scan_items_for_expression_wipes(items, out);
                }
            }
            _ => {}
        }
    }
}

/// Walk the statements of `block`. Only the statement-shaped constructs -- blocks and the
/// bodies of `if`/`match`/`loop` -- are descended into; every other expression is an
/// operand, and a wipe inside it is reported.
fn scan_block_for_expression_wipes(
    block: &syn::Block,
    out: &mut Vec<(usize, String, &'static str)>,
) {
    for statement in &block.stmts {
        match statement {
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    scan_expr_for_expression_wipes(&init.expr, out);
                }
            }
            syn::Stmt::Expr(expr, _) => scan_expr_for_expression_wipes(expr, out),
            // A `macro_rules!` body is `no_wipe_is_hidden_in_an_unexpanded_macro`'s
            // subject rather than an ordinary statement this walk should call reachable.
            syn::Stmt::Macro(_) => {}
            // A definition nested inside the body is *not* part of this function's flow.
            syn::Stmt::Item(item) => {
                for (line, name) in nested_item_wipe_calls(item) {
                    out.push((line, name, "defined inside a nested item"));
                }
            }
        }
    }
}

fn scan_expr_for_expression_wipes(expr: &syn::Expr, out: &mut Vec<(usize, String, &'static str)>) {
    match expr {
        syn::Expr::Block(block) => scan_block_for_expression_wipes(&block.block, out),
        syn::Expr::Unsafe(block) => scan_block_for_expression_wipes(&block.block, out),
        syn::Expr::TryBlock(block) => scan_block_for_expression_wipes(&block.block, out),
        syn::Expr::Async(block) => scan_block_for_expression_wipes(&block.block, out),
        syn::Expr::Const(block) => scan_block_for_expression_wipes(&block.block, out),
        syn::Expr::If(if_expr) => {
            // A condition is an operand: `if crate::zeroize_slice(&mut x).is_some() { … }`
            // wipes only on the path that takes it.
            out.extend(operand_wipes(&if_expr.cond));
            scan_block_for_expression_wipes(&if_expr.then_branch, out);
            if let Some((_, otherwise)) = &if_expr.else_branch {
                scan_expr_for_expression_wipes(otherwise, out);
            }
        }
        syn::Expr::Match(match_expr) => {
            out.extend(operand_wipes(&match_expr.expr));
            for arm in &match_expr.arms {
                if let Some((_, guard)) = &arm.guard {
                    out.extend(operand_wipes(guard));
                }
                scan_expr_for_expression_wipes(&arm.body, out);
            }
        }
        syn::Expr::Loop(loop_expr) => scan_block_for_expression_wipes(&loop_expr.body, out),
        syn::Expr::While(while_expr) => {
            out.extend(operand_wipes(&while_expr.cond));
            scan_block_for_expression_wipes(&while_expr.body, out);
        }
        syn::Expr::ForLoop(for_expr) => {
            out.extend(operand_wipes(&for_expr.expr));
            scan_block_for_expression_wipes(&for_expr.body, out);
        }
        // The shape every counted wipe must have.
        expr if is_wipe_call(expr) => {}
        // Everything else puts the call in expression position.
        operand => out.extend(operand_wipes(operand)),
    }
}

/// Every counted wipe is a statement, not an operand of a larger expression.
#[test]
fn every_counted_wipe_is_a_statement_not_an_expression_operand() {
    let source = non_test_source();
    let found = expression_position_wipes(&source);
    assert!(
        found.is_empty(),
        "wipe call(s) outside the enclosing function's statement flow: {found:?} (the third \
         field says which hole was used). An expression operand is not a statement: \
         `flag && {{ wipe; true }}` skips the wipe whenever `flag` is false, a closure body \
         runs only if the closure is called, and a `?`-propagated value is skipped on the \
         error path. A definition nested inside a body is not in that body's flow at all: a \
         wipe moved into `fn _never_called()` keeps every count in this file at the same \
         number while the region is never cleared (both shapes were measured leaving the \
         whole suite green). Write each wipe as a statement of the function body, or of an \
         `if`/`match`/`loop`/`unsafe` block, so the guards that read statements keep reading \
         a step that runs."
    );
}

/// The per-site attribute walk, pointed at the spellings it has to see and at the
/// statements that carry no attribute.
///
/// This walk is what the counted-wipe table consults, and every escape from it was found by
/// an audit rather than by this suite: a blank line between attribute and statement, an
/// attribute on the block opener, and -- measured -- a **multi-line** attribute, whose last
/// line is `)]` and whose first line is `#[cfg(feature = "pure"`, so a line-based scan saw
/// neither a `#` nor a trailing `]`. The single-line spelling of the same predicate was
/// caught, so the newline was the entire difference.
#[test]
fn the_site_attribute_walk_sees_every_spelling_above_a_statement() {
    // `body` ends with the statement the walk is pointed at; the return value is the
    // attribute text it found (whitespace-normalised by the caller, so compare that way).
    let walk = |body: &str| -> Vec<String> {
        // `at` is the *start* of the statement the walk is pointed at, which is how the
        // guard calls it: `body[..at]` then ends with the newline (or `{`) before it.
        let trimmed = body.trim_end();
        let at = trimmed.rfind('\n').map_or(0, |nl| nl + 1);
        assert!(
            trimmed[at..].ends_with(';'),
            "the test's body must end with a `;`-terminated statement, got `{}`",
            &trimmed[at..]
        );
        let _ = at;
        preceding_attributes(body, at)
            .into_iter()
            .map(|(_, attr)| attr.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    };
    for (name, body, want) in [
        (
            "one line",
            "#[cfg(feature = \"pure\")]\nwipe;",
            "feature = \"pure\"",
        ),
        (
            "blank line in between",
            "#[cfg(feature = \"pure\")]\n\nwipe;",
            "feature = \"pure\"",
        ),
        (
            "predicate broken across lines",
            "#[cfg(feature = \"pure\"\n)]\nwipe;",
            "feature = \"pure\"",
        ),
        (
            "whole attribute spread over lines",
            "#[cfg(all(\n    feature = \"pure\",\n))]\nwipe;",
            "feature = \"pure\"",
        ),
        // The walk is pointed *inside* the block, so the text before the statement ends
        // with the `{` the attribute is attached to -- the shape `#[cfg(…)] { wipe }`.
        (
            "attribute on the block opener",
            "#[cfg(feature = \"pure\")] {\nwipe;",
            "feature = \"pure\"",
        ),
        (
            "whitespace spelling",
            "# [cfg(feature = \"pure\")]\nwipe;",
            "feature = \"pure\"",
        ),
        ("constant predicate", "#[cfg(any())]\nwipe;", "any()"),
    ] {
        let found = walk(body);
        assert_eq!(
            found.len(),
            1,
            "the walk found {found:?} above the statement in the `{name}` shape, expected one \
             attribute. Every spelling here is legal Rust and the attribute applies to the \
             statement; a shape the walk does not see is a `cfg` the wipe table cannot veto."
        );
        assert!(
            found[0].contains(want),
            "the walk read `{}` above the `{name}` shape, which does not contain `{want}`",
            found[0]
        );
    }
    for (name, body) in [
        ("a plain statement", "wipe;"),
        ("a preceding statement", "let x = 1;\nwipe;"),
        ("a `let` above it", "let x = 1;\n\nwipe;"),
    ] {
        assert!(
            walk(body).is_empty(),
            "the walk reported an attribute above the `{name}` shape ({:?}), which would make              every wipe look gated",
            walk(body)
        );
    }
}

/// The shapes the statement-position guard must and must not report, pointed at synthetic
/// sources: a guard whose only input is the crate cannot show that it would notice anything,
/// and this guard's predecessor (every text rule above) was measured missing all of them.
#[test]
fn the_statement_position_guard_sees_every_expression_operand_shape() {
    // Each of these puts the wipe somewhere it need not run.
    for (name, body) in [
        (
            "a short-circuit `&&` with a constant-false left operand",
            "fn f() { let dead = false; let _ = dead && { crate::zeroize_array(&mut x); true }; }",
        ),
        (
            "a short-circuit `||` where the wipe is the left operand",
            "fn f() { let _ = crate::zeroize_array(&mut x) == () || true; }",
        ),
        (
            "a closure that is stored and maybe called",
            "fn f() { let g = || { crate::zeroize_array(&mut x); }; g(); }",
        ),
        (
            "a wipe as a call argument",
            "fn f() { core::mem::drop({ crate::zeroize_slice(&mut x); 0 }); }",
        ),
        (
            "a wipe whose value is propagated with `?`",
            "fn f() -> Option<()> { let y = crate::zeroize_slice(&mut x)?; Some(()) }",
        ),
        (
            "a wipe in an `if` condition",
            "fn f() { if crate::zeroize_slice(&mut x).is_some() { } }",
        ),
        (
            "a wipe in a `fn` nested inside the body",
            "fn f() { fn _never_called() { crate::zeroize_array(&mut x); } }",
        ),
    ] {
        let found = expression_position_wipes(&format!("{body}\nmod tests {{ }}"));
        assert!(
            found.len() == 1,
            "the guard missed the shape: {name} (found {found:?})"
        );
    }
    // ...and each of these is a statement, which must stay clean, or the guard would push
    // a real wipe out of the shape the other guards read.
    for (name, body) in [
        (
            "a direct statement",
            "fn f() { crate::zeroize_array(&mut x); }",
        ),
        (
            "a block tail expression",
            "fn f() { let y = 1; crate::zeroize_slice(&mut x) }",
        ),
        (
            "an `if` branch statement",
            "fn f(c: bool) { if c { crate::zeroize_array(&mut x); } }",
        ),
        (
            "a `match` arm statement",
            "fn f(c: bool) { match c { true => { crate::zeroize_array(&mut x); } false => {} } }",
        ),
        (
            "a `loop` body statement",
            "fn f() { loop { crate::zeroize_array(&mut x); break; } }",
        ),
        (
            "an `unsafe` block statement",
            "fn f() { unsafe { crate::zeroize_raw(x.as_mut_ptr(), 1); } }",
        ),
        (
            "an `if` in a `let` initialiser",
            "fn f(c: bool) { let y = if c { crate::zeroize_array(&mut x); 1 } else { 2 }; }",
        ),
        // The initialiser is evaluated exactly as a statement would be; what this guard
        // rejects is an operand whose *evaluation* a construct can skip (`&&`, a closure
        // body, `?`), not the `let` itself.
        (
            "a `let` whose initialiser is the call itself",
            "fn f() { let _ = crate::zeroize_raw(x.as_mut_ptr(), 1); }",
        ),
    ] {
        let found = expression_position_wipes(&format!("{body}\nmod tests {{ }}"));
        assert!(
            found.is_empty(),
            "the guard reported the clean shape: {name} (found {found:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Constant-time equality, and volatile wiping
//
// Two properties the crate's own documentation states, and which nothing else in this suite
// measures.
//
// Equality: `Plaintext`, `Key` and `locked::LockedKey` hand-write `PartialEq` so that a
// natural `==` on decrypted bytes cannot fall back to the short-circuiting slice comparison
// (the doc on `Plaintext`'s impls says exactly that, and says every implementation routes
// through `subtle::ConstantTimeEq`). Measured: rewriting one `bool::from(…ct_eq…)` body as
// `self.0.as_slice() == other` left `tests/` (security, decision_scope, variable_latency,
// plaintext_wipe) and `--lib` green -- `test_plaintext_eq_semantics` asserts the *answer*,
// which both spellings give, and no timing screen in this repository is sharp enough to see
// a few nanoseconds. The `LockedKey` impls are worse: they are behind `--features locked`,
// so the default build never type-checks them at all.
//
// Volatility: every wipe in the crate is `write_volatile`, which is what stops the optimizer
// from deleting a dead store -- the reason `zeroize_*` exists rather than `fill(0)`. Measured:
// changing `zeroize_raw`'s leading-loop store to `core::ptr::write(ptr.add(i), 0)` left
// `tests/` and `--lib` green. Kani proves "the bytes are zero afterwards", which a plain
// store also satisfies, and the allocator-observing tests only fail if this build's optimizer
// happens to elide the store.
//
// Both are source-shape properties, so both are checked as source: no build of the crate can
// see the `locked` impls or the `neon` wipe on an x86 host either.

/// Every `impl` block in `items`, including those nested in modules. The `locked` module's
/// impls are only compiled with that feature, so a default build never type-checks them.
fn collect_impls<'a>(items: &'a [syn::Item], out: &mut Vec<&'a syn::ItemImpl>) {
    for item in items {
        match item {
            syn::Item::Impl(block) => out.push(block),
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_impls(items, out);
                }
            }
            _ => {}
        }
    }
}

/// The last segment's name of a path type (`[u8; N]`/`Vec<u8>`-style `self_ty`s have none).
fn type_last_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// What an `eq`/`ne` body does: how often it calls `ct_eq`, and whether it uses `==`/`!=`.
#[derive(Default)]
struct EqBodyScan {
    ct_eq_calls: usize,
    comparison_operators: usize,
    /// `true` when a macro body reachable from the implementation carries `==`/`!=`. A
    /// macro body is a token stream, so `syn`'s walk never enters it: measured, a `Key::eq`
    /// that kept a discarded `ct_eq` for the counter and compared through `_same!(a, b)` (a
    /// macro expanding to `$a == $b`) left this guard green while the comparison it exists
    /// to prevent was the one being executed.
    macro_comparison: bool,
    /// `true` when a macro body carries `ct_eq`, which this scan cannot read either.
    macro_ct_eq: bool,
}

impl<'ast> syn::visit::Visit<'ast> for EqBodyScan {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let text = mac.tokens.to_string();
        if text.contains("==") || text.contains("!=") {
            self.macro_comparison = true;
        }
        if contains_identifier(&text, "ct_eq") {
            self.macro_ct_eq = true;
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "ct_eq" {
            self.ct_eq_calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let name = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if name == "ct_eq" {
                self.ct_eq_calls += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.comparison_operators += 1;
        }
        syn::visit::visit_expr_binary(self, binary);
    }
}

/// Whether `expr` calls `ct_eq` anywhere inside it.
fn expr_contains_ct_eq(expr: &syn::Expr) -> bool {
    #[derive(Default)]
    struct Finder(bool);
    impl<'ast> syn::visit::Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "ct_eq" {
                self.0 = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "ct_eq")
                {
                    self.0 = true;
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut finder = Finder(false);
    syn::visit::Visit::visit_expr(&mut finder, expr);
    finder.0
}

/// `(hand-written `PartialEq` impls seen, those whose `eq`/`ne` is not a `ct_eq` comparison)`,
/// the second as `(line, "Type::eq")`.
fn partial_eq_impls_without_ct_eq(source: &str) -> (usize, Vec<(usize, String)>) {
    let file = syn::parse_file(source).expect("the scanned source must parse as a Rust file");
    let mut impls = Vec::new();
    collect_impls(&file.items, &mut impls);
    let mut seen = 0usize;
    let mut bad = Vec::new();
    for block in impls {
        let is_partial_eq = block
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == "PartialEq");
        if !is_partial_eq {
            continue;
        }
        seen += 1;
        let type_name = type_last_name(&block.self_ty);
        for item in &block.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            let name = function.sig.ident.to_string();
            if name != "eq" && name != "ne" {
                continue;
            }
            let mut scan = EqBodyScan::default();
            syn::visit::Visit::visit_block(&mut scan, &function.block);
            // The comparison has to be what the body *returns*. Counting `ct_eq` calls
            // alone accepted a discarded one (`let _ = bool::from(a.ct_eq(&b)); a == b`),
            // i.e. a comparison through `==` with a `ct_eq` beside it for the counter.
            let tail_is_ct_eq =
                function
                    .block
                    .stmts
                    .last()
                    .is_some_and(|statement| match statement {
                        syn::Stmt::Expr(expr, None) => expr_contains_ct_eq(expr),
                        _ => false,
                    });
            if scan.ct_eq_calls == 0
                || scan.comparison_operators != 0
                || scan.macro_comparison
                || scan.macro_ct_eq
                || !tail_is_ct_eq
            {
                let mut why = Vec::new();
                if scan.ct_eq_calls == 0 {
                    why.push("no `ct_eq` call");
                }
                if scan.comparison_operators != 0 {
                    why.push("an `==`/`!=` operator");
                }
                if scan.macro_comparison {
                    why.push("a comparison inside a macro body");
                }
                if scan.macro_ct_eq {
                    why.push("a `ct_eq` inside a macro body, which this scan cannot read");
                }
                if !tail_is_ct_eq {
                    why.push("a result that is not the `ct_eq` comparison");
                }
                bad.push((
                    function.sig.ident.span().start().line,
                    format!("{type_name}::{name} ({})", why.join(", ")),
                ));
            }
        }
    }
    (seen, bad)
}

/// The wipe primitives whose stores must all be volatile.
const WIPE_FUNCTIONS: [&str; 8] = [
    "wipe",
    "wipe_words",
    "zeroize_array",
    "zeroize_neon",
    "zeroize_raw",
    "zeroize_slice",
    "zeroize_xmm",
    "zeroize_ymm",
];

/// Store-shaped calls that are **not** volatile. A wipe that uses one of these can be
/// removed by the optimizer when the value is dead afterwards, which is the whole reason
/// [`zeroize_raw`] writes through `write_volatile` rather than `fill`.
const NON_VOLATILE_STORES: [&str; 15] = [
    "_mm_store_si128",
    "_mm_store_si256",
    "_mm_storeu_si128",
    "_mm_storeu_si256",
    "copy_from_slice",
    "copy_nonoverlapping",
    "fill",
    "store_si128",
    "store_si256",
    "storeu_si128",
    "storeu_si256",
    "vst1q_u32",
    "write",
    "write_bytes",
    "write_unaligned",
];

/// The calls made by one function body, as `(line, callee name, path text)`.
///
/// The path text is what makes the volatility check alias-proof. `use core::ptr::write as
/// write_volatile;` leaves the callee's *name* `write_volatile` -- measured: a name-only
/// scan called that a volatile store and the whole suite stayed green -- while the path text
/// is still `write_volatile`, so the check below requires the path to be exactly
/// `core::ptr::write_volatile`. An alias, a re-export or a locally defined function of that
/// name therefore all fail it. An empty path is the method form (`p.write_volatile(0)`),
/// which resolves to the inherent method on raw pointers and cannot be shadowed.
#[derive(Default)]
struct CallScan(Vec<(usize, String, String)>);

impl<'ast> syn::visit::Visit<'ast> for CallScan {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(last) = path.path.segments.last() {
                let full = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                self.0
                    .push((last.ident.span().start().line, last.ident.to_string(), full));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push((
            call.method.span().start().line,
            call.method.to_string(),
            String::new(),
        ));
        syn::visit::visit_expr_method_call(self, call);
    }

    /// `*ptr = value` is a store with no call to inspect, and it is *not* volatile. It is
    /// recorded under its own name so the failure says which spelling was used: measured,
    /// rewriting `zeroize_raw`'s wide-loop store as `*(ptr.add(i) as *mut usize) = 0;` is
    /// caught only by the pinned count (`3` -> `2`), and the operator says nothing about
    /// what the new store is.
    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        use syn::spanned::Spanned;

        self.0.push((
            assign.left.span().start().line,
            "assignment".to_string(),
            String::new(),
        ));
        syn::visit::visit_expr_assign(self, assign);
    }
}

/// What the wipe primitives in one source file do, as
/// `(names found, non-volatile stores, volatile stores per function)`.
#[derive(Default)]
struct WipeStoreScan {
    /// Every `WIPE_FUNCTIONS` definition seen, in source order.
    found: Vec<String>,
    /// `(line, function, non-volatile store)` for each store that is not volatile.
    offending: Vec<(usize, String, String)>,
    /// `write_volatile` calls per function name.
    volatile: std::collections::BTreeMap<String, usize>,
    /// `(line, function, path text)` for each `write_volatile` call whose path is not
    /// exactly `core::ptr::write_volatile`.
    aliased: Vec<(usize, String, String)>,
    /// `(line, spelling)` for every `use` in the file that brings *another* item in under
    /// the name `write_volatile`; naming the culprit is what makes the failure actionable.
    aliasing_imports: Vec<(usize, String)>,
}

fn wipe_store_findings(source: &str) -> WipeStoreScan {
    let file = syn::parse_file(source).expect("the scanned source must parse as a Rust file");
    let mut scan = WipeStoreScan::default();
    scan_wipe_functions(&file.items, &mut scan);
    scan.aliasing_imports = write_volatile_aliasing_imports(source);
    scan
}

fn scan_wipe_functions(items: &[syn::Item], out: &mut WipeStoreScan) {
    for item in items {
        match item {
            syn::Item::Fn(function) => note_wipe_function(function, out),
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    scan_wipe_functions(items, out);
                }
            }
            syn::Item::Impl(block) => {
                for item in &block.items {
                    if let syn::ImplItem::Fn(function) = item {
                        note_wipe_body(&function.sig.ident.to_string(), &function.block, out);
                    }
                }
            }
            syn::Item::Trait(block) => {
                for item in &block.items {
                    if let syn::TraitItem::Fn(function) = item {
                        if let Some(body) = &function.default {
                            note_wipe_body(&function.sig.ident.to_string(), body, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn note_wipe_function(function: &syn::ItemFn, out: &mut WipeStoreScan) {
    note_wipe_body(&function.sig.ident.to_string(), &function.block, out);
}

fn note_wipe_body(name: &str, block: &syn::Block, out: &mut WipeStoreScan) {
    if !WIPE_FUNCTIONS.contains(&name) {
        return;
    }
    out.found.push(name.to_string());
    let mut calls = CallScan::default();
    syn::visit::Visit::visit_block(&mut calls, block);
    for (line, callee, path) in calls.0 {
        if callee == "write_volatile" {
            *out.volatile.entry(name.to_string()).or_default() += 1;
            if !path.is_empty() && path != "core::ptr::write_volatile" {
                out.aliased.push((line, name.to_string(), path));
            }
        } else if NON_VOLATILE_STORES.contains(&callee.as_str()) || callee == "assignment" {
            out.offending.push((line, name.to_string(), callee));
        }
    }
}

/// Every `use` that binds the name `write_volatile` to something other than
/// `core::ptr::write_volatile`, as `(line, spelling)`.
///
/// The per-call path check above catches an alias at the point of use; this catches the
/// import itself, wherever it is written, and names it. Both are needed: a wipe function
/// might not use the alias at all in the revision under review, and an import that is
/// merely *present* is the precondition for the next edit to be invisible.
fn write_volatile_aliasing_imports(source: &str) -> Vec<(usize, String)> {
    let file = syn::parse_file(source).expect("the scanned source must parse as a Rust file");
    let mut out = Vec::new();
    collect_aliasing_imports(&file.items, &mut out);
    out
}

fn collect_aliasing_imports(items: &[syn::Item], out: &mut Vec<(usize, String)>) {
    use syn::spanned::Spanned;

    for item in items {
        match item {
            syn::Item::Use(u) => {
                let text = u.span().source_text().unwrap_or_default();
                if use_tree_binds_write_volatile(&u.tree) {
                    out.push((u.span().start().line, text.replace('\n', " ")));
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_aliasing_imports(items, out);
                }
            }
            syn::Item::Fn(function) => {
                collect_aliasing_imports_in_block(&function.block, out);
            }
            syn::Item::Impl(block) => {
                for item in &block.items {
                    if let syn::ImplItem::Fn(function) = item {
                        collect_aliasing_imports_in_block(&function.block, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_aliasing_imports_in_block(block: &syn::Block, out: &mut Vec<(usize, String)>) {
    use syn::spanned::Spanned;

    for statement in &block.stmts {
        if let syn::Stmt::Item(syn::Item::Use(u)) = statement {
            if use_tree_binds_write_volatile(&u.tree) {
                let text = u.span().source_text().unwrap_or_default();
                out.push((u.span().start().line, text.replace('\n', " ")));
            }
        }
    }
}

/// Whether `tree` binds the name `write_volatile` to anything other than
/// `core::ptr::write_volatile` (`use core::ptr::write as write_volatile`, `use
/// core::ptr::{write as write_volatile}`, `use core::ptr::write_volatile as x` is *not*
/// this: it renames the real intrinsic, which the per-call path check still sees).
fn use_tree_binds_write_volatile(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(rename) => {
            rename.rename == "write_volatile" && rename.ident != "write_volatile"
        }
        syn::UseTree::Path(path) => use_tree_binds_write_volatile(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_binds_write_volatile),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

/// Every wipe primitive that performs volatile stores itself also ends with a
/// `compiler_fence(SeqCst)`.
///
/// `write_volatile` orders the stores against each other and against observable side
/// effects, but it does **not** stop the compiler from sinking or hoisting *ordinary*
/// accesses across the wipe: the derived key can be copied out of a register into a stack
/// slot the wipe's range does not cover, after the stores. The fence is the second half of
/// the guarantee, and nothing measured it -- deleting `zeroize_raw`'s trailing
/// `compiler_fence` left this file's suite 37/37 green, because the bytes are still zero and
/// the stores are still volatile.
///
/// The rule is per *store site*, not per name: a primitive that delegates (`zeroize_slice`
/// and `zeroize_array` both end in `zeroize_raw`) is covered by its callee's fence, and a
/// guard that demanded a fence in every one of them would be asking for a second fence that
/// protects nothing -- the kind of demand that gets satisfied by copying the line. So the
/// assertion is: a primitive with volatile stores of its own has a fence, and every
/// primitive without stores of its own calls one that has.
#[test]
fn every_wipe_primitive_that_stores_ends_with_a_compiler_fence() {
    let mut source = non_test_source();
    source.push_str(&non_test_source_of(include_str!("../src/witness.rs")));
    let file = syn::parse_file(&source).expect("the scanned source must parse as a Rust file");
    let mut found = Vec::new();
    collect_fence_status(&file.items, &mut found);
    assert_eq!(
        found.len(),
        10,
        "expected 10 wipe primitives (the same ten `every_wipe_store_is_volatile` scans), \
         found {:?}. A renamed primitive is no longer covered by this guard.",
        found
            .iter()
            .map(|status| status.name.clone())
            .collect::<Vec<_>>()
    );
    let by_name: std::collections::BTreeMap<String, &WipeFenceStatus> = found
        .iter()
        .map(|status| (status.name.clone(), status))
        .collect();
    assert!(
        by_name.contains_key("zeroize_raw"),
        "`zeroize_raw` is gone from the scanned source; this guard's subject is missing"
    );
    for status in &found {
        // The Kani-only no-ops in `src/witness.rs` are compiled only under `cfg(kani)`,
        // where the concrete harness compares hash values rather than wipes; they are
        // listed here so a *third* definition of either name cannot hide behind them.
        if is_kani_noop(status) {
            continue;
        }
        if status.volatile_stores > 0 {
            assert!(
                status.fenced,
                "`{}` performs {} volatile store(s) and has no `compiler_fence`. \
                 `write_volatile` does not order ordinary accesses across the wipe, so \
                 without the fence the compiler may copy the key out of a register into a \
                 slot the wipe does not cover, after the stores. Measured: deleting \
                 `zeroize_raw`'s trailing fence left the suite green.",
                status.name, status.volatile_stores
            );
        } else {
            assert!(
                status.delegates_to.iter().any(|callee| by_name
                    .get(callee)
                    .is_some_and(|callee_status| callee_status.volatile_stores > 0
                        || !callee_status.delegates_to.is_empty())),
                "`{}` performs no volatile store of its own and does not call a wipe \
                 primitive that does (it calls {:?}), so its name promises a wipe that \
                 nothing performs.",
                status.name,
                status.delegates_to
            );
        }
    }
}

/// The first parameter's pattern text, or `""` when the function takes none.
fn first_param_pattern(sig: &syn::Signature) -> String {
    sig.inputs
        .first()
        .map(|arg| match arg {
            syn::FnArg::Typed(pat) => quote_pattern(&pat.pat),
            syn::FnArg::Receiver(_) => "self".to_string(),
        })
        .unwrap_or_default()
}

/// A pattern rendered as text, for the identifiers this file compares.
fn quote_pattern(pat: &syn::Pat) -> String {
    match pat {
        syn::Pat::Ident(ident) => ident.ident.to_string(),
        syn::Pat::Wild(_) => "_".to_string(),
        other => {
            use syn::spanned::Spanned;
            other.span().source_text().unwrap_or_default()
        }
    }
}

/// Whether `status` is one of `src/witness.rs`'s `cfg(kani)`-only no-ops.
///
/// They are `fn wipe<T>(_value: &mut T) {}` and `fn wipe_words(_words: &mut [u32]) {}`: no
/// stores, no calls, and a `_`-prefixed parameter. The signature is what distinguishes them
/// from the real pair, which take `&mut T` / `&mut [u32]` and store.
fn is_kani_noop(status: &WipeFenceStatus) -> bool {
    (status.name == "wipe" || status.name == "wipe_words")
        && status.first_param.starts_with('_')
        && status.volatile_stores == 0
        && status.delegates_to.is_empty()
        && !status.fenced
}

/// What one wipe primitive does: its name, how many volatile stores it performs itself,
/// whether it calls `compiler_fence`, and which other wipe primitives it calls.
struct WipeFenceStatus {
    name: String,
    volatile_stores: usize,
    fenced: bool,
    delegates_to: Vec<String>,
    /// The first parameter's pattern text (`_value`, `_words`, `value`, `slice`, ...).
    first_param: String,
}

fn collect_fence_status(items: &[syn::Item], out: &mut Vec<WipeFenceStatus>) {
    for item in items {
        match item {
            syn::Item::Fn(function) => note_fence_status(
                &function.sig.ident.to_string(),
                &first_param_pattern(&function.sig),
                &function.block,
                out,
            ),
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_fence_status(items, out);
                }
            }
            syn::Item::Impl(block) => {
                for item in &block.items {
                    if let syn::ImplItem::Fn(function) = item {
                        note_fence_status(
                            &function.sig.ident.to_string(),
                            &first_param_pattern(&function.sig),
                            &function.block,
                            out,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn note_fence_status(
    name: &str,
    first_param: &str,
    block: &syn::Block,
    out: &mut Vec<WipeFenceStatus>,
) {
    if !WIPE_FUNCTIONS.contains(&name) {
        return;
    }
    let mut calls = CallScan::default();
    syn::visit::Visit::visit_block(&mut calls, block);
    let fenced = calls
        .0
        .iter()
        .any(|(_, callee, _)| callee == "compiler_fence");
    let volatile_stores = calls
        .0
        .iter()
        .filter(|(_, callee, _)| callee == "write_volatile")
        .count();
    let delegates_to = calls
        .0
        .iter()
        .map(|(_, callee, _)| callee.clone())
        .filter(|callee| WIPE_FUNCTIONS.contains(&callee.as_str()) && callee != name)
        .collect();
    out.push(WipeFenceStatus {
        name: name.to_string(),
        volatile_stores,
        fenced,
        delegates_to,
        first_param: first_param.to_string(),
    });
}

/// Every hand-written `PartialEq` in the crate compares in constant time.
#[test]
fn every_hand_written_partial_eq_compares_in_constant_time() {
    let mut source = non_test_source();
    source.push_str(&non_test_source_of(include_str!("../src/witness.rs")));
    let (seen, bad) = partial_eq_impls_without_ct_eq(&source);
    // 7 for `Plaintext` (slice, `&[u8]`, array, `&array`, `Vec`, `Plaintext`, `&Plaintext`),
    // 2 each for `Key` and `LockedKey`. The count is pinned so that deleting an impl -- and
    // with it this guard's subject -- is a deliberate change rather than a silent one.
    assert_eq!(
        seen, 11,
        "expected 11 hand-written `PartialEq` impls (7 `Plaintext`, 2 `Key`, 2 `LockedKey`), \
         found {seen}. Each one exists so that `==` on secret bytes cannot fall back to the \
         short-circuiting slice comparison; if one was removed, the documentation on \
         `Plaintext`'s impls is now wrong, and if one was added this guard must cover it."
    );
    assert!(
        bad.is_empty(),
        "these `PartialEq` implementations do not compare in constant time: {bad:?}. A \
         short-circuiting `==` on decrypted bytes leaks the matching prefix length, which is \
         exactly what the doc above `Plaintext`'s impls promises cannot happen. Measured: \
         rewriting one body as `self.0.as_slice() == other` left `tests/` and `--lib` green \
         (the equality *answer* is the same), so nothing else in this suite would notice. \
         Route every comparison through `subtle::ConstantTimeEq::ct_eq`."
    );
}

/// Every store in a wipe primitive is volatile.
#[test]
fn every_wipe_store_is_volatile() {
    let mut scan = wipe_store_findings(&non_test_source());
    let witness = wipe_store_findings(&non_test_source_of(include_str!("../src/witness.rs")));
    scan.found.extend(witness.found.iter().cloned());
    scan.offending.extend(witness.offending.iter().cloned());
    for (name, count) in &witness.volatile {
        *scan.volatile.entry(name.clone()).or_default() += count;
    }
    // `wipe` and `wipe_words` appear twice each in `src/witness.rs`: the real one and the
    // Kani-only no-op, which must stay visible to this scan. If a wipe primitive is renamed
    // it disappears from the list and stops being checked, so the list is pinned.
    assert_eq!(
        scan.found.len(),
        10,
        "expected 10 wipe-primitive definitions (6 in `src/lib.rs`, `wipe` and `wipe_words` \
         twice each in `src/witness.rs`), found {:?}. A renamed or deleted wipe primitive is \
         no longer scanned by this guard.",
        scan.found
    );
    assert!(
        scan.aliased.is_empty(),
        "wipe primitive(s) call a `write_volatile` whose path is not `core::ptr::write_volatile`: \
         {:?}. `use core::ptr::write as write_volatile;` leaves the callee's *name* unchanged, so \
         a name-matching scan reads an ordinary store as a volatile one -- measured: that alias \
         left this file's suite 37/37 green while every wipe in `zeroize_raw` became elidable. \
         Call the intrinsic by its full path, or use the inherent method \
         (`p.write_volatile(0)`), which cannot be shadowed.",
        scan.aliased
    );
    assert!(
        scan.aliasing_imports.is_empty(),
        "these `use` statements bind the name `write_volatile` to something else: {:?}. An \
         alias is the precondition for a wipe store that reads as volatile and is not; the \
         per-call check above catches its use, this one catches the import wherever it is \
         written, including in a file whose wipe functions do not use it yet.",
        scan.aliasing_imports
    );
    assert!(
        scan.offending.is_empty(),
        "wipe primitive(s) write through a non-volatile store: {:?}. `write_volatile` is what \
         keeps the optimizer from deleting a dead store, which is the entire reason these \
         functions exist instead of `fill(0)`; Kani proves only that the bytes are zero \
         afterwards, which a plain store satisfies too. Measured: changing `zeroize_raw`'s \
         leading-loop store to `core::ptr::write(ptr.add(i), 0)` left `tests/` and `--lib` \
         green.",
        scan.offending
    );
    // The count per primitive is pinned, not merely required to be positive. `> 0` was the
    // first version, and it accepts a wipe whose stores were rewritten as plain ones while a
    // single volatile store survives somewhere in the body -- or, in `zeroize_raw`, a
    // rewrite of the wide loop's store (the bulk of the wipe) that leaves the leading and
    // trailing loops' stores in place.
    for (name, expected) in [
        ("wipe", 1),
        ("wipe_words", 1),
        ("zeroize_neon", 1),
        ("zeroize_raw", 3),
        ("zeroize_xmm", 1),
        ("zeroize_ymm", 1),
    ] {
        assert_eq!(
            scan.volatile.get(name).copied().unwrap_or(0),
            expected,
            "`{name}` has {} `write_volatile` store(s), expected {expected} (all counts: \
             {:?}). A wipe that lost one of its volatile stores can be partially or wholly \
             elided by the optimizer, which is what `write_volatile` exists to prevent.",
            scan.volatile.get(name).copied().unwrap_or(0),
            scan.volatile
        );
    }
}

/// The shapes the two guards above must and must not report, pointed at synthetic sources.
#[test]
fn the_equality_and_wiping_guards_see_the_defects_built_for_them() {
    let wrap = |body: &str| format!("{body}\nmod tests {{ }}");
    // `PartialEq` impls that must be reportable ...
    for (name, body) in [
        (
            "a short-circuiting slice comparison",
            "impl PartialEq<[u8]> for Plaintext { fn eq(&self, o: &[u8]) -> bool { self.0.as_slice() == o } }",
        ),
        (
            "a `ne` that inverts a slice comparison",
            "impl PartialEq for Plaintext { fn eq(&self, o: &Plaintext) -> bool { bool::from(self.0.ct_eq(&o.0)) } fn ne(&self, o: &Plaintext) -> bool { self.0.as_slice() != o.0.as_slice() } }",
        ),
        (
            "an `eq` that calls neither `ct_eq` nor a comparison",
            "impl PartialEq<[u8]> for Plaintext { fn eq(&self, _o: &[u8]) -> bool { true } }",
        ),
        (
            "a discarded `ct_eq` beside a real `==`",
            "impl PartialEq for Key { fn eq(&self, o: &Key) -> bool { let _ = bool::from(self.0.ct_eq(&o.0)); self.0 == o.0 } }",
        ),
        (
            "a comparison through a macro body",
            "macro_rules! m { ($a:expr, $b:expr) => { $a == $b }; }\nimpl PartialEq for Key { fn eq(&self, o: &Key) -> bool { let _ = bool::from(self.0.ct_eq(&o.0)); m!(self.0, o.0) } }",
        ),
    ] {
        let (seen, bad) = partial_eq_impls_without_ct_eq(&wrap(body));
        assert_eq!(seen, 1, "the impl was not recognised: {name}");
        assert_eq!(bad.len(), 1, "the guard missed the shape: {name} ({bad:?})");
    }
    for (name, body) in [
        (
            "a `ct_eq` on a slice",
            "impl PartialEq<[u8]> for Plaintext { fn eq(&self, o: &[u8]) -> bool { bool::from(self.0.as_slice().ct_eq(o)) } }",
        ),
        (
            "a fully qualified `ct_eq` call",
            "impl PartialEq for Key { fn eq(&self, o: &Key) -> bool { bool::from(subtle::ConstantTimeEq::ct_eq(&self.0, &o.0)) } }",
        ),
    ] {
        let (seen, bad) = partial_eq_impls_without_ct_eq(&wrap(body));
        assert_eq!(seen, 1, "the impl was not recognised: {name}");
        assert!(bad.is_empty(), "the guard reported a clean shape: {name} ({bad:?})");
    }
    // ... and wipe primitives that must be.
    for (name, body) in [
        (
            "a path-form plain store",
            "fn zeroize_raw(p: *mut u8) { unsafe { core::ptr::write(p, 0) }; }",
        ),
        (
            "a method-form plain store",
            "unsafe fn zeroize_raw(p: *mut u8) { unsafe { p.write(0) }; }",
        ),
        (
            "a zeroing `fill`",
            "fn zeroize_slice(s: &mut [u8]) { s.fill(0); }",
        ),
        (
            "a zeroed vector store",
            "unsafe fn zeroize_xmm(v: &mut [__m128i]) { unsafe { _mm_storeu_si128(v.as_mut_ptr(), zero) }; }",
        ),
        (
            "a deref assignment (no call to inspect)",
            "unsafe fn zeroize_raw(p: *mut u8) { unsafe { *p = 0 }; }",
        ),
        (
            "an alias that keeps the callee name",
            "mod a { pub use core::ptr::write as write_volatile; }\nuse a::write_volatile;\nunsafe fn zeroize_raw(p: *mut u8) { unsafe { write_volatile(p, 0) }; }",
        ),
    ] {
        let scan = wipe_store_findings(body);
        // An alias import is reported by the import rule rather than as a store, so the
        // shape counts as caught when *either* rule fires.
        assert!(
            scan.offending.len() + scan.aliasing_imports.len() + scan.aliased.len() >= 1,
            "the wipe-store guard missed the shape: {name} (stores {:?}, aliased calls {:?}, \
             aliasing imports {:?})",
            scan.offending,
            scan.aliased,
            scan.aliasing_imports
        );
    }
    let clean = wipe_store_findings(
        "unsafe fn zeroize_raw(p: *mut u8) { unsafe { core::ptr::write_volatile(p, 0) }; }",
    );
    assert!(
        clean.offending.is_empty(),
        "the guard reported the clean wipe"
    );
    assert_eq!(clean.volatile.get("zeroize_raw"), Some(&1));
}

/// Every `scrub_stack` call site must survive — asserted here as well as in
/// `tests/ultra.rs`, because `ultra.rs` only compiles with `--features ultra` and
/// `scrub_stack` runs in *every* build. Measured: deleting `decrypt`'s
/// `crate::scrub_stack();` leaves this file's suite green by itself, and only the
/// feature-gated copy in `ultra.rs` goes red; the default `cargo test` — the one a
/// contributor runs — sees nothing. `scrub_stack` is best-effort with no behavioural
/// signature, so an existence count is its only witness.
#[test]
fn scrub_stack_survives_at_every_entry_point_in_every_build() {
    // Comments stripped, so replacing a real call with `// scrub_stack(); (planted)` reads
    // as a *missing* call site.
    let body = non_test_source();

    /// The body of `needle`, brace-matched.
    fn body_of<'a>(src: &'a str, needle: &str) -> &'a str {
        let start = src.find(needle).unwrap_or_else(|| panic!("no {needle}"));
        assert_eq!(
            src.matches(needle).count(),
            1,
            "{needle} must appear exactly once in the non-test source"
        );
        let after = &src[start..];
        let open = after.find('{').expect("body");
        let mut depth = 0usize;
        for (n, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &after[..=open + n];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in {needle}");
    }

    // Per function, not a whole-file total: a total is unbound to position, so a call
    // moved into a helper nobody calls would keep it at eight.
    let mut total = 0;
    for (name, expected) in [
        ("pub fn encrypt(", 3),
        ("pub fn encrypt_in_place_detached(", 1),
        ("pub fn decrypt(", 1),
        ("pub fn decrypt_in_place_detached(", 1),
        ("pub fn new(key: &[u8; crate::KEY_LEN])", 1),
        ("fn check_integrity(&self, bytes: &[u8; crate::KEY_LEN])", 1),
    ] {
        let function = body_of(&body, name);
        let found = function.matches("crate::scrub_stack();").count();
        assert_eq!(
            found, expected,
            "{name} must contain {expected} `crate::scrub_stack();` call sites, found \
             {found}: a dropped one leaves key material in the region it exists to clear, \
             and nothing else in the default build notices"
        );
        assert_eq!(
            function.matches("scrub_stack();").count(),
            found,
            "{name} must not contain an unqualified `scrub_stack();`: the absolute path is \
             what keeps a local import from shadowing the wipe"
        );
        assert!(
            !function.contains("black_box(false)") && !function.contains("if false"),
            "{name}'s scrub calls must not be nested in a constant-false block: the text \
             would still count while the region is never overwritten"
        );
        total += found;
    }
    assert_eq!(total, 8, "all eight scrub_stack call sites must remain");
}
