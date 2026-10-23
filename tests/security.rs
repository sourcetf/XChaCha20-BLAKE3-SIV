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

/// See [`non_test_source`]: the same cut applied to `text` rather than to `LIB`, for
/// the two files `no_constant_cfg_attribute_can_deaden_the_crypto_source` scans.
fn non_test_source_of(text: &str) -> String {
    let stripped = strip_comments(text);
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
    match find_cfg_test_attribute(&out, 0) {
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

/// The next `#[cfg(test)]` (or `#![cfg(test)]`) at or after `from`, as
/// `(index of the `#`, index just past the `]`, inner?)`. Whitespace is allowed between
/// the tokens, because `#[ cfg ( test ) ]` is the same attribute.
fn find_cfg_test_attribute(source: &str, from: usize) -> Option<(usize, usize, bool)> {
    let b = source.as_bytes();
    let mut i = from;
    while i < b.len() {
        if b[i] == b'#' {
            let mut j = i + 1;
            let inner = b.get(j) == Some(&b'!');
            if inner {
                j += 1;
            }
            if b.get(j) == Some(&b'[') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if b[j..].starts_with(b"cfg") {
                    j += 3;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if b.get(j) == Some(&b'(') {
                        j += 1;
                        while j < b.len() && b[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if b[j..].starts_with(b"test") {
                            let mut k = j + 4;
                            while k < b.len() && b[k].is_ascii_whitespace() {
                                k += 1;
                            }
                            if b.get(k) == Some(&b')') {
                                k += 1;
                                while k < b.len() && b[k].is_ascii_whitespace() {
                                    k += 1;
                                }
                                if b.get(k) == Some(&b']') {
                                    return Some((i, k + 1, inner));
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
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
    while let Some((start, close, inner)) = find_cfg_test_attribute(source, from) {
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
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
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
                        i += if escaped { 4 } else { 3 };
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
                    }
                    i += 2;
                } else if c == b'"' {
                    out.push('"');
                    mode = Mode::Code;
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
fn constant_cfg_value(pred: &str) -> Option<bool> {
    let normalized: String = pred.chars().filter(|c| !c.is_whitespace()).collect();
    let p = normalized.as_str();
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
        "test" => Some(false), // set only by the crate's own test harness
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// `inner` split at its **top-level** commas (`all(a, any(b, c))` -> `["a", "any(b, c)"]`).
fn split_cfg_args(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = &inner[start..];
    if !out.is_empty() || !last.trim().is_empty() {
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
            if b.get(j) == Some(&b'!') {
                j += 1; // the inner form `#![…]`
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
fn cfg_predicate_at(source: &str, open: usize) -> (String, usize) {
    let mut depth = 0usize;
    let mut close = None;
    for (n, c) in source[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + n);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.expect("unbalanced `cfg(` in the source");
    (source[open + 1..close].to_string(), close)
}

/// Every `cfg`-family attribute in `source` whose gating is constant, as
/// `(line number, attribute text with the reason it is constant)`.
///
/// `source` must be comment-free (and string-blanked) — the callers use
/// [`strip_comments`] — so a `#[cfg(any())]` written only in prose is not a finding.
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
        if line.starts_with("#[") || line.starts_with("#![") {
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
        } else {
            break;
        }
    }
    out
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
                    let hash = if i >= 1 && bytes[i - 1] == b'#' {
                        i - 1
                    } else if i >= 2 && bytes[i - 2] == b'#' && bytes[i - 1] == b'!' {
                        i - 2
                    } else {
                        return None; // the `[` is not part of an attribute
                    };
                    return Some(&line[hash..]);
                }
            }
            _ => {}
        }
    }
    None
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
        CfgAttribute::Cfg => {
            constant_cfg_value(args).map(|value| format!("its predicate is constant ({value})"))
        }
        CfgAttribute::CfgAttr => {
            let parts = split_cfg_args(args);
            let (condition, attributes) = parts.split_first()?;
            if let Some(value) = constant_cfg_value(condition) {
                return Some(format!(
                    "its condition `{condition}` is constant ({value}), so the attributes \
                     it lists always apply or never do"
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
    let raw = raw_lib_line(line);
    let (_, open, _) = find_cfg_attribute(raw, 0).unwrap_or_else(|| {
        panic!(
            "line {line} of `src/lib.rs` is an attribute in the stripped scan text but \
             carries no `cfg`-family attribute when read raw (`{raw}`); the predicate \
             cannot be checked, and passing it would be fail-open"
        )
    });
    let (args, _) = cfg_predicate_at(raw, open);
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
fn assert_wipes_are_not_deadened(
    name: &str,
    body: &str,
    body_line: usize,
    wipe: &str,
    allowed_cfg: &[&str],
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
        for (line_no, attr) in preceding_attributes(body, stmt_at) {
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
                assert!(
                    allowed_cfg.contains(&predicate.as_str()),
                    "`{name}`'s wipe `{wipe}` is directly preceded by `{}` (line {line}), \
                     whose predicate `{predicate}` is not one of the configurations this \
                     table enumerates for this wipe ({allowed_cfg:?}). A `cfg` on a counted \
                     wipe compiles the wipe out of every build the predicate is false in \
                     while leaving the counted text unchanged: `#[cfg(feature = \"pure\")]` \
                     on `encrypt`'s `enc_key` wipe was measured taking the wipe out of the \
                     default and `ultra` builds with the whole suite green. Delete the \
                     attribute, or add the predicate to the table deliberately, with the \
                     reason the wipe is not counted in the configurations it excludes.",
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
        let found = constant_cfg_attributes(&body);
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
            // The bare path form, so the turbofish spelling `Vec::<u8>::with_capacity` is
            // caught too: an injected `Vec::<u8>::with_capacity(1)` after `derive_enc`
            // walked straight past a `Vec::with_capacity` match.
            "Vec::",
            "Vec::from",
            "with_capacity",
            "try_reserve",
            ".to_vec()",
            ".to_owned(",
            ".collect(",
            "Box::new",
            "String::",
            "Rc::",
            "Arc::",
        ] {
            assert!(
                !body.contains(spelling),
                "{name} allocates through `{spelling}`, which the ordering above cannot \
                 place relative to the first derivation; route it through the fallible \
                 `alloc_zeroed` helper before the derivation, or add this spelling to the \
                 list deliberately and order it too"
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
    for (name, buffers) in [
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
    ] {
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
            // Pin the live shape at each site the count just found. `&[]` is the
            // allow-list: every wipe in this table exists in every configuration, so no
            // `cfg`-family attribute directly on one is acceptable.
            assert_wipes_are_not_deadened(name, &body, body_line, &wipe, &[]);
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
            // The failure path of `LockedKey::new` drops the page directly, with the key
            // and its integrity tag already written, so this wipe and not
            // `LockedKey::drop` is the one that covers it.
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
            assert_wipes_are_not_deadened(site.label, &body, body_line, wipe, allowed_cfg);
        }
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
    while let Some(start) = rest.find("macro_rules!") {
        let after = &rest[start..];
        let Some(open) = after.find('{') else {
            break;
        };
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

#[test]
fn no_wipe_is_hidden_in_an_unexpanded_macro() {
    for (name, source) in [
        ("src/lib.rs", non_test_source()),
        (
            "src/witness.rs",
            strip_comments(include_str!("../src/witness.rs")),
        ),
        (
            "src/proofs.rs",
            strip_comments(include_str!("../src/proofs.rs")),
        ),
    ] {
        for body in macro_bodies(&source) {
            for marker in [
                "zeroize_array(",
                "zeroize_slice(",
                "zeroize_raw(",
                "scrub_stack(",
            ] {
                assert!(
                    !body.contains(marker),
                    "`{name}` hides `{marker}` inside an unexpanded `macro_rules!`; the \
                     wipe count sees the text but no build executes it. Inline the calls \
                     or make the macro invocation part of the counted path:\n{body}"
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
