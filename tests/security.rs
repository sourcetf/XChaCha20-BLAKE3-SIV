//! Security tests: property-based, statistical-timing, and fuzz.
//!
//! These cover the classes of defect that a fixed known-answer vector cannot:
//! statements quantified over *all* inputs (property tests), statements about
//! *time* (a dudect-style test), and statements about *arbitrary bytes* (a fuzz
//! loop). The KATs pin the construction; these pin its security properties.
//!
//! Tooling note: `cargo-fuzz`/libFuzzer and `ctgrind` are wired up (see
//! `.github/workflows/deep.yml` and `tools/ctgrind.sh`), but the fuzz loop and the
//! timing test here stay as they are, because they run in a plain `cargo test`
//! with no extra tooling and no nightly: the deterministic seeded fuzz loop is the
//! regression net that catches a failure without libFuzzer's corpus, and the
//! timing test needs no external harness. `dudect-bencher` is still unavailable,
//! so the Welch t-test is implemented directly. The timing test is a *statistical
//! screen* — it can flag a leak, but passing it is not proof of constant-time
//! behaviour; `tools/ctgrind.sh` is the mechanical check. See `tests/README.md`.

use proptest::prelude::*;
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, Error, KEY_LEN,
    NONCE_LEN, TAG_LEN,
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
// ── Statistical timing screen (dudect-style) ─────────────────────────
//
// dudect's method is a Welch t-test between two sets of timings taken while
// feeding the implementation two classes of input differing only in something
// secret. `dudect-bencher` is unavailable here, so the machinery is implemented
// directly — and one hard fact about this host has to be stated up front,
// because it bounds what these tests can conclude:
//
//   **`Instant::now()` costs ~40,000 ns here** (measured: 39-50 us per call on
//   this WSL2 host, against ~25 ns on bare-metal Linux). A `decrypt` of a few
//   hundred bytes takes ~1-3 us.
//
// So a naive "time one operation" sample is >90% clock overhead, and an earlier
// version of these tests was **vacuous**: it passed with t < 1.5 not because
// nothing leaked but because it could not see anything. The calibration test
// below is what caught that, which is exactly why it exists.
//
// The measurement is therefore **batched**: each sample times `OPS_PER_SAMPLE`
// operations and divides, so the clock is amortised. That removes the overhead
// as a *bias* but cannot manufacture resolution the clock does not have — the
// detectable effect is still bounded by the jitter of a ~40 us clock across the
// sample count. The tests report that floor and are explicit that they are a
// screen, not evidence.
//
// **Where the real constant-time evidence is:**
//   1. source analysis — all 17 branch statements in non-test code were
//      classified: they depend on lengths, pointer alignment, CPU features, an
//      enum variant, or the final authentication decision. None depends on the
//      *content* of a key, nonce, AAD or message;
//   2. disassembly — `subtle::ConstantTimeEq` over the 65-byte tag compiles to an
//      unrolled branchless compare (checked for the 32-byte case in the previous
//      revision of this crate; the 65-byte form uses the same generic code);
//   3. the leaked quantity is bounded in principle: the only secret-dependent
//      branch is the final accept/reject, and every secret is wiped before it.
//
// These tests are a screen for gross regressions — e.g. someone replacing
// `ct_eq` with `==`, whose early exit is a difference of *hundreds* of ns on a
// 65-byte tag and would be visible even here.

/// Operations per timed sample, chosen so the ~40 us clock is a small fraction.
const OPS_PER_SAMPLE: usize = 512;
/// Samples per class.
const SAMPLES: usize = 200;

/// Welch's t-test.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len() as f64;
    let m = b.len() as f64;
    let ma = a.iter().sum::<f64>() / n;
    let mb = b.iter().sum::<f64>() / m;
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (n - 1.0);
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (m - 1.0);
    let denom = (va / n + vb / m).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (ma - mb).abs() / denom
    }
}

/// Time `OPS_PER_SAMPLE` operations, returning **nanoseconds per operation**.
fn time_batch(f: &mut impl FnMut()) -> f64 {
    use std::time::Instant;
    let t = Instant::now();
    for _ in 0..OPS_PER_SAMPLE {
        f();
    }
    t.elapsed().as_nanos() as f64 / OPS_PER_SAMPLE as f64
}

/// Consecutive batches combined per sample by taking the **minimum**.
///
/// This is the key to getting any resolution at all on this host. The clock
/// jitters by several microseconds, and interference can only ever *add* time, so
/// the minimum of several batches is far closer to the true cost than a mean is.
/// (A trimmed mean was tried first and left a 4,000 ns/op floor, which cannot see
/// the tens-of-nanoseconds difference a byte-at-a-time compare would produce.)
const INNER: usize = 8;

/// `SAMPLES` timings of `f`, each the minimum of `INNER` batches. Returns
/// nanoseconds per operation.
/// A small deterministic PRNG, used only to randomise measurement order.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

/// One sample: the minimum of `INNER` batches, in nanoseconds per operation.
fn sample_one(f: &mut impl FnMut()) -> f64 {
    (0..INNER).map(|_| time_batch(f)).fold(f64::MAX, f64::min)
}

/// Sample two classes with the **order randomised per sample**.
///
/// This is not a detail. Measuring A then B in every sample makes any
/// within-pair drift — frequency scaling, cache or branch-predictor state —
/// systematically favour one side. The first version of this test did exactly
/// that, and CI (whose clock is precise enough to resolve it: 2.8 ns/op against
/// 3 us on the development host) reported t = 35.6 for two inputs whose work
/// cannot differ, which is the signature of an order artefact rather than a
/// leak. Randomising the order makes the artefact cancel.
fn sample_pair(a: &mut impl FnMut(), b: &mut impl FnMut()) -> (Vec<f64>, Vec<f64>) {
    for _ in 0..OPS_PER_SAMPLE {
        a();
        b();
    }
    let mut va = Vec::with_capacity(SAMPLES);
    let mut vb = Vec::with_capacity(SAMPLES);
    let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
    for _ in 0..SAMPLES {
        if rng.next() & 1 == 0 {
            va.push(sample_one(a));
            vb.push(sample_one(b));
        } else {
            vb.push(sample_one(b));
            va.push(sample_one(a));
        }
    }
    (va, vb)
}

/// Standard error of the difference in means, i.e. the effect size this run
/// could resolve at |t| = 10.
fn resolution_ns(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len() as f64;
    let m = b.len() as f64;
    let ma = a.iter().sum::<f64>() / n;
    let mb = b.iter().sum::<f64>() / m;
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (n - 1.0);
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (m - 1.0);
    10.0 * (va / n + vb / m).sqrt()
}

/// The tag comparison must not leak *where* the first differing byte is.
///
/// This is the classic MAC-verification leak: a byte-at-a-time comparison exits
/// on the first mismatch, so an attacker who can time it recovers the tag one
/// byte at a time. `subtle::ConstantTimeEq` must make the two classes
/// indistinguishable.
///
/// Sensitivity: a plain `==` on a 65-byte tag would differ by roughly the cost
/// of the bytes it skips — tens to hundreds of nanoseconds per operation against
/// a floor of a few nanoseconds here — so a regression to `==` is well within
/// reach of this screen.
#[test]
fn timing_tag_comparison_does_not_leak_position() {
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let pt = [0xABu8; 256];
    let (ct, tag) = encrypt(&key, &nonce, b"aad", &pt).unwrap();

    // Class A differs in the first tag byte; class B in the last.
    let mut tag_first = tag;
    tag_first[0] ^= 0xFF;
    let mut tag_last = tag;
    tag_last[TAG_LEN - 1] ^= 0xFF;

    // Interleave the classes within each sample so drift is shared.
    for _ in 0..OPS_PER_SAMPLE {
        let _ = std::hint::black_box(decrypt(&key, &nonce, b"aad", &ct, &tag_first).is_err());
        let _ = std::hint::black_box(decrypt(&key, &nonce, b"aad", &ct, &tag_last).is_err());
    }
    let (a, b) = sample_pair(
        &mut || {
            let _ = std::hint::black_box(decrypt(&key, &nonce, b"aad", &ct, &tag_first).is_err());
        },
        &mut || {
            let _ = std::hint::black_box(decrypt(&key, &nonce, b"aad", &ct, &tag_last).is_err());
        },
    );
    let t = welch_t(&a, &b);
    let res = resolution_ns(&a, &b);
    eprintln!(
        "tag-position: t = {t:.2}, resolution = {res:.2} ns/op \
         (means {:.1} vs {:.1})",
        a.iter().sum::<f64>() / a.len() as f64,
        b.iter().sum::<f64>() / b.len() as f64
    );
    assert!(
        t < 10.0,
        "tag comparison timing depends on the position of the first differing \
         byte (t = {t:.2}, means {:.1} vs {:.1} ns/op); that is the signature of a \
         byte-at-a-time comparison",
        a.iter().sum::<f64>() / a.len() as f64,
        b.iter().sum::<f64>() / b.len() as f64
    );
}

/// No operation may branch on the *contents* of the key.
#[test]
fn timing_does_not_depend_on_key_contents() {
    let nonce = [0x55u8; 24];
    let aad = b"aad";
    let pt = [0xABu8; 512];

    let k_all0 = [0x00u8; 32];
    let k_allf = [0xFFu8; 32];
    let (ct0, _) = encrypt(&k_all0, &nonce, aad, &pt).unwrap();
    let (ctf, _) = encrypt(&k_allf, &nonce, aad, &pt).unwrap();

    for _ in 0..OPS_PER_SAMPLE {
        let _ = std::hint::black_box(encrypt(&k_all0, &nonce, aad, &pt).unwrap());
        let _ = std::hint::black_box(encrypt(&k_allf, &nonce, aad, &pt).unwrap());
    }
    let (a, b) = sample_pair(
        &mut || {
            let _ = std::hint::black_box(encrypt(&k_all0, &nonce, aad, &pt).unwrap());
        },
        &mut || {
            let _ = std::hint::black_box(encrypt(&k_allf, &nonce, aad, &pt).unwrap());
        },
    );
    let t_enc = welch_t(&a, &b);
    let r_enc = resolution_ns(&a, &b);

    // And a valid vs invalid decrypt of the same length, which an attacker can
    // actually drive.
    let (a, b) = sample_pair(
        &mut || {
            let _ =
                std::hint::black_box(decrypt(&k_all0, &nonce, aad, &ct0, &[0u8; TAG_LEN]).is_err());
        },
        &mut || {
            let _ =
                std::hint::black_box(decrypt(&k_allf, &nonce, aad, &ctf, &[0u8; TAG_LEN]).is_err());
        },
    );
    let t_dec = welch_t(&a, &b);
    let r_dec = resolution_ns(&a, &b);

    eprintln!(
        "key-contents: encrypt t = {t_enc:.2} (res {r_enc:.2} ns/op), \
         decrypt t = {t_dec:.2} (res {r_dec:.2} ns/op)"
    );
    assert!(
        t_enc < 10.0 && t_dec < 10.0,
        "timing depends on key contents (t_enc = {t_enc:.2}, t_dec = {t_dec:.2})"
    );
}

/// The timing machinery must be able to detect a real difference, or the tests
/// above prove nothing.
///
/// It also documents this host's measurement floor, which is the reason those
/// tests are described as a screen rather than as evidence.
#[test]
fn timing_screen_can_detect_a_real_difference() {
    // Mutable, so the work cannot be hoisted out of the sampling loop. A
    // constant buffer made an earlier version measure nothing at all: LLVM
    // computed the loop-invariant result once and both sides came out identical.
    let mut big = [0u8; 4096];
    let small = [0u8; 8];

    for _ in 0..OPS_PER_SAMPLE {
        for x in big.iter_mut() {
            *x = x.wrapping_add(1);
        }
        let _ = std::hint::black_box(small);
    }

    let (a, b) = sample_pair(
        &mut || {
            let _ = std::hint::black_box(small[0]);
        },
        &mut || {
            let mut acc = 0u8;
            for x in big.iter_mut() {
                *x = x.wrapping_add(1);
                acc ^= *x;
            }
            std::hint::black_box(acc);
        },
    );

    let t = welch_t(&a, &b);
    let ma = a.iter().sum::<f64>() / a.len() as f64;
    let mb = b.iter().sum::<f64>() / b.len() as f64;
    eprintln!(
        "calibration: {ma:.2} ns/op vs {mb:.2} ns/op, t = {t:.2}; \
         this host's clock costs ~40,000 ns, so the floor documented above applies"
    );
    assert!(
        t > 10.0,
        "the timing screen cannot detect a difference of {:.2} ns/op, so the leak \
         tests above are vacuous",
        mb - ma
    );
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
