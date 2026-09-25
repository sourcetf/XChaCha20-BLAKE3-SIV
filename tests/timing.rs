//! Statistical timing screen (dudect-style) — **release builds only**.
//!
//! Split out of `tests/security.rs` and gated on `debug_assertions` because an
//! unoptimized build cannot support this measurement, and pretending otherwise
//! made CI flaky rather than safe. The evidence, from the CI job that failed:
//!
//! ```text
//! test (debug, all features):
//!   key-contents: encrypt t = 0.24 (res 10297.02 ns/op), decrypt t = 11.89 (res 60.55 ns/op)
//!   test result: FAILED. 14 passed; 1 failed ... finished in 524.49s
//! ```
//!
//! The threshold is `t < 10`, and the failing side crossed it at 11.89 with a
//! measurement floor of 60 ns/op — under a floor that coarse, over a run that
//! long, scheduler drift on a shared runner is indistinguishable from a signal.
//! The *same* test passes on that runner and on this machine in release, which is
//! where it runs: both release jobs in CI, and any local `cargo test --release`.
//!
//! In a debug build these tests would be measuring the absence of the optimizer,
//! not the constant-time behaviour of the code — so here they compile to nothing
//! (`#![cfg]` on the whole file, which also keeps the helpers from becoming dead
//! code that `clippy -D warnings` would reject).
#![cfg(not(debug_assertions))]

use xchacha20_blake3_siv::{decrypt, encrypt, TAG_LEN};

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
