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
//! where it runs: any local `cargo test --release`, and CI's advisory job below.
//!
//! In a debug build these tests would be measuring the absence of the optimizer,
//! not the constant-time behaviour of the code — so here they compile to nothing
//! (`#![cfg]` on the whole file, which also keeps the helpers from becoming dead
//! code that `clippy -D warnings` would reject).
#![cfg(not(debug_assertions))]
//!
//! Two measurements explain why the two leak *screens* here are advisory in CI,
//! while the calibration test is gated: the assertion is `t < 10`, and a hosted VM
//! produces systematic bias between two classes whose work is identical --
//!
//! ```text
//! CI release job, no possible cause:  encrypt t = 10.96  (resolution 5.72 ns/op)
//! CI debug job,   no possible cause:  decrypt t = 11.89  (resolution 60.55 ns/op)
//! a real order artefact, this harness:                 t = 35.6
//! ```
//!
//! so 10 sits inside the noise and only 3x below the t = 35.6 order artefact above.
//! There is no threshold there that is both sensitive and stable, so CI runs the
//! two leak screens in a separate job that is allowed to fail (visible in the
//! checks list, but it does not gate the build); the calibration test alone is
//! blocking, in the `timing-instrument` job. The strict run of all three is
//! `./verify.sh` on a quiet machine — the timing screen is its stage 3c, run by
//! the default invocation as well as `--deep`/`--all` — where they report
//! `t < 0.4`. The threshold itself is unchanged: the same test must still pass on
//! hardware that can support the measurement. The three loops in this file are
//! serialised against each other (`TIMING_LOCK` below), because libtest runs them in
//! parallel by default and that CPU contention would land in the numbers the tests
//! attribute to the code.

use xchacha20_blake3_siv::{decrypt, encrypt, TAG_LEN};

/// Serialises the three measurement loops in this file.
///
/// libtest runs tests in parallel by default, and the CI job (`cargo test --release
/// --test timing`) does not pass `--test-threads=1`: without this guard the three
/// microsecond-scale loops share cores and caches, inflating the per-class variance and
/// moving `t` for reasons the header's noise discussion does not cover. A poisoned lock
/// is ignored deliberately — one failing measurement must not turn the others into
/// panics, since each test's own assertion decides.
static TIMING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn timing_guard() -> std::sync::MutexGuard<'static, ()> {
    TIMING_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Statistical timing screen (dudect-style) ─────────────────────────
//
// dudect's method is a Welch t-test between two sets of timings taken while
// feeding the implementation two classes of input differing only in something
// secret. `dudect-bencher` is unavailable here, so the machinery is implemented
// directly — and one hard fact about this host has to be stated up front,
// because it bounds what these tests can conclude:
//
//   **`Instant::now()` costs ~35 ns here** (re-measured; an earlier revision of
//   this file said ~40,000 ns, which was wrong by three orders of magnitude and
//   made the screen look far weaker than it is). `_rdtsc` would add ~7 ns on top of
//   that and is not used. The tests print the resolution they achieve: a few to a
//   few tens of ns/op (the tag test's doc records the measured range, ~8-57 ns/op,
//   and this file's own last release run at 24 ns/op for that test; ~168 ns/op under
//   `ultra`). A `ct_eq` -> `==` regression of a few tens of ns therefore sits *at*
//   the floor rather than comfortably inside it -- a figure this paragraph used to
//   put at ~0.16 us/op, which contradicted the tag test's own measurements by ~7x.
//
// So a naive "time one operation" sample is >90% clock overhead, and an earlier
// version of these tests was **vacuous**: it passed with t < 1.5 not because
// nothing leaked but because it could not see anything. The calibration test
// below is what caught that, which is exactly why it exists.
//
// The measurement is therefore **batched**: each sample times `OPS_PER_SAMPLE`
// operations and divides, so the clock is amortised. That removes the overhead
// as a *bias* but cannot manufacture resolution the clock does not have — the
// detectable effect is still bounded by the jitter of the clock across the
// sample count. The tests report that floor and are explicit that they are a
// screen, not evidence.
//
// **Where the real constant-time evidence is:**
//   1. source analysis — every branch statement in non-test code was classified
//      and is enumerated in `tests/variable_latency.rs`, whose table fails when
//      any count changes so each one is re-audited: they depend on lengths,
//      pointer alignment, CPU features, an enum variant, or the final
//      authentication decision. None depends on the *content* of a key, nonce,
//      AAD or message. (This comment used to carry a hand-copied count -- "all
//      17" -- which had drifted from the enforced table; the number now lives in
//      exactly one place, and that place fails the build when it stops being
//      true.)
//   2. disassembly — `subtle::ConstantTimeEq` over the 65-byte tag compiles to an
//      unrolled branchless compare (checked for the 32-byte case in the previous
//      revision of this crate; the 65-byte form uses the same generic code);
//   3. the leaked quantity is bounded in principle: the only secret-dependent
//      branch is the final accept/reject, and every secret is wiped before it.
//
// These tests are a screen for gross regressions — e.g. someone replacing
// `ct_eq` with `==`, whose early exit is a difference of *tens* of ns on a
// 65-byte tag, which is the same order as this screen's resolution (the tag test
// below says so and prints the figure): the effect sits *at* the floor rather
// than comfortably inside it. An earlier revision of this comment claimed
// "hundreds of ns ... visible even here", which the tag test's own doc contradicts.

/// Operations per timed sample: enough that the clock's own cost is a small
/// fraction of a sample, which at tens of nanoseconds per call is already true.
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
        // Both classes were perfectly constant. If their means differ, that is the
        // *strongest* possible signal (the t of infinite samples would be unbounded),
        // not "no difference": an earlier version returned 0.0 here, so a leak visible
        // without any within-class jitter landed on the passing side of `t < 10`. Equal
        // constant means really are no difference and stay 0.
        if ma == mb {
            0.0
        } else {
            f64::INFINITY
        }
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
/// that, and CI reported t = 35.6 for two inputs whose work cannot differ. That is
/// a systematic one-sided drift — bias, not a resolution question — and it is the
/// signature of an order artefact rather than a leak. Randomising the order makes
/// the artefact cancel.
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
/// # Why the message is empty
///
/// [`decrypt`] derives the decryption key from the **received tag**
/// (`derive_enc(&enc_seed, tag, …)`), so with a non-empty ciphertext the
/// recovered plaintext — and therefore the tag it is recomputed against —
/// differs between the two classes. Both classes are then mixtures over the
/// first-mismatch position of *that* recomputed tag, a position unrelated to
/// the flipped byte, and a byte-at-a-time comparison has no contrast to show:
/// an audit planted one in both decrypt gates and this screen passed 3/3. With
/// an **empty** ciphertext the recovered plaintext is empty whatever the
/// received tag is, so the recomputed tag is one fixed value; flipping byte 0
/// in one class and byte `TAG_LEN - 1` in the other makes the comparison itself
/// see a first mismatch at 0 versus at 64. The derivation still runs on both
/// tags and does identical work for both (a keyed BLAKE3 XOF over a
/// fixed-length input, then a zero-length keystream), so the comparison is the
/// only place the classes differ.
///
/// Sensitivity, in the terms the test prints. A plain `==` on a 65-byte tag exits
/// after the bytes that match, so the difference between a first-byte and a
/// last-byte mismatch is tens of nanoseconds here; the resolution the screen
/// achieves is the same order — measured between ~8 and ~57 ns/op depending on host
/// and load (the test prints the current value; this file's own last release run:
/// 24 ns/op for this test), and ~4.6x coarser under `ultra` (168 vs 36 ns/op in an
/// audit's side-by-side), which is the configuration where the screen is least
/// sensitive. A tens-of-ns effect is therefore *at* the floor, not
/// comfortably inside it: the screen catches gross regressions (an early exit
/// skipping hundreds of nanoseconds, or a per-byte difference), while the mechanical
/// evidence for the comparison itself is ctgrind.
#[test]
fn timing_tag_comparison_does_not_leak_position() {
    let _guard = timing_guard();
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    // Empty, so the recovered plaintext — and with it the recomputed tag — is
    // the same for both classes, and the comparison's first mismatch is exactly
    // the flipped byte. See the doc above: a non-empty message makes the two
    // classes mixtures over an unrelated mismatch position and this screen
    // cannot see the leak it names.
    let (ct, tag) = encrypt(&key, &nonce, b"aad", b"").unwrap();
    assert!(ct.is_empty());

    // Class A differs in the first tag byte; class B in the last.
    let mut tag_first = tag;
    tag_first[0] ^= 0xFF;
    let mut tag_last = tag;
    tag_last[TAG_LEN - 1] ^= 0xFF;

    // Both are forgeries of a fixed recomputed tag, so the gate rejects both and
    // the one permitted data-dependent branch (accept/reject) takes the same
    // direction in both classes. Asserted once outside the timed loops, where
    // the values are ordinary.
    assert!(decrypt(&key, &nonce, b"aad", &ct, &tag_first).is_err());
    assert!(decrypt(&key, &nonce, b"aad", &ct, &tag_last).is_err());

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
    let _guard = timing_guard();
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

    // And the same decrypt under two different keys. Both classes reject (the tag
    // passed is not the one either ciphertext was made with), so this measures
    // reject-vs-reject across key *contents*, which is the quantity this screen is
    // for: the earlier comment here called it "valid vs invalid", which it is not —
    // neither class is accepted, and an audit noticed the mismatch.
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
    let _guard = timing_guard();
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
         the resolution printed above is this host's floor, not the clock's"
    );
    assert!(
        t > 10.0,
        "the timing screen cannot detect a difference of {:.2} ns/op, so the leak \
         tests above are vacuous",
        mb - ma
    );
}
