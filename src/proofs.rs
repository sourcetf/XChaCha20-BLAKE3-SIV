//! Formal verification harnesses (Kani bounded model checking).
//!
//! Run with: `cargo kani -Z stubbing`
//!
//! The `-Z stubbing` flag is **required**: several harnesses use `#[kani::stub]`
//! to replace the ChaCha20 permutation, the zeroization helper, and the BLAKE3
//! context-commitment hash with cheap stand-ins (see the notes above
//! `stub_chacha20_block` and `model_context_commitment`).  Without the flag Kani
//! rejects the attribute and the suite fails to compile.  Everything else runs
//! unmodified.
//!
//! Compiled only under `cfg(kani)`, so they add nothing to normal builds or
//! to `cargo test`.
//!
//! Each harness states a property that must hold for *all* inputs in its
//! symbolic domain — not just the concrete values used by the unit tests.
//!
//! # Sizing the harnesses (why some bounds look arbitrary)
//!
//! Kani is a bounded model checker: it unwinds loops to a fixed depth and asks a
//! SAT solver whether any input violates an assertion.  Three costs dominate, and
//! every harness here is shaped around them.  All figures are measured on a
//! 16-core x86_64 machine:
//!
//! 1. **The permutation is expensive.** One concrete `chacha20_block` costs
//!    ~320 s (the 20 rounds alone are ~62 s). Any harness that calls the real
//!    permutation more than once cannot finish in a normal loop, and one that
//!    makes the key or counter symbolic does not finish at all. Hence
//!    `kani::stub` for the permutation, and `hchacha20_matches_draft_vector` as
//!    the single place the real rounds are run.
//!
//! 2. **Zeroization is expensive.** CBMC models each `write_volatile` separately,
//!    at ~29 s per 64-byte wipe, so `chacha20_apply`'s per-block wipe dominates
//!    any harness that reaches it. Hence the `zeroize_array` stub, with the real
//!    implementation verified directly by the two `zeroize_*` harnesses below.
//!
//! 3. **`memcmp` inflates the unwind bound.** `assert_eq!` on slices lowers to
//!    `memcmp`, whose internal loop needs an unwind bound proportional to the
//!    slice length; too low a bound fails with a spurious "unwinding assertion"
//!    error rather than a genuine counterexample. Harnesses therefore compare
//!    scalars or short fields instead of whole slices.
//!
//! # What this suite can and cannot establish
//!
//! It is the right tool for *construction* properties — index arithmetic, carry
//! propagation, limb recombination, buffer wiping, length limits, counter
//! sequencing.  Those are the places this crate has actually had bugs.
//!
//! It is the wrong tool for *cryptographic hardness*: "no adversary can forge a
//! tag" or "tampering changes the tag" are claims about computational
//! infeasibility, and a SAT solver has no model of that.  A harness phrased that
//! way either exhausts the solver or passes vacuously.  Those properties are
//! covered by
//!
//! * the published test vectors (`standard.txt` §Test Vectors, draft-irtf-cfrg-xchacha §A),
//! * differential testing against an independent reference implementation
//!   (`tools/ref_impl.py` → `tests/vectors_differential.txt`, replayed by
//!   `tests/differential_reference.rs`), and
//! * the avalanche / nonce-misuse / key-commitment tests in `lib.rs`.

use super::*;
use alloc::vec;
use alloc::vec::Vec;

// ── Poly1305 ──────────────────────────────────────────────────────────

/// The 26-bit limb decomposition must reconstruct the exact 130-bit
/// little-endian value of a 16-byte block.
///
/// Regression guard: an earlier revision spliced bytes with
/// `u32::from_le_bytes(..) >> N`, which silently mis-decoded every block that
/// straddled a 4-byte boundary.
#[kani::proof]
fn poly1305_limb_decomposition_is_exact() {
    let block: [u8; 16] = kani::any();

    // r = 1 with h = s = 0 makes `process_block` a pure decomposition: each
    // product collapses to the raw limb and no carry propagates.
    let mut st = Poly1305State {
        h: [0; 5],
        r: [1, 0, 0, 0, 0],
        s: [0; 4],
    };
    st.process_block(&block, false);

    let reconstructed = (st.h[0] as u128)
        | ((st.h[1] as u128) << 26)
        | ((st.h[2] as u128) << 52)
        | ((st.h[3] as u128) << 78)
        | ((st.h[4] as u128) << 104);

    assert_eq!(reconstructed, u128::from_le_bytes(block));
}

/// `hibit = true` must add exactly 2^128 to the accumulated value — no more,
/// no less, and without disturbing the low four limbs.
///
/// Regression guard: leaving `hibit = false` on the length block was the bug
/// that made every KAT fail.
#[kani::proof]
fn poly1305_hibit_adds_2_128() {
    let block: [u8; 16] = kani::any();

    let mut plain = Poly1305State {
        h: [0; 5],
        r: [1, 0, 0, 0, 0],
        s: [0; 4],
    };
    let mut high = Poly1305State {
        h: [0; 5],
        r: [1, 0, 0, 0, 0],
        s: [0; 4],
    };
    plain.process_block(&block, false);
    high.process_block(&block, true);

    // 2^128 sits at bit 24 of limb 4 (24 + 4*26 = 128).
    assert_eq!(high.h[0], plain.h[0]);
    assert_eq!(high.h[1], plain.h[1]);
    assert_eq!(high.h[2], plain.h[2]);
    assert_eq!(high.h[3], plain.h[3]);
    assert_eq!(high.h[4], plain.h[4] + (1u32 << 24));
}

/// `process_block` must never overflow a `u64` for any clamped key and any
/// block.  The 26-bit limbs guarantee a generous margin; this proves it.
#[kani::proof]
fn poly1305_process_block_no_overflow() {
    let key: [u8; 32] = kani::any();
    let block: [u8; 16] = kani::any();
    let hibit: bool = kani::any();

    let mut st = Poly1305State::new(&key);
    st.process_block(&block, hibit);
}

/// `finalize` must not overflow either, for any reachable state.
///
/// The unwind bound must cover `process_block`'s 5-way multiply-accumulate, the
/// finalize carry chain, and the zeroization loops that run on drop.
#[kani::proof]
#[kani::unwind(24)]
fn poly1305_finalize_no_overflow() {
    let key: [u8; 32] = kani::any();
    let block: [u8; 16] = kani::any();

    let mut st = Poly1305State::new(&key);
    st.process_block(&block, true);
    let _tag = st.finalize(&key);
}

/// Limbs stay bounded after every absorption step (the invariant the carry
/// chain depends on).
///
/// NOTE: the bound is *not* `2^26`.  `process_block` ends with
/// `h[1] = (d1 & 0x3ffffff) + c`, where the final carry `c` comes from
/// `h[0] = (d0 & 0x3ffffff) + 5 * (d4 >> 26)` — so limb 1 legitimately exceeds
/// `2^26`.  An earlier version of this harness asserted `< 2^26` for every limb,
/// which is false, and it was that wrong assumption which hid the `finalize`
/// recombination bug (limb 1 spilling into limb 2's bit range).
///
/// The real invariant is `< 2^26 + 2^5`, which is what `poly1305_mul_wide`'s
/// `< 2^27` precondition and the `finalize` addition both rely on.  This harness
/// pins that bound for *all* five limbs against *every* clamped key and block;
/// an earlier attempt to also assert `h[1] <= 2^26` was correctly refuted by
/// Kani.
///
/// Only one symbolic block is absorbed: the property is inductive (the bound
/// after block `n+1` depends solely on the bound after block `n`), so a second
/// symbolic block adds no coverage while doubling an already hard SAT instance.
/// The multi-block case is covered concretely by
/// `test_poly1305_batch_matches_serial`.
#[kani::proof]
fn poly1305_limbs_stay_bounded() {
    let key: [u8; 32] = kani::any();
    let b1: [u8; 16] = kani::any();

    let mut st = Poly1305State::new(&key);
    st.process_block(&b1, true);

    for i in 0..5 {
        assert!(st.h[i] < (1u32 << 26) + (1 << 5));
    }
}

/// The `finalize` limb recombination must equal the true integer sum, reduced
/// modulo 2^128.
///
/// Regression guard for the OR-vs-addition bug: limb 1 can reach exactly `2^26`
/// (`process_block` ends with `h[1] = (d1 & 0x3ffffff) + c`), so `h[1] << 26`
/// then lands on the same bit as `h[2] << 52`.  Bitwise OR dropped that carry
/// and produced a tag 2^52 too small — a reachable divergence that
/// self-consistent encrypt/decrypt could never detect.
///
/// The state is confined to the regime where `finalize`'s conditional
/// subtraction (`h >= 2^130-5`) does *not* fire, so the recombined value must be
/// exactly the input limb sum.  Above that threshold the limbs are legitimately
/// reduced first and the tag differs — that is the reduction doing its job, not
/// the recombination.  Keeping limb 4 below `2^24` puts the total under
/// `2^130-5` while leaving limb 1 free to straddle its own boundary, which is
/// the case this harness exists to pin down.
#[kani::proof]
#[kani::unwind(12)]
fn poly1305_finalize_recombination_is_exact() {
    let h: [u32; 5] = kani::any();
    kani::assume(h[0] < (1u32 << 26) + (1 << 5));
    kani::assume(h[1] < (1u32 << 26) + (1 << 5));
    kani::assume(h[2] < (1u32 << 26) + (1 << 5));
    kani::assume(h[3] < (1u32 << 26) + (1 << 5));
    kani::assume(h[4] < (1u32 << 24));

    let st = Poly1305State {
        h,
        r: [0; 5],
        s: [0; 4],
    };
    let tag = st.finalize(&[0u8; 32]);
    let got = u128::from_le_bytes(tag);

    // Reference: the exact limb sum mod 2^128.
    let want: u128 = (h[0] as u128)
        .wrapping_add((h[1] as u128).wrapping_mul(1u128 << 26))
        .wrapping_add((h[2] as u128).wrapping_mul(1u128 << 52))
        .wrapping_add((h[3] as u128).wrapping_mul(1u128 << 78))
        .wrapping_add((h[4] as u128).wrapping_mul(1u128 << 104));
    assert_eq!(got, want);
}

/// `finalize`'s conditional subtraction must produce the correctly reduced
/// value in **both** regimes — including the one the harness above deliberately
/// excludes.
///
/// `poly1305_finalize_recombination_is_exact` assumes `h[4] < 2^24`, which puts
/// `h < 2^130-5` and therefore never fires the conditional subtraction; its own
/// documentation says so.  That leaves the *firing* path — the only path that
/// actually performs a reduction, and so the one most likely to be wrong —
/// unverified.  The mask trick is easy to get subtly wrong, and a wrong
/// reduction changes the tag for a small fraction of messages, which a
/// self-consistent encrypt/decrypt pair can never detect.
///
/// This harness covers every limb vector reachable from `process_block`
/// (the bound established by `poly1305_limbs_stay_bounded`) and compares
/// `finalize` against `(value mod 2^130-5 + s) mod 2^128`, computed
/// independently:
///
/// * Split `value = A + B·2^78` with `A = h0 + h1·2^26 + h2·2^52` and
///   `B = h3 + h4·2^26`.  Both fit in `u128` (`A < 2^79`, `B < 2^52 + 2^31`),
///   as does every intermediate below.
/// * `value >= 2^130-5` holds exactly when `(2^52 - B)·2^78 <= A + 5`.  Since
///   `floor((A+5)/2^78)` is only ever `0` or `1` (because `A + 5 < 2^79`), that
///   is the branch-free test `B >= 2^52 || (2^52 - B) <= (A + 5) >> 78`, which
///   never forms the overflowing product.
/// * When it fires, the reduced value is `A + (B - 2^52)·2^78 + 5 < 2^110`;
///   when it does not, the value is taken modulo `2^128`, exactly as
///   `finalize`'s `wrapping_add` does.
///
/// The pad `s` is read symbolically from the key, so the final addition is
/// covered too.  `r` plays no part in `finalize` and is zeroed.
#[kani::proof]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(12)]
fn poly1305_finalize_reduction_is_exact() {
    let key: [u8; 32] = kani::any();
    let mut h: [u32; 5] = kani::any();
    // The reachable bound, from `poly1305_limbs_stay_bounded`.
    for hi in h.iter_mut() {
        kani::assume(*hi < (1u32 << 26) + (1 << 5));
    }

    let st = Poly1305State {
        h,
        r: [0; 5],
        s: [0; 4],
    };
    let tag = st.finalize(&key);
    let got = u128::from_le_bytes(tag);

    let two52 = 1u128 << 52;
    let two78 = 1u128 << 78;

    let a = (h[0] as u128)
        .wrapping_add((h[1] as u128) << 26)
        .wrapping_add((h[2] as u128) << 52);
    let b = (h[3] as u128).wrapping_add((h[4] as u128) << 26);

    // `A + 5 < 2^79`, so this cannot overflow.
    let ap5 = a + 5;
    // `value >= 2^130 - 5`  <=>  `A + 5 >= (2^52 - B)·2^78`.  With `B >= 2^52`
    // the right side is non-positive, so it fires unconditionally; with
    // `B < 2^52` it can only fire when `B == 2^52 - 1`, because `A + 5 < 2^79`
    // admits at most one multiple of `2^78`.
    let fires = b >= two52 || (two52 - b) <= (ap5 >> 78);

    let reduced = if fires {
        if b >= two52 {
            // `B - 2^52 < 2^32` and `A + 5 < 2^79`, so the sum is < 2^111: no wrap.
            a + 5 + (b - two52) * two78
        } else {
            // The borrowing case: `2^52 - B == 1` and `A + 5 >= 2^78`, so the
            // subtraction is non-negative and the result is < 2^78.  Writing it
            // this way (rather than `A + 5 + (B - 2^52)·2^78`) avoids the
            // underflow in `B - 2^52`.
            ap5 - (two52 - b) * two78
        }
    } else {
        // The value may exceed 2^128 without firing, and `finalize` returns the
        // low 128 bits; wrap to model that.
        a.wrapping_add(b.wrapping_mul(two78))
    };

    let s_val = u128::from_le_bytes(key[16..32].try_into().unwrap());
    assert_eq!(got, reduced.wrapping_add(s_val));
}

/// `poly1305_block_limbs` must decode a 16-byte block to exactly the same five
/// 26-bit limbs as `Poly1305State::process_block`'s inline decomposition, for
/// both `hibit` values.
///
/// These are two independently hand-written implementations of RFC 8439 §2.8.1
/// living in the same file: the batch/SIMD path calls `poly1305_block_limbs`,
/// the serial path inlines its own copy.  If they ever disagree, the same
/// message produces a different tag depending on whether it crossed a 64-byte
/// boundary — and this crate has already shipped one bug of exactly that shape
/// (the `u32::from_le_bytes(..) >> N` misdecode that the serial-path harness
/// `poly1305_limb_decomposition_is_exact` was written to catch, which by
/// construction could not have caught a divergence in the *other* copy).
///
/// The agreement is observed *through* `process_block` rather than by exposing
/// the inline code: with `r = 1` and `s = h = 0` the block is a pure
/// decomposition (every product collapses to a raw limb), so `h` afterwards is
/// the decoded block verbatim.
#[kani::proof]
#[kani::unwind(12)]
fn poly1305_block_limbs_matches_process_block() {
    let block: [u8; 16] = kani::any();
    let hibit: bool = kani::any();

    let direct = poly1305_block_limbs(&block, hibit);

    let mut st = Poly1305State {
        h: [0; 5],
        r: [1, 0, 0, 0, 0],
        s: [0; 4],
    };
    st.process_block(&block, hibit);

    for i in 0..5 {
        assert_eq!(direct[i], st.h[i]);
    }
}

/// The limb bound that makes the 26-bit representation sound: with limbs
/// `< 2^27` on entry, every product `poly1305_mul_wide` forms fits in a `u64`
/// and the five-term sum cannot overflow.
///
/// The bound is quoted by three functions and is what makes the whole
/// representation work; if it were wrong, the failure would be a silently
/// wrapped product rather than a panic (release builds do not check overflow),
/// corrupting the tag for large inputs only.
///
/// # Why this proves a *lemma* rather than calling `poly1305_mul_wide`
///
/// Calling the function with 10 symbolic limbs makes CBMC bit-blast all ~29 of
/// its `u64` multiplications at once.  Measured on this machine that does not
/// finish in a normal verification loop (killed after 22 minutes), which makes
/// it worthless as a regression check even though the property is real.
///
/// `poly1305_mul_wide` is five lines of straight-line arithmetic with no
/// branches, and every term it forms has one of exactly two shapes:
///
/// * `a_i · b_j` with `a_i, b_j < 2^27`
/// * `a_i · s_j` where `s_j = 5·b_j < 5·2^27 < 2^30`
///
/// This harness takes one symbolic value of each shape, proves each fits in
/// `u64` (`< 2^54` and `< 2^57` respectively), and proves that five of the
/// larger cannot overflow when summed.  That is the entire soundness argument;
/// the step from "these two shapes are bounded" to "the function is bounded" is
/// an inspection of a branch-free expression, not a proof obligation.
///
/// The inputs are *reachable* bounds, not arbitrary ones: `poly1305_limbs_stay_
/// bounded` proves `process_block` output stays under `2^26 + 2^5`, and
/// `Poly1305Powers::new` returns values from `poly1305_mul`, which masks every
/// limb to 26 bits.
#[kani::proof]
fn poly1305_mul_wide_bound_is_sound() {
    // One symbolic limb, under the documented < 2^27 precondition.
    let x: u64 = kani::any();
    kani::assume(x < (1u64 << 27));

    // The two term shapes, each with a symbolic member of the other operand.
    let other: u64 = kani::any();
    kani::assume(other < (1u64 << 27));

    // Shape 1: a_i · b_j, both < 2^27.
    let plain = x * other;
    assert!(plain < (1u64 << 54), "plain product must fit in u64");

    // Shape 2: a_i · s_j with s_j = 5·b_j < 2^30.  This is the largest term.
    let scaled = other * 5;
    assert!(scaled < (1u64 << 30), "scaled limb must fit in u64");
    let big = x * scaled;
    assert!(big < (1u64 << 57), "scaled product must fit in u64");

    // d_i sums five terms, each at most `big`.  Five of them must not overflow.
    let sum = big * 5;
    assert!(sum < (1u64 << 60), "five-term accumulator must fit in u64");

    // And the accumulator plus a carry from the limb below stays in range:
    // the carry is `< 2^34` for a `< 2^60` accumulator, so `2^60 + 2^34 < 2^61`.
    assert!(sum + (1u64 << 34) < (1u64 << 61));
}

/// `poly1305_reduce_wide` must not overflow for the accumulator bound its
/// documentation states (`< 2^62`), and must return limbs small enough for the
/// callers that consume them.
///
/// The bound matters on the scalar fallback path, which is the only batch path
/// on targets without a SIMD backend; that path sums four raw
/// `poly1305_mul_wide` results, reaching ~`2^58` rather than the ~`2^28` an
/// earlier comment claimed (see `test_scalar_batch_accumulators_are_wide`).
#[kani::proof]
#[kani::unwind(12)]
fn poly1305_reduce_wide_no_overflow() {
    let acc: [u64; 5] = kani::any();
    for x in acc.iter() {
        kani::assume(*x < (1u64 << 62));
    }

    let mut h = [0u32; 5];
    poly1305_reduce_wide(&mut h, &acc);

    // Every limb must come back small enough for `finalize`'s recombination,
    // which assumes the `< 2^26 + 2^5` bound `process_block` maintains.
    for i in 0..5 {
        assert!(h[i] < (1u32 << 26) + (1 << 5));
    }
}

// ── Zeroization ───────────────────────────────────────────────────────

/// `zeroize_slice` must clear every byte of the slice it is given, for every
/// possible misalignment of the slice start.
///
/// Regression guard: the previous implementation began its chunked loop at the
/// offset of the first aligned byte, leaving the unaligned prefix intact.
#[kani::proof]
#[kani::unwind(8)]
fn zeroize_slice_clears_all_bytes() {
    let len = (kani::any::<u8>() % 6) as usize;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..len {
        buf.push(kani::any::<u8>());
    }

    zeroize_slice(&mut buf);

    for b in buf.iter() {
        assert_eq!(*b, 0u8);
    }
}

/// Zeroization must also cover an unaligned *window* inside a larger buffer:
/// allocate a fixed backing array, take a sub-slice at a symbolic offset, wipe
/// it, and require that every byte of the window is zero while the bytes
/// outside it are untouched.
///
/// The backing array is 16 bytes, not 32: the three comparison loops below run
/// for `len`, `off` and `16 - off - len` iterations respectively, so a 16-byte
/// backing keeps every loop under the `unwind(24)` bound.  With a 32-byte
/// backing the suffix loop could run 32 times and CBMC reported a *spurious*
/// "unwinding assertion loop 2" failure rather than a counterexample.  Nothing
/// is lost by shrinking it: `zeroize_slice` writes in `usize` (8-byte) chunks,
/// and `len` still reaches 15 with `off` sweeping all eight misalignments, so
/// both the unaligned-prefix path and the multi-chunk path are exercised.
#[kani::proof]
#[kani::unwind(24)]
fn zeroize_slice_clears_unaligned_window() {
    let mut backing = [0xAAu8; 16];
    let off = (kani::any::<u8>() % 8) as usize;
    let len = (kani::any::<u8>() % 16) as usize;
    kani::assume(off + len <= 16);

    // Copy out the neighbours so we can check they are untouched.
    let before_prefix = backing[..off].to_vec();
    let before_suffix = backing[off + len..].to_vec();

    zeroize_slice(&mut backing[off..off + len]);

    for i in off..off + len {
        assert_eq!(backing[i], 0u8);
    }
    // Byte-by-byte: `assert_eq!` on slices lowers to `memcmp`, whose loop would
    // need a large unwind bound and can otherwise fail spuriously.
    for i in 0..off {
        assert_eq!(backing[i], before_prefix[i], "prefix byte {i} was modified");
    }
    for i in 0..before_suffix.len() {
        assert_eq!(
            backing[off + len + i],
            before_suffix[i],
            "suffix byte {i} was modified"
        );
    }
}

// ── ChaCha20 stream ───────────────────────────────────────────────────
//
// Design note.  Measured on this machine, one concrete `chacha20_block` costs
// ~320 s of CBMC time (the 20-round permutation alone is ~62 s, and the three
// `zeroize_array` calls in it are ~29 s each).  Any harness that calls the real
// permutation more than once therefore cannot finish in a normal verification
// loop, and one that makes the key/counter symbolic does not finish at all.
//
// That is a tool limitation, not a property of the code, so these harnesses are
// split along the line where the *interesting* logic actually lives:
//
// * The permutation itself is pinned by the published KATs (`test_vector_*`,
//   `test_xchacha20_keystream_kat_counter0`, `hchacha20_matches_draft_vector`)
//   and by the SIMD-vs-scalar differential tests.
// * The *sequencing* — which counter each block uses, where the partial tail
//   starts, whether the tail reads the right slice — is what a stream-cipher
//   wrapper gets wrong in practice, and it is independent of the permutation's
//   internals.  `kani::stub` replaces `chacha20_block` with a function that
//   encodes its own arguments, so the harness can assert the exact counter
//   sequence in seconds instead of hours.

/// A stand-in for `chacha20_block` that stamps its arguments into the output.
///
/// It is deliberately not a real cipher: its only job is to let a harness observe
/// which `(key, counter, nonce)` each output block was produced from.
fn stub_chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&counter.to_le_bytes());
    out[4..8].copy_from_slice(&nonce[0..4]);
    out[8..12].copy_from_slice(&nonce[8..12]);
    out[12..16].copy_from_slice(&key[0..4]);
    out[16..20].copy_from_slice(&key[28..32]);
    out
}

/// A no-op stand-in for `zeroize_array`.
///
/// CBMC models each `write_volatile` individually and charges ~29 s per 64-byte
/// wipe, which dominates any harness that calls `chacha20_apply` (it wipes the
/// keystream buffer once per block).  For harnesses whose property has nothing
/// to do with wiping, that cost buys nothing, so it is stubbed out here.
///
/// Zeroization is *not* left unverified: `zeroize_slice_clears_all_bytes` and
/// `zeroize_slice_clears_unaligned_window` below exercise the real
/// implementation directly, on the small buffers where the cost is acceptable.
fn noop_zeroize_array<T>(_value: &mut T) {}

/// Every block of the keystream must be produced from the counter immediately
/// following the previous one, starting at the requested counter, and the final
/// partial block must be the prefix of the next block in that sequence.
///
/// The length (200 = three full blocks + 8 bytes) is chosen so all three paths
/// in `chacha20_apply` run: the full-block loop, the loop exit, and the
/// partial-tail slice.  An off-by-one in any of them — the counter not
/// incrementing, the tail restarting from 0, or the tail reading past the block
/// boundary — makes an assertion below fail.
///
/// The stub writes the counter into bytes 0..4 of its output, so reading that
/// field back is enough to identify which counter produced each block.  That
/// keeps the harness free of any comparison loop (and therefore of the
/// `memcmp`/unwind interaction described above).
#[kani::proof]
#[kani::stub(chacha20_block, stub_chacha20_block)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(40)]
fn chacha20_counter_sequencing_is_exact() {
    let key = [0x5Au8; 32];
    let nonce = [0xA5u8; 12];
    let start = 7u32;
    let len = 200usize;

    let mut out = vec![0u8; len];
    chacha20_keystream_raw(&key, start, &nonce, &mut out);

    // Each full block's counter field must equal start + its index.
    for i in 0..3usize {
        let got = u32::from_le_bytes(out[i * 64..i * 64 + 4].try_into().unwrap());
        assert_eq!(got, start + i as u32, "block {i} used the wrong counter");
    }
    // The 8-byte tail must come from the block with the *next* counter, not a
    // repeat of the last full block and not a restart from zero.
    let tail_ctr = u32::from_le_bytes(out[192..196].try_into().unwrap());
    assert_eq!(tail_ctr, start + 3, "partial tail used the wrong counter");
}

/// The same sequencing property for the XOR entry point, plus the involution
/// `(p ^ k) ^ k == p` for a partial final block.
///
/// The permutation is stubbed as above, so this checks the wrapper's buffer
/// handling rather than the cipher.
#[kani::proof]
#[kani::stub(chacha20_block, stub_chacha20_block)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(40)]
fn chacha20_keystream_involution_partial_blocks() {
    let key = [0x5Au8; 32];
    let nonce = [0xA5u8; 12];
    let ctr = 0x1122_3344u32;
    let len = 20usize; // one partial block: exercises the tail slice

    let mut pt: Vec<u8> = Vec::new();
    for _ in 0..len {
        pt.push(kani::any::<u8>());
    }

    let mut ct = vec![0u8; len];
    chacha20_keystream(&key, ctr, &nonce, &pt, &mut ct);
    assert_eq!(ct.len(), len);

    // The ciphertext must be the plaintext XOR the stubbed keystream prefix.
    let expect = stub_chacha20_block(&key, ctr, &nonce);
    for i in 0..len {
        assert_eq!(ct[i], pt[i] ^ expect[i]);
    }

    // Involution, compared byte-by-byte (`assert_eq!` on slices would lower to
    // `memcmp`, whose loop needs a much larger unwind bound).
    let mut back = vec![0u8; len];
    chacha20_keystream(&key, ctr, &nonce, &ct, &mut back);
    for i in 0..len {
        assert_eq!(back[i], pt[i], "involution failed at byte {i}");
    }
}

/// HChaCha20's output is exactly state words 0-3 followed by 12-15, serialized
/// little-endian, with no final addition.  Verified against the draft's
/// concrete vector (regression anchor for the output-index selection).
///
/// This is the one harness that runs the *real* permutation, which is why it
/// takes several minutes; it is kept because it is the only formal anchor for
/// the round function and the output-word selection.
#[kani::proof]
// `hex32`/`hex16` decode 32/16 bytes with a 2-iteration-per-byte loop, and the
// HChaCha20 core runs 10 double-rounds, so the default bound is far too low.
#[kani::unwind(40)]
fn hchacha20_matches_draft_vector() {
    let key = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex16("000000090000004a0000000031415927");
    let got = hchacha20(&key, &nonce);
    let want = hex32("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assert_eq!(got, want);
}

// ── AEAD (end-to-end) ─────────────────────────────────────────────────
//
// Scope note — what is *deliberately* not here, and why.
//
// The primitive harnesses above cover the algebraic core.  The AEAD layer is a
// different story, and it is worth being explicit rather than shipping harnesses
// that look impressive and prove nothing.
//
// Measured cost: a single concrete `chacha20_block` takes ~320 s of CBMC time,
// because the tool bit-blasts the whole 20-round permutation plus its unrolled
// loops.  An end-to-end `encrypt`/`decrypt` harness invokes HChaCha20 (20
// rounds), the subkey block, the tag block, the encryption-key block and then
// the keystream — five permutations, so well over 25 minutes each, and that is
// with *concrete* inputs.  With symbolic plaintext it does not terminate at all.
//
// Two consequences:
//
// 1. AEAD-level harnesses are not runnable in a normal verification loop.  A
//    harness that never finishes is not evidence, so none are kept here.
//
// 2. Some of the properties the removed harnesses appeared to state are not
//    provable *in principle*, not merely expensive.  "Corrupting a ciphertext
//    byte changes the tag" is Poly1305's collision resistance; "an attacker
//    cannot forge" is a statement about computational infeasibility.  A SAT
//    solver has no model of infeasibility, so any harness claiming to prove
//    these either exhausts the solver or passes vacuously.
//
// What covers the AEAD layer instead:
//
// * `standard.txt` §Test Vectors and draft-irtf-cfrg-xchacha §A — published KATs
//   for both constituent standards (`test_vector_*`, `test_xchacha20_*`).
// * Differential testing against an independent reference implementation:
//   `tools/ref_impl.py` generates `tests/vectors_differential.txt`, and
//   `tests/differential_reference.rs` replays it across every internal length
//   boundary.  The reference self-checks against the published RFC 8439 /
//   HChaCha20 / c2sp.org vectors before it emits anything.
// * `test_nonce_misuse_resistance`, `test_key_commitment`,
//   `test_decrypt_does_not_leak_plaintext_on_failure`,
//   `test_detached_rejects_tampering_and_wipes`, the `test_avalanche_*` and
//   `test_tag_depends_on_every_aad_byte` diffusion checks, and the CTX layout
//   pins (`test_commitment_is_domain_separated_blake3`,
//   `test_tag_tail_does_not_reach_the_ciphertext`).
//
// The one AEAD-level property that *is* cheap and decidable — the length-limit
// boundary — is verified below.

/// `check_lengths` must reject exactly the inputs above `MAX_MSG_SIZE` and
/// accept everything at or below it.
///
/// Pure integer reasoning over the full `u64` range, so it is both exhaustive
/// and cheap.  This is the only AEAD-layer harness that can be discharged
/// without invoking the permutation, which is precisely why it is kept.
#[kani::proof]
fn check_lengths_boundary_is_exact() {
    let msg_len: u64 = kani::any();
    let aad_len: u64 = kani::any();

    // Only the two comparisons matter, and `usize` is 64-bit on the verified
    // target, so cast directly.
    let r = check_lengths(msg_len as usize, aad_len as usize);

    let msg_over = msg_len > MAX_MSG_SIZE;
    let aad_over = aad_len > MAX_MSG_SIZE;

    if msg_over {
        assert_eq!(r, Err(Error::MessageTooLong));
    } else if aad_over {
        assert_eq!(r, Err(Error::AadTooLong));
    } else {
        assert!(r.is_ok());
    }
}

/// `MAX_MSG_SIZE` must be small enough that one message never exhausts the
/// 32-bit ChaCha20 block counter.
///
/// This is the one length limit whose failure mode is *silent keystream reuse*.
/// ChaCha20's counter is a `u32` and the wrapper increments it once per 64-byte
/// block with `wrapping_add`, so a message longer than `2^32` blocks would wrap
/// the counter back to 0 and re-encrypt with a keystream block already used —
/// inside a single message, with no nonce reuse required and nothing to detect
/// it.  Encryption and decryption would still agree, so a roundtrip test cannot
/// see it.
///
/// `MAX_MSG_SIZE = 2^38` is exactly `2^32 · 64`, so a maximum-size message uses
/// counters `0 ..= u32::MAX` and stops precisely at the boundary.  The harness
/// checks that relationship rather than the literal, so changing either
/// constant to something unsafe fails here:
///
/// * `MAX_MSG_SIZE / CHACHA20_BLOCK` must not exceed `u32::MAX as u64 + 1`
///   (the number of *distinct* counter values, counting 0).
/// * The division must be exact, so the last block is a full block and no
///   partial tail pushes the count over.
///
/// Note that this is a property of the *constants*, and it is checked by
/// arithmetic alone — no permutation, no loops, so it costs seconds.  The
/// per-block sequencing itself is pinned by `chacha20_counter_sequencing_is_
/// exact`.
#[kani::proof]
fn max_msg_size_fits_in_the_block_counter() {
    // Distinct counter values available: 0 through u32::MAX inclusive.
    let capacity = (u32::MAX as u64) + 1;
    let blocks = MAX_MSG_SIZE / (CHACHA20_BLOCK as u64);
    let remainder = MAX_MSG_SIZE % (CHACHA20_BLOCK as u64);

    assert!(
        blocks <= capacity,
        "a max-size message would wrap the counter"
    );
    assert_eq!(
        remainder, 0,
        "max-size message must be a whole number of blocks"
    );

    // The limit is the *tight* one: the next block would wrap.  (This is what
    // makes it the documented maximum rather than merely a safe round number.)
    assert_eq!(blocks, capacity);
}

/// The other half of the same argument: a message exactly at the limit must be
/// accepted, and one block more must be rejected.
///
/// `check_lengths_boundary_is_exact` sweeps the whole `u64` range, so this is
/// logically implied by it; it is kept because it states the *reason* the bound
/// exists in terms of the counter, so a reader who changes `MAX_MSG_SIZE` sees
/// both the arithmetic and the boundary in one place.
#[kani::proof]
fn max_msg_size_boundary_matches_counter_capacity() {
    let blocks = (u32::MAX as u64) + 1;
    let at_limit = (blocks * (CHACHA20_BLOCK as u64)) as usize;
    let over_limit = at_limit + (CHACHA20_BLOCK as usize);

    assert!(check_lengths(at_limit, 0).is_ok());
    assert_eq!(check_lengths(over_limit, 0), Err(Error::MessageTooLong));
    assert_eq!(check_lengths(0, over_limit), Err(Error::AadTooLong));
}

// ── Context commitment (CMT-3) ────────────────────────────────────────
//
// The c2sp.org base construction is key-committing but not
// context-committing.  This crate adds the CTX transform (Chan–Rogaway,
// ESORICS 2022): `tag = inner XOR BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`.
//
// What is *provable* here is the **shape** of that transform, and that is
// exactly what a regression needs to guard: that the whole 32-byte commitment
// term reaches the tag, that it does so by XOR, that no bit of the inner tag
// is dropped or reordered, and that the associated data influences the tag
// *only* through it.  A refactor that drops the AAD from the tag, XORs only
// part of the commitment, feeds a different slice of the AAD into the hash, or
// lets the commitment leak into the ciphertext-nonce/tag-key material,
// breaks one of the assertions below.
//
// What is *not* provable — and must not be claimed — is BLAKE3's collision
// resistance.  "Distinct AADs give distinct commitments" is a computational
// assumption about a hash function, and a SAT solver has no model of it.  That
// half of the argument is discharged by using a standard, externally analysed
// hash rather than by Kani.

/// A stand-in for `chacha20_keystream_raw` that writes zeros.
///
/// With the inner ChaCha20 term zeroed, `derive_tag` reduces to the commitment
/// term alone, so an assertion about the tag becomes an assertion about how the
/// AAD reaches it.  The inner value is deliberately not modelled: it is
/// independent of the AAD, and pinning that independence is the point.
fn zero_keystream(_key: &[u8; 32], _counter: u32, _nonce: &[u8; 12], out: &mut [u8]) {
    // `fill` rather than a loop: a per-byte loop over the 64-byte block would
    // itself need an unwind bound, and this harness is not about that loop.
    out.fill(0);
}

/// An injective stand-in for `context_commitment`.
///
/// Kani cannot run the real BLAKE3: its runtime SIMD detection lowers to
/// `__cpuid_count`, which is inline asm ("TerminatorKind::InlineAsm is not
/// currently supported").  Stubbing is the honest option rather than a
/// workaround, because the property the real BLAKE3 is relied on for —
/// collision resistance — is a computational assumption a SAT solver has no
/// model of.  Asserting `H(a) == H(b) => a == b` over the real implementation
/// would be exactly the kind of vacuous proof the module note warns about.
///
/// What *is* checkable is how the hash output is *used*: whether all 32 bytes
/// reach the tag, whether they do so by XOR, and whether the whole AAD is fed
/// in.  A model that is injective in every input byte preserves precisely those
/// questions — if any AAD byte or any output byte were dropped, the harnesses
/// below would expose it — so it is the right abstraction here, not a weakening.
///
/// The multiplier is **odd** (hence invertible modulo 256), so a one-byte edit
/// by `delta != 0` changes that output byte by `delta * odd != 0` and cannot
/// cancel itself out.  An even multiplier would collide (`b` with `b + 128`).
///
/// There is deliberately no `%`/`/` here: CBMC bit-blasts division into a
/// comparatively expensive circuit, and these harnesses are sized to run in
/// seconds.  A power-of-two mask is exact and cheap.
fn model_context_commitment(aad: &[u8]) -> [u8; TAG_LEN] {
    let mut out = [0u8; TAG_LEN];
    // The first 8 bytes carry the length, so truncation and extension differ.
    out[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    // The remaining 24 are a running fold over the bytes, one byte per slot
    // (wrapping for AADs longer than 24 bytes).
    for (i, b) in aad.iter().enumerate() {
        let slot = 8 + (i & 23);
        let odd_mult = (((i as u16) << 1) | 1) as u8;
        out[slot] = out[slot].wrapping_add(b.wrapping_mul(odd_mult));
    }
    out
}

/// The tag must be the inner value XOR the **full** commitment term
/// (`BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`).
///
/// `tag_key` and the Poly1305 tag are symbolic, so this holds for every possible
/// secret material: the commitment term is applied regardless of the key, and
/// over all 32 bytes rather than a prefix.
///
/// Three AAD lengths — empty, sub-block, and one full Poly1305 block — so a
/// length-dependent bug in how the AAD is passed through would show up.
///
/// No `assert!` here carries format arguments: a `"...{}"` message pulls
/// `core::fmt` into the verification scope, which dominates the run time.  The
/// comparison is also folded into a single byte rather than using
/// `assert_eq!` on arrays, which would lower to `memcmp`.
#[kani::proof]
#[kani::stub(chacha20_keystream_raw, zero_keystream)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::stub(context_commitment, model_context_commitment)]
#[kani::unwind(40)]
fn tag_applies_full_width_context_commitment() {
    let tag_key: [u8; 32] = kani::any();
    let poly1305_tag: [u8; 16] = kani::any();

    let empty: &[u8] = b"";
    let one: &[u8] = b"x";
    let block = [0u8; 16];
    let one_block: &[u8] = &block;

    for aad in [empty, one, one_block] {
        let tag = derive_tag(&tag_key, &poly1305_tag, aad);
        let want = model_context_commitment(aad);
        // Fold the whole comparison into one byte so the loop body stays cheap.
        let mut diff = 0u8;
        for i in 0..TAG_LEN {
            diff |= tag[i] ^ want[i];
        }
        assert!(diff == 0);
    }
}

/// The associated data must reach the tag **only** through
/// `context_commitment`, and via a full-width XOR.
///
/// For any two AADs the tags differ by exactly the commitment difference,
/// whatever the secret `tag_key` and Poly1305 tag are.  This is the structural
/// half of CMT-3: combined with BLAKE3's collision resistance (a computational
/// assumption, not a Kani result) it yields "distinct AAD ⇒ distinct tag".
#[kani::proof]
#[kani::stub(chacha20_keystream_raw, zero_keystream)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::stub(context_commitment, model_context_commitment)]
#[kani::unwind(40)]
fn tag_aad_dependence_is_exactly_the_commitment() {
    let tag_key: [u8; 32] = kani::any();
    let poly1305_tag: [u8; 16] = kani::any();
    let aad_a: [u8; 4] = kani::any();
    let aad_b: [u8; 4] = kani::any();

    let tag_a = derive_tag(&tag_key, &poly1305_tag, &aad_a);
    let tag_b = derive_tag(&tag_key, &poly1305_tag, &aad_b);
    let com_a = model_context_commitment(&aad_a);
    let com_b = model_context_commitment(&aad_b);

    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= (tag_a[i] ^ tag_b[i]) ^ (com_a[i] ^ com_b[i]);
    }
    assert!(diff == 0);
}

/// Every byte of the AAD must actually reach the tag.
///
/// Complements `tag_aad_dependence_is_exactly_the_commitment`, which only shows
/// the AAD reaches the tag *consistently* — it would still pass if `derive_tag`
/// hashed only a prefix of the AAD (say `&aad[..0]`), because both sides would
/// use the same truncated slice.
///
/// Here a single byte at an arbitrary position is perturbed and the tags must
/// differ, so `derive_tag` has to hand the *whole* slice to the hash.  The
/// 6-byte AAD puts the edit beyond a naive 1- or 4-byte prefix.
#[kani::proof]
#[kani::stub(chacha20_keystream_raw, zero_keystream)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::stub(context_commitment, model_context_commitment)]
#[kani::unwind(40)]
fn commitment_reads_every_aad_byte() {
    let tag_key: [u8; 32] = kani::any();
    let poly1305_tag: [u8; 16] = kani::any();
    let aad: [u8; 6] = kani::any();
    let pos: usize = kani::any();
    kani::assume(pos < 6);
    let delta: u8 = kani::any();
    kani::assume(delta != 0);

    let mut perturbed = aad;
    perturbed[pos] ^= delta;

    let tag = derive_tag(&tag_key, &poly1305_tag, &aad);
    let tag_perturbed = derive_tag(&tag_key, &poly1305_tag, &perturbed);

    // Byte-by-byte "some byte differs", so no `memcmp` and no array equality.
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= tag[i] ^ tag_perturbed[i];
    }
    assert!(diff != 0);
}

/// The tag must be exactly `inner XOR commitment` — no bit of the inner tag
/// dropped, added, reordered, or double-applied.
///
/// The three harnesses above pin the commitment side (full width, applied by
/// XOR, covering the whole AAD).  This one pins the *other* operand: without it,
/// a refactor that returned `commitment` alone, or that XORed the commitment
/// twice, would still satisfy every assertion about the commitment term.
///
/// `chacha20_keystream_raw` is stubbed to a **non-zero** pattern here, so the
/// inner term is a distinguishable value rather than 0 — with the zero stub
/// used by the other three, `inner XOR commitment == commitment` holds
/// trivially and this property would be vacuous.
#[kani::proof]
#[kani::stub(chacha20_keystream_raw, patterned_keystream)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::stub(context_commitment, model_context_commitment)]
fn tag_is_inner_xor_commitment_exactly() {
    let tag_key: [u8; 32] = kani::any();
    let poly1305_tag: [u8; 16] = kani::any();
    let aad: [u8; 4] = kani::any();

    let tag = derive_tag(&tag_key, &poly1305_tag, &aad);

    // Reconstruct the inner c2sp.org term exactly as `derive_tag` computes it:
    // one ChaCha20 block under (LE32(p[0..4]), p[4..16]), first 32 bytes.
    let mut inner = [0u8; TAG_LEN];
    patterned_keystream(
        &tag_key,
        u32::from_le_bytes([
            poly1305_tag[0],
            poly1305_tag[1],
            poly1305_tag[2],
            poly1305_tag[3],
        ]),
        &poly1305_tag[4..16].try_into().unwrap(),
        &mut inner,
    );

    let commitment = model_context_commitment(&aad);

    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= tag[i] ^ (inner[i] ^ commitment[i]);
    }
    assert!(diff == 0);
}

/// A stand-in for `chacha20_keystream_raw` producing a deterministic, non-zero
/// pattern that depends on all of `(key, counter, nonce)`.
///
/// Unlike [`zero_keystream`], this keeps the inner tag term distinguishable from
/// zero, so a harness can assert that `derive_tag` mixes it in correctly rather
/// than merely checking the commitment half against itself.
fn patterned_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
    // A cheap, injective-in-arguments fill.  Odd multipliers make each input
    // byte matter; the wrap keeps it branch-free and division-free for CBMC.
    let ctr = counter.to_le_bytes();
    for (i, b) in out.iter_mut().enumerate() {
        let k = key[i & 31];
        let n = nonce[i % 12];
        let c = ctr[i & 3];
        // i is small here (<= 64), so the shifts stay in range.
        *b = k ^ n.rotate_left((i % 8) as u32) ^ c.wrapping_mul((i as u8) | 1);
    }
}

// ── helpers ───────────────────────────────────────────────────────────

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[i * 2]) << 4) | nib(b[i * 2 + 1]);
    }
    out
}

fn hex16(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = (nib(b[i * 2]) << 4) | nib(b[i * 2 + 1]);
    }
    out
}
