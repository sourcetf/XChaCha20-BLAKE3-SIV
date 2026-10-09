//! Formal verification harnesses (Kani bounded model checking).
//!
//! Run with: `cargo kani -Z stubbing`
//!
//! The `-Z stubbing` flag is **required**: several harnesses use `#[kani::stub]`
//! to replace the ChaCha20 permutation, the zeroization helper, and the keyed
//! BLAKE3 MAC with cheap stand-ins (see the notes above `stub_chacha20_block`
//! and `model_blake3_keyed_multi`).  Without the flag Kani rejects the attribute
//! and the suite fails to compile.  Everything else runs unmodified.
//!
//! Compiled only under `cfg(kani)`, so they add nothing to normal builds or
//! to `cargo test`.
//!
//! Each harness states a property, and its own doc says what domain it quantifies
//! over: most take symbolic inputs, while the KAT anchors, the constant properties,
//! the sequencing experiments and the concrete tag comparison run concrete values
//! and say so rather than implying full coverage.
//!
//! # Sizing the harnesses (why some bounds look arbitrary)
//!
//! Kani is a bounded model checker: it unwinds loops to a fixed depth and asks a
//! SAT solver whether any input violates an assertion.  Three costs dominate, and
//! every harness here is shaped around them.  All figures are measured on a
//! 16-core x86_64 machine:
//!
//! 1. **The permutation is expensive.** One concrete `chacha20_block` cost ~320 s
//!    on the CBMC these bounds were shaped against (the 20 rounds alone ~62 s) — an
//!    order of magnitude slower than today's toolchain, whose current figures the
//!    design note in the ChaCha20-stream section carries. Any harness that calls
//!    the real permutation more than once cannot finish in a normal loop, and one
//!    that makes the key or counter symbolic does not finish at all. Hence
//!    `kani::stub` for the permutation, and `hchacha20_matches_draft_vector` as
//!    the single place the real rounds are run.
//!
//! 2. **Zeroization is expensive.** CBMC models each `write_volatile` separately —
//!    ~29 s per 64-byte wipe under that same older tool — so `chacha20_apply`'s
//!    per-block wipe dominates any harness that reaches it. Hence the
//!    `zeroize_array` stub, with the real implementation verified directly by the
//!    two `zeroize_*` harnesses below.
//!
//! 3. **`memcmp` inflates the unwind bound.** `assert_eq!` on slices lowers to
//!    `memcmp`, whose internal loop needs an unwind bound proportional to the
//!    slice length; too low a bound fails with a spurious "unwinding assertion"
//!    error rather than a genuine counterexample. Harnesses therefore compare
//!    scalars or short fields instead of whole slices.
//!
//! Ten of the thirteen harnesses carry an explicit `#[kani::unwind]`; the other
//! three contain no loops.  The bounds are deliberately generous, and the
//! unwinding assertions they turn on are what make a bound that is ever too low
//! fail the harness rather than silently truncate the loop it guards.
//!
//! # What this suite can and cannot establish
//!
//! It is the right tool for *construction* properties — buffer wiping, length
//! limits, counter sequencing, the tag's input layout and its MAC argument shapes.
//! Those are the places this crate has actually had bugs.  (An earlier version of
//! this list named "index arithmetic, carry propagation, limb recombination",
//! inherited boilerplate: this crate has no limb arithmetic and no harness for
//! carry propagation.)
//!
//! It is the wrong tool for *cryptographic hardness*: "no adversary can forge a
//! tag" or "tampering changes the tag" are claims about computational
//! infeasibility, and a SAT solver has no model of that.  A harness phrased that
//! way either exhausts the solver or passes vacuously.  Those properties are
//! covered by
//!
//! * the published test vectors (`standard.txt`'s draft-irtf-cfrg-xchacha-03 §2.2.1,
//!   §A.2.1 and §A.3.1 vectors; `standard.txt`'s own §Test Vectors are the c2sp
//!   construction's, which this crate is not interoperable with and does not replay),
//! * differential testing against an independent reference implementation
//!   (`tools/ref_impl.py` → `tests/vectors_differential.txt`, replayed by
//!   `tests/differential_reference.rs`), and
//! * the avalanche / nonce-misuse / key-commitment tests in `lib.rs`.
//!
//! # Two limits of this suite, so a green run is not over-read
//!
//! 1. **The MAC is stubbed in every harness that reaches it.** Kani cannot run
//!    the real BLAKE3 — its CPU-feature detection lowers to inline asm, which
//!    CBMC rejects — so `blake3_keyed_multi` is replaced by the model below. The
//!    real function is therefore never *executed* here; it is executed by every
//!    `cargo test` run, so its behaviour as a call is covered there, but the
//!    claim that its `zeroize()` pair clears BLAKE3's internal key material rests
//!    on reading the function and on the release disassembly showing both calls
//!    emitted, not on a proof.
//! 2. **The model bounds the assertion strength.** It folds each input byte into
//!    a positional accumulator, and a *symbolic* harness requiring *every* output
//!    byte to move when a whole field changes could not be unrolled in reasonable
//!    time (measured: over 18 minutes for one harness). The symbolic harnesses
//!    here therefore state one-sided properties; full-width coverage comes from
//!    the concrete comparison in `tag_matches_the_model_on_a_concrete_input` (all
//!    65 bytes, one input), and from the KATs and
//!    `test_tag_matches_blake3_over_the_documented_input` in `lib.rs`, which
//!    compares all 65 tag bytes against an independently assembled input with the
//!    real BLAKE3.

use super::*;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Zeroization ───────────────────────────────────────────────────────

/// `zeroize_slice` must clear every byte of the slice it is given.
///
/// This harness covers the short-length path only: `len` is at most 5, so
/// `zeroize_raw`'s `usize`-chunk loop never runs and the slicing-misalignment
/// regression cannot show here. The misaligned-start case — where the previous
/// implementation began its chunked loop at the first aligned byte and left the
/// prefix intact — is `zeroize_slice_clears_unaligned_window` below, which sweeps
/// all eight offsets.
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
/// is lost by shrinking it: `off` still sweeps all eight misalignments and `len`
/// still reaches 15, so a window with `off > 0` exercises the byte-prefix path
/// and (when `len >= 8 + off`) at least one full `usize` chunk write.  At this
/// size at most two chunk stores fit, and only an aligned 16-byte window reaches
/// two; the longer multi-chunk iteration is covered by the 64-byte unit test in
/// `lib.rs`, not here.
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
// Design note.  Measured on an older CBMC, one concrete `chacha20_block` cost
// ~320 s of model-checking time (the 20-round permutation alone ~62 s, each 64-byte
// `zeroize_array` ~29 s). Those figures are now pessimistic by roughly an order of
// magnitude: with Kani 0.68.0 / CBMC 6.11.0 the one harness that runs the real
// permutation (`hchacha20_matches_draft_vector`, 20 rounds, real inputs) finishes in
// **roughly 33-61 s depending on host and flags** — 37 s re-measured on this machine,
// 33.2 s on the auditor's host, and 1:01 on the CI runner with `--extra-pointer-checks`
// (the figure `tools/kani_shards.py` records for the same shard) — so none of those is
// exact for another host. The whole shard set (13 harnesses) runs in ~875 s with the
// slowest single harness at ~460 s (an audit measured the suite). The
// *design* is unchanged — the permutation and the wipe are still stubbed where the
// property does not need them, because symbolic-key harnesses over the real rounds
// still do not terminate — but the numbers above are history, not current costs.
//
// That is a tool limitation, not a property of the code, so these harnesses are
// split along the line where the *interesting* logic actually lives:
//
// * The permutation itself is pinned by the published KATs
//   (`test_hchacha20_and_chacha20_match_draft_vector`,
//   `test_xchacha20_keystream_kat_counter0`, `hchacha20_matches_draft_vector`)
//   and by the SIMD-vs-scalar differential tests.
// * The *sequencing* — which counter each block uses, where the partial tail
//   starts, whether the tail reads the right slice — is what a stream-cipher
//   wrapper gets wrong in practice, and it is independent of the permutation's
//   internals.  `kani::stub` replaces `chacha20_block` with a function that
//   encodes its own arguments, so the harness can assert the exact counter
//   sequence in seconds instead of hours.

/// A stand-in for `chacha20_block` that stamps part of its arguments into the output.
///
/// It is deliberately not a real cipher: its only job is to let a harness observe
/// the counter a block was produced from.  Bytes 0..4 receive the counter, 4..8
/// `nonce[0..4]`, 8..12 `nonce[8..12]`, 12..16 `key[0..4]` and 16..20
/// `key[28..32]`; the remaining 44 bytes are zero, so key and nonce bytes outside
/// those fields are not observable through it.
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
/// CBMC models each `write_volatile` individually, and the original note here
/// charged ~29 s per 64-byte wipe (again an older-CBMC figure; today's toolchain is
/// far faster, see the design note above).  Whatever the constant, it lands once per
/// block in any harness that calls `chacha20_apply`, and for a harness whose property
/// has nothing to do with wiping that cost buys nothing — so it is stubbed out here.
///
/// Zeroization is *not* left unverified: `zeroize_slice_clears_all_bytes` and
/// `zeroize_slice_clears_unaligned_window` below exercise the real
/// implementation directly, on the small buffers where the cost is acceptable.
///
/// **What those two verify is `zeroize_slice`/`zeroize_raw`, not the generic
/// `zeroize_array` wrapper itself**: no harness *asserts* anything about
/// `zeroize_array`'s own `size_of`/pointer/slice arithmetic. The wrapper is executed
/// for real, unasserted, by the one harness that does not stub it
/// (`hchacha20_matches_draft_vector`, whose 64-byte wipe goes through it), and its
/// behaviour is pinned on the test side by `test_zeroize_covers_unaligned_prefix` and
/// the other zeroize tests in `lib.rs`.
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
///
/// The key, nonce, start and length are concrete literals: this is a bounded
/// experiment on the wrapper's sequencing, not a statement over all keys, and
/// the permutation itself is stubbed out (the KATs pin the real one).
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

/// The XOR entry point's buffer handling across a **block boundary**: one full
/// block plus a tail must be XORed with the keystream of *consecutive* counters
/// (the tail from the counter after the full block), and applying it a second time
/// must return the plaintext.
///
/// The permutation is stubbed as above, so this is about the wrapper rather than
/// the cipher, and the counter sequence itself is pinned by
/// `chacha20_counter_sequencing_is_exact`; what this adds is the XOR path's
/// per-block dispatch at a length that crosses blocks — the first version used a
/// single 20-byte partial block and so never advanced the counter — plus the
/// involution on the partial tail. (Longer buffers were tried and abandoned here:
/// every byte of the buffer is a loop bound for CBMC, and 130 bytes at
/// `unwind 200` exhausted its memory. 66 bytes at `unwind 80` verifies in ~77 s
/// and already crosses the boundary; the sequencing harness covers the rest.)
#[kani::proof]
#[kani::stub(chacha20_block, stub_chacha20_block)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(80)]
fn chacha20_keystream_involution_partial_blocks() {
    let key = [0x5Au8; 32];
    let nonce = [0xA5u8; 12];
    let ctr = 0x1122_3344u32;
    let len = 66usize; // one full block plus a 2-byte tail: the counter must advance

    let mut pt: Vec<u8> = Vec::new();
    for _ in 0..len {
        pt.push(kani::any::<u8>());
    }

    let mut ct = vec![0u8; len];
    chacha20_keystream(&key, ctr, &nonce, &pt, &mut ct);

    // The ciphertext must be the plaintext XOR the stubbed keystream, block by
    // block: byte `i` comes from the block at `ctr + i/64`, offset `i%64`. (That
    // is the part a single-block harness could not see.)
    for i in 0..len {
        let expect = stub_chacha20_block(&key, ctr + (i / 64) as u32, &nonce);
        assert_eq!(
            ct[i],
            pt[i] ^ expect[i % 64],
            "keystream mismatch at byte {i}"
        );
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
/// Note the statement this *does* and does not establish: the inputs are concrete
/// literals, so it is a KAT anchor for the output-word selection rather than a proof
/// of it for all inputs.  The general statement rests on the draft's own
/// specification and on `test_all_accelerated_paths_agree_on_a_boundary_corpus`,
/// which compares the scalar and SIMD paths over many inputs.
///
/// This is the one harness that runs the *real* permutation, which makes it the
/// suite's most expensive harness (the design note above carries the measured
/// figures); it is kept because it is the only formal anchor for the round
/// function and the output-word selection.
#[kani::proof]
// `hex32`/`hex16` decode 32/16 bytes one output byte per loop iteration (two
// `nib` calls in the body), the HChaCha20 core runs 10 double-rounds, and its
// output loop runs 8 times; 40 covers the longest loop (32 iterations, in
// `hex32`) with room for its exit, and the bound is what carries that loop's
// unwinding assertion.
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
// Cost, then and now: the original note here put a single concrete
// `chacha20_block` at ~320 s because the tool bit-blasts the whole 20-round
// permutation plus its unrolled loops — measured again with Kani 0.68.0 / CBMC
// 6.11.0, the one harness that runs the real rounds takes **roughly 33-61 s depending
// on host and flags** (the range in the design note above) and the whole
// 13-harness set ~875 s.  The structural point stands: an end-to-end
// `encrypt`/`decrypt` harness invokes HChaCha20 (20 rounds), the two
// `derive_material` keystream blocks and then one keystream block per 64 bytes of
// message — three permutations for an empty message and one more per message block
// (the tag itself costs none; it is BLAKE3) — and with *symbolic* plaintext it does
// not terminate at all.  So the AEAD level is still reached through the model, not
// by proving the primitive end to end.
//
// Two consequences:
//
// 1. AEAD-level harnesses are not runnable in a normal verification loop.  A
//    harness that never finishes is not evidence, so none are kept here.
//
// 2. Some of the properties the removed harnesses appeared to state are not
//    provable *in principle*, not merely expensive.  "Corrupting a ciphertext
//    byte changes the tag" is the collision resistance of the tag's hash; "an
//    attacker cannot forge" is a statement about computational infeasibility.  A
//    SAT solver has no model of infeasibility, so any harness claiming to prove
//    these either exhausts the solver or passes vacuously.
//
// What covers the AEAD layer instead:
//
// * Published KATs for the constituent standards
//   (`test_hchacha20_and_chacha20_match_draft_vector`,
//   `test_xchacha20_keystream_kat_counter0`, and the in-crate tag KATs).
// * Differential testing against an independent reference implementation:
//   `tools/ref_impl.py` generates `tests/vectors_differential.txt`, and
//   `tests/differential_reference.rs` replays it across every internal length
//   boundary.  The reference self-checks against the published RFC 8439 /
//   HChaCha20 and BLAKE3-official vectors before it emits anything.
// * `test_message_swap_under_a_reused_nonce_is_rejected`,
//   `test_tag_changes_when_only_the_key_changes`,
//   `test_decrypt_does_not_leak_plaintext_on_failure`,
//   `test_detached_rejects_tampering_and_wipes`, the `test_avalanche_*`
//   diffusion checks, and the construction pins
//   (`test_blake3_keyed_matches_official_vectors`,
//   `test_tag_binds_both_derived_keys`, `test_aad_message_split_is_unambiguous`,
//   `test_every_tag_byte_reaches_the_ciphertext`).
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
///
/// The `as usize` below (like the one in `check_lengths_boundary_is_exact`)
/// assumes a 64-bit `usize`; on a 32-bit target the product truncates and the
/// harness fails at an assertion rather than passing silently.
#[kani::proof]
fn max_msg_size_boundary_matches_counter_capacity() {
    let blocks = (u32::MAX as u64) + 1;
    let at_limit = (blocks * (CHACHA20_BLOCK as u64)) as usize;
    let over_limit = at_limit + (CHACHA20_BLOCK as usize);

    assert!(check_lengths(at_limit, 0).is_ok());
    assert_eq!(check_lengths(over_limit, 0), Err(Error::MessageTooLong));
    assert_eq!(check_lengths(0, over_limit), Err(Error::AadTooLong));
}

// ── The MAC and the tag (the new construction) ─────────────────────────
//
// The MAC is two keyed BLAKE3 invocations (the NMAC shape), and the whole tag
// is the outer one's XOF output:
//
//     X   = BLAKE3_keyed(k_in,  DOM_PRE || N || le64(|A|) || le64(|M|) || A || M)
//     tag = BLAKE3_keyed(k_out, DOM_TAG || X)
//
// What is *provable* here is the **shape** of the construction, which is
// exactly what a regression would break:
//
//   * both lengths reach the inner hash and equal the actual AAD/message lengths,
//     and the head is exactly `HEAD_LEN` bytes, so nothing can be dropped from the
//     commitment;
//   * the outer hash's input is exactly the 32-byte digest, nothing truncated;
//   * all `TAG_LEN` output bytes are returned, none truncated;
//   * `derive_enc` consumes **every** tag byte, which is what makes the
//     ciphertext commit to all 520 bits;
//   * a change to any AAD or message byte changes the hash input;
//   * no master key is in any hash message (the inner head is `DOM_PRE`, not the
//     old `DOM_TAG || K || …`).
//
// One field is *not* varied by this shard's symbolic harnesses, stated so the bullet
// above is not read as more than it is: the nonce `N` occupies `head[8..32]` and no
// symbolic harness varies it (the stub checks the domain prefix, the head length and
// the two length fields).  A regression that dropped `N` from the head is caught by
// the concrete comparison in `tag_matches_the_model_on_a_concrete_input` (which
// reconstructs the head, nonce included) and by
// `test_tag_matches_blake3_over_the_documented_input` with the real BLAKE3; the
// symbolic harnesses alone would not see it.
//
// What is *not* provable — and must not be claimed — is BLAKE3's collision
// resistance or PRF security. "Distinct inputs give distinct tags" is a
// computational assumption, and a SAT solver has no model of it. That half is
// discharged by using a standard, externally analysed hash, anchored to BLAKE3's
// official test vectors (see `test_blake3_keyed_matches_official_vectors`).
//
// Two further limits of this shard, stated so they are not mistaken for
// coverage:
//
//   * Every harness here stubs `blake3_keyed_multi`, so the real function —
//     including its `reader.zeroize(); hasher.zeroize();` pair — is **never
//     executed under Kani at all**.  The claim that BLAKE3's internal key
//     material is wiped therefore rests on reading that five-line function, not
//     on a proof.  (A harness that ran it is impossible: real BLAKE3 lowers to
//     inline asm, which CBMC rejects.)
//   * The stub verifies the *shape* of each call, by asserting on the arguments
//     at the call site.  The model also folds `key` into its output, which is what
//     lets the symbolic `tag_changes_when_the_key_changes` see a `derive_tag` that
//     ignores a caller-visible key.  It cannot say *which* secret reaches which
//     internal call — the symbolic keys are interchangeable, so a swapped
//     `k_in`/`k_out` inside `derive_tag` passes every symbolic harness (the
//     concrete `tag_matches_the_model_on_a_concrete_input` is the one that catches
//     it), and `derive_enc`'s key choice is never compared against a model
//     evaluation at any call site here.

/// Fixed width of the inner hash's head: domain word, nonce, and the two
/// little-endian lengths.  Must match `derive_tag`.
const HEAD_LEN: usize = 8 + NONCE_LEN + 16;

/// Width of the outer hash's input: `DOM_TAG || X`, the 32-byte inner digest.
/// Must match `derive_tag`.
const OUTER_LEN: usize = 8 + 32;

/// The two length fields at their fixed offsets in that head.
///
/// Only call after establishing `head.len() >= HEAD_LEN`.
fn head_lengths(head: &[u8]) -> (u64, u64) {
    let mut aad_len = [0u8; 8];
    aad_len.copy_from_slice(&head[8 + NONCE_LEN..16 + NONCE_LEN]);
    let mut msg_len = [0u8; 8];
    msg_len.copy_from_slice(&head[16 + NONCE_LEN..24 + NONCE_LEN]);
    (u64::from_le_bytes(aad_len), u64::from_le_bytes(msg_len))
}

/// Counts calls to the stubbed keyed hash. A stub's own `assert!`s run only when it
/// is called, so a harness that inspects only the return value cannot tell a real
/// call from a `derive_tag` that returned a constant; this counter can. Reset by
/// the harness that checks it, so a stale value from another verification cannot
/// make it pass.
static MODEL_BLAKE3_CALLS: AtomicUsize = AtomicUsize::new(0);

/// A stand-in for `blake3_keyed_multi` whose output depends on the key and on
/// every input byte.
///
/// Kani cannot run the real BLAKE3: its runtime CPU-feature detection lowers to
/// `__cpuid_count`, which is inline asm ("TerminatorKind::InlineAsm is not
/// currently supported").  Stubbing is the honest option rather than a
/// workaround, because the property the real BLAKE3 is relied on for — collision
/// resistance — is a computational assumption a SAT solver has no model of.
///
/// What the model does preserve, and what the harnesses below therefore really
/// test:
///
///   * **The key reaches the output.**  Its bytes are folded into the model, so a
///     harness that varies the caller-visible key sees the result move.  This is
///     load-bearing: an earlier version accepted `key` and never read it, so
///     `tag_changes_when_the_key_changes` could not have noticed a `derive_tag`
///     that ignored its key arguments.  What folding does *not* establish is that
///     the right secret reaches each internal call — the symbolic keys are
///     interchangeable, so a swapped `k_in`/`k_out` passes the symbolic
///     harnesses, and `derive_enc`'s key choice is never compared with a model
///     evaluation here.  See the shard's "two further limits" note above.
///   * **Any single-byte edit to the input is visible.**  Each input byte is
///     XORed into one accumulator slot, and the output byte at that slot is a
///     function of it, so changing one byte by a nonzero amount changes the
///     output.  An earlier version folded only a 24-byte prefix of each part,
///     which silently weakened `derive_enc_reads_every_tag_byte`: that call site
///     feeds 73 bytes (`DOM_ENC` || 65-byte tag), so tag bytes past the prefix
///     could not affect the output at all.
///   * **The total input length is in the output**, so truncation or extension
///     is visible even when no individual byte is edited.
///
/// What it deliberately does *not* model: collisions between *simultaneous*
/// compensating edits (two different bytes landing in the same slot can cancel,
/// since a 65-byte output cannot distinguish 80 folded bytes injectively), and
/// BLAKE3's actual cryptographic strength.  Every harness here perturbs one byte
/// at a time, so the first limit is not reachable; the second is the reason the
/// real function is anchored to BLAKE3's official vectors instead.
fn model_blake3_keyed_multi(key: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
    MODEL_BLAKE3_CALLS.fetch_add(1, Ordering::Relaxed);
    // ── Assert the call shape, directly on the arguments ──
    //
    // Asserting inside the stub is the idiomatic Kani technique for "is this
    // called with what it should be": it inspects the real arguments at every
    // call site and costs nothing to unwind.  The alternative -- reconstructing
    // the expected concatenation and comparing hashes -- needs a loop over every
    // input byte (about 110 here), which pushes CBMC past its unwind budget and
    // fails with a spurious "unwinding assertion" rather than a real
    // counterexample.
    //
    // The fold below is still a loop, so it is only as cheap as CBMC's ability to
    // bound it.  With constant-length parts at the call site it unwinds to the
    // real length; a call site inside a loop hands it slice values CBMC cannot
    // resolve, and the fold is then unwound to the harness's unwind bound with a
    // *symbolic* accumulator index -- measured as a factor of 30 in memory.  See
    // `tag_is_keyed_hash_of_the_whole_context` for the numbers.
    //
    // Arity is itself an assertion: there are three one-part call sites -- `derive_enc`
    // (through `blake3_keyed_xof`, prefix `DOM_ENC`), the inner hash's contiguous path
    // (prefix `DOM_PRE`) and the outer tag hash (prefix `DOM_TAG`) -- and one three-part
    // call site, the inner hash's incremental path. Nothing else exists, so a future
    // call site cannot quietly slip past every branch below by using a fifth shape.
    assert!(parts.len() == 1 || parts.len() == 3);

    if parts.len() == 3 {
        // The inner hash's three-update shape: the fixed-width head, then AAD,
        // then the message.  The head starts with DOM_PRE -- the master key is
        // *not* in it (that is the point of the two-level shape).
        //
        // The output width is part of the shape: a call that asked the model for
        // fewer than 32 bytes would leave the rest of the inner buffer at whatever
        // the caller had there, and the fold's own output would depend on
        // `out.len()` (it wraps at that width).  An audit found the harnesses could
        // not see a tag truncated past byte 40 precisely because nothing asserted
        // the output width; this assertion and the DOM_TAG one below are the fix.
        assert!(out.len() == 32);
        assert!(parts[0].len() == HEAD_LEN);
        assert!(parts[0][0..8] == DOM_PRE[..]);

        // Both lengths are encoded, and they are the *actual* lengths -- this is
        // what makes `A || M` unambiguous.
        let (aad_len, msg_len) = head_lengths(parts[0]);
        assert!(aad_len == parts[1].len() as u64);
        assert!(msg_len == parts[2].len() as u64);
    } else {
        // One part: three call sites, told apart by the 8-byte domain word.  The
        // `DOM_PRE` (contiguous-inner) branch is reachable only for totals in
        // `TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT`, which no harness here reaches, so its
        // assertions are structural documentation rather than Kani coverage -- the
        // two shapes' equivalence is pinned by `test_both_tag_call_shapes_hash_the_same_bytes`.
        assert!(parts[0].len() >= 8);
        if parts[0][0..8] == DOM_ENC[..] {
            // `derive_enc`: the domain word and the whole tag, nothing else, so
            // a truncated tag cannot reach the encryption key derivation.
            assert!(parts[0].len() == 8 + TAG_LEN);
            assert!(out.len() == 44);
        } else if parts[0][0..8] == DOM_TAG[..] {
            // The outer tag hash: `DOM_TAG || X`, exactly the 32-byte inner
            // digest and nothing else, so a truncated digest cannot reach the tag.
            assert!(parts[0].len() == OUTER_LEN);
            // ...and the caller must want the whole tag: `&mut tag[..40]` used to
            // satisfy every assertion in this file.
            assert!(out.len() == TAG_LEN);
        } else {
            // `derive_tag`'s inner contiguous path: byte-for-byte the same input
            // as the three-part shape above, so the head's own length fields must
            // account for the remaining bytes exactly -- no more, no less.  (Which
            // of the two shapes a given message takes is a performance decision,
            // never a semantic one: the differential vectors hash the concatenated
            // input on both sides of the threshold, and
            // `test_both_tag_call_shapes_hash_the_same_bytes` compares the two
            // shapes at the four totals where the choice flips.)
            assert!(parts[0][0..8] == DOM_PRE[..]);
            assert!(parts[0].len() >= HEAD_LEN);
            assert!(out.len() == 32);
            let (aad_len, msg_len) = head_lengths(parts[0]);
            let total = (HEAD_LEN as u64)
                .wrapping_add(aad_len)
                .wrapping_add(msg_len);
            assert!(parts[0].len() as u64 == total);
        }
    }

    // ── Produce the output ──
    let out_len = out.len();
    let mut acc = [0u8; TAG_LEN];
    let mut n = 0usize;

    // The key first, as a leading segment of the stream.
    for b in key.iter() {
        acc[n % out_len] ^= *b;
        n += 1;
    }
    for p in parts {
        for b in p.iter() {
            acc[n % out_len] ^= *b;
            n += 1;
        }
    }

    let mut total = 0u64;
    for p in parts {
        total = total.wrapping_add(p.len() as u64);
    }
    let len_bytes = total.to_le_bytes();

    for (i, o) in out.iter_mut().enumerate() {
        // The length occupies the first eight bytes; the rest is the fold.
        let l = if i < 8 { len_bytes[i] } else { 0 };
        *o = acc[i] ^ l;
    }
}

/// The tag must be **computed through the exact two-level construction** the model
/// encodes: this harness pins the call graph and the input layout, plus that the stubbed
/// hash is reached at all. The returned tag's *value* is compared against a
/// reconstruction by `tag_matches_the_model_on_a_concrete_input` below — an earlier
/// revision of this comment read as though this harness made that comparison, and it
/// does not (see the paragraph on what its own assertion can and cannot do).
///
/// ```text
/// X   = BLAKE3_keyed(k_in,  DOM_PRE || N || le64(|A|) || le64(|M|) || A || M)
/// tag = BLAKE3_keyed(k_out, DOM_TAG || X)
/// ```
///
/// `k_in`, `k_out` and `nonce` are symbolic, so the *shape* claim holds for every
/// possible secret material.  The stub checks the shape of each call it receives — domain
/// prefixes, the head length, both encoded lengths against the actual parts, and
/// the output widths — so a length, domain separator or digest dropped from
/// either hash fails those assertions.  The nonce bytes themselves are not read
/// back by the stub (the shard note above says the same); the concrete harness
/// below reconstructs the head including the nonce.  The outer input being
/// exactly `DOM_TAG || X` is what pins the master key's removal from the hash
/// input and the two-level shape.
///
/// **The harness keeps the stub's assertions from being skipped.** A stub's
/// `assert!`s run only if the stubbed function is *called*, so a `derive_tag` that
/// returned a constant without reaching the hash would satisfy a harness that only
/// inspects the return value — which is what the earlier version did. The harness
/// therefore requires the hash to have been reached, through the call counter the
/// stub increments, and adds a nonzero-output smoke check. What its own assertion
/// cannot do is compare the tag against a reconstruction; that is
/// `tag_matches_the_model_on_a_concrete_input` below, and the layout catches above
/// all live in the stub's per-call assertions.
///
/// **Two kinds of shape, doing two different jobs.** The four symbolic shapes
/// exercise the four input combinations under the stub's per-call assertions
/// (and the counter), but with symbolic keys they cannot say *which* secret
/// reaches which hash — nothing symbolic distinguishes "inner keyed by `k_in`"
/// from "inner keyed by `k_out`", and the nonce is only *present*, not read back.
/// `tag_matches_the_model_on_a_concrete_input` covers both: it reconstructs the whole
/// expected tag through the model on one concrete input and compares all `TAG_LEN`
/// bytes, which catches a swapped `k_in`/`k_out` or a tag truncated past byte 40. (It
/// is a separate harness, not a block here: the reconstruction is affordable only
/// because it is concrete, and adding it to this symbolic harness pushed its CBMC run
/// past fifteen minutes — measured.)
///
/// Four shapes of input: all-zero lengths, both non-empty (where the two encoded
/// lengths differ, 4 vs 8, so a mix-up between the length fields cannot hide),
/// AAD only, and message only.
///
/// They are four **separate call sites**, and that is load-bearing rather than a
/// stylistic choice.  Written as a loop over `[(empty, empty), (aad, msg)]` the
/// two iterations are merged, the `&[&[u8]]` handed to the stub becomes a value
/// CBMC can no longer bound statically, and it unwinds the stub's per-byte fold
/// to this harness's unwind bound instead: 130 iterations writing through a
/// *symbolic* index into the 65-byte accumulator, which measured >30 GB of CBMC
/// formula — more than any hosted runner has, and the reason the tag shard never
/// completed in CI.  Split, each call site's parts are constants and the fold
/// unwinds to its real length, so all four shapes verify with a small peak.
///
/// `assert!` carries no format arguments: a `"...{}"` message pulls `core::fmt`
/// into the verification scope, which dominates the run time.  The comparison is
/// folded into one byte rather than `assert_eq!` on arrays, which would lower to
/// `memcmp` and inflate the unwind bound.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
// The longest loop to unwind is the stub's fold over the inner call's key and
// parts (under 100 iterations), then the tag-byte smoke check (65).  The
// unwinding assertions fire if a bound is ever too low, so the headroom here is
// safe.
#[kani::unwind(130)]
fn tag_is_keyed_hash_of_the_whole_context() {
    let k_in: [u8; 32] = kani::any();
    let k_out: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let empty: &[u8] = b"";
    let aad: &[u8] = b"aad!";
    let msg: &[u8] = b"message!";

    // The stub asserts the argument layout (domain, key, nonce, both lengths,
    // then AAD, then message) at every call -- but *only when it is called*.
    // Returning a constant from `derive_tag` without ever reaching the hash
    // would satisfy a mere "the tag is non-zero" check while skipping every
    // layout assertion. What this harness shows is therefore narrower than the
    // paragraph that used to stand here claimed: the macro below only smoke-checks
    // that the tag is non-zero, and the reconstruction-and-compare lives in
    // `tag_matches_the_model_on_a_concrete_input`, which rebuilds the tag from the
    // model on a concrete input and compares all `TAG_LEN` bytes -- that is where a
    // dropped field (the nonce included) or a wrong field order is caught.
    //
    // A macro rather than a loop or a helper function: each shape has to be its
    // own call site (see the doc comment), and a helper would take the slices as
    // symbolic parameters, which is the same merge by another route.
    //
    // The macro's own assertion is a smoke check only (`nz != 0`): with symbolic
    // keys the model folds *one of* them into each hash, and nothing symbolic says
    // which value belongs to the inner hash and which to the outer one, so a
    // `derive_tag` that swapped `k_in` and `k_out` (or truncated the output) still
    // produces a nonzero tag here.  `tag_matches_the_model_on_a_concrete_input`
    // is the harness that reconstructs the expected tag and compares all `TAG_LEN`
    // bytes; an earlier revision of this comment claimed this macro did that, and
    // it did not.
    macro_rules! shape {
        ($a:expr, $m:expr) => {{
            let tag = derive_tag(&k_in, &k_out, &nonce, $a, $m);
            let mut nz = 0u8;
            for b in tag.iter() {
                nz |= *b;
            }
            // A smoke check on the stub and the output buffer: a tag of all
            // zeros would mean the model's fold produced nothing.
            assert!(nz != 0);
        }};
    }

    // Reset first, then require the hash to have been reached: a `derive_tag` that
    // returned a constant never calls the stub, so its own layout `assert!`s never
    // run and this counter stays at zero. That is what makes the harness
    // non-vacuous (the return value alone cannot distinguish the two).
    MODEL_BLAKE3_CALLS.store(0, Ordering::Relaxed);

    shape!(empty, empty);
    shape!(aad, msg);
    shape!(aad, empty);
    shape!(empty, msg);

    // Four shapes, each an inner and an outer keyed hash: eight calls. `>=`, not
    // `==`, so adding a call shape does not turn this into a false failure.
    assert!(MODEL_BLAKE3_CALLS.load(Ordering::Relaxed) >= 8);
}

/// The tag, compared byte for byte against the model, on one **concrete** input.
///
/// Why this is a harness of its own rather than a block inside the symbolic one: with
/// symbolic keys the model folds whatever key it is handed, so nothing in the proof says
/// which of the two secrets belongs to the inner hash and which to the outer one — a
/// `derive_tag` that swapped `k_in`/`k_out` passed every harness in this shard (an audit
/// measured it). Concrete inputs make the expected tag computable *here*, so the
/// comparison covers all `TAG_LEN` bytes and catches both the swap and a tag truncated
/// at the call site. Mixing the block into the symbolic harness pushed its CBMC run past
/// fifteen minutes (measured) because that harness is the expensive one; separated, the
/// concrete proof is cheap and the symbolic one keeps its previous cost.
///
/// What it does not generalise: the nonce is one fixed value here (the symbolic shapes
/// and the in-crate KATs cover variation), and it proves one input rather than all of
/// them. It is a structural regression check — the tag must be the model evaluated on
/// the documented construction — not a statement about every input.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(130)]
fn tag_matches_the_model_on_a_concrete_input() {
    let k_in_c = [0x11u8; 32];
    let k_out_c = [0x22u8; 32];
    let nonce_c = [0x33u8; NONCE_LEN];
    let aad_c: &[u8] = b"aad!";
    let msg_c: &[u8] = b"message!";
    let got = derive_tag(&k_in_c, &k_out_c, &nonce_c, aad_c, msg_c);

    // The documented input, rebuilt here exactly as the specification writes it.
    let mut head = [0u8; HEAD_LEN];
    head[..8].copy_from_slice(&DOM_PRE);
    head[8..8 + NONCE_LEN].copy_from_slice(&nonce_c);
    head[8 + NONCE_LEN..16 + NONCE_LEN].copy_from_slice(&(aad_c.len() as u64).to_le_bytes());
    head[16 + NONCE_LEN..24 + NONCE_LEN].copy_from_slice(&(msg_c.len() as u64).to_le_bytes());

    let mut x = [0u8; 32];
    model_blake3_keyed_multi(&k_in_c, &[&head, aad_c, msg_c], &mut x);
    let mut outer = [0u8; OUTER_LEN];
    outer[..8].copy_from_slice(&DOM_TAG);
    outer[8..].copy_from_slice(&x);
    let mut want = [0u8; TAG_LEN];
    model_blake3_keyed_multi(&k_out_c, &[&outer], &mut want);

    // Folded into one byte rather than `assert_eq!`, which would lower to `memcmp` and
    // inflate the unwind bound (same reason as elsewhere here).
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= got[i] ^ want[i];
    }
    assert!(diff == 0);
}

/// A change to either derived key must change the tag.
///
/// The perturbed byte position is **symbolic** in each key (every position in `0..32`),
/// not fixed at byte 0: a fixed position would let an implementation that read only
/// `k[0]` pass, which an audit noted of the earlier revision.
///
/// **What this does not establish**, despite what an earlier version of this doc
/// claimed: it asserts only that *some* tag byte moved, so an implementation that filled
/// a prefix of the output and left the rest constant passes. The stronger "all 65 bytes
/// move" form is not usable here — asking CBMC to unroll the model's positional fold over
/// a whole field exceeded 18 minutes (measured, twice). The full-width property is covered
/// instead by `test_tag_matches_blake3_over_the_documented_input` in `lib.rs`, which runs
/// the **real** BLAKE3 and compares all 65 bytes, and by
/// `tag_matches_the_model_on_a_concrete_input`. (`derive_enc_reads_every_tag_byte`
/// below does *not* cover it: that harness never calls `derive_tag`.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(130)]
fn tag_changes_when_the_key_changes() {
    let k_in: [u8; 32] = kani::any();
    let k_out: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let tag = derive_tag(&k_in, &k_out, &nonce, b"aad", b"msg");

    // Flip one byte of each derived key, at a *symbolic* position, so every one of the 32
    // bytes is covered rather than byte 0 only.  The index is symbolic into a 32-byte key,
    // the same shape as `derive_enc_reads_every_tag_byte`'s `pos` -- not a symbolic index
    // into the model's 65-byte accumulator, which is what inflates CBMC elsewhere.
    // The assertion stays deliberately one-sided ("some tag byte moved", not "all did") --
    // see the doc comment for why, and for where the full-width property is established.
    let pos_in: usize = kani::any();
    kani::assume(pos_in < 32);
    let mut k_in2 = k_in;
    k_in2[pos_in] ^= 0xff;
    let tag_in = derive_tag(&k_in2, &k_out, &nonce, b"aad", b"msg");

    let pos_out: usize = kani::any();
    kani::assume(pos_out < 32);
    let mut k_out2 = k_out;
    k_out2[pos_out] ^= 0xff;
    let tag_out = derive_tag(&k_in, &k_out2, &nonce, b"aad", b"msg");

    let mut moved_in = 0u32;
    let mut moved_out = 0u32;
    for i in 0..TAG_LEN {
        moved_in |= (tag[i] ^ tag_in[i]) as u32;
        moved_out |= (tag[i] ^ tag_out[i]) as u32;
    }
    assert!(moved_in != 0);
    assert!(moved_out != 0);
}

/// `derive_enc` must consume **every** byte of the tag.
///
/// The ciphertext's key and nonce come from here, so a tag byte that never
/// reaches this function is a tag byte the ciphertext does not commit to.  The
/// previous construction had exactly that hole (`tag[28..32]` was unused); the
/// new one must not.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(130)]
fn derive_enc_reads_every_tag_byte() {
    let enc_seed: [u8; 32] = kani::any();
    let pos: usize = kani::any();
    kani::assume(pos < TAG_LEN);

    let mut tag: [u8; TAG_LEN] = kani::any();
    let mut perturbed = tag;
    perturbed[pos] ^= 0xff;

    // `derive_enc` writes through caller slices rather than returning a 44-byte
    // aggregate: returning one makes the compiler materialise an unnamed temporary
    // that no `zeroize_array` can reach, and a stack scan found the tail of exactly
    // that value surviving a round trip.  (This harness is the caller that had to be
    // updated with it -- it is `#[cfg(kani)]`, so `cargo test` never compiled it, and
    // the breakage only showed up in the Formal job.)
    let mut k1 = [0u8; 32];
    let mut n1 = [0u8; 12];
    derive_enc(&enc_seed, &tag, &mut k1, &mut n1);
    let mut k2 = [0u8; 32];
    let mut n2 = [0u8; 12];
    derive_enc(&enc_seed, &perturbed, &mut k2, &mut n2);

    // Some byte of (key, nonce) must differ.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= k1[i] ^ k2[i];
    }
    for i in 0..12 {
        diff |= n1[i] ^ n2[i];
    }
    assert!(diff != 0);

    // (`tag` is consumed by `derive_enc` above, so it needs no artificial use. An
    // earlier revision had `tag[0] = tag[0];` here with a comment claiming it kept the
    // binding alive; the value was already live, so it was a no-op that read as though
    // the proof depended on it.)
}

/// A change to the associated data or to the message must change the tag, for
/// **every** byte position of either — at a fixed input size.
///
/// Complements `tag_is_keyed_hash_of_the_whole_context`, which pins the call
/// layout and the output widths; this checks that no AAD or message byte is
/// dropped on the way in. The four-byte AAD and four-byte message keep every
/// position beyond a naive 1-byte prefix. **The lengths are part of the fixed
/// domain**: a defect conditioned on a longer input (a byte dropped only when
/// `len > 4`) is outside this symbolic harness, which is why the in-crate sweeps
/// `test_tag_covers_every_aad_and_message_byte` (200-byte AAD, 300-byte message)
/// and `test_tag_depends_on_every_aad_byte` (1100-byte AAD) run the real BLAKE3
/// over every position. (An earlier revision of this line said "three-byte and
/// four-byte inputs"; the three-byte inputs are in
/// `tag_changes_when_the_key_changes`, not here.)
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
#[kani::unwind(130)]
fn every_aad_and_message_byte_reaches_the_tag() {
    let k_in: [u8; 32] = kani::any();
    let k_out: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let aad: [u8; 4] = kani::any();
    let msg: [u8; 4] = kani::any();
    let pos: usize = kani::any();
    kani::assume(pos < 4);
    let delta: u8 = kani::any();
    kani::assume(delta != 0);

    let tag = derive_tag(&k_in, &k_out, &nonce, &aad, &msg);

    let mut aad2 = aad;
    aad2[pos] ^= delta;
    let tag_aad = derive_tag(&k_in, &k_out, &nonce, &aad2, &msg);

    let mut msg2 = msg;
    msg2[pos] ^= delta;
    let tag_msg = derive_tag(&k_in, &k_out, &nonce, &aad, &msg2);

    let mut d1 = 0u8;
    let mut d2 = 0u8;
    for i in 0..TAG_LEN {
        d1 |= tag[i] ^ tag_aad[i];
        d2 |= tag[i] ^ tag_msg[i];
    }
    assert!(d1 != 0);
    assert!(d2 != 0);
}

// ── helpers ───────────────────────────────────────────────────────────

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        // Loud rather than silent: this used to map any other byte to 0, which
        // would quietly turn a typo'd vector (or an uppercase digit) into a
        // different, valid-looking input. Bare `panic!()`: a formatted message
        // would pull `core::fmt` into the verification scope.
        _ => panic!(),
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
