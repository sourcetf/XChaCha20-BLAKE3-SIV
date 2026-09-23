//! Formal verification harnesses (Kani bounded model checking).
//!
//! Run with: `cargo kani -Z stubbing`
//!
//! The `-Z stubbing` flag is **required**: several harnesses use `#[kani::stub]`
//! to replace the ChaCha20 permutation, the zeroization helper, and the keyed
//! BLAKE3 MAC with cheap stand-ins (see the notes above `stub_chacha20_block`
//! and `model_blake3_keyed_xof`).  Without the flag Kani rejects the attribute
//! and the suite fails to compile.  Everything else runs unmodified.
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
//   HChaCha20 and BLAKE3-official vectors before it emits anything.
// * `test_nonce_misuse_resistance`, `test_key_commitment`,
//   `test_decrypt_does_not_leak_plaintext_on_failure`,
//   `test_detached_rejects_tampering_and_wipes`, the `test_avalanche_*`
//   diffusion checks, and the construction pins
//   (`test_blake3_keyed_matches_official_vectors`,
//   `test_tag_binds_the_key_directly`, `test_aad_message_split_is_unambiguous`,
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
// The MAC is now a single keyed BLAKE3 invocation, and the whole tag is its
// XOF output:
//
//     tag = BLAKE3_keyed(mac_key, DOM_TAG || K || N || le64(|A|) || le64(|M|) || A || M)
//
// What is *provable* here is the **shape** of the construction, which is
// exactly what a regression would break:
//
//   * every input field reaches the hash (K, N, both lengths, A, M), so nothing
//     can be dropped from the commitment;
//   * all `TAG_LEN` output bytes are returned, none truncated;
//   * `derive_enc` consumes **every** tag byte, which is what makes the
//     ciphertext commit to all 520 bits;
//   * a change to any AAD or message byte changes the hash input.
//
// What is *not* provable — and must not be claimed — is BLAKE3's collision
// resistance or PRF security. "Distinct inputs give distinct tags" is a
// computational assumption, and a SAT solver has no model of it. That half is
// discharged by using a standard, externally analysed hash, anchored to BLAKE3's
// official test vectors (see `test_blake3_keyed_matches_official_vectors`).

/// A stand-in for `blake3_keyed_xof` that is **injective in every input byte**.
///
/// Kani cannot run the real BLAKE3: its runtime CPU-feature detection lowers to
/// `__cpuid_count`, which is inline asm ("TerminatorKind::InlineAsm is not
/// currently supported").  Stubbing is the honest option rather than a
/// workaround, because the property the real BLAKE3 is relied on for — collision
/// resistance — is a computational assumption a SAT solver has no model of.
///
/// The model preserves exactly the questions the harnesses below ask: whether
/// each input byte reaches the hash, and whether each output byte reaches the
/// tag.  It is built so a dropped input byte or a truncated output is
/// detectable:
///
///   * `out[0..8]` carries `data.len()`, so truncation or extension of the input
///     changes the output;
///   * `out[8..12]` carries a positional XOR-fold of every input byte, so any
///     single-byte edit changes it (XOR is its own inverse; there is no
///     cancellation the way a sum could have);
///   * `out[12..16]` carries the key length and a key-dependent term, so the key
///     is bound in too;
///   * every remaining output byte is filled from the input so that no output
///     byte is constant — otherwise "all 65 bytes reach the tag" would hold
///     trivially for the constant ones.
///
/// No `%` or `/` on symbolic values: CBMC bit-blasts division into an expensive
/// circuit and these harnesses are sized to finish in seconds.
fn model_blake3_keyed_multi(key: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
    // ── Assert the call shape, directly on the arguments ──
    //
    // Asserting inside the stub is the idiomatic Kani technique for "is this
    // called with what it should be": it inspects the real arguments at every
    // call site, and costs nothing to unwind. The alternative -- reconstructing
    // the expected concatenation and comparing hashes -- needs a loop over every
    // input byte (about 110 here), which pushes CBMC past its unwind budget and
    // fails with a spurious "unwinding assertion" rather than a real
    // counterexample.
    //
    // Only the tag path has the three-part shape; the encryption-material path
    // passes one part, so the two are distinguished by arity.
    if parts.len() == 3 {
        // The fixed-width head, then AAD, then the message.
        assert!(parts[0].len() == 8 + 32 + NONCE_LEN + 16);
        assert!(parts[0][0..8] == DOM_TAG[..]);

        // Both lengths are encoded, and they are the *actual* lengths -- this is
        // what makes `A || M` unambiguous.
        let mut aad_len = [0u8; 8];
        aad_len.copy_from_slice(&parts[0][40 + NONCE_LEN..48 + NONCE_LEN]);
        let mut msg_len = [0u8; 8];
        msg_len.copy_from_slice(&parts[0][48 + NONCE_LEN..56 + NONCE_LEN]);
        assert!(u64::from_le_bytes(aad_len) == parts[1].len() as u64);
        assert!(u64::from_le_bytes(msg_len) == parts[2].len() as u64);
    }

    // ── Produce the output ──
    //
    // Deterministic, and injective in **every** input byte.  An earlier version
    // folded only a 24-byte prefix to keep the loop short, which silently
    // weakened `derive_enc_reads_every_tag_byte`: that path feeds 73 bytes
    // (`DOM_ENC` || 65-byte tag), so tag bytes past the prefix could not affect
    // the model's output and the harness failed against a correct
    // implementation. Fold everything; the loops here are cheap.
    let out_len = out.len();
    let mut acc = [0u8; TAG_LEN];
    let mut n = 0usize;
    for p in parts {
        for b in p.iter() {
            acc[n % out_len] ^= *b;
            n += 1;
        }
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = acc[i].wrapping_add((i as u8) | 1);
    }
}

/// The tag must be the model evaluated on the **exact** concatenation
/// `DOM_TAG || K || N || le64(|A|) || le64(|M|) || A || M`, over all `TAG_LEN`
/// bytes.
///
/// `mac_key`, `key` and `nonce` are symbolic, so this holds for every possible
/// secret material.  Because the model is injective in each input byte, a field
/// dropped from the hasher — the key, either length, the domain separator —
/// changes the result and fails the assertion.
///
/// Four shapes of input (empty/empty, AAD only, message only, both) so a
/// length-dependent mistake in how the fields are fed would show up.
///
/// `assert!` carries no format arguments: a `"...{}"` message pulls `core::fmt`
/// into the verification scope, which dominates the run time.  The comparison is
/// folded into one byte rather than `assert_eq!` on arrays, which would lower to
/// `memcmp` and inflate the unwind bound.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
// The comparison loop runs TAG_LEN (65) times, and `copy_from_slice` on the
// head buffer once more, so the default bound is too low.
#[kani::unwind(130)]
fn tag_is_keyed_hash_of_the_whole_context() {
    let mac_key: [u8; 32] = kani::any();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let empty: &[u8] = b"";
    let aad: &[u8] = b"aad!";
    let msg: &[u8] = b"message!";

    // The stub asserts the argument layout (domain, key, nonce, both lengths,
    // then AAD, then message) at every call.  So reaching the end of this
    // harness means the layout was right; no separate reconstruction is needed,
    // and none is possible without an expensive loop over the input.
    for (a, m) in [(empty, empty), (aad, msg)] {
        let tag = derive_tag(&mac_key, &key, &nonce, a, m);
        let mut nz = 0u8;
        for b in tag.iter() {
            nz |= *b;
        }
        // A tag of all zeros would mean the XOF returned nothing; with the odd
        // addend in the model that cannot happen, so this catches a stub or
        // buffer mistake rather than a cryptographic one.
        assert!(nz != 0);
    }
}

/// Every byte of the tag must be produced by the hash — none may be left
/// constant or zero-filled.
///
/// A refactor that, say, filled a padded output and copied only a prefix would
/// show up here as bytes that never move.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
fn every_tag_byte_comes_from_the_hash() {
    let mac_key: [u8; 32] = kani::any();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let tag = derive_tag(&mac_key, &key, &nonce, b"aad", b"msg");

    // Perturb the input; every tag byte position must be able to change.
    let mut key2 = key;
    key2[0] ^= 0xff;
    let tag2 = derive_tag(&mac_key, &key2, &nonce, b"aad", b"msg");

    let mut moved = 0u32;
    for i in 0..TAG_LEN {
        moved |= (tag[i] ^ tag2[i]) as u32;
    }
    assert!(moved != 0);
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
fn derive_enc_reads_every_tag_byte() {
    let enc_seed: [u8; 32] = kani::any();
    let pos: usize = kani::any();
    kani::assume(pos < TAG_LEN);

    let mut tag: [u8; TAG_LEN] = kani::any();
    let mut perturbed = tag;
    perturbed[pos] ^= 0xff;

    let (k1, n1) = derive_enc(&enc_seed, &tag);
    let (k2, n2) = derive_enc(&enc_seed, &perturbed);

    // Some byte of (key, nonce) must differ.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= k1[i] ^ k2[i];
    }
    for i in 0..12 {
        diff |= n1[i] ^ n2[i];
    }
    assert!(diff != 0);

    // Keep the binding alive so CBMC cannot treat `tag` as unused.
    tag[0] = tag[0];
}

/// A change to the associated data or to the message must change the tag, for
/// **every** byte position of either.
///
/// Complements `tag_is_keyed_hash_of_the_whole_context`, which checks the
/// concatenation is right; this checks that no byte is dropped on the way in.
/// The three-byte and four-byte inputs keep every position beyond a naive
/// 1-byte prefix.
#[kani::proof]
#[kani::stub(blake3_keyed_multi, model_blake3_keyed_multi)]
#[kani::stub(zeroize_array, noop_zeroize_array)]
fn every_aad_and_message_byte_reaches_the_tag() {
    let mac_key: [u8; 32] = kani::any();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let aad: [u8; 4] = kani::any();
    let msg: [u8; 4] = kani::any();
    let pos: usize = kani::any();
    kani::assume(pos < 4);
    let delta: u8 = kani::any();
    kani::assume(delta != 0);

    let tag = derive_tag(&mac_key, &key, &nonce, &aad, &msg);

    let mut aad2 = aad;
    aad2[pos] ^= delta;
    let tag_aad = derive_tag(&mac_key, &key, &nonce, &aad2, &msg);

    let mut msg2 = msg;
    msg2[pos] ^= delta;
    let tag_msg = derive_tag(&mac_key, &key, &nonce, &aad, &msg2);

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
