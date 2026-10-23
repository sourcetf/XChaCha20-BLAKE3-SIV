//! Differential tests for the vendored BLAKE3 fork.
//!
//! The fork's `Platform::hash_many` sends complete SIMD groups to the C/assembly
//! kernels and the remainder to the portable implementation. The original tail path
//! over-read `inputs[0]` at +16/+32/+48 (reproduced with a guard page in
//! `blake3/examples/guard_page_probe.rs`); this test checks that the split preserves
//! every chaining value, including empty inputs and both counter modes.
//!
//! `Platform::xof_many`'s multi-block path is also forced through the documented Rust
//! construction in the fork (the unix AVX-512 assembly does not zero-extend
//! `block_len`/`flags`). Compare it with the portable implementation here.

use blake3::hazmat::{left_subtree_len, HasherExt};
use blake3::platform::Platform;
use blake3::{Hasher, IncrementCounter};

#[test]
fn reset_clears_the_hazmat_input_offset() {
    let mut hasher = Hasher::new();
    hasher.set_input_offset(blake3::CHUNK_LEN as u64);
    hasher.reset();
    hasher.update(b"abc");
    assert_eq!(
        hasher.finalize(),
        blake3::hash(b"abc"),
        "reset left initial_chunk_counter behind (upstream D-04)"
    );
}

#[test]
fn left_subtree_len_is_total_at_u64_max() {
    assert_eq!(
        left_subtree_len(u64::MAX),
        1u64 << 63,
        "u64::MAX + 1 overflowed in left_subtree_len (upstream D-05)"
    );
}

#[test]
fn hash_many_tail_matches_portable() {
    let key = [0x0102_0304u32; 8];
    let normal = [0xA5u8; 64];

    for n in 0..=17usize {
        let inputs: Vec<&[u8; 64]> = (0..n).map(|_| &normal).collect();
        for (increment, mode) in [(IncrementCounter::Yes, "Yes"), (IncrementCounter::No, "No")] {
            let mut got = vec![0u8; n * 32];
            let mut want = vec![0u8; n * 32];
            Platform::detect().hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut got);
            Platform::portable()
                .hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut want);
            assert_eq!(
                got, want,
                "hash_many diverged from portable at n={n}, counter mode {mode}"
            );
        }
    }
}

#[test]
fn xof_many_multiblock_matches_portable() {
    let cv = [0x0102_0304u32; 8];
    let block = [0x5Au8; 64];
    for blocks in 1..=4usize {
        let mut got = vec![0u8; blocks * 64];
        let mut want = vec![0u8; blocks * 64];
        Platform::detect().xof_many(&cv, &block, 64, 9, 0x44, &mut got);
        Platform::portable().xof_many(&cv, &block, 64, 9, 0x44, &mut want);
        assert_eq!(got, want, "xof_many diverged at {blocks} block(s)");
    }
}

/// The safe API accepts a short output slice. The single-block AVX-512 path wrote a
/// whole 64-byte block for a 1..=63-byte request in release (the `debug_assert` was
/// compiled out), up to 63 bytes past the caller's slice. The fork computes the
/// partial block through `compress_xof`; this test canaries the write and checks the
/// prefix against the portable implementation for every length.
#[test]
fn xof_many_short_output_stays_in_bounds_and_matches_portable() {
    let cv = [0x0102_0304u32; 8];
    let block = [0x5Au8; 64];
    let platform = Platform::detect();

    for len in 1..64usize {
        let mut backing = [0xAAu8; 64];
        platform.xof_many(&cv, &block, 64, 9, 0x44, &mut backing[..len]);
        assert!(
            backing[len..].iter().all(|&b| b == 0xAA),
            "xof_many wrote past a {len}-byte output slice"
        );
    }

    for len in 0..=130usize {
        let mut got = vec![0u8; len];
        let mut want = vec![0u8; len];
        platform.xof_many(&cv, &block, 64, 9, 0x44, &mut got);
        Platform::portable().xof_many(&cv, &block, 64, 9, 0x44, &mut want);
        assert_eq!(got, want, "short xof_many diverged at len={len}");
    }
}
