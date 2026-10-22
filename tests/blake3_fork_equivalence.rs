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
