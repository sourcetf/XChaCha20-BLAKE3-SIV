//! Differential tests for the vendored BLAKE3 fork.
//!
//! The fork's `Platform::hash_many` sends complete SIMD groups to the widest kernel
//! and sub-group tails to the safe 4-wide SSE2/SSE4.1 kernels. The original tail path
//! over-read the last 64-byte block at +16/+32/+48; the Linux
//! `hash_many_tail_does_not_cross_a_guard_page` test puts inputs against a `PROT_NONE`
//! page, and the output comparisons below check every counter mode and both input
//! widths.
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

/// The fork routes sub-group tails differently by input width: 64-byte parent blocks
/// go to SSE2/SSE4.1 (the AVX2/AVX-512 tails over-read them), while 1 KiB chunks keep
/// the normal SIMD dispatcher. Both paths must match portable for every n, including
/// 2..=7 and 18..=23 where the original AVX2/AVX-512 tails over-read.
fn check_hash_many_tail<const N: usize>(last_n: usize) {
    let key = [0x0102_0304u32; 8];
    let normal = [0xA5u8; N];

    for n in 0..=last_n {
        let inputs: Vec<&[u8; N]> = (0..n).map(|_| &normal).collect();
        for (increment, mode) in [(IncrementCounter::Yes, "Yes"), (IncrementCounter::No, "No")] {
            let mut got = vec![0u8; n * 32];
            let mut want = vec![0u8; n * 32];
            Platform::detect().hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut got);
            Platform::portable()
                .hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut want);
            assert_eq!(
                got, want,
                "hash_many diverged from portable at N={N}, n={n}, counter mode {mode}"
            );
        }
    }
}

#[test]
fn hash_many_tail_matches_portable() {
    check_hash_many_tail::<64>(40);
    check_hash_many_tail::<1024>(40);
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

/// The fork's tail policy must be safe at a real page boundary, on Linux.
///
/// `tests/blake3_fork_equivalence.rs`'s output comparisons cannot see an over-read:
/// the original AVX2/AVX-512 tails produced correct values while reading past the
/// 64-byte block. This test puts the input block at the end of a page and `mprotect`s
/// the next page `PROT_NONE`; a single byte past the block faults the test process.
/// It covers both routes: 64-byte parent blocks go to SSE2/SSE4.1, and 1 KiB chunks
/// keep the normal SIMD dispatcher.
#[cfg(target_os = "linux")]
#[test]
fn hash_many_tail_does_not_cross_a_guard_page() {
    use std::alloc::{alloc, dealloc, Layout};

    let page = 4096usize;
    let layout = Layout::from_size_align(2 * page, page).expect("layout");
    // SAFETY: `layout` is a valid two-page allocation; the first page is initialised
    // before any reference is formed, and the second is made inaccessible only while
    // the calls below run, which never dereference it unless the kernel is buggy.
    unsafe {
        let base = alloc(layout);
        assert!(!base.is_null(), "two-page allocation failed");
        core::ptr::write_bytes(base, 0xA5, page);
        let guard = base.add(page);
        assert_eq!(
            libc::mprotect(guard.cast(), page, libc::PROT_NONE),
            0,
            "mprotect(PROT_NONE) failed"
        );

        let key = [0x0102_0304u32; 8];
        let mut out = [0u8; 40 * 32];

        // 64-byte parent blocks: the sizes that faulted with the original AVX2/AVX-512
        // tails. The fork routes these to SSE2/SSE4.1.
        for &n in &[1usize, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24, 31, 32, 40] {
            let block: &[u8; 64] = &*guard.sub(64).cast::<[u8; 64]>();
            let inputs = vec![block; n];
            Platform::detect().hash_many(
                &inputs,
                &key,
                0,
                IncrementCounter::Yes,
                0,
                0,
                0,
                &mut out[..n * 32],
            );
        }

        // 1 KiB chunks: the tail loads at +16/+32/+48 stay inside the input, so the
        // normal SIMD dispatcher is used.
        for &n in &[1usize, 2, 3, 4, 5, 8, 16] {
            let block: &[u8; 1024] = &*guard.sub(1024).cast::<[u8; 1024]>();
            let inputs = vec![block; n];
            Platform::detect().hash_many(
                &inputs,
                &key,
                7,
                IncrementCounter::No,
                0x11,
                0x22,
                0x33,
                &mut out[..n * 32],
            );
        }

        assert_eq!(
            libc::mprotect(guard.cast(), page, libc::PROT_READ | libc::PROT_WRITE),
            0,
            "mprotect restore failed"
        );
        dealloc(base, layout);
    }
}

/// `hash_many` must match the assembly's silent wrap at `u64::MAX`.
///
/// The portable and Rust-SIMD implementations used `counter += 1`, which panics in a
/// debug build at the end of the counter space while the C/assembly kernels wrap. The
/// public `Platform::hash_many` counter is caller-supplied, so this is reachable with
/// the hazmat API even though the crate's own callers start at zero.
#[test]
fn hash_many_counter_wraps_at_u64_max() {
    let key = [0x0102_0304u32; 8];

    let block64 = [0xA5u8; 64];
    for n in [1usize, 2, 3, 4, 8, 17] {
        let inputs = vec![&block64; n];
        let mut got = vec![0u8; n * 32];
        let mut want = vec![0u8; n * 32];
        Platform::detect().hash_many(
            &inputs,
            &key,
            u64::MAX,
            IncrementCounter::Yes,
            0,
            0,
            0,
            &mut got,
        );
        Platform::portable().hash_many(
            &inputs,
            &key,
            u64::MAX,
            IncrementCounter::Yes,
            0,
            0,
            0,
            &mut want,
        );
        assert_eq!(got, want, "64-byte counter wrap diverged at n={n}");
    }

    let block1024 = [0x5Au8; 1024];
    for n in [1usize, 2, 4, 5, 16] {
        let inputs = vec![&block1024; n];
        let mut got = vec![0u8; n * 32];
        let mut want = vec![0u8; n * 32];
        Platform::detect().hash_many(
            &inputs,
            &key,
            u64::MAX,
            IncrementCounter::Yes,
            0,
            0,
            0,
            &mut got,
        );
        Platform::portable().hash_many(
            &inputs,
            &key,
            u64::MAX,
            IncrementCounter::Yes,
            0,
            0,
            0,
            &mut want,
        );
        assert_eq!(got, want, "1 KiB counter wrap diverged at n={n}");
    }
}
