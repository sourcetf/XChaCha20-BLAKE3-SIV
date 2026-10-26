//! Differential tests for the vendored BLAKE3 fork.
//!
//! The fork's `Platform::hash_many` sends complete SIMD groups to the widest kernel and
//! sub-group tails to safe kernels: AVX-512 peels an 8-wide `hash8` group before the
//! final 1..=7 inputs go to SSE2/SSE4.1, all of whose loads end at the block's last
//! byte. The original tail path over-read the last 64-byte block at +16/+32/+48; the
//! Linux `hash_many_tail_does_not_cross_a_guard_page` test puts inputs against a
//! `PROT_NONE` page, and the output comparisons below use distinct bytes per input and
//! check every counter mode and both input widths.
//!
//! `Platform::xof_many`'s multi-block path is also forced through the documented Rust
//! construction in the fork (the unix AVX-512 assembly does not zero-extend
//! `block_len`/`flags`). Its expected bytes are built here from `compress_xof`, one
//! block at a time, so the comparison does not call the loop under test on both sides.

use blake3::hazmat::{left_subtree_len, HasherExt};
use blake3::platform::Platform;
use blake3::{Hasher, IncrementCounter};

/// Every backend this host can actually execute, not only `detect()`'s widest one.
/// The fork's routing differs per backend (`hash16`/`hash8`/`hash4`/`hash1`), and a
/// runner whose CPU has AVX-512 would otherwise leave the AVX2 and SSE routes untested.
fn platforms_to_test() -> Vec<Platform> {
    let mut platforms = vec![Platform::portable(), Platform::detect()];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        platforms.extend(
            [Platform::sse2(), Platform::sse41(), Platform::avx2()]
                .into_iter()
                .flatten(),
        );
    }
    platforms
}

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

/// The fork routes sub-group tails differently by width: 64-byte parent blocks and
/// 1 KiB chunks both use safe kernels for 1..=15 inputs, and complete groups keep the
/// widest dispatcher. Every input has distinct bytes, so a kernel that reads the wrong
/// lane (or returns `inputs[0]`'s CV for every lane) cannot pass by matching a shared
/// constant buffer.
fn check_hash_many_tail<const N: usize>(platform: Platform, last_n: usize) {
    let key = [0x0102_0304u32; 8];

    for n in 0..=last_n {
        let arrays: Vec<[u8; N]> = (0..n)
            .map(|lane| [lane.wrapping_mul(7).wrapping_add(3) as u8; N])
            .collect();
        let inputs: Vec<&[u8; N]> = arrays.iter().collect();
        for (increment, mode) in [(IncrementCounter::Yes, "Yes"), (IncrementCounter::No, "No")] {
            let mut got = vec![0u8; n * 32];
            let mut want = vec![0u8; n * 32];
            platform.hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut got);
            Platform::portable()
                .hash_many(&inputs, &key, 7, increment, 0x11, 0x22, 0x33, &mut want);
            assert_eq!(
                got, want,
                "hash_many diverged from portable on {platform:?} at N={N}, n={n}, counter mode {mode}"
            );
        }
    }
}

#[test]
fn hash_many_tail_matches_portable() {
    for platform in platforms_to_test() {
        check_hash_many_tail::<64>(platform, 40);
        check_hash_many_tail::<1024>(platform, 40);
    }
}

/// Build the expected XOF stream one block at a time from `compress_xof`.
///
/// Calling `Platform::portable().xof_many` as the reference is tautological: both
/// `xof_many` calls take the same multi-block loop in `platform.rs`, so a wrong block
/// counter inside that loop would appear on both sides. `compress_xof` is the
/// per-block primitive and takes the counter explicitly.
fn expected_xof(
    cv: &[u32; 8],
    block: &[u8; 64],
    block_len: u8,
    counter: u64,
    flags: u8,
    len: usize,
) -> Vec<u8> {
    let mut want = vec![0u8; len];
    for (index, chunk) in want.chunks_mut(64).enumerate() {
        let produced = Platform::portable().compress_xof(
            cv,
            block,
            block_len,
            counter.wrapping_add(index as u64),
            flags,
        );
        chunk.copy_from_slice(&produced[..chunk.len()]);
    }
    want
}

#[test]
fn xof_many_multiblock_matches_independent_blocks() {
    let cv = [0x0102_0304u32; 8];
    let block = [0x5Au8; 64];
    for platform in platforms_to_test() {
        for blocks in 1..=4usize {
            let mut got = vec![0u8; blocks * 64];
            platform.xof_many(&cv, &block, 64, 9, 0x44, &mut got);
            let want = expected_xof(&cv, &block, 64, 9, 0x44, got.len());
            assert_eq!(
                got, want,
                "xof_many diverged on {platform:?} at {blocks} block(s)"
            );
        }
    }
}

/// The safe API accepts a short output slice. The single-block AVX-512 path wrote a
/// whole 64-byte block for a 1..=63-byte request in release (the `debug_assert` was
/// compiled out), up to 63 bytes past the caller's slice. The fork computes the
/// partial block through `compress_xof`; this test canaries the write and checks the
/// stream against independently computed blocks for every length.
#[test]
fn xof_many_short_output_stays_in_bounds_and_matches_independent_blocks() {
    let cv = [0x0102_0304u32; 8];
    let block = [0x5Au8; 64];

    for platform in platforms_to_test() {
        for len in 1..64usize {
            let mut backing = [0xAAu8; 64];
            platform.xof_many(&cv, &block, 64, 9, 0x44, &mut backing[..len]);
            assert!(
                backing[len..].iter().all(|&b| b == 0xAA),
                "xof_many on {platform:?} wrote past a {len}-byte output slice"
            );
        }

        for len in 0..=130usize {
            let mut got = vec![0u8; len];
            platform.xof_many(&cv, &block, 64, 9, 0x44, &mut got);
            let want = expected_xof(&cv, &block, 64, 9, 0x44, len);
            assert_eq!(
                got, want,
                "short xof_many diverged on {platform:?} at len={len}"
            );
        }
    }
}

/// The fork's tail policy must be safe at a real page boundary, on Linux.
///
/// `tests/blake3_fork_equivalence.rs`'s output comparisons cannot see an over-read:
/// the original AVX2/AVX-512 tails produced correct values while reading past the
/// 64-byte block. This test puts the input block at the end of a page and `mprotect`s
/// the next page `PROT_NONE`; a single byte past the block faults the test process.
/// It covers both input widths and the 8-wide AVX-512 peel plus the 1..=7 SSE tail.
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
        // tails. On AVX-512, 8 and 15 exercise the hash8 peel and the SSE remainder.
        for platform in platforms_to_test() {
            for &n in &[1usize, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24, 31, 32, 40] {
                let block: &[u8; 64] = &*guard.sub(64).cast::<[u8; 64]>();
                let inputs = vec![block; n];
                platform.hash_many(
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
        }

        // 1 KiB chunks: the same tail routing, with the last block's +48-byte load
        // ending at the guard page.
        for platform in platforms_to_test() {
            for &n in &[1usize, 2, 3, 4, 5, 8, 9, 15, 16] {
                let block: &[u8; 1024] = &*guard.sub(1024).cast::<[u8; 1024]>();
                let inputs = vec![block; n];
                platform.hash_many(
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
        }

        assert_eq!(
            libc::mprotect(guard.cast(), page, libc::PROT_READ | libc::PROT_WRITE),
            0,
            "mprotect restore failed"
        );
        dealloc(base, layout);
    }
}

/// The same guard-page witness on Windows, where the original D-01 fault was first
/// reproduced. The Linux test's `mprotect` is not available there, so this uses
/// `VirtualAlloc`/`VirtualProtect` from kernel32 in a self-contained test.
#[cfg(target_os = "windows")]
#[test]
fn hash_many_tail_does_not_cross_a_guard_page_windows() {
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(
            lpaddress: *mut c_void,
            dwsize: usize,
            flallocationtype: u32,
            flprotect: u32,
        ) -> *mut c_void;
        fn VirtualProtect(
            lpaddress: *mut c_void,
            dwsize: usize,
            flnewprotect: u32,
            lpfloldprotect: *mut u32,
        ) -> i32;
        fn VirtualFree(lpaddress: *mut c_void, dwsize: usize, dwfreetype: u32) -> i32;
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_NOACCESS: u32 = 0x01;
    let page = 4096usize;

    // SAFETY: `VirtualAlloc` returns a two-page region or null (checked). The first
    // page is written before references are formed; the second is made inaccessible
    // only for the duration of the calls, and the region is released exactly once.
    unsafe {
        let base = VirtualAlloc(
            core::ptr::null_mut(),
            2 * page,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        assert!(!base.is_null(), "VirtualAlloc failed");
        core::ptr::write_bytes(base.cast::<u8>(), 0xA5, page);
        let guard = base.cast::<u8>().add(page);
        let mut old = 0u32;
        assert_ne!(
            VirtualProtect(guard.cast(), page, PAGE_NOACCESS, &mut old),
            0,
            "VirtualProtect(PAGE_NOACCESS) failed"
        );

        let key = [0x0102_0304u32; 8];
        let mut out = [0u8; 40 * 32];
        for platform in platforms_to_test() {
            for &n in &[1usize, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24, 31, 32, 40] {
                let block: &[u8; 64] = &*guard.sub(64).cast::<[u8; 64]>();
                let inputs = vec![block; n];
                platform.hash_many(
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
            for &n in &[1usize, 2, 3, 4, 5, 8, 9, 15, 16] {
                let block: &[u8; 1024] = &*guard.sub(1024).cast::<[u8; 1024]>();
                let inputs = vec![block; n];
                platform.hash_many(
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
        }

        assert_ne!(VirtualFree(base, 0, MEM_RELEASE), 0, "VirtualFree failed");
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

    let arrays64: Vec<[u8; 64]> = (0u8..17)
        .map(|lane| [lane.wrapping_mul(11).wrapping_add(5); 64])
        .collect();
    for platform in platforms_to_test() {
        for n in [1usize, 2, 3, 4, 8, 17] {
            let inputs: Vec<&[u8; 64]> = arrays64[..n].iter().collect();
            let mut got = vec![0u8; n * 32];
            let mut want = vec![0u8; n * 32];
            platform.hash_many(
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
            assert_eq!(
                got, want,
                "64-byte counter wrap diverged on {platform:?} at n={n}"
            );
        }

        let arrays1024: Vec<[u8; 1024]> = (0u8..16)
            .map(|lane| [lane.wrapping_mul(13).wrapping_add(7); 1024])
            .collect();
        for n in [1usize, 2, 4, 5, 8, 16] {
            let inputs: Vec<&[u8; 1024]> = arrays1024[..n].iter().collect();
            let mut got = vec![0u8; n * 32];
            let mut want = vec![0u8; n * 32];
            platform.hash_many(
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
            assert_eq!(
                got, want,
                "1 KiB counter wrap diverged on {platform:?} at n={n}"
            );
        }
    }
}
