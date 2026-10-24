//! Temporary probe for the BLAKE3 1.8.7 `hash_many` tail over-read.
//!
//! Place a 64-byte block at the last 64 bytes of a readable page, make the next page
//! inaccessible, and call the public `Platform::hash_many` with 2/3/4 inputs. The
//! reported AVX2/AVX-512 2/4-wide tail loads from `inputs[0]` at +16/+32/+48, so the
//! guarded input should fault before the fix and run clean after it.

use blake3::platform::Platform;
use blake3::IncrementCounter;

#[cfg(windows)]
fn guarded_block() -> &'static [u8; 64] {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(
            lp_address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
    }

    const PAGE: usize = 4096;
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 4;
    const PAGE_NOACCESS: u32 = 1;

    // SAFETY: a fresh two-page reservation; the second page is made inaccessible.
    unsafe {
        let base = VirtualAlloc(
            std::ptr::null_mut(),
            2 * PAGE,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        );
        assert!(!base.is_null(), "VirtualAlloc failed");
        let mut old = 0u32;
        assert_ne!(
            VirtualProtect(
                (base as *mut u8).add(PAGE) as *mut c_void,
                PAGE,
                PAGE_NOACCESS,
                &mut old
            ),
            0,
            "VirtualProtect failed"
        );
        // The last 64 bytes of the first page: a valid `[u8; 64]` that ends exactly at
        // the guard page.
        &*((base as *mut u8).add(PAGE - 64) as *const [u8; 64])
    }
}

#[cfg(unix)]
fn guarded_block() -> &'static [u8; 64] {
    use std::alloc::{alloc, Layout};

    const PAGE: usize = 4096;
    let layout = Layout::from_size_align(2 * PAGE, PAGE).expect("layout");
    // SAFETY: a fresh two-page allocation; the first page is initialised and the
    // second is made inaccessible. The allocation is intentionally leaked for the
    // process lifetime, because the probe hands out a `'static` reference into it.
    unsafe {
        let base = alloc(layout);
        assert!(!base.is_null(), "two-page allocation failed");
        std::ptr::write_bytes(base, 0xA5, PAGE);
        let guard = base.add(PAGE);
        assert_eq!(
            libc::mprotect(guard.cast(), PAGE, libc::PROT_NONE),
            0,
            "mprotect(PROT_NONE) failed"
        );
        &*(guard.sub(64) as *const [u8; 64])
    }
}

#[cfg(not(any(windows, unix)))]
fn guarded_block() -> &'static [u8; 64] {
    // No guard page on this platform: the probe still exercises the call shape, but
    // it cannot claim the boundary property. The Linux/Windows paths above and the
    // `PROT_NONE` test in `tests/blake3_fork_equivalence.rs` are the real checks.
    println!("note: no guard page on this platform; this run is a smoke test only");
    Box::leak(Box::new([0xA5u8; 64]))
}

fn main() {
    let platform = Platform::detect();
    println!("platform: {platform:?}");
    let guarded = guarded_block();
    let normal = [0xA5u8; 64];
    let key = [0u32; 8];
    for n in [2usize, 3, 4, 8] {
        let mut out = vec![0u8; n * 32];
        let inputs: Vec<&[u8; 64]> = (0..n)
            .map(|i| if i == 0 { guarded } else { &normal })
            .collect();
        println!("calling hash_many with n={n}");
        platform.hash_many(&inputs, &key, 0, IncrementCounter::No, 0, 0, 0, &mut out);
        println!("n={n}: returned, first byte {}", out[0]);
    }
}
