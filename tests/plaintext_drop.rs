//! Behavioural witness for `Plaintext::drop`'s wipe.
//!
//! `tests/security.rs` counts the wipe statements as *text*, which is the only witness
//! a write with no return value can have from inside the crate. This test observes the
//! bytes themselves: a global allocator records the contents of the `Plaintext` buffer
//! at the moment it is freed, before the allocator can reuse it. The first half is a
//! control -- a plain `Vec` must be seen **not** wiped -- so the assertion cannot pass
//! because the hook never ran.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use xchacha20_blake3_siv::{decrypt, encrypt, KEY_LEN, NONCE_LEN};

/// Address whose deallocation is being watched (0 = none).
static WATCH: AtomicUsize = AtomicUsize::new(0);
/// Whether the watched allocation was all zero when it was freed.
static WIPED: AtomicBool = AtomicBool::new(false);

struct WatchingAllocator;

// SAFETY: every method forwards to `System` with the same arguments. `dealloc` reads
// `layout.size()` bytes only while the allocation is still live (the read happens before
// the forwarding `dealloc`), and touches no state that can allocate.
unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCH.load(Ordering::SeqCst) {
            // SAFETY: `ptr`/`layout` describe a live allocation that has not been freed
            // yet; the bytes are initialised (they held data), and nothing else writes
            // through this pointer during the read.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            WIPED.store(bytes.iter().all(|&b| b == 0), Ordering::SeqCst);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

#[test]
fn plaintext_buffer_is_zeroed_before_it_is_freed() {
    // Control: a `Vec`'s drop does not wipe. The allocator must observe this buffer as
    // non-zero, or the hook is not seeing the free and the real assertion is vacuous.
    let control = vec![0xAAu8; 64];
    WATCH.store(control.as_ptr() as usize, Ordering::SeqCst);
    WIPED.store(true, Ordering::SeqCst);
    drop(control);
    assert!(
        !WIPED.load(Ordering::SeqCst),
        "control failed: the allocator did not observe a non-zero buffer at free time, \
         so this test cannot witness Plaintext's wipe either"
    );

    let key = [0x42u8; KEY_LEN];
    let nonce = [0x55u8; NONCE_LEN];
    let secret = b"a plaintext buffer whose bytes must not survive the drop";
    let (ct, tag) = encrypt(&key, &nonce, b"aad", secret).unwrap();
    let pt = decrypt(&key, &nonce, b"aad", &ct, &tag).unwrap();
    assert_eq!(pt.as_slice(), secret.as_slice());

    WATCH.store(pt.as_ptr() as usize, Ordering::SeqCst);
    WIPED.store(false, Ordering::SeqCst);
    drop(pt);

    assert!(
        WIPED.load(Ordering::SeqCst),
        "the Plaintext allocation was freed without being zeroed: its bytes would be \
         visible in the freed heap"
    );
}
