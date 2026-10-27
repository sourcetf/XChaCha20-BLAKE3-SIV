//! A behavioural witness for `Plaintext`'s drop wipe.
//!
//! The source-text guards in `tests/security.rs` count wipe statements; they cannot see
//! whether a wipe is compiled out, moved into an unexpanded macro, or hidden in a
//! multi-line `cfg` block. This test does not read the source: it watches the global
//! allocator, records the decrypted `Plaintext`'s buffer, drops the value, and checks the
//! bytes at the moment `dealloc` is called. `Plaintext::drop` wipes before the `Vec`
//! releases the block, so a missing wipe is visible as the original plaintext still being
//! present in a block that is about to be handed back to the allocator.
//!
//! The test is deliberately about the *returned* plaintext, the allocation an attacker
//! with a use-after-free or an allocator bug would read. Stack residue is a different
//! witness: every build now runs `scrub_stack` for the derivation region, and
//! `tools/stack_residue.sh` checks the master key and the `locked` integrity tag. This
//! test covers the heap copy the public API hands to the caller.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use xchacha20_blake3_siv::{decrypt, encrypt, Error};

struct WatchAlloc;

static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
static SAW_RESIDUE: AtomicBool = AtomicBool::new(false);
/// The first allocation of `WATCH_LEN` bytes made while `ARM_ALLOC` is set; the failure
/// path's plaintext buffer. `SAW_WATCHED_FREE` is its liveness witness: without it a
/// `mem::forget` of the buffer passes the residue check by never freeing anything.
static ARM_ALLOC: AtomicBool = AtomicBool::new(false);
static WATCH_ALLOC_PTR: AtomicUsize = AtomicUsize::new(0);
static SAW_WATCHED_FREE: AtomicBool = AtomicBool::new(false);
/// libtest runs the tests in a binary concurrently; the watch state is global.
static SERIAL: Mutex<()> = Mutex::new(());

// SAFETY: this forwards every allocation to `System` unchanged. The only extra work is a
// read of a still-live allocation in `dealloc`, before it is handed to `System`; the read
// is of the length recorded by the test, which is within the allocation the test owns.
unsafe impl GlobalAlloc for WatchAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller of `GlobalAlloc::alloc` upholds the layout contract, and this
        // forwards it unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if ARM_ALLOC.load(Ordering::SeqCst)
            && layout.size() == WATCH_LEN.load(Ordering::SeqCst)
            && WATCH_ALLOC_PTR.load(Ordering::SeqCst) == 0
        {
            WATCH_ALLOC_PTR.store(ptr as usize, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller of `GlobalAlloc::realloc` guarantees that `ptr` is currently
        // allocated with `layout`; the arguments are forwarded to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if ARM_ALLOC.load(Ordering::SeqCst)
            && new_size == WATCH_LEN.load(Ordering::SeqCst)
            && WATCH_ALLOC_PTR.load(Ordering::SeqCst) == 0
        {
            WATCH_ALLOC_PTR.store(new as usize, Ordering::SeqCst);
        }
        new
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watched_alloc = WATCH_ALLOC_PTR.load(Ordering::SeqCst);
        if watched_alloc == ptr as usize {
            SAW_WATCHED_FREE.store(true, Ordering::SeqCst);
        }
        let watch = WATCH_PTR.load(Ordering::SeqCst);
        // Inspect only the two pointers the test itself recorded. Scanning every buffer
        // of a matching size (the earlier `WATCH_ANY`) read allocations the test did not
        // own -- potentially uninitialized memory -- and could report a false residue.
        if (watch != 0 && watch == ptr as usize)
            || (watched_alloc != 0 && watched_alloc == ptr as usize)
        {
            let len = WATCH_LEN.load(Ordering::SeqCst);
            if layout.size() >= len && len != 0 {
                // SAFETY: `ptr` is the allocation being deallocated, `len` is no larger
                // than its layout size, and both the successful `Plaintext` and the
                // failure-path buffer are fully initialized (plaintext + wipe) before
                // this deallocation.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                if bytes.contains(&0xA7) {
                    SAW_RESIDUE.store(true, Ordering::SeqCst);
                }
            }
        }
        if watched_alloc == ptr as usize {
            WATCH_ALLOC_PTR.store(0, Ordering::SeqCst);
        }
        if watch == ptr as usize {
            WATCH_PTR.store(0, Ordering::SeqCst);
        }
        // SAFETY: the pointer/layout pair is the one being deallocated, forwarded to
        // `System` exactly once.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: WatchAlloc = WatchAlloc;

#[test]
fn plaintext_vec_is_wiped_before_deallocation() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 24];
    let aad = b"wipe-witness";
    let message = vec![0xA7u8; 4096];

    let (ciphertext, tag) = encrypt(&key, &nonce, aad, &message).unwrap();
    let plaintext = decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();
    assert_eq!(plaintext.as_slice(), message.as_slice());

    SAW_RESIDUE.store(false, Ordering::SeqCst);
    WATCH_LEN.store(message.len(), Ordering::SeqCst);
    WATCH_PTR.store(plaintext.as_slice().as_ptr() as usize, Ordering::SeqCst);
    drop(plaintext);

    assert_eq!(
        WATCH_PTR.load(Ordering::SeqCst),
        0,
        "the Plaintext allocation was never deallocated through the global allocator"
    );
    assert!(
        !SAW_RESIDUE.load(Ordering::SeqCst),
        "the Plaintext buffer still contained plaintext bytes (0xA7) when it was \
         deallocated: the drop wipe did not run"
    );
}

/// The same witness for the *failure* path of the allocating entry point: a correct key
/// with a tampered tag decrypts the known plaintext, then rejects and must wipe the
/// internal buffer before freeing it. `decrypt`'s own test can only observe the error
/// variant; this observes the bytes the allocator is about to hand out.
#[test]
fn decrypt_failure_wipes_internal_plaintext() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 24];
    let aad = b"wipe-witness";
    let message = vec![0xA7u8; 4096];

    let (ciphertext, tag) = encrypt(&key, &nonce, aad, &message).unwrap();
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    SAW_RESIDUE.store(false, Ordering::SeqCst);
    SAW_WATCHED_FREE.store(false, Ordering::SeqCst);
    WATCH_ALLOC_PTR.store(0, Ordering::SeqCst);
    WATCH_LEN.store(message.len(), Ordering::SeqCst);
    ARM_ALLOC.store(true, Ordering::SeqCst);
    let error = decrypt(&key, &nonce, aad, &ciphertext, &bad_tag).unwrap_err();
    ARM_ALLOC.store(false, Ordering::SeqCst);

    assert_eq!(error, Error::AuthenticationFailed);
    // Liveness: the failure path must actually free the buffer it decrypted into. Without
    // this, `mem::forget(plaintext)` leaks it and the residue assertion below passes by
    // never seeing a deallocation at all.
    assert!(
        SAW_WATCHED_FREE.load(Ordering::SeqCst),
        "a failed decrypt never deallocated the plaintext-sized buffer it allocated, so \
         the residue check below would be vacuous (a leaked buffer is not a wiped one)"
    );
    assert!(
        !SAW_RESIDUE.load(Ordering::SeqCst),
        "a failed decrypt deallocated a buffer still containing the unverified \
         plaintext (0xA7): the failure wipe did not run"
    );
}
