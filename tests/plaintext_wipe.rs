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

/// How many same-sized allocations the failure-path window can hold. `decrypt` makes a
/// handful; the test asserts the window did not overflow so a pathological refactor cannot
/// silently push the real buffer out of the set.
const MAX_WATCHED: usize = 64;

static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
static SAW_RESIDUE: AtomicBool = AtomicBool::new(false);
/// Every same-sized allocation made while `ARM_ALLOC` is set, up to `MAX_WATCHED`. The
/// failure path's plaintext buffer is whichever of these `decrypt` filled, and the test
/// cannot know which in advance: latching only the *first* match let a scratch allocation
/// of the same size stand in for it, so a refactor that added one would hide a missing
/// wipe (measured: a same-sized `vec![0u8; n]` after `check_lengths` plus both failure
/// wipes deleted left this test at `2 passed`). Watching all of them puts the real buffer
/// in the set. `SAW_WATCHED_FREE` is the liveness witness: without it a `mem::forget` of
/// the buffer passes the residue check by never freeing anything.
static ARM_ALLOC: AtomicBool = AtomicBool::new(false);
static WATCHED: [AtomicUsize; MAX_WATCHED] = [const { AtomicUsize::new(0) }; MAX_WATCHED];
static WATCHED_COUNT: AtomicUsize = AtomicUsize::new(0);
static SAW_WATCHED_FREE: AtomicBool = AtomicBool::new(false);
/// libtest runs the tests in a binary concurrently; the watch state is global.
static SERIAL: Mutex<()> = Mutex::new(());

// SAFETY: this forwards every allocation to `System` unchanged. The only extra work is a
// read of a still-live allocation in `dealloc`, before it is handed to `System`; that read
// is confined to buffers the test recorded while `ARM_ALLOC` was set (allocations the
// window's own `decrypt` made, or the `Plaintext` the successful test owns), so no memory
// the test did not allocate is read.
unsafe impl GlobalAlloc for WatchAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller of `GlobalAlloc::alloc` upholds the layout contract, and this
        // forwards it unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if ARM_ALLOC.load(Ordering::SeqCst) && layout.size() == WATCH_LEN.load(Ordering::SeqCst) {
            let i = WATCHED_COUNT.fetch_add(1, Ordering::SeqCst);
            if i < MAX_WATCHED {
                WATCHED[i].store(ptr as usize, Ordering::SeqCst);
            }
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller of `GlobalAlloc::realloc` guarantees that `ptr` is currently
        // allocated with `layout`; the arguments are forwarded to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if ARM_ALLOC.load(Ordering::SeqCst) && new_size == WATCH_LEN.load(Ordering::SeqCst) {
            let i = WATCHED_COUNT.fetch_add(1, Ordering::SeqCst);
            if i < MAX_WATCHED {
                WATCHED[i].store(new as usize, Ordering::SeqCst);
            }
        }
        new
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let len = WATCH_LEN.load(Ordering::SeqCst);
        let n = WATCHED_COUNT.load(Ordering::SeqCst).min(MAX_WATCHED);
        for slot in WATCHED.iter().take(n) {
            if slot.load(Ordering::SeqCst) != ptr as usize {
                continue;
            }
            SAW_WATCHED_FREE.store(true, Ordering::SeqCst);
            if layout.size() >= len && len != 0 {
                // SAFETY: `ptr` is the allocation being deallocated, `len` is no larger than
                // its layout size, and a buffer recorded while the window was armed was
                // initialized (a zeroed or decrypt-filled allocation owned by this test).
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                if bytes.contains(&0xA7) {
                    SAW_RESIDUE.store(true, Ordering::SeqCst);
                }
            }
            slot.store(0, Ordering::SeqCst);
        }
        let watch = WATCH_PTR.load(Ordering::SeqCst);
        if watch != 0 && watch == ptr as usize {
            if layout.size() >= len && len != 0 {
                // SAFETY: as above -- the `Plaintext` buffer the successful test recorded.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                if bytes.contains(&0xA7) {
                    SAW_RESIDUE.store(true, Ordering::SeqCst);
                }
            }
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
/// and tag, but a corrupted ciphertext, decrypts under the correct keystream (leaving
/// most of the known 0xA7 plaintext in the buffer), then rejects because the recomputed
/// tag differs, and must wipe the internal buffer before freeing it. Tampering with the
/// tag instead would change the KDF input and make the recovered buffer pseudorandom,
/// so the 0xA7 residue check would be probabilistic; this is the meaningful sentinel.
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
    let mut bad_ciphertext = ciphertext.clone();
    bad_ciphertext[0] ^= 1;

    SAW_RESIDUE.store(false, Ordering::SeqCst);
    SAW_WATCHED_FREE.store(false, Ordering::SeqCst);
    WATCHED_COUNT.store(0, Ordering::SeqCst);
    WATCH_LEN.store(message.len(), Ordering::SeqCst);
    ARM_ALLOC.store(true, Ordering::SeqCst);
    let error = decrypt(&key, &nonce, aad, &bad_ciphertext, &tag).unwrap_err();
    ARM_ALLOC.store(false, Ordering::SeqCst);
    let watched = WATCHED_COUNT.load(Ordering::SeqCst);

    assert_eq!(error, Error::AuthenticationFailed);
    assert!(
        watched <= MAX_WATCHED,
        "the failure path made {watched} same-sized allocations, more than the \
         {MAX_WATCHED} the watch set holds: the real plaintext buffer may have been pushed \
         out of the watched set, so a missing wipe could go unseen. Raise MAX_WATCHED."
    );
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
