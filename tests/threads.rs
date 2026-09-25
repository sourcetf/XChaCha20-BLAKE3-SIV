//! Concurrent use: the crate must be correct when many threads call it at once.
//!
//! Nothing in the public API takes `&mut` on shared state, and the whole suite
//! runs single-threaded by default, so the one piece of global state the crate
//! *does* have is the interesting part: the cached AVX2 detection (`AVX2_CACHE`
//! in `src/lib.rs`, an `AtomicU8`).  A single-threaded test cannot reach the case
//! where several threads populate that cache from cold, so this test compares the
//! threads' results with each other rather than against a reference computed up
//! front — computing one would warm the cache and remove the case under test.
//!
//! The run that makes this concrete is ThreadSanitizer, which is why the test
//! keeps every thread on the same inputs:
//!
//! ```text
//! RUSTFLAGS='-Zsanitizer=thread' cargo +nightly test --test threads \
//!     --target x86_64-unknown-linux-gnu
//! ```
//!
//! A data race in the cache would not corrupt the derived material (the answer
//! CPUID returns is the same whichever thread asks), so the assertions here are
//! about the *outputs* staying identical across threads; the race itself is what
//! TSAN reports.

use std::thread;

use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, TAG_LEN,
};

/// More threads than this machine has cores, so the first calls genuinely race.
const THREADS: usize = 32;
const ROUNDS: usize = 64;

/// **Negative control.** Deliberately races, and `tools/tsan.sh` requires
/// ThreadSanitizer to *report* it — the same idea as the ctgrind control in
/// `tests/ctgrind.rs`, and for the same reason: a "clean" run from a sanitizer
/// whose flag was dropped somewhere looks exactly like a clean run from a working
/// one.
///
/// Never run this outside a sanitizer run.  An unsynchronised write to a shared
/// `static` *is* a data race, which is the point — it is what TSAN is asked to
/// find — and it must not run under any other configuration.  It is `#[ignore]`d
/// so that a plain `cargo test` cannot reach it.
#[test]
#[ignore = "deliberately races; run under ThreadSanitizer, which tools/tsan.sh does"]
fn deliberate_race_is_detected() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static mut COUNTER: u64 = 0;
    static START: AtomicBool = AtomicBool::new(false);

    let handles: Vec<_> = (0..2)
        .map(|_| {
            thread::spawn(|| {
                while !START.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..1_000 {
                    // SAFETY: deliberately unsound. This is the defect under test.
                    unsafe {
                        let p = core::ptr::addr_of_mut!(COUNTER);
                        let v = core::ptr::read_volatile(p);
                        core::ptr::write_volatile(p, v.wrapping_add(1));
                    }
                }
            })
        })
        .collect();

    START.store(true, Ordering::Release);
    for h in handles {
        h.join().expect("thread");
    }
    core::hint::black_box(unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COUNTER)) });
}

#[test]
fn concurrent_use_agrees_across_threads() {
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let aad = b"threads".to_vec();
    // 777 bytes spans the scalar tail and both SIMD widths (64/256/512), so the
    // dispatch decision is exercised in every thread, not just the first.
    let msg: Vec<u8> = (0..777u32).map(|i| (i % 251) as u8).collect();

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let aad = aad.clone();
            let msg = msg.clone();
            thread::spawn(move || {
                let mut last = None;
                for _ in 0..ROUNDS {
                    let (ct, tag) = encrypt(&key, &nonce, &aad, &msg).expect("encrypt");
                    assert_eq!(tag.len(), TAG_LEN);
                    let back = decrypt(&key, &nonce, &aad, &ct, &tag).expect("decrypt");
                    assert_eq!(back.as_slice(), msg.as_slice());

                    // The detached API derives the same material, so a race in
                    // the derivation would surface here as well.
                    let mut buf = msg.clone();
                    let detached_tag =
                        encrypt_in_place_detached(&key, &nonce, &aad, &mut buf).expect("encrypt");
                    assert_eq!(buf, ct);
                    assert_eq!(detached_tag, tag);
                    decrypt_in_place_detached(&key, &nonce, &aad, &mut buf, &detached_tag)
                        .expect("decrypt");
                    assert_eq!(buf, msg);

                    last = Some((ct, tag));
                }
                last.expect("at least one round")
            })
        })
        .collect();

    let results: Vec<(Vec<u8>, [u8; TAG_LEN])> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();

    for (ct, tag) in &results {
        assert_eq!(ct, &results[0].0, "threads disagree on the ciphertext");
        assert_eq!(tag, &results[0].1, "threads disagree on the tag");
    }
    assert_ne!(results[0].0.as_slice(), msg.as_slice());
}
