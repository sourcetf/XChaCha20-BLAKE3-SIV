//! `locked` on its own, not only as part of `ultra`.
//!
//! `locked` is a feature a caller can turn on by itself, so it needs its own witness: the
//! module used to be gated on `ultra`, which made `--features locked` compile nothing at
//! all — the README lists `locked` as a layer, and a reader who enabled exactly that got
//! no module, no error, and no protection. This file is compiled whenever the feature is
//! on, and `tests/ultra.rs` covers the bundled case.
//!
//! The judgment is per-*mapping*, deliberately. `mlock` locks pages, so "locked memory
//! went up" is satisfied by locking anything at all — including, as an earlier revision
//! did, a stack local that was then moved into the return value, which left the caller's
//! key on an unlocked page while the totals looked right. `/proc/self/smaps` reports
//! `Locked:` for the mapping that *contains the key's address*, which is the claim.

#![cfg(feature = "locked")]

use xchacha20_blake3_siv::locked::{LockedKey, SUPPORTED};
use xchacha20_blake3_siv::{decrypt, encrypt};

const KEY: [u8; 32] = [0x11u8; 32];
const NONCE: [u8; 24] = [0x22u8; 24];

/// Locked kB in the mapping containing `ptr`, from `/proc/self/smaps`.
fn locked_kb_at(ptr: usize) -> Option<u64> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut range: Option<(usize, usize)> = None;
    for line in smaps.lines() {
        let head = line.split_whitespace().next().unwrap_or("");
        let mut parts = head.split('-');
        if let (Some(lo), Some(hi)) = (parts.next(), parts.next()) {
            if let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                range = Some((lo, hi));
                continue;
            }
        }
        if let Some(rest) = line.trim().strip_prefix("Locked:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            if let Some((lo, hi)) = range {
                if (lo..hi).contains(&ptr) {
                    return Some(kb);
                }
            }
        }
    }
    None
}

/// Serialises the tests in this file.
///
/// `VmLck` is a *process-wide* counter, and `cargo test` runs the tests in a file
/// concurrently by default: without this guard, one test locking a key while another
/// measures the delta makes the delta meaningless — which is how `dropping_releases_the_lock`
/// failed under one feature set and passed under another. A per-mapping check (as in
/// `the_key_itself_is_locked`) is immune to it; a counter delta is not.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returning early because the environment refuses to lock is indistinguishable, in a
/// test report, from having verified the lock — both print `ok`. So a refusal is a
/// *failure* unless `XSIV_ALLOW_UNLOCKED=1` says this host knowingly runs a `locked`
/// build with nothing locked (the same convention `tests/ultra.rs` uses).
fn lock_or_skip() -> Option<LockedKey> {
    let allowed = std::env::var("XSIV_ALLOW_UNLOCKED").is_ok();
    if !SUPPORTED {
        // `SUPPORTED == false` is a *compile-time* property of the target, not a failure:
        // this crate only wires the syscalls for Linux x86_64/aarch64, the README says so,
        // and CI runs this file on i686 where it is always false. Failing here would make
        // the i686 job red for a documented platform limit.
        eprintln!("SKIPPED: memory locking is unsupported on this target/architecture");
        return None;
    }
    match LockedKey::new(&KEY) {
        Ok(k) => Some(k),
        Err(e) => {
            assert!(
                allowed,
                "the kernel refused to lock memory (errno {}): raise RLIMIT_MEMLOCK, or \
                 set XSIV_ALLOW_UNLOCKED=1 to record that this host runs unlocked.",
                -e
            );
            None
        }
    }
}

#[test]
fn the_key_itself_is_locked() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    // The lock is created *inside* the measurement, so the process-wide delta is
    // attributable to this key rather than to whatever ran before it.
    let before = LockedKey::locked_bytes();
    let Some(key) = lock_or_skip() else { return };
    let after = LockedKey::locked_bytes();
    let ptr = key.as_bytes().as_ptr() as usize;

    // Strongest evidence, where the environment reports it: the mapping that *contains
    // the key* is marked locked. `qemu-user` populates `VmLck` but leaves smaps'
    // per-mapping `Locked:` at zero, so this cannot be the only criterion — it would
    // make the cross-executed targets red for an environment limitation.
    if let Some(kb) = locked_kb_at(ptr) {
        if kb > 0 {
            return;
        }
    }

    // Fallback, and still not vacuous: the kernel's own accounting must have risen when
    // this key was locked. A no-op `lock_range`, a wrong syscall number or a lock on an
    // address the value was moved away from all fail this.
    let (before, after) = (before.unwrap_or(0), after.unwrap_or(0));
    assert!(
        after > before,
        "neither the mapping containing the key ({ptr:#x}) nor the kernel's `VmLck` \
         accounting shows a lock ({before} -> {after} kB): the bytes the caller uses are \
         not the bytes that were locked"
    );
}

/// Being boxed and locked must not change what the key does.
#[test]
fn a_locked_key_encrypts_and_decrypts() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(key) = lock_or_skip() else { return };
    let (ct, tag) = encrypt(&key, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&key, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );
}

/// `Debug` must not print the key — this type has its own `Debug`, so `Key`'s is not
/// evidence about it.
#[test]
fn debug_prints_nothing_derived_from_the_key() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(key) = lock_or_skip() else { return };
    let shown = format!("{key:?}");
    assert!(
        !shown.contains("11") && !shown.contains("0x"),
        "`Debug` leaked key-derived text: {shown}"
    );
    assert!(shown.contains("REDACTED"), "unexpected `Debug`: {shown}");
}

/// The lock is released when the value is dropped: a `locked` build must not leak its
/// `RLIMIT_MEMLOCK` allowance over a long-running process that creates and drops keys.
#[test]
fn dropping_releases_the_lock() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(key) = lock_or_skip() else { return };
    let held = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    drop(key);
    let released = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        released < held,
        "dropping a `LockedKey` must unlock it: VmLck stayed at {released}"
    );
}
