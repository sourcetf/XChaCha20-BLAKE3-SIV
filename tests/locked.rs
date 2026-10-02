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

use xchacha20_blake3_siv::locked::{deny_debugging, is_dumpable, LockedKey, SUPPORTED};
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

/// The `VmFlags` of the mapping containing `ptr`, from `/proc/self/smaps`.
///
/// The flags are where `VM_DONTDUMP` shows up as `dd`, which is the only place a process
/// can see that it is excluded from core dumps — `Locked:` tells you about `mlock`, not
/// about the dump advice, and the two are set and cleared by different syscalls.
fn flags_at(ptr: usize) -> Option<String> {
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
        if let Some(rest) = line.trim().strip_prefix("VmFlags:") {
            if let Some((lo, hi)) = range {
                if (lo..hi).contains(&ptr) {
                    return Some(rest.trim().to_string());
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

/// Unlocking must also **undo the core-dump exclusion**.
///
/// This is the test that was missing, and its absence let a documented behaviour not exist:
/// `madvise(MADV_DONTDUMP)` sets `VM_DONTDUMP` on the *mapping*, that flag is sticky, and
/// `munlock` cannot clear it — only `MADV_DODUMP` (17) can. So an `unlock_range` that only
/// calls `munlock` leaves the page excluded from core dumps, and because `LockedKey` gives
/// its page back to the allocator on drop, **unrelated** data that later lands there is
/// silently excluded too, for the rest of the process's life.
///
/// The assertion has to be about the kernel's own view, which is why it reads `VmFlags`
/// from `/proc/self/smaps`: no API of this crate exposes the dump advice, and a test that
/// merely called `unlock_range` and checked nothing would have passed against the bug for
/// as long as it existed (it did: `CHANGELOG.md` claimed the `MADV_DODUMP` call was there).
#[test]
fn unlocking_restores_core_dump_inclusion() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    if !SUPPORTED {
        // Same convention as `lock_or_skip`: `SUPPORTED == false` is a compile-time property
        // of the target (the module compiles its `ENOSYS` arm on i686, ppc64 and anything
        // not Linux x86_64/aarch64), so `lock_range` here returns `-ENOSYS` by construction
        // and asserting on it would make the i686 and big-endian jobs red for a documented
        // platform limit. Measured: they were, before this branch existed.
        eprintln!("SKIPPED: memory locking is unsupported on this target/architecture");
        return;
    }

    // A live buffer: `lock_range`/`unlock_range` page-align the range themselves, so this
    // need not be page-aligned. It is deliberately not a `LockedKey`, because that type
    // frees its page on drop and this test wants to read the mapping's flags after
    // unlocking.
    let mut buf = vec![0u8; 4096];
    let ptr = buf.as_ptr() as usize;

    let Some(before) = flags_at(ptr) else {
        eprintln!("SKIPPED: /proc/self/smaps is not readable here");
        return;
    };
    assert!(
        !before.split_whitespace().any(|f| f == "dd"),
        "the buffer starts out excluded from core dumps, so this test cannot tell the \
         exclusion it sets from one that was already there: {before}"
    );

    match xchacha20_blake3_siv::locked::lock_range(buf.as_ptr(), buf.len()) {
        Ok(()) => {}
        Err(e) => {
            assert!(
                std::env::var("XSIV_ALLOW_UNLOCKED").is_ok(),
                "the kernel refused to lock memory (errno {}); raise RLIMIT_MEMLOCK or set \
                 XSIV_ALLOW_UNLOCKED=1 to record that this host runs unlocked",
                -e
            );
            return;
        }
    }

    let locked = flags_at(ptr).expect("smaps is readable");
    if !locked.split_whitespace().any(|f| f == "lo") {
        // The channel is not describing *our own* mapping, so nothing below would mean
        // anything. Measured, under `qemu-aarch64` on this host: a successful `mlock`
        // leaves `VmFlags` at `rd wr mr mw` with neither `lo` nor `dd`, and the raw
        // `madvise` result is not visible in the file either — the emulator keeps the
        // guest's mappings in its own bookkeeping and does not synthesize this field.
        //
        // Skipping here cannot hide the defect this test exists for: a broken `mlock` is
        // caught earlier and elsewhere (`the_key_itself_is_locked` reads `Locked:`, which
        // *is* reported, and this function refuses to proceed unless `lock_range` returned
        // `Ok`), and the *call itself* — the `MADV_DODUMP` line that was missing for as
        // long as the bug existed — is pinned against the shipped source by
        // `the_dump_advice_is_issued_on_the_right_range` below, which needs no kernel
        // cooperation at all. What is genuinely not verified on such a host is the
        // *effect*, and saying so is the point of printing this.
        xchacha20_blake3_siv::locked::unlock_range(buf.as_ptr(), buf.len());
        eprintln!(
            "SKIPPED: VmFlags does not report `lo` for the mapping that holds the buffer, so \
             this environment does not reflect the guest's memory advice here (qemu-user does \
             not); the effect of MADV_DODUMP is then unobservable, and the call is checked at \
             source level instead. flags: {locked}"
        );
        return;
    }
    assert!(
        locked.split_whitespace().any(|f| f == "dd"),
        "locking left the range in core dumps: `lo` and `dd` are set by two different \
         syscalls and only one of them is the lock. flags: {locked}"
    );

    xchacha20_blake3_siv::locked::unlock_range(buf.as_ptr(), buf.len());

    let unlocked = flags_at(ptr).expect("smaps is readable");
    assert!(
        !unlocked.split_whitespace().any(|f| f == "dd"),
        "the range is still excluded from core dumps after `unlock_range`: VM_DONTDUMP is \
         per-mapping and sticky, and `munlock` cannot clear it — that is what this test \
         exists for. Unrelated allocations that reuse the page inherit the exclusion for \
         the rest of the process's life. flags: {unlocked}"
    );
    assert!(
        !unlocked.split_whitespace().any(|f| f == "lo"),
        "the range is still locked after `unlock_range`: {unlocked}"
    );

    // Keep the buffer alive to the end, so neither `flags_at` read could have been of a
    // freed mapping that happened to be re-mapped.
    buf[0] = 1;
    assert_eq!(buf[0], 1);
}

/// The text of the shipped source, so the assertions below are about what a user compiles
/// rather than about a copy that can drift.
const LIB: &str = include_str!("../src/lib.rs");

/// Every brace-matched block in `LIB` that starts at `needle`, `needle` included.
///
/// The same helper `tests/decision_scope.rs` uses; it is duplicated rather than shared
/// because a test binary cannot import another test binary's items, and a third file
/// existing only to hold it would be a file to keep in `tests/README.md` for four lines.
fn brace_blocks(needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = LIB;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i..];
        let open = after.find('{').expect("block without a body");
        let mut depth = 0usize;
        let mut end = None;
        for (n, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + n);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("unbalanced braces");
        out.push(after[..=end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// The `BLAKE3(key)` integrity tag is wiped in **both** callers, before any early exit.
///
/// The value is a hash of the key — key material by this crate's own classification — and
/// `integrity_tag` returning it leaves a copy in the caller's frame that the function cannot
/// reach. `check_integrity` is `#[inline(never)]` and runs on every `as_bytes()`, i.e. on
/// every encryption and decryption through a `LockedKey`, so a missed wipe there is a residue
/// on the ordinary stack on the hot path; and its `panic!` path unwinds without running any
/// statement after it, so the wipe has to come *before* the branch. A wiped stack local is not
/// observable from a test, so this is a source-shape assertion, like the ones above.
#[test]
fn the_integrity_tag_is_wiped_in_both_callers() {
    // `integrity_tag` must not *return* the tag: a returning version kept a copy in its own
    // frame, which no caller can reach, and `tools/stack_residue.sh` measured exactly that as
    // an 8-byte residue in the `locked` case. Writing through the caller's slice is what
    // leaves a single copy for the caller to wipe.
    assert!(
        LIB.contains("fn integrity_tag(key: &[u8], out: &mut [u8; KEY_TAG_LEN])"),
        "integrity_tag no longer writes through a caller slice, so it keeps its own copy of \
         a hash of the key in a frame no wipe reaches"
    );

    let news = brace_blocks("pub fn new(key: &[u8; crate::KEY_LEN])");
    assert_eq!(news.len(), 1, "expected exactly one `LockedKey::new`");
    let new = &news[0];
    let wipe = new
        .find("crate::zeroize_array(&mut tag);")
        .expect("LockedKey::new no longer wipes the integrity tag it computed");
    let fallible = new
        .find("lock_range(page.as_ptr(), page.len())?;")
        .expect("LockedKey::new no longer calls lock_range");
    assert!(
        wipe < fallible,
        "the tag wipe must precede the fallible `lock_range`, or the `?` returns through it"
    );

    let checks = brace_blocks("fn check_integrity(&self, bytes: &[u8; crate::KEY_LEN])");
    assert_eq!(checks.len(), 1, "expected exactly one `check_integrity`");
    let check = &checks[0];
    let wipe = check
        .find("crate::zeroize_array(&mut expected);")
        .expect("check_integrity no longer wipes the tag it computed");
    let branch = check
        .find("if !bool::from(ok)")
        .expect("check_integrity no longer branches on the comparison");
    assert!(
        wipe < branch,
        "the wipe must precede the `if`, or the panic path leaves the tag in the frame"
    );
}

/// The advice constants are the ABI's, and both are actually passed to `madvise`.
///
/// This exists because the effect of `MADV_DODUMP` is only *observable* on a host whose
/// `/proc/self/smaps` describes this process's own mappings — see the skip in
/// `unlocking_restores_core_dump_inclusion` — and because the original defect was invisible
/// to every other kind of check: the constant did not exist and the call was never made,
/// while a commit message said it was. Three things are pinned against the shipped text,
/// each of which is a defect the crate has had or could have:
///
/// * **the values.** `MADV_DONTDUMP` is 16 and `MADV_DODUMP` is 17
///   (`asm-generic/mman-common.h`). A wrong one is not an error the kernel reports — 4 is
///   `MADV_DONTNEED`, which *discards* the pages it is applied to, and this module shipped
///   with 4 at one point (`CHANGELOG.md`);
/// * **the call, with three arguments.** `madvise(addr, length, advice)` takes three, and
///   the module also shipped a version that passed two through `syscall2` — which put the
///   advice in the *length* slot and left the advice undefined;
/// * **a page-aligned range**, because `madvise` (unlike `mlock`) rejects an unaligned
///   address with `EINVAL`. The third shipped defect.
#[test]
fn the_dump_advice_is_issued_on_the_right_range() {
    assert!(
        LIB.contains("const MADV_DONTDUMP: usize = 16;"),
        "MADV_DONTDUMP must be 16 (asm-generic/mman-common.h)"
    );
    assert!(
        LIB.contains("const MADV_DODUMP: usize = 17;"),
        "MADV_DODUMP must be 17 (asm-generic/mman-common.h)"
    );

    // Two definitions each: the real one, and the `ENOSYS` stub for other targets. The
    // real one is the block that names the syscall.
    let lock: Vec<String> = brace_blocks("pub fn lock_range(")
        .into_iter()
        .filter(|b| b.contains("NR_MLOCK"))
        .collect();
    assert_eq!(lock.len(), 1, "one syscall-backed `lock_range` expected");
    assert!(
        lock[0].contains("syscall3(NR_MADVISE, start, end - start, MADV_DONTDUMP)"),
        "lock_range must set the dump exclusion with a three-argument madvise over the \
         page-aligned range"
    );

    let unlock: Vec<String> = brace_blocks("pub fn unlock_range(")
        .into_iter()
        .filter(|b| b.contains("NR_MUNLOCK"))
        .collect();
    assert_eq!(
        unlock.len(),
        1,
        "one syscall-backed `unlock_range` expected"
    );
    assert!(
        unlock[0].contains("syscall3(NR_MADVISE, start, end - start, MADV_DODUMP)"),
        "unlock_range must undo the dump exclusion with `MADV_DODUMP`: `VM_DONTDUMP` is \
         per-mapping and sticky, so `munlock` alone leaves the range — and whatever the \
         allocator puts there next — out of every core dump the process writes afterwards"
    );
    assert!(
        unlock[0].contains("syscall2(NR_MUNLOCK"),
        "unlock_range must still unlock; reverting the advice is an addition, not a \
         replacement"
    );
    for (name, body) in [("lock_range", &lock[0]), ("unlock_range", &unlock[0])] {
        assert!(
            body.contains("& !(ps - 1)") && body.contains("saturating_add(ps - 1)"),
            "{name} must expand its range to whole pages: madvise rejects unaligned \
             addresses, and mlock does not"
        );
    }
}

/// A locked key can be moved to a worker thread, read there, and dropped there.
///
/// `LockedKey` owns a raw pointer, so the compiler derives neither `Send` nor `Sync`, and the
/// module states both by hand. A `SAFETY` comment is not evidence, so this test uses the
/// capability instead: the key is created on the test thread, read on another, and dropped
/// there — which is where the wipe, `munlock`, `MADV_DODUMP` and the free all run, i.e. the
/// whole of the type's interaction with the kernel happens off the creating thread. Before
/// the impls existed this file did not compile, so the failure mode is a build error rather
/// than a subtle one; the impls are `unsafe`, which is why the claim is exercised at all.
#[test]
fn a_locked_key_can_move_to_another_thread() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    // Compile-time half: runs on every target and under every feature set, including the
    // ones where `SUPPORTED` is false and the runtime half below returns early.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LockedKey>();

    let Some(key) = lock_or_skip() else {
        return;
    };

    let handle = std::thread::spawn(move || {
        // Read through `&self` here, then let `key` drop here.
        let first = key.as_bytes()[0];
        let deref_first = key[0];
        (first, deref_first)
    });
    assert_eq!(handle.join().unwrap(), (KEY[0], KEY[0]));
}

/// `deny_debugging` changes what the *kernel* allows, and the change can be undone.
///
/// This is the one attack class from `SECURITY-ANALYSIS.md` §8.2 that a library can answer in
/// software. Power, EM, laser faults, cold boot, Rowhammer and speculative execution are
/// properties of the machine; ptrace is not — the kernel refuses `PTRACE_MODE_ATTACH` for a
/// non-dumpable process even from the same user, and `/proc/<pid>/mem` goes with it.
///
/// The flag is read back from the kernel (`PR_GET_DUMPABLE`) rather than trusted from our own
/// bookkeeping, and **every path restores it**: this test runs inside the shared test binary,
/// and leaving it non-dumpable would remove core dumps for every other test in the process and
/// stop `strace`/`gdb` from attaching to a run that is failing — which is exactly when someone
/// wants them.
#[test]
fn deny_debugging_is_enforced_by_the_kernel_and_reversible() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    if !SUPPORTED {
        eprintln!("SKIPPED: prctl is not wired for this target/architecture");
        return;
    }

    let Some(before) = is_dumpable() else {
        eprintln!("SKIPPED: the kernel would not report the dumpable flag here");
        return;
    };
    if !before {
        eprintln!(
            "SKIPPED: the process is already non-dumpable, so this test cannot observe the \
             transition (something in the environment set it)"
        );
        return;
    }

    let previous = match deny_debugging() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "SKIPPED: prctl(PR_SET_DUMPABLE, 0) refused with errno {}",
                -e
            );
            return;
        }
    };
    // Arm the restore *now*, so it happens on a panic as well as on the success path. The doc
    // above says every path restores the flag, and until this guard existed that was false:
    // the two assertions below, or anything else that panicked in between, would have returned
    // through `Drop` without ever reaching the explicit restore at the end — leaving the whole
    // test binary non-dumpable, which costs every later test its core dump and stops `gdb` and
    // `strace` attaching to a run that is failing. That is exactly when someone wants them.
    let _armed = RestoresDumpable;
    assert_eq!(previous, 1, "the previous state should have been dumpable");
    assert_eq!(
        is_dumpable(),
        Some(false),
        "the kernel still reports the process as dumpable after `deny_debugging`"
    );

    // The consequence, observed rather than assumed: a non-dumpable process cannot open its
    // own memory through procfs. (Same-user `ptrace` fails for the same kernel check, which
    // would take a second process to demonstrate.)
    let mem = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/proc/self/mem");
    let denied = mem.is_err();
    if !denied {
        // Not asserted: procfs behaviour differs between kernels and container
        // configurations (an early kernel, or a namespace where the check passes). What *is*
        // asserted is the flag, which is the kernel's own account of the policy.
        eprintln!("NOTE: /proc/self/mem still opened while non-dumpable; flag check is the assert");
    }

    // Undo, and verify the undo. There is deliberately no public API for setting the flag
    // back — a library that can make a process *more* debuggable is a footgun — so the test
    // issues the syscall itself.
    let restored = set_dumpable(1);
    assert!(
        restored,
        "could not restore the dumpable flag: the rest of this test binary now runs without \
         core dumps or ptrace"
    );
    assert_eq!(is_dumpable(), Some(true), "the restore did not take");
}

/// `prctl(PR_SET_DUMPABLE, value)`, for the test's own cleanup.
///
/// `#[cfg]`-selected inline asm rather than a crate API: see the comment above.
fn set_dumpable(value: usize) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: isize;
        // SAFETY: prctl with PR_SET_DUMPABLE takes integers only and reads no pointer.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 157isize => ret,
                in("rdi") 4usize,
                in("rsi") value,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        return ret >= 0;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let ret: isize;
        // SAFETY: as above; 167 is prctl in the generic syscall table.
        unsafe {
            core::arch::asm!(
                "svc 0",
                inlateout("x8") 167isize => _,
                inlateout("x0") 4isize => ret,
                in("x1") value,
                options(nostack),
            );
        }
        return ret >= 0;
    }
    #[allow(unreachable_code)]
    {
        let _ = value;
        false
    }
}

/// Puts the process's dumpable flag back to `1` when it goes out of scope.
///
/// The safety net behind `deny_debugging_is_enforced_by_the_kernel_and_reversible`: a test that
/// flips process-wide state and then panics would otherwise leave every *later* test in the same
/// binary without core dumps and without a debuggable process, which is the opposite of what a
/// failing test needs. `Drop` runs on the panic path, so "every path restores it" is true by
/// construction rather than by discipline.
struct RestoresDumpable;

impl Drop for RestoresDumpable {
    fn drop(&mut self) {
        let _ = set_dumpable(1);
    }
}
