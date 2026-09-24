//! ctgrind-style constant-time verification, using valgrind's memcheck.
//!
//! # What this is
//!
//! `ctgrind` is an *approach*, not a tool: mark secret bytes as **undefined**
//! (poisoned) in valgrind's shadow memory, run the code, and let memcheck report
//! any conditional jump, memory index, or syscall argument that depends on them.
//! That is a mechanical answer to "does this branch on secret data?" — stronger
//! than reading the source, because it does not depend on the reader spotting
//! every path.
//!
//! The `ctgrind` crate is not available in this environment, and neither is
//! `ctgrind`'s C macro. But the machinery underneath is just a documented
//! valgrind *client request*: a magic instruction sequence that valgrind
//! recognises at translation time. That is reimplemented below, with the
//! instruction sequence and the request codes taken verbatim from valgrind
//! 3.24.0's own `valgrind.h` / `memcheck.h` (see the comments) rather than
//! recalled from memory.
//!
//! Outside valgrind the sequence executes as four rotates that cancel and a
//! no-op `xchg`, so every function here returns its default and has no effect.
//! The tests therefore pass trivially in a normal `cargo test` run; the verdict
//! comes from running the binary under valgrind, which `verify.sh --ctgrind`
//! does.
//!
//! # Why there is a test that is *supposed* to fail
//!
//! `deliberate_leak_is_detected` branches on a poisoned byte on purpose. Under
//! valgrind it must be reported, which is what proves the harness can see a leak
//! at all — a poisoning test that never fires is worse than none, because it
//! reads as a clean bill of health. It is `#[ignore]`d so the default run stays
//! green, and `verify.sh --ctgrind` runs it separately and *requires* valgrind to
//! report an error.

// ── valgrind client request ───────────────────────────────────────────

/// The magic instruction sequence valgrind recognises as a client request.
///
/// Verbatim from valgrind 3.24.0 `valgrind.h`, the `PLAT_amd64_linux` branch:
///
/// ```text
/// #define __SPECIAL_INSTRUCTION_PREAMBLE
///              "rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
///              "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
/// ...
///   "xchgq %%rbx,%%rbx"     /* %RDX = client_request ( %RAX ) */
/// ```
///
/// The four rotates sum to 128, so `%rdi` is restored to its original value —
/// they exist only to be an otherwise-impossible sequence that valgrind can
/// spot.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn client_request(default: usize, args: &mut [usize; 6]) -> usize {
    let result: usize;
    core::arch::asm!(
        "rolq $3,  %rdi",
        "rolq $13, %rdi",
        "rolq $61, %rdi",
        "rolq $51, %rdi",
        "xchgq %rbx, %rbx",
        in("rax") args.as_mut_ptr(),
        inout("rdx") default => result,
        // `%rdi` is clobbered from the compiler's point of view: the four
        // rotates cancel mathematically, but the compiler must not assume that.
        // Flags need no declaration — omitting `preserves_flags` tells the
        // compiler they may be clobbered, which is what `rolq` does. `%rbx` is
        // not declared because `xchgq %rbx,%rbx` does not change it, and LLVM
        // reserves the register and rejects it as an operand.
        lateout("rdi") _,
        // AT&T syntax, so the instruction text matches valgrind's own header
        // verbatim. Rust's default is Intel, where `$3` is not a valid immediate
        // and the sequence fails to assemble.
        options(att_syntax, nostack),
    );
    result
}

/// `VG_USERREQ__MAKE_MEM_NOACCESS = VG_USERREQ_TOOL_BASE('M','C')`, and the two
/// we want are the next entries in that enum — so `UNDEFINED` is `base + 1`, not
/// `base`. Getting this wrong would silently mark memory *inaccessible* instead
/// of undefined, which valgrind reports as a different (and noisier) class.
///
/// From valgrind 3.24.0 `memcheck.h`:
///
/// ```text
/// VG_USERREQ__MAKE_MEM_NOACCESS = VG_USERREQ_TOOL_BASE('M','C'),
/// VG_USERREQ__MAKE_MEM_UNDEFINED,
/// VG_USERREQ__MAKE_MEM_DEFINED,
/// ```
const MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const MAKE_MEM_DEFINED: usize = 0x4d43_0002;

/// Mark `len` bytes at `ptr` as undefined, so valgrind reports any branch or
/// index that depends on them.
///
/// A no-op outside valgrind.
#[cfg(target_arch = "x86_64")]
pub fn poison(ptr: *const u8, len: usize) {
    // SAFETY: the request is a documented valgrind ABI; the pointer is only read
    // by valgrind, and only for `len` bytes which the caller guarantees are
    // valid. Outside valgrind the sequence touches nothing.
    unsafe {
        let mut args = [MAKE_MEM_UNDEFINED, ptr as usize, len, 0, 0, 0];
        let _ = client_request(0, &mut args);
    }
}

/// Mark `len` bytes at `ptr` as defined again — used on the *public* outputs so
/// that the test itself may legitimately branch on them.
///
/// A no-op outside valgrind.
#[cfg(target_arch = "x86_64")]
pub fn unpoison(ptr: *const u8, len: usize) {
    // SAFETY: as `poison`.
    unsafe {
        let mut args = [MAKE_MEM_DEFINED, ptr as usize, len, 0, 0, 0];
        let _ = client_request(0, &mut args);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn poison(_ptr: *const u8, _len: usize) {}
#[cfg(not(target_arch = "x86_64"))]
pub fn unpoison(_ptr: *const u8, _len: usize) {}

// ── Tests ─────────────────────────────────────────────────────────────

use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, NONCE_LEN, TAG_LEN,
};

/// No branch, index or comparison in `encrypt` may depend on `key`, `nonce` or
/// the AAD **contents**.
///
/// The secrets are poisoned, the operation runs, and only then are the *public*
/// outputs unpoisoned so this test can inspect them. Anything inside the library
/// that branched on a secret would be reported by memcheck.
///
/// Run under valgrind (see `verify.sh --ctgrind`); in a plain `cargo test` the
/// poisoning is inert and this only checks the outputs are consistent.
#[test]
fn encrypt_does_not_branch_on_secrets() {
    let key = [0x5Au8; 32];
    let nonce = [0x3Cu8; NONCE_LEN];
    let aad = *b"poisoned aad";
    let pt: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();

    // The plaintext is public here (an attacker-chosen message), so it stays
    // defined. The key, nonce and AAD are the secrets.
    poison(key.as_ptr(), key.len());
    poison(nonce.as_ptr(), nonce.len());
    poison(aad.as_ptr(), aad.len());

    let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();

    // Public outputs: safe to branch on from here.
    unpoison(ct.as_ptr(), ct.len());
    unpoison(tag.as_ptr(), TAG_LEN);
    unpoison(key.as_ptr(), key.len());
    unpoison(nonce.as_ptr(), nonce.len());
    unpoison(aad.as_ptr(), aad.len());

    // Assertions go through a fresh, unpoisoned call: `ct`/`tag` were computed
    // from poisoned secrets, so branching on them directly would report against
    // this file rather than against the library.
    assert_eq!(ct.len(), pt.len());
    let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
    assert_eq!(back.as_slice(), pt.as_slice());
}

/// The same for `decrypt`, where the *tag* is additionally secret-adjacent: the
/// comparison must not reveal which byte differs.
///
/// The tag is public in the protocol, so it stays defined; what is poisoned is
/// the key, nonce and AAD. The point is that authenticating must not branch on
/// any of them beyond the unavoidable final decision.
#[test]
fn decrypt_does_not_branch_on_secrets() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; NONCE_LEN];
    let aad = *b"aad";
    let pt: Vec<u8> = (0..200).map(|i| (i % 241) as u8).collect();
    let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();

    let mut bad_tag = tag;
    bad_tag[TAG_LEN - 1] ^= 1;

    // Poison the key material for the call under test.
    let k = key;
    let n = nonce;
    let a = aad;
    poison(k.as_ptr(), k.len());
    poison(n.as_ptr(), n.len());
    poison(a.as_ptr(), a.len());

    // The failure path wipes the plaintext and must not branch on the key or
    // AAD either.  The *result* is derived from poisoned bytes, so the test must
    // not branch on it: it is consumed through `black_box` instead.  Asserting on
    // it here would produce a valgrind report against this file rather than
    // against the library, which is noise that hides a real finding.
    let r = decrypt(&k, &n, &a, &ct, &bad_tag);
    core::hint::black_box(&r);

    unpoison(k.as_ptr(), k.len());
    unpoison(n.as_ptr(), n.len());
    unpoison(a.as_ptr(), a.len());

    // And the in-place variant, whose failure path zeroizes the caller's buffer.
    let mut buf = ct.clone();
    poison(k.as_ptr(), k.len());
    poison(n.as_ptr(), n.len());
    poison(a.as_ptr(), a.len());
    let r2 = decrypt_in_place_detached(&k, &n, &a, &mut buf, &bad_tag);
    core::hint::black_box(&r2);
    unpoison(k.as_ptr(), k.len());
    unpoison(n.as_ptr(), n.len());
    unpoison(a.as_ptr(), a.len());

    // Now the same calls with nothing poisoned, so the assertions are ordinary.
    assert!(decrypt(&key, &nonce, &aad, &ct, &bad_tag).is_err());
    let mut buf2 = ct.clone();
    assert_eq!(
        decrypt_in_place_detached(&key, &nonce, &aad, &mut buf2, &bad_tag),
        Err(xchacha20_blake3_siv::Error::AuthenticationFailed)
    );
    assert!(
        buf2.iter().all(|&b| b == 0),
        "failure must zeroize the buffer"
    );
}

/// The detached encryption entry point, so the in-place XOR path is covered too
/// (it takes a different code path through `chacha20_apply`).
#[test]
fn encrypt_in_place_does_not_branch_on_secrets() {
    let key = [0x77u8; 32];
    let nonce = [0x88u8; NONCE_LEN];
    let aad = *b"in-place aad";
    let mut buf: Vec<u8> = (0..256).map(|i| (i % 253) as u8).collect();
    let expect = buf.clone();

    poison(key.as_ptr(), key.len());
    poison(nonce.as_ptr(), nonce.len());
    poison(aad.as_ptr(), aad.len());
    let tag = encrypt_in_place_detached(&key, &nonce, &aad, &mut buf).unwrap();
    unpoison(buf.as_ptr(), buf.len());
    unpoison(tag.as_ptr(), TAG_LEN);
    unpoison(key.as_ptr(), key.len());
    unpoison(nonce.as_ptr(), nonce.len());
    unpoison(aad.as_ptr(), aad.len());

    assert_ne!(
        buf, expect,
        "in-place encryption should have changed the buffer"
    );
}

/// `subtle::ConstantTimeEq` itself must not branch on the bytes it compares —
/// this is the property the tag comparison rests on.
///
/// The comparison result is derived from poisoned bytes and is therefore itself
/// undefined, so it is unpoisoned before being branched on. That is exactly the
/// situation in `decrypt`: the comparison must be branchless, and only the
/// resulting decision may branch.
#[test]
fn constant_time_eq_does_not_branch_on_operands() {
    let mut a = [0u8; TAG_LEN];
    let mut b = [0u8; TAG_LEN];
    for i in 0..TAG_LEN {
        a[i] = (i * 7) as u8;
        b[i] = if i == TAG_LEN - 1 { 1 } else { (i * 7) as u8 };
    }

    use subtle::ConstantTimeEq;

    poison(a.as_ptr(), a.len());
    poison(b.as_ptr(), b.len());
    let choice = a.ct_eq(&b);
    // The decision is output, not input; it may legitimately branch.
    unpoison(
        &choice as *const _ as *const u8,
        core::mem::size_of_val(&choice),
    );
    unpoison(a.as_ptr(), a.len());
    unpoison(b.as_ptr(), b.len());

    assert!(!bool::from(choice));
}

/// **Negative control.** Branches on a poisoned byte on purpose, so that running
/// this under valgrind *must* produce an error.
///
/// Ignored by default because it makes valgrind fail by design — its value is in
/// `verify.sh --ctgrind`, which runs it expecting exactly that. Without this,
/// the three tests above could be passing because the poisoning never took
/// effect, and nobody would know.
#[test]
#[ignore = "deliberately leaks; run under valgrind to confirm the harness detects it"]
fn deliberate_leak_is_detected() {
    let secret = [0u8; 32];
    poison(secret.as_ptr(), secret.len());

    // A textbook secret-dependent branch.
    let mut out = 0u8;
    if secret[0] > 128 {
        out = 1;
    }

    unpoison(secret.as_ptr(), secret.len());
    unpoison(&out as *const u8, 1);
    assert!(out <= 1);
}
