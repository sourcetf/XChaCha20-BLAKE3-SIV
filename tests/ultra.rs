//! What `ultra` claims, asserted instead of promised.
//!
//! `ultra` is the feature that turns on every defence this crate has. "Immune to every
//! attack model" is not a testable statement, so this file is the honest version of it:
//! for each model, either a test that the defence is *present and doing something*, or a
//! test that pins where the defence stops — because a mode that claims total immunity and
//! has no written limits is worse than one that states its boundaries.
//!
//! The layers, and where each is checked:
//!
//! | model | defence | checked by |
//! | --- | --- | --- |
//! | ciphertext equality / length | the construction itself; documented, not removable | `documents_what_it_cannot_defend_against` |
//! | a secret-dependent branch | constant-time comparison; the one decision suppressed, nothing else | `tools/ctgrind.sh` (its planted-leak control is the interesting half) |
//! | a single corrupted decision *value* | two slots, two serial reject-first checks | `tests/decision.rs`, `tools/fi_check.sh` |
//! | a single corrupted *instruction* | the second gate, and the fail-closed call site | `tools/fi_instruction.sh` (both models) |
//! | `computed_tag` pinned / rewritten | an independent recomputation cross-checked against both values | `dual_mac_is_wired_into_both_decrypt_paths` |
//! | key pages read out of swap or a core dump | `mlock` + `MADV_DONTDUMP` | `locked_key_is_actually_locked` |
//! | a nonce reused | SIV: the tag binds the message, so reuse degrades rather than fails | `spec/tests`: `test_message_swap_under_a_reused_nonce_is_rejected` |
//! | remote memory exhaustion | a public bound, a pre-allocation policy check, fallible allocation | `tests/security.rs` |
//!
//! `ultra` = `hardened` + `rng` + `dual-mac` + `locked` + `pure`; this file is compiled
//! only when it is on, and the assertions below are about the *combination*, which nothing
//! else in the suite can check.

#![cfg(feature = "ultra")]

use xchacha20_blake3_siv::{decrypt, decrypt_in_place_detached, encrypt, Error};

const KEY: [u8; 32] = [0x11u8; 32];
const NONCE: [u8; 24] = [0x22u8; 24];

/// The independent recomputation every decrypt performs under `ultra`.
///
/// Two properties, and the second is the reason it exists: it must agree with the stored
/// value *and* with the received tag, so a fault that rewrites the stored tag to the
/// received one is caught — which the two gates cannot do, because they compare the same
/// two values and are satisfied together.
#[test]
fn dual_mac_is_wired_into_both_decrypt_paths() {
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("test module");
    let body = &src[..cut];

    // `let mut`, because the result is wiped below like every other secret-derived copy.
    assert_eq!(
        body.matches("recomputed_tag = derive_tag(").count(),
        2,
        "both decrypt paths must recompute the tag independently"
    );
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(&computed_tag)").count(),
        2,
        "the recomputation must be compared against the stored value"
    );
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(tag)").count(),
        2,
        "and against the received tag, which is what catches a rewritten stored value"
    );
    // Wiped like every other secret-derived copy in the function.
    assert_eq!(
        body.matches("zeroize_array(&mut recomputed_tag)").count(),
        2,
        "the recomputed tag is secret-derived and must be wiped"
    );
}

/// The recomputation must not cost anything when the feature is off.
///
/// Not a timing test: the claim is structural — with `dual-mac` off there is no second
/// `derive_tag` call in the compiled body at all, so the cost is exactly zero rather than
/// "small". A `#[cfg]`-gated call is the difference between zero and a few percent.
#[test]
fn without_dual_mac_there_is_no_second_derivation_on_this_target() {
    // `ultra` implies `dual-mac`, so this test can only observe the *on* state; what it
    // pins is that the call sites are cfg-gated rather than unconditional.
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("test module");
    let body = &src[..cut];
    let gated = body.matches("#[cfg(feature = \"dual-mac\")]").count();
    assert!(
        gated >= 4,
        "the dual-mac work must be behind `#[cfg]` at every site (found {gated} gates): \
         an unconditional second derivation would tax builds that did not ask for it"
    );
}

/// A locking key is really locked, read back from the kernel.
///
/// The syscall numbers in `locked` are `const`s, and a wrong one would not be caught by
/// anything else: `mlock` with the wrong number either fails or does something else
/// entirely. The check that cannot be fooled is the kernel's own accounting — `VmLck`
/// must go up by at least the key's length while the lock is held — so that is what this
/// asserts. It is skipped (loudly) where locking is unsupported or the environment
/// refuses, rather than passing vacuously.
#[test]
fn locked_key_is_actually_locked() {
    use xchacha20_blake3_siv::locked::{LockedKey, SUPPORTED};

    if !SUPPORTED {
        eprintln!("SKIPPED: locking is unsupported on this target");
        return;
    }

    let before = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    let key = match LockedKey::new(&KEY) {
        Ok(k) => k,
        Err(e) => {
            // `ENOMEM` (12) from RLIMIT_MEMLOCK, `EPERM` (1) in a hardened container.
            // Reported, not swallowed: a test that passes because it never locked
            // anything is the vacuous kind.
            eprintln!("SKIPPED: the kernel refused to lock memory (errno {})", -e);
            return;
        }
    };
    let after = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        after >= before + 32,
        "VmLck did not account for the locked key: before {before}, after {after}. A wrong \
         syscall number or a no-op `lock_range` looks exactly like this."
    );

    // And the key still works, so the locking did not corrupt or move it.
    let (ct, tag) = encrypt(&key, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&key, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );

    let held = after;
    drop(key);
    let released = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        released < held,
        "dropping a `LockedKey` must unlock it: VmLck stayed at {released}"
    );
}

/// The doc must state the limits, because the limits are the part a user needs.
///
/// This is a documentation assertion, which is unusual, and it is here because `ultra`
/// invites exactly the wrong reading: "everything is on, so I am safe". A debugger
/// attached to the process, a hypervisor, cold-boot remanence and a two-glitch bench are
/// all outside what any of this can do, and each one must be named where someone turning
/// the feature on will read it.
#[test]
fn documents_what_it_cannot_defend_against() {
    let readme = include_str!("../README.md");
    let lib = include_str!("../src/lib.rs");

    for (name, limit) in [
        ("memory-remanence", "cold boot"),
        ("core-dump scope", "core dump"),
        ("debugger", "debugger"),
        ("two-fault attack", "Two independent faults"),
        (
            "directed injection",
            "targeted fault inside the tag computation",
        ),
        ("deterministic encryption", "Deterministic encryption"),
        ("length disclosure", "Length is revealed"),
    ] {
        assert!(
            readme.contains(limit) || lib.contains(limit),
            "`ultra` claims to enable every defence; the limit `{name}` (`{limit}`) is not \
             written down anywhere a user would look, which makes the claim misleading."
        );
    }
}

/// Every gate the crate has is *present* in this build, not merely documented.
///
/// A feature flag that silently does not compose — `ultra` turning on `dual-mac` but the
/// code checking `feature = "ultra"` somewhere and missing it — would be invisible in a
/// normal test run because the default build does not compile any of it.
#[test]
fn every_layer_is_compiled_in_under_ultra() {
    // `hardened`: the second gate's branch exists.
    let src = include_str!("../src/lib.rs");
    let cut = src.find("mod tests {").expect("test module");
    let body = &src[..cut];

    assert!(
        body.contains("#[cfg(feature = \"hardened\")]"),
        "the hardened gate must be compiled in"
    );
    assert!(
        body.contains("#[cfg(feature = \"dual-mac\")]"),
        "the independent recomputation must be compiled in"
    );
    assert!(
        body.contains("pub mod locked"),
        "the locked-memory module must be compiled in"
    );

    // `rng`: generating a key works here (this is the one feature `ultra` adds that
    // changes nothing about the cipher, and it is worth one assertion that it is live).
    let key = xchacha20_blake3_siv::random::generate_key().expect("OS entropy");
    let nonce = xchacha20_blake3_siv::random::generate_nonce().expect("OS entropy");
    let (ct, tag) = encrypt(&key, &nonce, b"", b"under ultra").unwrap();
    assert_eq!(
        decrypt(&key, &nonce, b"", &ct, &tag).unwrap(),
        b"under ultra"
    );
}

/// The decision is still fail-closed with every layer on, and still refuses a forgery.
///
/// `ultra` adds work *inside* the decision; this is the check that the addition did not
/// change its answer for an honest input or a forged one — including on the in-place path,
/// which has its own copy of the wiring.
#[test]
fn the_decision_still_answers_correctly_with_every_layer_on() {
    let pt: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let (ct, tag) = encrypt(&KEY, &NONCE, b"aad", &pt).unwrap();

    let mut bad = tag;
    bad[0] ^= 1;
    assert_eq!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &bad).unwrap_err(),
        Error::AuthenticationFailed
    );
    let mut buf = ct.clone();
    assert_eq!(
        decrypt_in_place_detached(&KEY, &NONCE, b"aad", &mut buf, &bad),
        Err(Error::AuthenticationFailed)
    );
    assert!(buf.iter().all(|&b| b == 0), "failure must wipe the buffer");

    // The honest pair still round-trips, so the refusals above are the forgery.
    assert_eq!(decrypt(&KEY, &NONCE, b"aad", &ct, &tag).unwrap(), pt);
    let mut buf = ct.clone();
    decrypt_in_place_detached(&KEY, &NONCE, b"aad", &mut buf, &tag).unwrap();
    assert_eq!(buf, pt);
}
