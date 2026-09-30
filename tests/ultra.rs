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
//! | a nonce reused | SIV: the tag binds the message, so reuse degrades rather than fails | `src/lib.rs`: `test_message_swap_under_a_reused_nonce_is_rejected` |
//! | remote memory exhaustion | a public bound, a pre-allocation policy check, fallible allocation | `tests/security.rs` |
//!
//! `ultra` = `hardened` + `rng` + `dual-mac` + `locked`. (`pure` is deliberately *not*
//! part of it — it is a cross-compile/perf switch that forces BLAKE3's portable backends,
//! costs 24-32% and buys no security — and `Cargo.toml` and `README.md` both say so; this
//! line used to list it, which contradicted them.) This file is compiled only when
//! `ultra` is on, and the assertions below are about the *combination*, which nothing
//! else in the suite can check.

#![cfg(feature = "ultra")]

use xchacha20_blake3_siv::{decrypt, decrypt_in_place_detached, encrypt, Error};

// `ultra` is a bundle, and this asserts the bundle is wired -- at *compile* time,
// which is the right place for a fact about which features are on. The previous
// version grepped `src/lib.rs` for the text `#[cfg(feature = "dual-mac")]`: that
// string is in the file in every configuration, so the assertion held even if
// `ultra` enabled nothing, which is how three defects in the `locked` layer
// survived a suite that claimed to test it.
const _: () = {
    // `if !.. { panic!(..) }` rather than `assert!`: clippy's
    // `assertions_on_constants` rejects `assert!` on a constant, and it is right
    // that a fact about which features are on belongs in a `const` block.
    if !cfg!(feature = "hardened") {
        panic!("`ultra` must enable `hardened`");
    }
    if !cfg!(feature = "dual-mac") {
        panic!("`ultra` must enable `dual-mac`");
    }
    if !cfg!(feature = "locked") {
        panic!("`ultra` must enable `locked`");
    }
    if !cfg!(feature = "rng") {
        panic!("`ultra` must enable `rng`");
    }
};

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
    // Two, and the count is exact rather than "at least": one comparison of each kind per
    // entry point, on the single `second` line that every configuration compiles. It was
    // four when `ultra` had an arm of its own for this expression, which is the shape the
    // comment in the gate explains was removed.
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(&computed_tag)").count(),
        2,
        "the recomputation must be compared against the stored value, once per entry point"
    );
    assert_eq!(
        body.matches("recomputed_tag.ct_eq(tag)").count(),
        2,
        "and against the received tag, which is what catches a rewritten stored value"
    );
    // Under `ultra` the independent *implementation* joins the same gate: the stored tag
    // agreeing with the received one is not enough if both came from a rewritten
    // computation, so the witness's own answer is required too. It is folded into
    // `gate_pair` -- the line every configuration compiles -- rather than into a
    // `#[cfg]`-selected arm, so `cargo mutants` sees it in every run.
    assert_eq!(
        body.matches("second_gate_comparison(&computed_tag_copy, &tag_copy) & witness_ok")
            .count(),
        2,
        "`ultra`'s witness agreement must be ANDed into the second gate of both entry points"
    );
    // Wiped like every other secret-derived copy in the function.
    assert_eq!(
        body.matches("zeroize_array(&mut recomputed_tag)").count(),
        2,
        "the recomputed tag is secret-derived and must be wiped"
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
    use xchacha20_blake3_siv::locked::{unlock_range, LockedKey, SUPPORTED};

    // Returning early when the environment refuses to lock is indistinguishable,
    // in a test report, from having verified the lock: both say `ok`. That is the
    // vacuous shape this test exists to prevent, so a refusal is a *failure* by
    // default. `XSIV_ALLOW_UNLOCKED=1` is the explicit, recorded way to say "this
    // host cannot lock and that is not a regression" -- and setting it is a
    // decision that `ultra`'s `locked` layer is knowingly inactive here.
    let allow_unlocked = std::env::var("XSIV_ALLOW_UNLOCKED").is_ok();

    if !SUPPORTED {
        // `SUPPORTED == false` is a compile-time property of the target, not a failure: the
        // syscalls are wired for Linux x86_64/aarch64 only, the README says so, and
        // `cargo test --features ultra` on i686 would otherwise be red for a documented
        // platform limit. What *is* a failure is the runtime refusal below: there the target
        // should have worked and did not.
        eprintln!(
            "SKIPPED: memory locking is unsupported on this target/architecture, so \
             `ultra`'s `locked` layer is inactive here (as documented)"
        );
        return;
    }

    let before = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    let key = match LockedKey::new(&KEY) {
        Ok(k) => k,
        Err(e) => {
            // `ENOMEM` (12) from RLIMIT_MEMLOCK, `EPERM` (1) in a hardened container.
            assert!(
                allow_unlocked,
                "the kernel refused to lock memory (errno {}), so `ultra` promises \
                 mlock + MADV_DONTDUMP and this host is not getting it. Raise \
                 RLIMIT_MEMLOCK or grant CAP_IPC_LOCK, or set XSIV_ALLOW_UNLOCKED=1 to \
                 record that this host knowingly runs unlocked.",
                -e
            );
            return;
        }
    };
    let after = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        after >= before + 32,
        "VmLck did not account for the locked key: before {before}, after {after}. A wrong \
         syscall number or a no-op `lock_range` looks exactly like this."
    );

    // The lock must be on the *live* key's page, not on an address the value was
    // moved away from. `mlock` is address-based, and a `LockedKey` returned by
    // value moves its 32 bytes -- so an earlier version locked a stack slot in
    // `new` and left the returned copy on an unlocked page, while VmLck (and the
    // assertion above) still looked right. Unlocking the live key's own page must
    // show up in the kernel's accounting; if it does not, the locked page is
    // somewhere else and the protection is not on the key.
    let held = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    unlock_range(key.as_bytes().as_ptr(), 32);
    let after_unlocking_live = LockedKey::locked_bytes().expect("VmLck is readable on Linux");
    assert!(
        after_unlocking_live < held,
        "unlocking the live key's page did not change VmLck ({held} -> {after_unlocking_live}), \
         so the page that was locked is not the page the key is on: the value was moved \
         after being locked. The key must be heap-allocated (`Box`) so its address is stable."
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
fn every_layer_answers_correctly_in_the_ultra_build() {
    // Replaces a test that asserted `src/lib.rs` contains the strings
    // `#[cfg(feature = "hardened")]` and `pub mod locked` -- true in every build, so it
    // passed whether or not the layers were compiled. What is worth asserting here is
    // that the assembled build still answers correctly end to end; the per-layer
    // behaviour is checked by the `const _` assertion at the top of this file,
    // `locked_key_is_actually_locked` and the unit tests in `src/lib.rs`.
    let (ct, tag) = encrypt(&KEY, &NONCE, b"aad", b"message").unwrap();
    assert_eq!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &tag).unwrap(),
        b"message"
    );
    let mut bad = tag;
    bad[0] ^= 1;
    assert!(
        decrypt(&KEY, &NONCE, b"aad", &ct, &bad).is_err(),
        "a tampered tag must be rejected with every layer on"
    );

    // `locked::SUPPORTED` is a `const bool`, so asserting on it is an assertion on a
    // constant (clippy rejects it, and it would be a compile-time fact anyway). That
    // the locking module is usable is asserted where it is observable:
    // `locked_key_is_actually_locked`, which now fails -- rather than skipping when
    // the kernel refuses -- and checks the lock is on the live key's page.

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

/// The witness must be a *separate implementation* — and that is checked, not promised.
///
/// `ultra`'s value is that the second answer comes from code sharing nothing with the
/// first: not `derive_tag`, not the SIMD kernels, and not the `blake3` or `subtle`
/// dependencies either, because a fault in `blake3`'s compression kernel would move both
/// answers if the witness hashed through the same crate. What the two *must* share is the
/// specification — the domain strings, the nonce and tag widths — since those are the
/// construction rather than an implementation of it.
///
/// This is a source-shape test for the reason the others in this file are: a
/// "simplification" that reached for `crate::zeroize_slice`, or hashed with
/// `blake3::Hasher`, would leave every behavioural test passing. The witness would still
/// agree with the crate — it would simply have stopped being a second implementation, and
/// the fault model `ultra` exists for would quietly be single-implementation again.
#[test]
fn the_witness_shares_only_the_specification_with_the_crate() {
    let src = include_str!("../src/witness.rs");
    let cut = src.find("mod tests {").expect("the witness test module");
    // Comments stripped, so a mention in prose neither trips the check nor hides a use.
    let code: String = src[..cut]
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

    // The one permitted import: the specification's constants.
    let allowed = "use crate::{DOM_ENC, DOM_TAG, NONCE_LEN, SUBKEY_DOMAIN, TAG_LEN};";
    assert!(
        code.contains(allowed),
        "the witness must import the specification's constants explicitly, and nothing \
         else; expected to find:\n  {allowed}"
    );
    let without_imports = code.replace(allowed, "");
    assert!(
        !without_imports.contains("crate::"),
        "the witness uses crate internals, so it is no longer a second implementation \
         (the fault model it exists for assumes it shares no *code* with the crate): \
         {}",
        without_imports
            .lines()
            .filter(|l| l.contains("crate::"))
            .collect::<Vec<_>>()
            .join(" | ")
    );

    // And no use of the crate's dependencies: those are the shared code that a fault
    // could move both answers with.
    for dep in [
        "blake3::",
        "subtle::",
        "zeroize::",
        "getrandom::",
        "use blake3",
        "use subtle",
    ] {
        assert!(
            !without_imports.contains(dep),
            "the witness borrows `{dep}`, which the crate's own path also uses: a fault in \
             that shared code would move both answers, which is the one thing the second \
             implementation is there to prevent"
        );
    }

    // A sanity floor: the file must actually contain an implementation of each primitive,
    // so a future refactor cannot satisfy the assertions above by deleting the module.
    for f in [
        "fn hchacha20(",
        "fn block(",
        "fn compress(",
        "pub fn decrypt(",
        "pub fn encrypt_tag(",
    ] {
        assert!(
            code.contains(f),
            "the witness no longer defines `{f}` — these assertions would pass on an empty module"
        );
    }
}
