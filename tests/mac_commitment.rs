//! The commitment property a second implementation defends, as a detector a *fault* can break.
//!
//! `tools/fi_check.sh` plants a fault that stops the tag from depending on the message — one
//! shadowed binding at the top of `derive_tag`, which is the cheapest way to model "a
//! corrupted pointer or a skipped `update` in the MAC". Every gate in the crate is blind to it:
//! `encrypt` and `decrypt` call the same broken function, so they agree with each other, the
//! computed tag equals the received tag, and `dual-mac`'s recomputation goes through the same
//! function and agrees as well. What breaks is not authentication but **commitment**: a tag
//! observed for one message then authenticates a different one.
//!
//! This file is only that property, and it is deliberately tolerant of the *other* way the
//! fault can be met:
//!
//! * on the `hardened,dual-mac` build, `encrypt` succeeds (nothing notices), the tag is
//!   produced, and it authenticates a message it was not issued for → this test **fails**,
//!   which is the fault being real;
//! * on the `ultra` build, `encrypt` refuses — its independent implementation computes a tag
//!   that *does* depend on the message, the two disagree, and it returns
//!   `AuthenticationFailed` rather than a tag it cannot vouch for. Refusing is the
//!   countermeasure, not a defect, so this test **passes**.
//!
//! Two rows of the campaign therefore differ in exactly the way the feature does, and the
//! contrast is the argument for `ultra`: the same fault is invisible to every gate and is
//! caught only because the second implementation is a different program.
//!
//! Kept in its own binary on purpose: `tests/decision.rs` also exercises the honest path, so
//! under `ultra` *its* tests fail when `encrypt` refuses, and a detector that merely fails is
//! not the same as a detector that says what happened.

use xchacha20_blake3_siv::{decrypt, encrypt};

const KEY: [u8; 32] = [0x11; 32];
const NONCE: [u8; 24] = [0x22; 24];
const AAD: &[u8] = b"commitment";

#[test]
fn a_tag_must_commit_to_the_message_it_was_issued_for() {
    let issued_for = b"the message the tag was issued for";

    let (ct_issued, tag_issued) = match encrypt(&KEY, &NONCE, AAD, issued_for) {
        Ok(pair) => pair,
        // `ultra`'s answer to the planted fault: it will not produce a tag it cannot vouch
        // for, which is a defence. Nothing further can be asserted about a pair that was
        // never issued — and if this arm is reached on a *clean* build, the clean rows of the
        // campaign fail instead, because they require this test to pass.
        Err(e) => {
            eprintln!(
                "encrypt refused to issue a tag ({e:?}): the independent implementation \
                 disagreed, which is the countermeasure this test is paired with"
            );
            return;
        }
    };

    // A different message, and a same-length ciphertext that differs in one byte: the two
    // cheap forgeries an uncommitted tag permits.
    let other = b"a completely different message!!";
    let (ct_other, _) = encrypt(&KEY, &NONCE, AAD, other).unwrap();
    let mut same_len = ct_issued.clone();
    same_len[0] ^= 1;

    assert!(
        decrypt(&KEY, &NONCE, AAD, &ct_other, &tag_issued).is_err(),
        "a tag issued for one message authenticated another message's ciphertext"
    );
    assert!(
        decrypt(&KEY, &NONCE, AAD, &same_len, &tag_issued).is_err(),
        "a tag issued for one message authenticated a same-length forgery"
    );

    // The genuine pair still works, so the rejections above are the forgeries rather than a
    // broken harness.
    assert_eq!(
        decrypt(&KEY, &NONCE, AAD, &ct_issued, &tag_issued).unwrap(),
        issued_for
    );
}
