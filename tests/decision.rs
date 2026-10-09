//! The accept/reject decision, as a test that a *fault* can break.
//!
//! `tools/fi_check.sh` runs this in eleven configurations — the eleven rows of its
//! **fourteen-row** campaign that name `--test decision` (two further rows drive
//! `tests/mac_commitment.rs` and one drives `tests/security.rs`) —
//! each one a fault written down as a source change and applied to a fresh copy of the
//! crate. On the clean `hardened` and opt-out (`--no-default-features`) builds it must
//! pass, and the rows that must *fail* are the real faults: a neutralised gate on the
//! opt-out build (that is the fault being real rather than hypothetical), a second gate
//! reduced to a copy of the first, the computed tag replaced by the received one, and
//! both call-site checks neutralised. The rows that must pass are the countermeasures:
//! the same neutralised, corrupted or substituted value on the `hardened` build, and the
//! substituted tag on the `ultra` build, where the independent recomputation disagrees
//! with it. (This comment has three times carried a stale count — "three configurations",
//! then "eleven rows" when the campaign already had thirteen, then "ten rows" when it had
//! fourteen — so the numbers here are written to be checkable against `tools/fi_check.sh`'s
//! `run_row` lines.)
//!
//! It is also a plain test: a tag or ciphertext with one bit flipped must be
//! rejected, through both entry points, at the sizes where the tag is hashed in
//! one buffer and where it is hashed in three parts.
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, TAG_LEN,
};

const KEY: [u8; 32] = [0x11; 32];
const NONCE: [u8; 24] = [0x22; 24];
const AAD: &[u8] = b"decision";

#[test]
fn a_forged_tag_must_not_be_accepted() {
    for pt_len in [0usize, 1, 64, 1024, 4096] {
        let pt: Vec<u8> = (0..pt_len).map(|i| (i % 251) as u8).collect();
        let (ct, tag) = encrypt(&KEY, &NONCE, AAD, &pt).unwrap();
        assert_eq!(
            decrypt(&KEY, &NONCE, AAD, &ct, &tag).unwrap().as_slice(),
            pt
        );

        // Every byte position of the tag, so a decision that only checks a prefix
        // cannot pass this.
        for pos in 0..TAG_LEN {
            let mut forged = tag;
            forged[pos] ^= 0x80;
            assert!(
                decrypt(&KEY, &NONCE, AAD, &ct, &forged).is_err(),
                "forged tag accepted at message length {pt_len}, tag byte {pos}"
            );
        }

        // And a corrupted ciphertext against a valid tag — *every* byte position, not
        // just the first. A tag that stopped committing to the message's tail accepts a
        // flip there and rejects one in byte 0, so a single first-byte flip proves only
        // that the tag depends on the prefix. (Measured: `let msg: &[u8] =
        // &msg[..1.min(msg.len())];` at the top of `derive_tag` passed the earlier
        // first-byte-only check through both entry points.)
        for pos in 0..ct.len() {
            let mut forged_ct = ct.clone();
            forged_ct[pos] ^= 0x01;
            assert!(
                decrypt(&KEY, &NONCE, AAD, &forged_ct, &tag).is_err(),
                "corrupted ciphertext accepted at message length {pt_len}, byte {pos}"
            );
        }

        // The in-place entry point has its own decision and needs its own check —
        // the same full sweep of all `TAG_LEN` byte positions, because a decision
        // that only checked a prefix would be a *prefix-checking* implementation in
        // place exactly as much as in the allocating path. (This used to flip only
        // the last byte here while the module doc claimed "through both entry
        // points".)
        let mut buf = pt.clone();
        let detached = encrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf).unwrap();
        assert_eq!(buf, ct);
        assert_eq!(detached, tag);
        decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf, &detached).unwrap();
        assert_eq!(buf, pt);
        for pos in 0..TAG_LEN {
            let mut forged = detached;
            forged[pos] ^= 0x80;
            let mut buf = ct.clone();
            assert!(
                decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf, &forged).is_err(),
                "forged tag accepted in place at message length {pt_len}, tag byte {pos}"
            );
        }

        // A corrupted ciphertext under the valid tag, through the in-place entry too.
        // The allocating path's flip above is not evidence for the in-place decision:
        // the two are separate call sites, and "through both entry points" is the
        // claim this test makes. Every byte position here as well, for the reason
        // given over the allocating sweep.
        for pos in 0..ct.len() {
            let mut forged_ct = ct.clone();
            forged_ct[pos] ^= 0x01;
            assert!(
                decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut forged_ct, &detached).is_err(),
                "corrupted ciphertext accepted in place at message length {pt_len}, byte {pos}"
            );
        }

        let mut forged = detached;
        forged[TAG_LEN - 1] ^= 0x01;
        let mut buf = ct.clone();
        assert!(
            decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf, &forged).is_err(),
            "forged tag accepted in place at message length {pt_len}"
        );
    }
}

/// A tag observed for one message must not authenticate a **different** one.
///
/// This is the fault that the gates cannot see, and it is worth being precise about why: if
/// the tag computation is faulted so that it stops depending on the message — one corrupted
/// pointer, one skipped `update`, a hasher fed an empty slice — then `encrypt` and `decrypt`
/// still agree with each other, because they run the same broken function. Every gate compares
/// the computed tag against the received one and finds them equal, `dual-mac` recomputes
/// through the same function and agrees too. What breaks is the *construction*: the tag stops
/// committing to the message, so one observed `(ciphertext, tag)` pair authenticates any
/// ciphertext at all under the same key, nonce and AAD.
///
/// `tools/fi_check.sh` writes that fault down as a source change (`let msg: &[u8] = &[];` at
/// the top of `derive_tag`) and runs **`tests/mac_commitment.rs`** against it, in two
/// configurations: the `hardened,dual-mac` build *fails* it — the fault is invisible there —
/// and the `ultra` build passes, because the independent implementation in `witness` is a
/// different program and its tag does depend on the message. That contrast is the whole
/// argument for the second implementation; without it that test would only be another
/// bit-flip test. (This comment used to say the campaign runs "this test": the row's target is
/// `mac_commitment`, not this file — both files carry a test for the same property, and the
/// campaign's fault is applied to the other one.)
#[test]
fn a_tag_from_one_message_must_not_authenticate_another() {
    let a = b"the message the tag was issued for";
    let b_msg = b"a different message entirely";

    let (ct_a, tag_a) = encrypt(&KEY, &NONCE, AAD, a).unwrap();
    let (ct_b, _tag_b) = encrypt(&KEY, &NONCE, AAD, b_msg).unwrap();

    // `a`'s tag must not authenticate `b`'s ciphertext ...
    assert!(
        decrypt(&KEY, &NONCE, AAD, &ct_b, &tag_a).is_err(),
        "a tag issued for one message authenticated another"
    );
    assert!(
        decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut ct_b.to_vec(), &tag_a).is_err(),
        "a tag issued for one message authenticated another (in place)"
    );

    // ... and neither must it authenticate a ciphertext of the same length, which is the
    // cheap forgery: same tag, different bytes. Every byte position, because a tag that
    // commits only to the message's first byte still permits a forgery everywhere else —
    // a flip in byte 0 is the one position such a fault *would* catch. (Measured:
    // `let msg: &[u8] = &msg[..1.min(msg.len())];` in `derive_tag` passed the earlier
    // first-byte-only version.)
    for pos in 0..ct_a.len() {
        let mut same_len = ct_a.clone();
        same_len[pos] ^= 1;
        assert!(
            decrypt(&KEY, &NONCE, AAD, &same_len, &tag_a).is_err(),
            "a tag authenticated a ciphertext it was not issued for (byte {pos})"
        );
    }

    // The genuine pair still works, so the rejections above are the forgery.
    assert_eq!(decrypt(&KEY, &NONCE, AAD, &ct_a, &tag_a).unwrap(), a);
}
