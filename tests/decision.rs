//! The accept/reject decision, as a test that a *fault* can break.
//!
//! `tools/fi_check.sh` runs this in three configurations: on a clean `hardened`
//! build, on the default build with the decision "glitched" (the fault written
//! down as a source change), and on the `hardened` build with the same glitch. The
//! middle one must *fail* — that is the fault being real rather than hypothetical —
//! and the last must pass, which is the whole point of the hardening.
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

        // And a corrupted ciphertext against a valid tag.
        if !ct.is_empty() {
            let mut forged_ct = ct.clone();
            forged_ct[0] ^= 0x01;
            assert!(
                decrypt(&KEY, &NONCE, AAD, &forged_ct, &tag).is_err(),
                "corrupted ciphertext accepted at message length {pt_len}"
            );
        }

        // The in-place entry point has its own decision and needs its own check.
        let mut buf = pt.clone();
        let detached = encrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf).unwrap();
        assert_eq!(buf, ct);
        assert_eq!(detached, tag);
        decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf, &detached).unwrap();
        assert_eq!(buf, pt);

        let mut forged = detached;
        forged[TAG_LEN - 1] ^= 0x01;
        let mut buf = ct.clone();
        assert!(
            decrypt_in_place_detached(&KEY, &NONCE, AAD, &mut buf, &forged).is_err(),
            "forged tag accepted in place at message length {pt_len}"
        );
    }
}
