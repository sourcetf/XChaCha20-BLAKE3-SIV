//! Fuzz the AEAD end to end: encrypt then decrypt, and decrypt arbitrary bytes.
//!
//! Run:  cargo +nightly fuzz run roundtrip
//!
//! Two properties, both of which must hold for *every* input:
//!
//!   1. **No panic, no out-of-bounds, no hang.** The input is arbitrary bytes,
//!      interpreted as `(key, nonce, aad, plaintext)`; every field length is a
//!      function of the fuzzer's input, so length handling is exercised at every
//!      boundary.
//!   2. **No plaintext without a valid tag.** When the round trip is corrupted by
//!      a single flipped bit — in the ciphertext, the tag, or the AAD —
//!      decryption must return an error and must not hand back the plaintext.
//!      That is the property an implementation which compared a prefix, or which
//!      returned plaintext before verifying, would violate.
//!
//! Structured rather than raw: the first two bytes choose which field to corrupt,
//! so the fuzzer spends its budget on meaningful cases instead of discarding
//! almost every input as malformed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, KEY_LEN, NONCE_LEN,
    TAG_LEN,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 + KEY_LEN + NONCE_LEN {
        return;
    }

    let mode = data[0];
    let mut rest = &data[1..];

    let key: [u8; KEY_LEN] = rest[..KEY_LEN].try_into().unwrap();
    rest = &rest[KEY_LEN..];
    let nonce: [u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().unwrap();
    rest = &rest[NONCE_LEN..];

    // Split the remainder into AAD and plaintext at a fuzzer-chosen point, so
    // both are usually non-empty and their relative sizes vary freely.
    let split = if rest.is_empty() {
        0
    } else {
        (rest[0] as usize) % (rest.len() + 1)
    };
    let (aad, pt) = if rest.is_empty() {
        (&rest[..0], &rest[..0])
    } else {
        (&rest[1..1 + split.min(rest.len() - 1)], &rest[1 + split.min(rest.len() - 1)..])
    };

    let (ct, tag) = match encrypt(&key, &nonce, aad, pt) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Property 1: the honest round trip must always succeed and match.
    let back = decrypt(&key, &nonce, aad, &ct, &tag).expect("round trip must verify");
    assert_eq!(back.as_slice(), pt, "round trip must recover the plaintext");

    // Property 2: corrupt exactly one thing and require rejection.
    let mut bad_ct = ct.clone();
    let mut bad_tag = tag;
    let mut bad_aad = aad.to_vec();
    match mode % 3 {
        0 if !bad_ct.is_empty() => {
            let i = (mode as usize / 3) % bad_ct.len();
            bad_ct[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, aad, &bad_ct, &bad_tag).is_err(),
                "a corrupted ciphertext byte must not authenticate"
            );
        }
        1 => {
            let i = (mode as usize / 3) % TAG_LEN;
            bad_tag[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, aad, &ct, &bad_tag).is_err(),
                "a corrupted tag byte must not authenticate"
            );
        }
        _ if !bad_aad.is_empty() => {
            let i = (mode as usize / 3) % bad_aad.len();
            bad_aad[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, &bad_aad, &ct, &tag).is_err(),
                "a corrupted AAD byte must not authenticate"
            );
        }
        _ => {}
    }

    // The in-place paths, including the wipe-on-failure contract.
    let mut buf = pt.to_vec();
    let t2 = encrypt_in_place_detached(&key, &nonce, aad, &mut buf).unwrap();
    assert_eq!(buf, ct);

    let mut buf2 = ct.clone();
    match decrypt_in_place_detached(&key, &nonce, aad, &mut buf2, &t2) {
        Ok(()) => assert_eq!(buf2, pt),
        Err(_) => panic!("the honest in-place round trip must verify"),
    }

    // A failing in-place decrypt must leave no plaintext behind.
    let mut buf3 = ct.clone();
    if !bad_tag_is_ok(&bad_tag, &tag) && decrypt_in_place_detached(&key, &nonce, aad, &mut buf3, &bad_tag).is_err() {
        assert!(
            buf3.iter().all(|&b| b == 0),
            "a failed in-place decrypt must zeroize the buffer"
        );
    }
});

/// Only used to skip the wipe assertion when the "corruption" left the tag
/// unchanged (possible when the flip lands on a bit that was already set).
fn bad_tag_is_ok(bad: &[u8; TAG_LEN], good: &[u8; TAG_LEN]) -> bool {
    bad == good
}
