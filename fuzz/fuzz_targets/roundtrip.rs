//! Fuzz the AEAD end to end: encrypt then decrypt, decrypt *arbitrary* wire bytes, and
//! check that a failed in-place decrypt leaves no plaintext behind.
//!
//! Run:  cargo +nightly fuzz run roundtrip
//!
//! Four properties, all of which must hold for *every* input:
//!
//!   1. **No panic, no out-of-bounds, no hang.** The input is arbitrary bytes,
//!      interpreted as `(key, nonce, aad, plaintext)`; the AAD/plaintext split is a
//!      function of the fuzzer's input, so those lengths are exercised widely,
//!      while key, nonce and tag lengths are fixed by the API's array types.
//!   2. **No plaintext without a valid tag.** When the round trip is corrupted by
//!      a single flipped bit — in the ciphertext, the tag, or the AAD —
//!      decryption must return an error and must not hand back the plaintext.
//!      That is the property an implementation which compared a prefix, or which
//!      returned plaintext before verifying, would violate. (This is now
//!      unconditional: when the field `mode` selects is empty, the tag is corrupted
//!      instead of the check being skipped. The corrupted position is drawn from two
//!      input bytes, so it reaches the tail of fields longer than 86 bytes.)
//!   3. **Arbitrary wire bytes neither panic nor authenticate wrongly.** A tag and
//!      ciphertext taken straight from the fuzzer — not the output of `encrypt` —
//!      are fed to `decrypt`. Either it rejects, or (with the `2^-520` probability a
//!      random 65-byte tag authenticates) it accepts and the recovered plaintext must
//!      re-encrypt to exactly the ciphertext and tag it came with. An earlier version
//!      of this target only ever fed `decrypt` the output of `encrypt` or a one-bit
//!      corruption of it, so a *structurally* invalid tag never reached it.
//!   4. **A failed in-place decrypt rejects and zeroizes the caller's buffer** —
//!      the rejection itself is asserted, not only the wipe: with
//!      `if ...is_err() { assert!(zeroed) }` an implementation that wrongly
//!      returned `Ok` skipped the whole check.
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
    // A second selector byte widens the tamper index below: `mode / 3` alone tops
    // out at 85, so bytes past 85 of a long ciphertext or AAD were never corrupted.
    let tweak = data[1] as usize;
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

    // `encrypt` can only fail on allocation failure or a length above `MAX_MSG_SIZE`,
    // neither reachable at fuzz sizes. The silent `return` this replaces let a
    // regression that made `encrypt` refuse a valid input turn all four properties
    // vacuously green.
    let (ct, tag) = encrypt(&key, &nonce, aad, pt).expect("encrypt refuses a valid input");

    // Property 1: the honest round trip must always succeed and match.
    let back = decrypt(&key, &nonce, aad, &ct, &tag).expect("round trip must verify");
    assert_eq!(back.as_slice(), pt, "round trip must recover the plaintext");

    // Property 2: corrupt exactly one thing and require rejection. The final arm makes
    // this unconditional -- when the selected field is empty there is nothing to corrupt,
    // so the tag (always `TAG_LEN` bytes) is corrupted instead, rather than the check
    // being skipped as it was before.
    let mut bad_ct = ct.clone();
    let mut bad_tag = tag;
    let mut bad_aad = aad.to_vec();
    match mode % 3 {
        0 if !bad_ct.is_empty() => {
            let i = (tweak * 256 + mode as usize / 3) % bad_ct.len();
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
        2 if !bad_aad.is_empty() => {
            let i = (tweak * 256 + mode as usize / 3) % bad_aad.len();
            bad_aad[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, &bad_aad, &ct, &tag).is_err(),
                "a corrupted AAD byte must not authenticate"
            );
        }
        _ => {
            let i = (mode as usize / 3) % TAG_LEN;
            bad_tag[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, aad, &ct, &bad_tag).is_err(),
                "a corrupted tag byte must not authenticate"
            );
        }
    }

    // Property 3: arbitrary wire bytes. Take a tag and ciphertext straight from the
    // fuzzer (not from `encrypt`) and require either rejection, or acceptance that is
    // self-consistent -- the recovered plaintext must re-encrypt to exactly the bytes
    // presented. This is the structurally-invalid input the target never used to reach.
    if rest.len() >= TAG_LEN {
        let (raw_tag, raw_ct) = rest.split_at(TAG_LEN);
        let raw_tag: [u8; TAG_LEN] = raw_tag.try_into().unwrap();
        if let Ok(recovered) = decrypt(&key, &nonce, b"", raw_ct, &raw_tag) {
            let (re_ct, re_tag) =
                encrypt(&key, &nonce, b"", &recovered).expect("re-encrypt must succeed");
            assert_eq!(
                re_ct.as_slice(),
                raw_ct,
                "an authenticating ciphertext must re-encrypt to itself"
            );
            assert_eq!(
                re_tag, raw_tag,
                "an authenticating tag must re-encrypt to itself"
            );
        }
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

    // Property 4: a failing in-place decrypt must reject *and* leave no plaintext
    // behind. Requiring the rejection -- not merely checking the buffer when one
    // happens -- is the point: with `if ... .is_err() { assert!(zeroed) }` an
    // implementation that wrongly returned `Ok` here skipped the wipe assertion
    // entirely and the target still called it covered. The tag is corrupted
    // unconditionally (it is always `TAG_LEN` bytes), so this runs on every input.
    let mut bad_tag2 = tag;
    bad_tag2[0] ^= 0x01;
    let mut buf3 = ct.clone();
    assert!(
        decrypt_in_place_detached(&key, &nonce, aad, &mut buf3, &bad_tag2).is_err(),
        "a corrupted tag must not authenticate in place"
    );
    assert!(
        buf3.iter().all(|&b| b == 0),
        "a failed in-place decrypt must zeroize the buffer"
    );
});