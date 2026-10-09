//! Fuzz the AEAD end to end: encrypt then decrypt, decrypt *arbitrary* wire bytes,
//! require the key and nonce (and the empty-vs-non-empty AAD spelling) to be binding,
//! and check that a failed in-place decrypt leaves no plaintext behind.
//!
//! Run:  cargo +nightly fuzz run roundtrip
//!
//! The CI runs pass `-max_len=8192`; see "Coverage scope" at the bottom.
//!
//! Five properties, all of which must hold for *every* input:
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
//!      The same property covers *key* and *nonce* binding — decrypting the honest
//!      ciphertext under a second key or nonce derived from the input must fail —
//!      and the empty-AAD substitution: a tag made under one AAD must not
//!      authenticate under an empty-vs-non-empty swap. A build that ignored its key
//!      entirely (or dropped the nonce, or treated `[]` as "no AAD to check") is
//!      self-consistent under every other arm and used to be invisible to this
//!      target; only the KATs caught it.
//!   3. **Arbitrary wire bytes neither panic nor authenticate wrongly.** A tag and
//!      ciphertext taken straight from the fuzzer — not the output of `encrypt` —
//!      are fed to `decrypt`, once with an empty AAD and once with a non-empty one.
//!      Either it rejects, or (with the `2^-520` probability a random 65-byte tag
//!      authenticates) it accepts and the recovered plaintext must re-encrypt to
//!      exactly the ciphertext and tag it came with. An earlier version of this
//!      target only ever fed `decrypt` the output of `encrypt` or a one-bit
//!      corruption of it, so a *structurally* invalid tag never reached it, and its
//!      arbitrary-wire class was empty-AAD-only.
//!   4. **A failed in-place decrypt rejects and zeroizes the caller's buffer** —
//!      the rejection itself is asserted, not only the wipe: with
//!      `if ...is_err() { assert!(zeroed) }` an implementation that wrongly
//!      returned `Ok` skipped the whole check.
//!   5. **`decrypt_bounded` enforces the caller's policy bound**: the ciphertext's
//!      own length must be accepted, one byte less must be refused with
//!      `MessageTooLong` before any allocation. This is the only reachable way to
//!      hit the length-error class.
//!
//! ## Coverage scope
//!
//! Deliberately out of reach: `Error::MessageTooLong`/`Error::AadTooLong` from the
//! *format* limit (`MAX_MSG_SIZE`, 2^38 bytes) and `Error::AllocationFailed` (needs
//! an OOM) — no input this target can be handed reaches them; the `rng` feature's
//! `Key::generate_*` constructors (off in this configuration) are entropy plumbing
//! rather than a property of the input space and are not exercised. Message lengths
//! are capped by libFuzzer's `-max_len` (4096 by default, 8192 in CI), so a fault
//! that only appears on messages above that cap needs the flag raised; the
//! >65535-byte AAD/plaintext split region is likewise above the cap.
//!
//! Structured rather than raw: the first two bytes choose which field to corrupt,
//! so the fuzzer spends its budget on meaningful cases instead of discarding
//! almost every input as malformed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xchacha20_blake3_siv::{
    decrypt, decrypt_bounded, decrypt_in_place_detached, encrypt, encrypt_in_place_detached, Error,
    KEY_LEN, NONCE_LEN, TAG_LEN,
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
    // both are usually non-empty and their relative sizes vary freely. The selector is
    // drawn from *two* bytes: with one, `split <= 255` and no input could produce an AAD
    // longer than 255 bytes, so those lengths were unreachable while the header claimed
    // they were exercised widely (an audit decoded the corpus and found the cap).
    let (aad, pt) = if rest.len() < 2 {
        (&rest[..0], &rest[..0])
    } else {
        let sel = rest[0] as usize | ((rest[1] as usize) << 8);
        let body = &rest[2..];
        let split = sel % (body.len() + 1);
        (&body[..split], &body[split..])
    };

    // A second key and a second nonce, derived from the same input bytes so they vary
    // with it. Everything below used to run with a single key/nonce per input, so a
    // build that ignored its key (or nonce) was self-consistent under every arm;
    // these reach the mismatch class that only the KATs used to catch.
    //
    // The difference is *checked*, not forced by a constant flip: an input-dependent
    // XOR can cancel any fixed bit (the first version flipped `other_key[0] ^= 0x80`
    // after the loop, and the fuzzer found a 60-byte input with `tail[0] == 0x80`
    // that reproduced the original key, making the key-mismatch arm assert on a valid
    // round trip). The equality check is what makes the arm's premise true for every
    // input.
    let mut other_key = key;
    let mut other_nonce = nonce;
    for (dst, src) in other_key
        .iter_mut()
        .chain(other_nonce.iter_mut())
        .zip(rest.iter().copied())
    {
        *dst ^= src;
    }
    if other_key == key {
        other_key[0] ^= 0x80;
    }
    if other_nonce == nonce {
        other_nonce[0] ^= 0x80;
    }

    // `encrypt` can only fail on allocation failure or a length above `MAX_MSG_SIZE`,
    // neither reachable at fuzz sizes. The silent `return` this replaces let a
    // regression that made `encrypt` refuse a valid input turn all five properties
    // vacuously green.
    let (ct, tag) = encrypt(&key, &nonce, aad, pt).expect("encrypt refuses a valid input");

    // Property 1: the honest round trip must always succeed and match.
    let back = decrypt(&key, &nonce, aad, &ct, &tag).expect("round trip must verify");
    assert_eq!(back.as_slice(), pt, "round trip must recover the plaintext");

    // Property 2a: the key and the nonce are binding. The ciphertext and tag above
    // were made under `key`/`nonce`; the same wire bytes under either derived value
    // must be rejected. Corrupting ciphertext/tag/AAD (property 2 below) cannot see a
    // key- or nonce-ignoring build: encrypt and decrypt stay mutually consistent.
    assert!(
        decrypt(&other_key, &nonce, aad, &ct, &tag).is_err(),
        "a ciphertext must not authenticate under a different key"
    );
    assert!(
        decrypt(&key, &other_nonce, aad, &ct, &tag).is_err(),
        "a ciphertext must not authenticate under a different nonce"
    );

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
            let i = (tweak * 256 + mode as usize / 3) % TAG_LEN;
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
            let i = (tweak * 256 + mode as usize / 3) % TAG_LEN;
            bad_tag[i] ^= 1 << (mode % 8);
            assert!(
                decrypt(&key, &nonce, aad, &ct, &bad_tag).is_err(),
                "a corrupted tag byte must not authenticate"
            );
        }
    }

    // Property 2b: the empty AAD is a value, not a wildcard. `tag` was made under
    // `aad`; swapping that for an empty AAD (when it was non-empty) or for a
    // non-empty one (when it was empty) must be rejected. The corruption arm above
    // only ever corrupts a *non-empty* AAD -- it has to skip an empty one -- so an
    // implementation that special-cased `[]` as "nothing to bind" stays invisible
    // there.
    let other_aad: &[u8] = if aad.is_empty() { &[0x5A] } else { &[] };
    assert!(
        decrypt(&key, &nonce, other_aad, &ct, &tag).is_err(),
        "a tag bound to one AAD must not authenticate under another (empty is a value)"
    );

    // Property 3: arbitrary wire bytes. Take a tag and ciphertext straight from the
    // fuzzer (not from `encrypt`) and require either rejection, or acceptance that is
    // self-consistent -- the recovered plaintext must re-encrypt to exactly the bytes
    // presented. This is the structurally-invalid input the target never used to reach.
    // Both an empty and a non-empty AAD are tried: with only `b""`, a tag-splice bug
    // conditioned on a non-empty AAD was unreachable.
    if rest.len() >= TAG_LEN {
        let (raw_tag, raw_ct) = rest.split_at(TAG_LEN);
        let raw_tag: [u8; TAG_LEN] = raw_tag.try_into().unwrap();
        // The non-empty choice is `aad` when the split produced one, and the raw tag
        // (always `TAG_LEN` bytes) when it did not.
        let wire_aad: &[u8] = if aad.is_empty() { &raw_tag } else { aad };
        for wire_aad in [b"".as_slice(), wire_aad] {
            if let Ok(recovered) = decrypt(&key, &nonce, wire_aad, raw_ct, &raw_tag) {
                let (re_ct, re_tag) =
                    encrypt(&key, &nonce, wire_aad, &recovered).expect("re-encrypt must succeed");
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
    }

    // Property 5: `decrypt_bounded` applies the caller's policy bound before any
    // allocation. The ciphertext's own length is a valid bound and must be accepted;
    // one byte less must be refused with `MessageTooLong`. This is the length-error
    // class the format limit (2^38 bytes) puts out of fuzz reach.
    let bounded = decrypt_bounded(&key, &nonce, aad, &ct, &tag, ct.len())
        .expect("the ciphertext's own length is a valid bound");
    assert_eq!(
        bounded.as_slice(),
        pt,
        "the bounded decrypt must recover the plaintext"
    );
    if !ct.is_empty() {
        assert_eq!(
            decrypt_bounded(&key, &nonce, aad, &ct, &tag, ct.len() - 1),
            Err(Error::MessageTooLong),
            "a bound one byte below the ciphertext must refuse"
        );
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
