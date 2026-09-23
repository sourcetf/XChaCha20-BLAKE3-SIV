//! Differential tests against the independent reference implementation.
//!
//! The vectors in `tests/vectors_differential.txt` come from
//! `tools/ref_impl.py` — an implementation written from the RFC 8439 /
//! draft-irtf-cfrg-xchacha-03 pseudocode and the BLAKE3 specification, not
//! derived from this crate.  It self-checks against published RFC, HChaCha20 and
//! official-BLAKE3 vectors before emitting anything.  Regenerate with
//! `python3 tools/gen_test_vectors.py`.
//!
//! These pin the public 24-byte-nonce API across every internal length boundary
//! (ChaCha20 blocks, the SSE2/NEON/AVX2 SIMD widths, and BLAKE3's chunk
//! boundary).  The in-crate KATs cover a handful of inputs; this covers the
//! boundaries where stream-cipher wrappers and buffered hashes actually break.

use xchacha20_blake3_siv::{decrypt, encrypt, TAG_LEN};

/// Must match `tools/gen_test_vectors.py`.
fn pt_for(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 37 + 11) % 256) as u8).collect()
}

fn aad_for(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 91 + 7) % 256) as u8).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    // `-` is the fixture's placeholder for an empty ciphertext (an empty field
    // would collapse under whitespace splitting).
    if s == "-" {
        return Vec::new();
    }
    // `% 2 == 0` rather than `is_multiple_of`: the latter is stable only since
    // Rust 1.87, and Cargo.toml declares a 1.85 MSRV. Clippy's
    // `manual_is_multiple_of` suggestion is MSRV-aware and does not fire here.
    assert!(s.len() % 2 == 0, "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

struct Fixture {
    key: [u8; 32],
    nonce: [u8; 24],
    rows: Vec<(usize, usize, Vec<u8>, [u8; TAG_LEN])>,
}

fn parse_fixture() -> Fixture {
    let text = include_str!("vectors_differential.txt");

    let mut key = None;
    let mut nonce = None;
    let mut rows = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            // `# key   = <hex>` / `# nonce = <hex>`
            if let Some(v) = rest.trim().strip_prefix("key") {
                if let Some(v) = v.split('=').nth(1) {
                    let v = v.trim();
                    if !v.is_empty() {
                        key = Some(hex_decode(v));
                    }
                }
            } else if let Some(v) = rest.trim().strip_prefix("nonce") {
                if let Some(v) = v.split('=').nth(1) {
                    let v = v.trim();
                    if !v.is_empty() {
                        nonce = Some(hex_decode(v));
                    }
                }
            }
            continue;
        }

        let mut it = line.split_whitespace();
        let msg_len: usize = it.next().expect("msg len").parse().expect("int");
        let aad_len: usize = it.next().expect("aad len").parse().expect("int");
        let ct_hex = it.next().unwrap_or("");
        let tag_hex = it.next().expect("tag hex");
        rows.push((
            msg_len,
            aad_len,
            hex_decode(ct_hex),
            <[u8; TAG_LEN]>::try_from(hex_decode(tag_hex).as_slice())
                .unwrap_or_else(|_| panic!("tag must be {TAG_LEN} bytes")),
        ));
    }

    let key: [u8; 32] = key.expect("key header").try_into().expect("32-byte key");
    let nonce: [u8; 24] = nonce
        .expect("nonce header")
        .try_into()
        .expect("24-byte nonce");

    assert!(!rows.is_empty(), "fixture has no vectors");
    assert!(rows.len() >= 40, "fixture lost vectors: {}", rows.len());

    Fixture { key, nonce, rows }
}

#[test]
fn differential_encrypt_matches_reference() {
    let f = parse_fixture();
    for (msg_len, aad_len, want_ct, want_tag) in &f.rows {
        let pt = pt_for(*msg_len);
        let aad = aad_for(*aad_len);
        let (ct, tag) = encrypt(&f.key, &f.nonce, &aad, &pt).unwrap();
        assert_eq!(
            &ct, want_ct,
            "ciphertext mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        assert_eq!(
            &tag, want_tag,
            "tag mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
    }
}

#[test]
fn differential_decrypt_matches_reference() {
    let f = parse_fixture();
    for (msg_len, aad_len, ct, tag) in &f.rows {
        let pt = pt_for(*msg_len);
        let aad = aad_for(*aad_len);
        let back = decrypt(&f.key, &f.nonce, &aad, ct, tag).unwrap();
        assert_eq!(
            back.as_slice(),
            pt.as_slice(),
            "roundtrip mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
    }
}

/// The detached API must agree with the reference vectors too, so the two
/// entry points cannot drift apart on any length boundary.
#[test]
fn differential_detached_matches_reference() {
    use xchacha20_blake3_siv::{decrypt_in_place_detached, encrypt_in_place_detached};

    let f = parse_fixture();
    for (msg_len, aad_len, want_ct, want_tag) in &f.rows {
        let aad = aad_for(*aad_len);

        let mut buf = pt_for(*msg_len);
        let tag = encrypt_in_place_detached(&f.key, &f.nonce, &aad, &mut buf).unwrap();
        assert_eq!(
            &buf, want_ct,
            "detached ciphertext mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        assert_eq!(
            &tag, want_tag,
            "detached tag mismatch at msg_len={msg_len} aad_len={aad_len}"
        );

        decrypt_in_place_detached(&f.key, &f.nonce, &aad, &mut buf, want_tag).unwrap();
        assert_eq!(
            buf,
            pt_for(*msg_len),
            "detached roundtrip mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
    }
}

/// Every byte position of the ciphertext and of the tag must be covered by
/// authentication: flipping any single bit anywhere must be rejected.
///
/// This is the property `test_tampered_ct` samples once; here it is swept over
/// every position of several sizes.
#[test]
fn differential_every_position_is_authenticated() {
    let f = parse_fixture();
    for (msg_len, aad_len, ct, tag) in &f.rows {
        // Sweep a subset of rows: all of them would be O(total bytes).
        if *msg_len > 300 {
            continue;
        }
        let aad = aad_for(*aad_len);

        for pos in 0..ct.len() {
            let mut bad = ct.clone();
            bad[pos] ^= 0x01;
            assert!(
                decrypt(&f.key, &f.nonce, &aad, &bad, tag).is_err(),
                "ciphertext byte {pos} not authenticated (msg_len={msg_len}, aad_len={aad_len})"
            );
        }
        for pos in 0..TAG_LEN {
            let mut bad = *tag;
            bad[pos] ^= 0x80;
            assert!(
                decrypt(&f.key, &f.nonce, &aad, ct, &bad).is_err(),
                "tag byte {pos} not authenticated (msg_len={msg_len}, aad_len={aad_len})"
            );
        }
    }
}

/// The AAD must be authenticated in full: flipping any AAD bit must be
/// rejected, at every position, including beyond a 16-byte and a 64-byte
/// boundary.
#[test]
fn differential_every_aad_bit_is_authenticated() {
    let f = parse_fixture();
    for (msg_len, aad_len, ct, tag) in &f.rows {
        if *aad_len > 130 {
            continue;
        }
        let aad = aad_for(*aad_len);
        for pos in 0..aad.len() {
            let mut bad = aad.clone();
            bad[pos] ^= 0x01;
            assert!(
                decrypt(&f.key, &f.nonce, &bad, ct, tag).is_err(),
                "aad byte {pos} not authenticated (msg_len={msg_len}, aad_len={aad_len})"
            );
        }
    }
}
