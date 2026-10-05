//! Audit tool: a hex-in/hex-out batch interface to the crate, for differential
//! testing against a reference implementation in another language.
//!
//! Reads one vector per line from stdin —
//!
//! ```text
//! key_hex nonce_hex aad_hex msg_hex
//! ```
//!
//! — and writes `ct_hex tag_hex` per line, in order.  `-` is the empty string,
//! so a vector with no AAD does not collapse under whitespace splitting.  Blank
//! lines and `#` comments are skipped, and anything that is not a hex string of
//! the right length aborts rather than being silently mangled: this is a
//! verification tool, so a malformed vector must be loud. The diagnostics name
//! the offending field but never echo its bytes, so a malformed `key` or `msg`
//! line cannot put key material or plaintext into stderr.
//!
//! ```text
//! cargo run --release --example xsiv_stdin < vectors.txt > rust-side.txt
//! ```
//!
//! With `--roundtrip`, each vector is also decrypted (both the allocating and the
//! in-place entry point) and the plaintext is compared to the input. Encrypt-only is
//! what the differential fixture needs; the decrypt half is what
//! `tools/cache_profile.sh` needs, because the cache/branch profile of `decrypt` -- the
//! path the crate's whole hardening story is about, and under `ultra` the path a second
//! implementation runs on -- is not exercised by encrypting at all.
//!
//! Exists so `tools/broad_differential.py` can push thousands of random vectors
//! through the crate without a generated fixture living in the repository.  Not
//! part of the library, and not used by the test suite.

use std::io::{self, BufRead, Write};

use xchacha20_blake3_siv::{decrypt, decrypt_in_place_detached, encrypt};

fn from_hex(name: &str, field: &str) -> Vec<u8> {
    if field == "-" {
        return Vec::new();
    }
    // `name` rather than the bytes: a malformed key or message line must not echo
    // its contents into stderr, where they could be logged. The field index is in
    // the name, so the offending field is still identified.
    assert!(field.len() % 2 == 0, "{name}: odd-length hex field");
    // A leading sign is the one thing `from_str_radix` *accepts* that hex must not
    // (`+1` decodes to 0x01); everything else that is not a hex digit is rejected by
    // `from_str_radix` itself, loudly, through the `.expect` below.
    //
    // Deliberately not a per-byte `bytes().all(is_ascii_hexdigit)` scan, and the reason
    // is measured: `tools/cache_profile.sh` compares *instruction counts* for two
    // different keys, so a value-dependent predicate over the hex characters makes the
    // harness's own profile depend on the key. With such a guard here the counts
    // differential failed on a pristine tree ("FAIL: the enc cache or branch profile
    // depends on the key", exit 1), because '0' and 'f' take different paths through it.
    // These two comparisons execute the same instructions whatever the first byte is.
    assert!(
        !field.starts_with('+') && !field.starts_with('-'),
        "{name}: signed hex field"
    );
    // Chunked over the *bytes* rather than `&field[i..i + 2]`: slicing a `&str` by byte
    // index panics when the pair straddles a character boundary, and the panic message
    // quotes the offending character — which put a byte of the caller's field into stderr,
    // the one thing the contract above forbids (an audit measured it with a non-ASCII
    // field: `end byte index 2 is not a char boundary; it is inside 'é'`). `from_utf8` on
    // each two-byte chunk is what rejects a non-ASCII pair, and — like the two comparisons
    // above — it keeps '0' and 'f' on the same path, which the counts differential needs.
    field
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            // The field's *name*, never its bytes: this is the panic the doc comment above
            // promises will not leak the line's contents.
            let pair =
                core::str::from_utf8(pair).unwrap_or_else(|_| panic!("{name}: non-hex field"));
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("{name}: non-hex field"))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    s
}

fn main() {
    // A flag rather than a default: the differential fixture compares *encryption*
    // against the reference implementation, and a decrypt call in that path would make
    // the fixture's own output depend on a second computation.
    let roundtrip = std::env::args().skip(1).any(|a| a == "--roundtrip");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut n = 0usize;

    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            4,
            "expected 4 whitespace-separated fields (key nonce aad msg)"
        );
        let key = from_hex("key", fields[0]);
        let nonce = from_hex("nonce", fields[1]);
        let aad = from_hex("aad", fields[2]);
        let msg = from_hex("msg", fields[3]);

        let key: [u8; 32] = key
            .try_into()
            .unwrap_or_else(|_| panic!("key not 32 bytes"));
        let nonce: [u8; 24] = nonce
            .try_into()
            .unwrap_or_else(|_| panic!("nonce not 24 bytes"));

        let (ct, tag) = encrypt(&key, &nonce, &aad, &msg).expect("encrypt");
        if roundtrip {
            let pt = decrypt(&key, &nonce, &aad, &ct, &tag).expect("decrypt");
            // `assert!` rather than `assert_eq!`: the latter prints both operands on failure,
            // and `msg` is the caller's plaintext (this file's contract is that no field's
            // bytes reach stderr).
            assert!(pt == msg, "round trip differs from the message");
            // The in-place entry point has its own copy of the decision wiring, so it
            // is a separate path to profile rather than a duplicate of the one above.
            let mut buf = ct.clone();
            decrypt_in_place_detached(&key, &nonce, &aad, &mut buf, &tag)
                .expect("in-place decrypt");
            assert!(buf == msg, "in-place round trip differs from the message");
        }
        // `-` for an empty ciphertext, matching the input convention: an empty
        // field would collapse under whitespace splitting.
        let ct = if ct.is_empty() {
            "-".to_string()
        } else {
            to_hex(&ct)
        };
        writeln!(out, "{} {}", ct, to_hex(&tag)).expect("stdout");
        n += 1;
    }

    out.flush().expect("stdout");
    eprintln!("xsiv_stdin: {n} vectors");
}
