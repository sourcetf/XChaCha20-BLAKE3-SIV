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
//!
//! **Bounds on the coverage, stated here rather than assumed.** The *full-byte*
//! sweeps below are capped per field, and each says which rows it scans:
//! `differential_every_position_is_authenticated` takes every ciphertext+tag bit of
//! every row with `msg_len <= 300` (40 of the 49 rows — including nine whose AADs are
//! longer than the *other* sweep's cap), and `differential_every_aad_bit_is_authenticated`
//! takes every AAD bit of every row with `aad_len <= 130`. Nothing in either field is
//! then left outside a deterministic tamper sweep:
//! `differential_long_rows_sampled_positions_are_authenticated` covers, per field,
//! every row with `msg_len > 300` (the fixture's nine long rows and all nine
//! large-size rows, the two ~1 MiB rows included) and every row with `aad_len > 130`,
//! plus the large fixture's other non-empty AADs, which the full AAD sweep never
//! iterates. For each such row it flips all eight bits at a deterministic, documented
//! *sample* of positions: first and last two, up to 16 evenly spaced, plus
//! `60000`/`60001` wherever the field holds them — the two ~1 MiB rows take the end
//! anchors and the 60000 pair but no spread on either field, for their measured wall
//! clock.
//! That test exists because a single-bit gap at a long-message offset is invisible to
//! the full sweeps' caps and to random sampling, which reaches byte 60000 with
//! probability ~6e-5 per case; the sample is not exhaustive, and for positions
//! outside it — and for the long rows' tag bytes, which no sweep tampers — the
//! coverage is the replay against the reference here (untampered, but byte-for-byte),
//! the sampled differential (`tools/broad_differential.py`) and the fuzzer. The
//! large-size fixture replays both call shapes against its digests — the allocating
//! `encrypt`/`decrypt` pair and the detached in-place pair — at the sizes where the
//! tag's concatenation window changes.

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

/// The `# key = ...` / `# nonce = ...` header, shared by both fixtures.
fn header(text: &str) -> ([u8; 32], [u8; 24]) {
    let mut key = None;
    let mut nonce = None;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim();
        if let Some(v) = rest.strip_prefix("key").and_then(|v| v.split('=').nth(1)) {
            let v = v.trim();
            if !v.is_empty() {
                key = Some(hex_decode(v));
            }
        } else if let Some(v) = rest.strip_prefix("nonce").and_then(|v| v.split('=').nth(1)) {
            let v = v.trim();
            if !v.is_empty() {
                nonce = Some(hex_decode(v));
            }
        }
    }
    (
        key.expect("key header").try_into().expect("32-byte key"),
        nonce
            .expect("nonce header")
            .try_into()
            .expect("24-byte nonce"),
    )
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

    // The exact count, not a floor. `>= 40` was satisfied after deleting any nine rows,
    // and deleting a row removes its boundary from the coverage while the test stays
    // green; 49 is what `tools/gen_test_vectors.py --check` reports for the checked-in
    // fixture. Regenerating the fixture with a different set is meant to require
    // editing this line deliberately.
    assert_eq!(
        rows.len(),
        49,
        "the differential fixture changed size: {} rows (49 are checked in; update this \
         line deliberately together with tools/gen_test_vectors.py)",
        rows.len()
    );

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
/// every position — all eight bits of every ciphertext and tag byte — of every
/// fixture row with `msg_len <= 300`. The rows above that cap, and the large
/// fixture's rows (where byte 60000 first exists), are swept at a deterministic
/// sample of positions by `differential_long_rows_sampled_positions_are_authenticated`
/// below; the cap here is a cost bound, not the file's coverage boundary.
#[test]
fn differential_every_position_is_authenticated() {
    let f = parse_fixture();
    // Count what was actually swept. The row filter below is a size cap, and a
    // regenerated fixture whose sizes all exceeded it would make this test scan
    // zero positions and pass vacuously; the exact count at the end forbids that.
    //
    // The cap is a cost bound, not a boundary: every swept position costs one full
    // decryption per bit, so the 300-byte rows are ~600 positions each, while a 1 MiB
    // row would be 2^23. Above the cap the long-row test below sweeps a deterministic
    // sample, and the sampled differential and the fuzzer cover random positions.
    let mut swept_rows = 0usize;
    let mut swept_positions = 0usize;
    for (msg_len, aad_len, ct, tag) in &f.rows {
        // Sweep a subset of rows: all of them would be O(total bytes).
        if *msg_len > 300 {
            continue;
        }
        swept_rows += 1;
        swept_positions += ct.len() + TAG_LEN;
        let aad = aad_for(*aad_len);

        // The untampered row must authenticate first, or the sweep certifies
        // nothing: under a broken tag (an audit made `derive_tag` hash the empty
        // message) every `is_err()` below holds because the *untampered* row is
        // rejected too, and this was one of the two only-green tests in the file.
        let back = decrypt(&f.key, &f.nonce, &aad, ct, tag).unwrap_or_else(|_| {
            panic!(
                "the untampered fixture row must authenticate before its tampers can \
                 mean anything (msg_len={msg_len}, aad_len={aad_len})"
            )
        });
        assert_eq!(
            back.as_slice(),
            pt_for(*msg_len).as_slice(),
            "the untampered row must round-trip (msg_len={msg_len}, aad_len={aad_len})"
        );

        // Every bit, not one fixed bit per byte: the old sweep flipped 0x01 in every
        // ciphertext byte and 0x80 in every tag byte, so seven of the eight bits per byte
        // were never tried by the test whose docstring says "any single bit anywhere". A
        // tag computation that ignored one bit of the absorbed ciphertext would survive it.
        // (The property tests in `security.rs` sample the bit, so the suite did cover this;
        // the sweep that *claims* the exhaustive form now is one.) Cost is 8x, bounded by
        // the cap above.
        for pos in 0..ct.len() {
            for bit in 0..8 {
                let mut bad = ct.clone();
                bad[pos] ^= 1u8 << bit;
                assert!(
                    decrypt(&f.key, &f.nonce, &aad, &bad, tag).is_err(),
                    "ciphertext byte {pos} bit {bit} not authenticated (msg_len={msg_len}, \
                     aad_len={aad_len})"
                );
            }
        }
        for pos in 0..TAG_LEN {
            for bit in 0..8 {
                let mut bad = *tag;
                bad[pos] ^= 1u8 << bit;
                assert!(
                    decrypt(&f.key, &f.nonce, &aad, ct, &bad).is_err(),
                    "tag byte {pos} bit {bit} not authenticated (msg_len={msg_len}, \
                     aad_len={aad_len})"
                );
            }
        }
    }
    // Exact, not a floor: `>= 10` and `> 0` were satisfied after deleting rows, and the
    // point of counting is that the sweep covers the fixture's below-cap rows in full.
    // The numbers come from the checked-in fixture under this test's cap (40 of its 49
    // rows, 5871 ciphertext+tag positions): a fixture regeneration that changes either
    // should fail here.
    assert_eq!(
        (swept_rows, swept_positions),
        (40, 5871),
        "the swept set changed ({swept_rows} rows, {swept_positions} positions): the cap \
         or the fixture moved, so update these counts deliberately"
    );
}

/// The AAD must be authenticated in full: flipping any AAD bit must be rejected, at
/// every position — all eight bits of every AAD byte — of every fixture row with
/// `aad_len <= 130`, including positions beyond a 16-byte and a 64-byte boundary.
/// Ten rows (including the nine whose AADs exceed the cap while their messages stay
/// below the message sweep's) have larger AADs; theirs are swept at a deterministic
/// sample of positions by `differential_long_rows_sampled_positions_are_authenticated`
/// below, and the large fixture's non-empty AADs — which this sweep never iterates —
/// are sampled there too. The cap is a cost bound, not this test's coverage of "any
/// AAD bit anywhere".
#[test]
fn differential_every_aad_bit_is_authenticated() {
    let f = parse_fixture();
    // As above: an exact count, so a fixture with no small-AAD rows cannot make this vacuous.
    // The 130 cap is the same cost bound as the message sweep's 300: the AAD sweep is
    // O(aad_len) per row, and the fixture's non-empty AADs go up to 300 -- the largest
    // *below* this cap is 65, so **ten** of the twenty-six non-empty rows are outside it
    // (seven *distinct lengths*: 191, 192, 193, 255, 256, 257, 300 -- the first version of
    // this sentence said "seven ... rows", which is the distinct-length count, not the row
    // count). Those ten are exactly the AAD set of the sampled sweep below, so their AAD
    // fields are tampered there rather than here; nine of them have `msg_len <= 300` and
    // reach no message sweep either.
    // (This said "go up to 130", which was never true of the fixture; an audit parsed
    // it.) The cap is a cost bound, not the file's coverage boundary: every row is still
    // checked by the whole-fixture test above, and the rows above the cap have their AAD
    // swept at a deterministic sample of positions by
    // `differential_long_rows_sampled_positions_are_authenticated`.
    let mut swept_rows = 0usize;
    for (msg_len, aad_len, ct, tag) in &f.rows {
        if *aad_len > 130 {
            continue;
        }
        if *aad_len > 0 {
            swept_rows += 1;
        }
        let aad = aad_for(*aad_len);

        // As above: the untampered row must authenticate, or every rejection below
        // below is the broken tag rather than the tampered AAD. The empty-AAD rows
        // are checked too -- they sweep no positions, so this is the only thing the
        // loop asserts for them.
        let back = decrypt(&f.key, &f.nonce, &aad, ct, tag).unwrap_or_else(|_| {
            panic!(
                "the untampered fixture row must authenticate before its AAD tampers can \
                 mean anything (msg_len={msg_len}, aad_len={aad_len})"
            )
        });
        assert_eq!(
            back.as_slice(),
            pt_for(*msg_len).as_slice(),
            "the untampered row must round-trip (msg_len={msg_len}, aad_len={aad_len})"
        );

        // As in the message sweep: every bit of every AAD byte, not one fixed bit per
        // byte, so the docstring's "any AAD bit" is what runs.
        for pos in 0..aad.len() {
            for bit in 0..8 {
                let mut bad = aad.clone();
                bad[pos] ^= 1u8 << bit;
                assert!(
                    decrypt(&f.key, &f.nonce, &bad, ct, tag).is_err(),
                    "aad byte {pos} bit {bit} not authenticated (msg_len={msg_len}, \
                     aad_len={aad_len})"
                );
            }
        }
    }
    // Exact, as above: 16 non-empty AAD rows below the cap (the fixture's non-empty AADs
    // top out at 300, largest below the cap 65). A floor of 5 would survive eleven rows being
    // dropped from the
    // sweep.
    assert_eq!(
        swept_rows, 16,
        "the AAD sweep covered {swept_rows} non-empty rows, not the fixture's 16 below the \
         cap: update the count deliberately if the fixture changed"
    );
}

/// The large-size fixture, whose expected output is a digest rather than bytes.
///
/// The fixture above stops at 2 KiB — a megabyte of message is two megabytes of hex
/// — which left everything above `TAG_CONCAT_LIMIT` (65 536 bytes) witnessed only
/// by the claim that the tag's hash *call shape* does not change the bytes it
/// produces. These rows check that claim against the reference implementation
/// instead. The switch is on the *total* `48 + aad + msg`, so with this fixture's
/// empty AAD the boundary in message lengths is 65488 (the last contiguous-path
/// message here) and 65489 (the first three-part one); an earlier revision of this
/// comment said 64 KiB/65 537, which ignored the 48-byte head.
///
/// The digest is plain BLAKE3 over `ciphertext || tag` — a comparison device, so
/// deliberately not the keyed construction whose output it is checking.
#[test]
fn differential_large_vectors_match_reference() {
    let text = include_str!("vectors_differential_large.txt");
    let (key, nonce) = header(text);

    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let msg_len: usize = it.next().expect("msg len").parse().expect("int");
        let aad_len: usize = it.next().expect("aad len").parse().expect("int");
        let digest = hex_decode(it.next().expect("digest"));
        rows.push((msg_len, aad_len, digest));
    }
    // The fixture holds nine vectors. The count is exact and the two sizes that
    // straddle `TAG_CONCAT_MIN`/`TAG_CONCAT_LIMIT` are required, so dropping rows (or
    // the boundary pair) fails here instead of shrinking the test silently.
    let sizes: Vec<usize> = rows.iter().map(|(m, _, _)| *m).collect();
    assert_eq!(
        rows.len(),
        9,
        "the large fixture changed size: {} rows at {sizes:?} (9 are checked in; update \
         this line deliberately together with tools/gen_test_vectors.py)",
        rows.len()
    );
    assert!(
        sizes.contains(&1999)
            && sizes.contains(&2000)
            && sizes.contains(&65488)
            && sizes.contains(&65489),
        "large fixture lost a boundary vector: {sizes:?}"
    );
    // ...and each of those four must carry the *empty* AAD the docstring above assumes.
    // The switch is on `48 + aad + msg`, so a nonzero AAD on one of these rows moves the
    // boundary in message lengths: `sizes.contains(&65488)` would keep passing while the
    // row no longer sits at the top of the window, which is the one thing this fixture
    // exists to witness. Pin the AAD too, so a regeneration that changes it fails here
    // deliberately rather than silently retiring the boundary.
    for (want_len, want_aad) in [(1999usize, 0usize), (2000, 0), (65488, 0), (65489, 0)] {
        assert!(
            rows.iter()
                .any(|(m, a, _)| *m == want_len && *a == want_aad),
            "large fixture lost the boundary vector msg_len={want_len} aad_len={want_aad} \
             (the pair only straddles the tag's concatenation window with an empty AAD): \
             {sizes:?}"
        );
    }

    for (msg_len, aad_len, want) in &rows {
        let pt = pt_for(*msg_len);
        let aad = aad_for(*aad_len);
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&ct);
        hasher.update(&tag);
        assert_eq!(
            hasher.finalize().as_bytes().as_slice(),
            want.as_slice(),
            "digest mismatch at msg_len={msg_len} aad_len={aad_len}"
        );

        // Decryption at these sizes too, so the path is not only covered one way.
        let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(
            back.as_slice(),
            pt.as_slice(),
            "roundtrip at msg_len={msg_len}"
        );

        // And the detached in-place shape at the same sizes, against the same digest:
        // these are the rows where the tag's concatenation window changes, so a
        // coverage claim about them that exercised only the allocating entry point
        // would miss exactly the call shape the in-place API uses.
        let mut buf = pt.clone();
        let in_place_tag =
            xchacha20_blake3_siv::encrypt_in_place_detached(&key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(
            in_place_tag, tag,
            "detached tag differs from the allocating one at msg_len={msg_len}"
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf);
        hasher.update(&in_place_tag);
        assert_eq!(
            hasher.finalize().as_bytes().as_slice(),
            want.as_slice(),
            "detached digest mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        xchacha20_blake3_siv::decrypt_in_place_detached(
            &key,
            &nonce,
            &aad,
            &mut buf,
            &in_place_tag,
        )
        .unwrap();
        assert_eq!(buf, pt, "detached roundtrip at msg_len={msg_len}");
    }
}

/// The spread of the long-row tamper sample: at most this many evenly spaced positions,
/// in addition to the four end anchors. See [`spread_for`] for the cost bound this cap
/// is, and for the further cap the ~1 MiB rows take.
const SPREAD_POSITIONS: usize = 16;

/// No spread at all on rows whose message exceeds this length: every sampled position
/// of such a row — message *or* AAD — costs a full `msg_len`-byte decryption, so the
/// row's whole sample is reduced to its four end anchors and the `60000`/`60001` pair.
/// See [`spread_for`] for the measured numbers.
const SPREAD_LEN_CUTOFF: usize = 100_000;

/// The number of evenly spaced positions [`sampled_positions`] adds to one field of a
/// row: zero when the row's message exceeds [`SPREAD_LEN_CUTOFF`] bytes, otherwise
/// `field_len / 64`, at least one and at most [`SPREAD_POSITIONS`].
///
/// Both bounds are wall-clock bounds, because each sampled position costs eight full
/// decryptions (one per bit) and a decryption is milliseconds at these sizes in a debug
/// build — measured in this profile with `profile_probe` (allocating round trips, so
/// half per direction): 0.49 ms at 2 000 bytes, 14.8 ms at 65 489, 22.5 ms at 100 000,
/// 261 ms at 1 MiB; one comparison in the sweep's shape — clone plus allocating
/// `decrypt` — measures 7.1 / 10.9 / 115 ms at 65 489 / 100 000 / 1 MiB.
/// One sampled position on a 1 MiB row therefore costs ~0.9 s. Measured, admitting the
/// fixture's two ~1 MiB rows uncapped — 21 message positions each plus 19 AAD positions
/// on `(1 000 000, 12 345)`, 488 comparisons — takes this test from 6.0 s to 64.7 s
/// (debug, single test); with the row cap it takes 18-23 s across three runs
/// (18.4, 20.2, 22.6 s). (An earlier revision of this comment said "a 64-position
/// spread over the 1 MiB row would add ~17 s": 17-18 s is the *21-position* sample,
/// and a 64-position spread is ~51 s.) The spread positions the cap drops would have
/// covered the middle of a field above 100 000 bytes, which the 100 000-byte row's
/// uncapped spread still covers in
/// full, and which the property tests and the sampled differential probe at random.
fn spread_for(msg_len: usize, field_len: usize) -> usize {
    if msg_len > SPREAD_LEN_CUTOFF {
        0
    } else {
        (field_len / 64).clamp(1, SPREAD_POSITIONS)
    }
}

/// The deterministic position sample the long-row sweep tampers for one field of a row
/// whose message is `msg_len` bytes: the first two and last two bytes of the field,
/// [`spread_for`] further positions evenly spaced over it, and `60000`/`60001` whenever
/// the field is long enough to hold them.
///
/// Nothing here is random: the set is a function of `(msg_len, field_len)` alone, so a
/// failure reproduces exactly and a regenerated fixture keeps the same coverage. The
/// audit's "ignore bit 4 of `ct[60000]`" is the reason for the 60000 pair:
/// `pt_for(60000)` (= `(60000 * 37 + 11) % 256` = 235 = `0b1110_1011`) has bit 4
/// *clear*, and the encryption does not move it, so a defect that ignores that bit does
/// not change the large fixture's digests either — the tamper sweep has to visit the
/// position itself.
fn sampled_positions(msg_len: usize, field_len: usize) -> Vec<usize> {
    if field_len == 0 {
        return Vec::new();
    }
    let mut positions = vec![0, field_len - 1];
    if field_len > 1 {
        positions.push(1);
        positions.push(field_len - 2);
    }
    let spread = spread_for(msg_len, field_len);
    for k in 0..spread {
        positions.push(k * field_len / spread);
    }
    if field_len > 60000 {
        positions.push(60000);
    }
    if field_len > 60001 {
        positions.push(60001);
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// What the sampled sweep actually tampered, split by field. Exact counts, not floors:
/// the point of counting is that each sample rule's *set* is pinned, so a regenerated
/// fixture or a moved cap fails the test's assertions deliberately instead of shrinking
/// the sweep.
#[derive(Default)]
struct SampledSweepCounts {
    message_rows: usize,
    message_positions: usize,
    message_comparisons: usize,
    aad_rows: usize,
    aad_positions: usize,
    aad_comparisons: usize,
}

/// Tamper-sweep one **already-anchored** row over the sampled positions of the requested
/// fields: every bit of every sampled message and AAD position must be rejected.
/// `counts` accumulates what ran, so a caller counting a sweep counts what actually
/// happened. `sweep_message` applies [`sampled_positions`] to `ct`;
/// `sweep_aad` applies it to `aad`; a row may need either, both, or (the full sweeps
/// having taken it) neither.
///
/// The caller anchors the row against the reference first (the fixture tag for the
/// differential fixture's rows, the digest for the large-size fixture's). The untampered
/// checks then come first, as in the full sweeps above: under a broken tag every
/// `is_err()` below would hold because the *untampered* row is rejected too.
/// Which fields of a row the sampled sweep tampers. One value rather than two booleans:
/// every call states a combination its loop has already decided, and the two flags pushed
/// the argument list past clippy's limit without saying anything the enum does not.
#[derive(Clone, Copy)]
enum RowFields {
    Message,
    Aad,
    Both,
}

fn sweep_sampled_positions(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    fields: RowFields,
    counts: &mut SampledSweepCounts,
) {
    let (msg_len, aad_len) = (ct.len(), aad.len());
    let back = decrypt(key, nonce, aad, ct, tag).unwrap_or_else(|_| {
        panic!(
            "the untampered row must authenticate before its tampers can mean anything \
             (msg_len={msg_len}, aad_len={aad_len})"
        )
    });
    assert_eq!(
        back.as_slice(),
        pt_for(msg_len).as_slice(),
        "the untampered row must round-trip (msg_len={msg_len}, aad_len={aad_len})"
    );

    if matches!(fields, RowFields::Message | RowFields::Both) {
        let positions = sampled_positions(msg_len, msg_len);
        counts.message_rows += 1;
        counts.message_positions += positions.len();
        for pos in positions {
            for bit in 0..8 {
                counts.message_comparisons += 1;
                let mut bad = ct.to_vec();
                bad[pos] ^= 1u8 << bit;
                assert!(
                    decrypt(key, nonce, aad, &bad, tag).is_err(),
                    "sampled ciphertext byte {pos} bit {bit} not authenticated \
                     (msg_len={msg_len}, aad_len={aad_len})"
                );
            }
        }
    }
    if matches!(fields, RowFields::Aad | RowFields::Both) {
        let positions = sampled_positions(msg_len, aad_len);
        counts.aad_rows += 1;
        counts.aad_positions += positions.len();
        for pos in positions {
            for bit in 0..8 {
                counts.aad_comparisons += 1;
                let mut bad = aad.to_vec();
                bad[pos] ^= 1u8 << bit;
                assert!(
                    decrypt(key, nonce, &bad, ct, tag).is_err(),
                    "sampled aad byte {pos} bit {bit} not authenticated \
                     (msg_len={msg_len}, aad_len={aad_len})"
                );
            }
        }
    }
}

/// The tamper property of `differential_every_position_is_authenticated` for the rows and
/// fields the full-byte sweeps cannot reach, **per field** — the two rules are separate
/// on purpose, because the fixture's caps have different row sets:
///
/// * **Message field**, every row with `msg_len > 300`: the differential fixture's nine
///   long rows `(511, 0) … (2049, 0)`, and **all nine** large-fixture rows, the two
///   ~1 MiB rows `(1 000 000, 12 345)` and `(1 048 576, 0)` included — their spread is
///   capped by [`spread_for`] for the measured wall clock, but their end anchors and
///   the `60000`/`60001` pair are swept like every other long row's.
/// * **AAD field**, every row the full AAD sweep cannot reach: the differential
///   fixture's ten rows with `aad_len > 130` — **nine of them have `msg_len <= 300`**,
///   so they are in no message sweep, and the tenth is the long row `(1025, 300)` —
///   plus the large fixture's two non-empty AADs, `(100 000, 64)` and
///   `(1 000 000, 12 345)`, because `differential_every_aad_bit_is_authenticated` only
///   iterates the differential fixture. The ~1 MiB row's AAD sample is capped with its
///   message: every sampled position there costs a full 1 MiB decryption whatever
///   field it tampers.
///
/// Each row is anchored against the independent reference before tampering: the
/// differential fixture byte-for-byte (ciphertext and tag), the large fixture by its
/// `BLAKE3(ct || tag)` digest. The row set each field's rule covers, the exact-position
/// counts and the comparisons are asserted at the end.
///
/// What the deterministic sweeps do *not* touch, and what is therefore covered only by
/// the untampered replays above (`differential_encrypt_matches_reference`,
/// `differential_detached_matches_reference`, `differential_large_vectors_match_reference`)
/// and by the property tests and fuzzer: the **tag bytes** of every row with
/// `msg_len > 300` (the full sweep owns the tag only below its cap; this one tampers
/// long rows' message and AAD fields), the positions outside the capped sample on the
/// two ~1 MiB rows (message and AAD alike), and every other position outside a sample
/// on a long field.
///
/// The sample is deterministic — a function of `(msg_len, field_len)` alone, see
/// [`sampled_positions`] — because the audit's "ignore bit 4 of `ct[60000]`" injection
/// hid behind exactly the gap a random sampler leaves: it reaches byte 60000 with
/// probability ~6e-5 per case. Re-running that injection in a scratch copy still fails
/// this test, and an AAD injection at a sampled position of one of the nine rows
/// (which no sweep touched before the AAD rule above existed) fails it too.
#[test]
fn differential_long_rows_sampled_positions_are_authenticated() {
    let f = parse_fixture();
    let mut counts = SampledSweepCounts::default();

    // The differential fixture's rows with a field above the full sweeps' caps. Each is
    // anchored against the fixture first, so the sweep tampers reference output rather
    // than this crate's own.
    for (msg_len, aad_len, ct, tag) in &f.rows {
        let fields = match (*msg_len > 300, *aad_len > 130) {
            (true, true) => RowFields::Both,
            (true, false) => RowFields::Message,
            (false, true) => RowFields::Aad,
            (false, false) => continue,
        };
        let aad = aad_for(*aad_len);
        let (got_ct, got_tag) = encrypt(&f.key, &f.nonce, &aad, &pt_for(*msg_len)).unwrap();
        assert_eq!(
            &got_ct, ct,
            "ciphertext mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        assert_eq!(
            &got_tag, tag,
            "tag mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        sweep_sampled_positions(&f.key, &f.nonce, &aad, ct, tag, fields, &mut counts);
    }

    // The large fixture, where rows long enough to reach byte 60000 live. Every row is
    // above the message sweep's cap, so all of them get the message sample; an AAD is
    // sampled whenever it is non-empty, because no full sweep iterates this fixture.
    // Its expected output is a digest rather than bytes, so the anchor is the digest: a
    // row is swept only once its encryption reproduces the independent reference's
    // digest.
    let text = include_str!("vectors_differential_large.txt");
    let (key, nonce) = header(text);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let msg_len: usize = it.next().expect("msg len").parse().expect("int");
        let aad_len: usize = it.next().expect("aad len").parse().expect("int");
        let want = hex_decode(it.next().expect("digest"));
        let pt = pt_for(msg_len);
        let aad = aad_for(aad_len);
        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&ct);
        hasher.update(&tag);
        assert_eq!(
            hasher.finalize().as_bytes().as_slice(),
            want.as_slice(),
            "digest mismatch at msg_len={msg_len} aad_len={aad_len}"
        );
        sweep_sampled_positions(
            &key,
            &nonce,
            &aad,
            &ct,
            &tag,
            if aad_len > 0 {
                RowFields::Both
            } else {
                RowFields::Message
            },
            &mut counts,
        );
    }

    // The audit's byte 60000 must stay in the sample wherever it exists, the capped
    // ~1 MiB rows included; that pair is why this test exists.
    assert!(
        (60000..60002).all(|p| sampled_positions(65_489, 65_489).contains(&p))
            && (60000..60002).all(|p| sampled_positions(100_000, 100_000).contains(&p))
            && (60000..60002).all(|p| sampled_positions(1_000_000, 1_000_000).contains(&p))
            && (60000..60002).all(|p| sampled_positions(1_048_576, 1_048_576).contains(&p)),
        "the sample stopped covering the long-message positions: this test exists for \
         byte 60000"
    );
    // Exact, not a floor: `> 0` would survive the sample shrinking to one row, and the
    // point of counting is that every rule's row set is pinned. The numbers come from
    // the checked-in fixtures under the rules above.
    //   Message: 9 fixture rows above 300 bytes (145 positions) + all 9 large rows
    //   (153 positions, the two ~1 MiB rows at 6 each after the row cap) = 18 rows.
    //   AAD: 10 fixture rows above 130 bytes (64 positions; the nine with msg_len <= 300
    //   contribute 57 of them) + the large fixture's two non-empty AADs (8 positions;
    //   the 100 000-byte row's 4-position spread is the rule's floor, the ~1 MiB row's
    //   is capped with its message) = 12 rows.
    assert_eq!(
        (
            counts.message_rows,
            counts.message_positions,
            counts.message_comparisons
        ),
        (18, 298, 2384),
        "the message sample changed ({} rows, {} positions, {} comparisons): the rule, \
         the fixture or the spread cap moved, so update these numbers deliberately",
        counts.message_rows,
        counts.message_positions,
        counts.message_comparisons
    );
    assert_eq!(
        (
            counts.aad_rows,
            counts.aad_positions,
            counts.aad_comparisons
        ),
        (12, 72, 576),
        "the AAD sample changed ({} rows, {} positions, {} comparisons): the rule, the \
         fixture or the spread cap moved, so update these numbers deliberately",
        counts.aad_rows,
        counts.aad_positions,
        counts.aad_comparisons
    );
}
