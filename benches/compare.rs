//! Head-to-head throughput against RustCrypto's `chacha20poly1305`.
//!
//! `XChaCha20Poly1305` is the natural reference point: same 24-byte nonce, same
//! ChaCha20 core, and it is what a caller would otherwise reach for. The
//! 12-byte-nonce `ChaCha20Poly1305` is included because the final encryption step
//! of a c2sp.org SIV-like construction is a 12-byte-nonce ChaCha20 operation --
//! the vendored `standard.txt`'s CCP-SIV MACs the *plaintext* with Poly1305 and
//! then encrypts with `ChaCha20(encKey, 0, tag[16..28])` -- so this is the closest
//! `aead` shape to that step, not the construction itself. `aead`'s in-place
//! interface is used for both sides so neither pays for an API shape the other
//! does not have.
//!
//! Run with `cargo bench --bench compare`. Numbers are host-specific and
//! hot-cache (neither side flushes between iterations); the *ratios* are the
//! stable signal. This crate derives more key material per message and wipes it,
//! and the default `hardened` build pays an extra fixed cost on decrypt, so the
//! crate's per-message overhead dominates at 64 bytes and disappears by 16 KiB.
//! Encrypt, decrypt and round-trip are all measured -- the decrypt asymmetry (SIV
//! decrypts before it can verify) is clean in the decrypt group and diluted inside
//! the round-trip group, whose second half calls the same in-place decrypt.
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached,
};

// Power-of-two sizes compare the dispatch paths cleanly; the in-between sizes keep
// the *tails* visible, which is where a message that is not a multiple of the SIMD
// stride actually spends time. That stride is 512 bytes on AVX2 and 256 on SSE2/NEON,
// so both decompositions are shown: 700 = 1x512 + 188 = 2x256 + 188;
// 5000 = 9x512 + 392 = 19x256 + 136.
const SIZES: [usize; 9] = [64, 256, 700, 1024, 4096, 5000, 16384, 65536, 1048576];

fn bench_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce24 = [0x55u8; 24];
    let nonce12 = [0x55u8; 12];
    let aad = b"associated data";
    let xcp = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));
    let cp = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));

    let mut group = c.benchmark_group("encrypt_in_place_detached");
    for size in SIZES {
        let pt = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Correctness before timing, in every arm: the `.unwrap()`s below only exclude
        // an implementation that returns `Err`. One that returns `Ok` of the wrong bytes
        // -- a stub, or a decrypt that verifies but never writes -- would be timed as a
        // throughput *win*, so each arm's outputs are round-tripped once here, outside
        // the measured closures.
        {
            let (ct, tag) = encrypt(&key, &nonce24, aad, &pt).unwrap();
            assert_eq!(
                decrypt(&key, &nonce24, aad, &ct, &tag).unwrap().as_slice(),
                &pt[..],
                "xchacha20-blake3-siv round trip, size {size}"
            );
            let mut buf = pt.clone();
            let tag = xcp
                .encrypt_in_place_detached(&nonce24.into(), aad, &mut buf)
                .unwrap();
            xcp.decrypt_in_place_detached(&nonce24.into(), aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, pt, "xchacha20-poly1305 round trip, size {size}");
            let mut buf = pt.clone();
            let tag = cp
                .encrypt_in_place_detached(&nonce12.into(), aad, &mut buf)
                .unwrap();
            cp.decrypt_in_place_detached(&nonce12.into(), aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, pt, "chacha20-poly1305 round trip, size {size}");
        }

        group.bench_with_input(
            BenchmarkId::new("xchacha20-blake3-siv", size),
            &size,
            |b, _| {
                let mut buf = pt.clone();
                b.iter(|| {
                    std::hint::black_box(
                        encrypt_in_place_detached(&key, &nonce24, aad, &mut buf).unwrap(),
                    )
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("xchacha20-poly1305", size),
            &size,
            |b, _| {
                let mut buf = pt.clone();
                b.iter(|| {
                    // `.unwrap()` like the crate's own arm and the whole decrypt
                    // group: without it an implementation that returned `Err`
                    // would be timed as the error path and read as a win.
                    std::hint::black_box(
                        xcp.encrypt_in_place_detached(&nonce24.into(), aad, &mut buf)
                            .unwrap(),
                    )
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("chacha20-poly1305", size),
            &size,
            |b, _| {
                let mut buf = pt.clone();
                b.iter(|| {
                    // `.unwrap()` for the same reason as the `xchacha20-poly1305`
                    // arm above.
                    std::hint::black_box(
                        cp.encrypt_in_place_detached(&nonce12.into(), aad, &mut buf)
                            .unwrap(),
                    )
                })
            },
        );
    }
    group.finish();
}

/// The decrypt half, which the two sides do not do the same way.
///
/// SIV has to decrypt *before* it can verify — that is what makes the tag depend
/// on the plaintext — so this crate pays a second full ChaCha20 pass plus the whole
/// tag recomputation and a constant-time comparison. `chacha20poly1305` 0.10.1
/// does not interleave: `decrypt_in_place_detached` authenticates the *ciphertext*
/// with Poly1305, verifies, and only then applies the keystream (its source still
/// carries `TODO(tarcieri): interleave decryption with Poly1305`). It also walks
/// the buffer twice, but its MAC pass needs no plaintext, it recomputes no tag,
/// and it stops before decrypting on a bad tag. That asymmetry is the thing this
/// group exists to measure; the encrypt group cannot show it.
///
/// Each side is given a *valid* tag: `Poly1305`'s decrypt path checks the tag
/// first and returns before touching the buffer, so an invalid tag would time the
/// comparison rather than the decryption.
fn bench_decrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce24 = [0x55u8; 24];
    let nonce12 = [0x55u8; 12];
    let aad = b"associated data";
    let xcp = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));
    let cp = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));

    let mut group = c.benchmark_group("decrypt_in_place_detached");
    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let pt = vec![0xA5u8; size];

        let (siv_ct, siv_tag) = encrypt(&key, &nonce24, aad, &pt).unwrap();
        let mut xcp_ct = pt.clone();
        let xcp_tag = xcp
            .encrypt_in_place_detached(&nonce24.into(), aad, &mut xcp_ct)
            .unwrap();
        let mut cp_ct = pt.clone();
        let cp_tag = cp
            .encrypt_in_place_detached(&nonce12.into(), aad, &mut cp_ct)
            .unwrap();

        // Correctness before timing, in every arm: each tag above must authenticate
        // and recover `pt` exactly. `.unwrap()` alone would accept a decrypt that
        // returned `Ok` without writing (or wrote garbage), which would then be timed
        // as a win.
        assert_eq!(
            decrypt(&key, &nonce24, aad, &siv_ct, &siv_tag)
                .unwrap()
                .as_slice(),
            &pt[..],
            "xchacha20-blake3-siv tagged decrypt, size {size}"
        );
        {
            let mut buf = xcp_ct.clone();
            xcp.decrypt_in_place_detached(&nonce24.into(), aad, &mut buf, &xcp_tag)
                .unwrap();
            assert_eq!(buf, pt, "xchacha20-poly1305 decrypt, size {size}");
            let mut buf = cp_ct.clone();
            cp.decrypt_in_place_detached(&nonce12.into(), aad, &mut buf, &cp_tag)
                .unwrap();
            assert_eq!(buf, pt, "chacha20-poly1305 decrypt, size {size}");
        }

        // `iter_batched` so the per-iteration reset to the ciphertext is *setup*,
        // not measured work: in-place decryption consumes its buffer, and charging
        // every side for the copy equally would hide exactly the difference above.
        let batch = BatchSize::SmallInput;
        group.bench_with_input(
            BenchmarkId::new("xchacha20-blake3-siv", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || siv_ct.clone(),
                    |mut buf| {
                        decrypt_in_place_detached(&key, &nonce24, aad, &mut buf, &siv_tag).unwrap();
                        // Return the plaintext: an in-place call returns `()`, so
                        // `black_box` on that leaves the buffer unread and lets the
                        // whole decryption be optimized away.
                        std::hint::black_box(buf)
                    },
                    batch,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("xchacha20-poly1305", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || xcp_ct.clone(),
                    |mut buf| {
                        xcp.decrypt_in_place_detached(&nonce24.into(), aad, &mut buf, &xcp_tag)
                            .unwrap();
                        std::hint::black_box(buf)
                    },
                    batch,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("chacha20-poly1305", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || cp_ct.clone(),
                    |mut buf| {
                        cp.decrypt_in_place_detached(&nonce12.into(), aad, &mut buf, &cp_tag)
                            .unwrap();
                        std::hint::black_box(buf)
                    },
                    batch,
                )
            },
        );
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let aad = b"associated data";
    let xcp = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));

    let mut group = c.benchmark_group("encrypt_then_decrypt");
    for size in SIZES {
        let pt = vec![0xA5u8; size];
        // Each iteration encrypts *and* decrypts `size` bytes, so the honest byte
        // count is `2 * size`: the old `Bytes(size)` label credited one direction
        // only and read the reported MiB/s 2x too high (arm-to-arm ratios are
        // unaffected, both sides pay the same).
        group.throughput(Throughput::Bytes((2 * size) as u64));

        // Correctness before timing, in every arm. A no-op (or wrong-`Ok`) decrypt
        // would otherwise be timed as a throughput win, since `.unwrap()` only
        // excludes one that returns `Err`.
        {
            let mut buf = pt.clone();
            let tag = encrypt_in_place_detached(&key, &nonce, aad, &mut buf).unwrap();
            decrypt_in_place_detached(&key, &nonce, aad, &mut buf, &tag).unwrap();
            assert_eq!(
                buf, pt,
                "xchacha20-blake3-siv in-place round trip, size {size}"
            );
            let (ct, tag) = encrypt(&key, &nonce, aad, &pt).unwrap();
            assert_eq!(
                decrypt(&key, &nonce, aad, &ct, &tag).unwrap().as_slice(),
                &pt[..],
                "xchacha20-blake3-siv allocating round trip, size {size}"
            );
            let mut buf = pt.clone();
            let tag = xcp
                .encrypt_in_place_detached(&nonce.into(), aad, &mut buf)
                .unwrap();
            xcp.decrypt_in_place_detached(&nonce.into(), aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, pt, "xchacha20-poly1305 round trip, size {size}");
        }

        // Both sides in place, with the per-iteration buffer reset as setup. A
        // round trip through this crate's *allocating* API would also pay two
        // allocations and three copies per iteration at a megabyte, which is a
        // property of the API shape rather than of the construction -- so that is
        // measured separately, and labelled.
        let batch = BatchSize::SmallInput;
        group.bench_with_input(
            BenchmarkId::new("xchacha20-blake3-siv", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || pt.clone(),
                    |mut buf| {
                        let tag = encrypt_in_place_detached(&key, &nonce, aad, &mut buf).unwrap();
                        decrypt_in_place_detached(&key, &nonce, aad, &mut buf, &tag).unwrap();
                        std::hint::black_box(buf)
                    },
                    batch,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("xchacha20-poly1305", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || pt.clone(),
                    |mut buf| {
                        let tag = xcp
                            .encrypt_in_place_detached(&nonce.into(), aad, &mut buf)
                            .unwrap();
                        xcp.decrypt_in_place_detached(&nonce.into(), aad, &mut buf, &tag)
                            .unwrap();
                        std::hint::black_box(buf)
                    },
                    batch,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("xchacha20-blake3-siv (allocating API)", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let (ct, tag) = encrypt(&key, &nonce, aad, &pt).unwrap();
                    std::hint::black_box(decrypt(&key, &nonce, aad, &ct, &tag).unwrap())
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_roundtrip);
criterion_main!(benches);
