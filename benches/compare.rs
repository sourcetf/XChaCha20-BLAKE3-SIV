//! Head-to-head throughput against RustCrypto's `chacha20poly1305`.
//!
//! `XChaCha20Poly1305` is the natural reference point: same 24-byte nonce, same
//! ChaCha20 core, and it is what a caller would otherwise reach for. The
//! 12-byte-nonce `ChaCha20Poly1305` is included because it is what the c2sp.org
//! SIV construction wraps, and `aead`'s in-place interface is used for both sides
//! so neither pays for an API shape the other does not have.
//!
//! Run with `cargo bench --bench compare`. Numbers are host-specific and the
//! *ratios* are the stable signal: this crate derives more key material per
//! message and wipes it, which costs a fixed amount that dominates at 64 bytes
//! and disappears by 16 KiB. Encrypt, decrypt and round-trip are all measured --
//! the decrypt asymmetry (SIV decrypts before it can verify) only shows up in the
//! second of those.
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached,
};

const SIZES: [usize; 7] = [64, 256, 1024, 4096, 16384, 65536, 1048576];

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
                    std::hint::black_box(xcp.encrypt_in_place_detached(
                        &nonce24.into(),
                        aad,
                        &mut buf,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("chacha20-poly1305", size),
            &size,
            |b, _| {
                let mut buf = pt.clone();
                b.iter(|| {
                    std::hint::black_box(cp.encrypt_in_place_detached(
                        &nonce12.into(),
                        aad,
                        &mut buf,
                    ))
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
/// tag recomputation and a constant-time comparison. Poly1305 verifies a running
/// MAC while it decrypts, so it pays neither. That asymmetry is the thing this
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
        group.throughput(Throughput::Bytes(size as u64));

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
