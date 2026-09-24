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
//! and disappears by 16 KiB.
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use xchacha20_blake3_siv::{decrypt, encrypt, encrypt_in_place_detached};

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

fn bench_roundtrip(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let aad = b"associated data";

    let mut group = c.benchmark_group("encrypt_then_decrypt");
    for size in SIZES {
        let pt = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("xchacha20-blake3-siv", size),
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

criterion_group!(benches, bench_encrypt, bench_roundtrip);
criterion_main!(benches);
