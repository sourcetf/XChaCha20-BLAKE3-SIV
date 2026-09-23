use criterion::{black_box, criterion_group, criterion_main, Criterion};
use xchacha20_blake3_siv::{decrypt, encrypt};

fn bench_encrypt(c: &mut Criterion) {
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            let _ = encrypt(
                black_box(&[0xAAu8; 32]),
                black_box(&[0xBBu8; 24]),
                black_box(b"associated data"),
                black_box(&plaintext),
            );
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let (ct, tag) = encrypt(&[0xAAu8; 32], &[0xBBu8; 24], b"associated data", &plaintext).unwrap();

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            let _ = decrypt(
                black_box(&[0xAAu8; 32]),
                black_box(&[0xBBu8; 24]),
                black_box(b"associated data"),
                black_box(&ct),
                black_box(&tag),
            );
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
