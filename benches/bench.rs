use criterion::{black_box, criterion_group, criterion_main, Criterion};
use xchacha20_blake3_siv::{decrypt, encrypt};

fn bench_encrypt(c: &mut Criterion) {
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

    // Correctness before timing: the output must decrypt back to the input. The
    // `.unwrap()`s in the closures below only exclude an implementation that returns
    // `Err`; one that returns `Ok` of the *wrong* bytes -- a stub, or a decrypt that
    // verifies but never writes -- would be timed as a throughput *win*. This is
    // outside the measured closure, so nothing that is measured changes.
    let (ct, tag) = encrypt(&[0xAAu8; 32], &[0xBBu8; 24], b"associated data", &plaintext).unwrap();
    assert_eq!(
        decrypt(&[0xAAu8; 32], &[0xBBu8; 24], b"associated data", &ct, &tag)
            .unwrap()
            .as_slice(),
        plaintext.as_slice(),
        "the ciphertext this benchmark times must round-trip"
    );

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            // `black_box` the result: with the returned `(ciphertext, tag)` unused,
            // nothing would force the computation to be kept.  `unwrap` so a call
            // that returned `Err` -- an implementation that is a stub, or has
            // regressed into one -- panics here instead of being measured as the
            // (instant) error path, which would read as a throughput *win*.
            let _ = black_box(
                encrypt(
                    black_box(&[0xAAu8; 32]),
                    black_box(&[0xBBu8; 24]),
                    black_box(b"associated data"),
                    black_box(&plaintext),
                )
                .unwrap(),
            );
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let (ct, tag) = encrypt(&[0xAAu8; 32], &[0xBBu8; 24], b"associated data", &plaintext).unwrap();

    // Correctness before timing, as in `bench_encrypt`: `.unwrap()` alone excludes
    // only `Err`, so a decrypt that returned `Ok` without writing the plaintext would
    // otherwise be measured as a speedup.
    assert_eq!(
        decrypt(&[0xAAu8; 32], &[0xBBu8; 24], b"associated data", &ct, &tag)
            .unwrap()
            .as_slice(),
        plaintext.as_slice(),
        "the ciphertext this benchmark times must decrypt to the plaintext"
    );

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            // As in `bench_encrypt`: the recovered `Plaintext` must be observed,
            // and the call must have succeeded rather than taken an error path.
            let _ = black_box(
                decrypt(
                    black_box(&[0xAAu8; 32]),
                    black_box(&[0xBBu8; 24]),
                    black_box(b"associated data"),
                    black_box(&ct),
                    black_box(&tag),
                )
                .unwrap(),
            );
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
