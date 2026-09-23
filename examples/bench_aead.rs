//! AEAD 性能基准：自定义 SIV 实现
//!
//! 运行: cargo run --release --example bench_aead
use std::time::Instant;
use xchacha20_blake3_siv::{decrypt, encrypt};

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn run<T>(rounds: usize, mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..rounds {
        f();
    }
    start.elapsed().as_secs_f64()
}

fn main() {
    let key: [u8; 32] = [0x42; 32];
    let nonce: [u8; 24] = [0x55; 24];
    let aad = b"associated data";

    println!("=== XChaCha20-BLAKE3-SIV 性能基准 ===\n");
    println!("消息大小\t\t加密 (MB/s)\t解密 (MB/s)");
    println!("=============================================");

    for &size in &[64usize, 256, 1024, 4096, 16384, 65536, 1048576] {
        let pt: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let rounds = if size < 4096 {
            2000
        } else if size < 200_000 {
            500
        } else {
            50
        };

        // 预计算密文用于解密基准
        let (ct, tag) = encrypt(&key, &nonce, aad, &pt).unwrap();

        let enc_secs = run(rounds, || {
            encrypt(&key, &nonce, aad, &pt).unwrap();
        });

        let dec_secs = run(rounds, || {
            decrypt(&key, &nonce, aad, &ct, &tag).unwrap();
        });

        println!(
            "{:>10} bytes\t{:>10.2}\t{:>10.2}",
            size,
            mbps(rounds * size, enc_secs),
            mbps(rounds * size, dec_secs),
        );
    }
}
