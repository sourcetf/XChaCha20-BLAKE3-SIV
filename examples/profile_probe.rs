//! Profiling driver: N iterations of encrypt+decrypt at one size, no I/O in the loop.
//!
//! Exists because the benchmark harness (`benches/compare.rs`) answers "how fast",
//! which is not the same question as "where does the time go". A profiler needs a
//! tight loop with nothing else in it, and the sizes that matter for the fixed-cost
//! analysis are the small ones, where a caller pays per message rather than per
//! byte.
//!
//! ```text
//! cargo build --release --example profile_probe --config 'profile.release.strip=false'
//! valgrind --tool=callgrind --callgrind-out-file=cg.out \
//!     target/release/examples/profile_probe 64 20000
//! callgrind_annotate --auto=yes cg.out | head -40
//! ```
//!
//! Also usable as a plain timing probe (`time target/release/examples/profile_probe
//! 1024 200000`) — but with `strip = true`, which the shipped release profile sets,
//! the symbols a profiler needs are gone, hence the override above.

use std::hint::black_box;
use std::time::Instant;

use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let size: usize = args.first().map(|s| s.parse().expect("size")).unwrap_or(64);
    let iters: usize = args
        .get(1)
        .map(|s| s.parse().expect("iterations"))
        .unwrap_or(1000);

    let key = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let aad = b"aad";
    let pt: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    // Warm up the AVX2 cache and the allocator, then measure the allocating API.
    let (warm_ct, _warm_tag) = encrypt(&key, &nonce, aad, &pt).expect("encrypt");
    black_box(&warm_ct);

    let t = Instant::now();
    for _ in 0..iters {
        let (ct, tag) = encrypt(&key, &nonce, aad, &pt).expect("encrypt");
        black_box((&ct, &tag));
        let back = decrypt(&key, &nonce, aad, &ct, &tag).expect("decrypt");
        black_box(&back);
    }
    let alloc = t.elapsed();

    // No reset inside the loop: decrypt restores the plaintext, so the next
    // iteration encrypts it again. (A `copy_from_slice` before the decrypt would
    // overwrite the ciphertext and authenticate the plaintext -- which fails, as
    // the first version of this probe did.)
    let mut buf = pt.clone();
    let t = Instant::now();
    for _ in 0..iters {
        let tag = encrypt_in_place_detached(&key, &nonce, aad, &mut buf).expect("encrypt");
        black_box(&tag);
        decrypt_in_place_detached(&key, &nonce, aad, &mut buf, &tag).expect("decrypt");
    }
    let in_place = t.elapsed();

    println!(
        "size {size}, {iters} iterations\n  \
         allocating round trip: {:>9.2} us/message\n  \
         in-place round trip:   {:>9.2} us/message (includes the buffer reset)",
        alloc.as_secs_f64() * 1e6 / iters as f64,
        in_place.as_secs_f64() * 1e6 / iters as f64,
    );
    black_box(warm_ct);
    black_box(pt);
}
