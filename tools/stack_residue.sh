#!/usr/bin/env bash
# Measure what key material survives in the stack frames of an AEAD call.
#
# This is a *measurement*, not a gate, and it is not wired into CI on purpose.
# What it finds today is dominated by the `blake3` dependency: its XOF output
# buffer sits in frames this crate cannot name, let alone wipe (the key itself is
# not left -- measured). A gate that fails for a reason upstream of this crate
# would be a gate someone eventually deletes, so it is a tool instead, and the
# finding is written down in README's "cannot fix for you" list.
#
# Method, and why it has to be this way:
#   * a stack region is painted with a sentinel by a function that then returns,
#     so the frames of the call under test land in memory this program has
#     already written -- any secret found there is residue, not stale memory;
#   * the region is then snapshotted to the HEAP with a minimal-stack copy and
#     the search runs over the heap copy. Searching in place does not work: the
#     analyser's own allocations land in the region being searched and overwrite
#     the evidence, which produces hits that fail to re-verify.
#
# Usage:  tools/stack_residue.sh [--pure]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# `--pure` forces BLAKE3's portable Rust backends; `--ultra` runs against the
# feature bundle whose `scrub_stack` is supposed to clear the residue.
FEATURES=""
case "${1:-}" in
  --pure)  FEATURES="--features=xchacha20-blake3-siv/pure" ;;
  --ultra) FEATURES="--features=xchacha20-blake3-siv/ultra" ;;
esac

mkdir -p "$WORK/src"
cat > "$WORK/Cargo.toml" <<EOF
[package]
name = "stack_residue"
version = "0.0.0"
edition = "2021"
[dependencies]
xchacha20-blake3-siv = { path = "$ROOT" }
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
EOF

cat > "$WORK/src/main.rs" <<'RS'
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached,
};

const PAINT: usize = 1 << 20;
const SENTINEL: u8 = 0x5A;

/// Minimal stack: no allocation, so the snapshot cannot disturb its source.
#[inline(never)]
fn snapshot(src: *const u8, dst: *mut u8, len: usize) {
    unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
}
#[inline(never)]
fn paint() -> *const u8 {
    let mut buf = [SENTINEL; PAINT];
    std::hint::black_box(&mut buf);
    buf.as_ptr()
}
fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}
#[inline(never)]
fn do_encrypt(k: &[u8; 32], n: &[u8; 24]) {
    let p = vec![b'A'; 64];
    let (c, t) = encrypt(k, n, b"", &p).unwrap();
    std::hint::black_box((&c, &t));
}
#[inline(never)]
fn do_decrypt(k: &[u8; 32], n: &[u8; 24]) {
    let p = vec![b'A'; 64];
    let (c, t) = encrypt(k, n, b"", &p).unwrap();
    std::hint::black_box(decrypt(k, n, b"", &c, &t).unwrap());
}
#[inline(never)]
fn do_enc_ip(k: &[u8; 32], n: &[u8; 24]) {
    let mut b = vec![b'A'; 64];
    std::hint::black_box(encrypt_in_place_detached(k, n, b"", &mut b).unwrap());
}
#[inline(never)]
fn do_dec_ip(k: &[u8; 32], n: &[u8; 24]) {
    let p = vec![b'A'; 64];
    let (c, t) = encrypt(k, n, b"", &p).unwrap();
    let mut b = c.clone();
    decrypt_in_place_detached(k, n, b"", &mut b, &t).unwrap();
    std::hint::black_box(&b);
}

fn main() {
    let key: [u8; 32] = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into().unwrap();
    let nonce: [u8; 24] = hx("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into().unwrap();

    // The caller knows these two; the derived values (k_in, k_out, enc_seed, enc_key,
    // enc_nonce) are not reachable from the public API, which is why the in-tree
    // version of this measurement needed crate internals.
    let known: [(&str, Vec<u8>); 2] = [
        ("master KEY (must never appear)", key.to_vec()),
        (
            "control (never used, must not appear)",
            hx("deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"),
        ),
    ];

    let cases: [(&str, fn(&[u8; 32], &[u8; 24])); 4] = [
        ("encrypt", do_encrypt),
        ("encrypt+decrypt", do_decrypt),
        ("encrypt_in_place_detached", do_enc_ip),
        ("decrypt_in_place_detached", do_dec_ip),
    ];

    let mut failures = 0usize;
    println!("stack-residue scan: {} KiB of call-chain stack per entry point", PAINT / 1024);
    for (name, f) in cases {
        let ptr = paint();
        f(&key, &nonce);
        let mut snap = vec![0u8; PAINT];
        snapshot(ptr, snap.as_mut_ptr(), PAINT);

        let mut line = String::new();
        for (label, pat) in known.iter() {
            let mut best = 0usize;
            let mut at = 0usize;
            for r in 0..snap.len() {
                for s in 0..pat.len() {
                    let mut l = 0usize;
                    while r + l < snap.len() && s + l < pat.len() && snap[r + l] == pat[s + l] {
                        l += 1;
                    }
                    if l > best {
                        best = l;
                        at = r;
                    }
                }
            }
            // The master key is the one thing this scan can check that matters: it
            // is the caller's secret, and it is supposed to reach the cipher only
            // through copies the crate wipes.  The `control` entry is a symbol that
            // is *never* placed on the stack, so a run that "finds" it is a false
            // positive and the scan cannot be trusted — it is counted as a failure
            // too, because the PASS text below claims exactly that control (and,
            // until this branch existed, claimed a check the code did not perform).
            if label.starts_with("master KEY") && best >= 16 {
                failures += 1;
                line.push_str(&format!(" | KEY RESIDUE: {}-byte run @{}", best, at));
            } else if label.starts_with("control") && best >= 16 {
                failures += 1;
                line.push_str(&format!(" | CONTROL FALSE POSITIVE: {}-byte run @{}", best, at));
            } else {
                line.push_str(&format!(" | {}: {} B", label.split(' ').next().unwrap(), best));
            }
        }
        println!("  {:<28}{}", name, line);
    }

    if failures == 0 {
        println!();
        println!("PASS: the master key never appears in the call-chain stack region,");
        println!("      and the control shows the scan produces no false positives.");
    } else {
        println!();
        println!("FAIL: {} entry point(s) left the master key on the stack.", failures);
        std::process::exit(1);
    }
    println!();
    println!("Not covered here: the derived per-message values, which are unreachable");
    println!("from the public API. The dominant residue for those is inside the blake3");
    println!("dependency (its XOF output buffer), in frames this crate cannot wipe --");
    println!("see README, 'What this crate cannot fix for you'.");
}
RS

cd "$WORK"
# shellcheck disable=SC2086
cargo run --release --quiet $FEATURES
