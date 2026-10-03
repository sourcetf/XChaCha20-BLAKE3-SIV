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
# Usage:  tools/stack_residue.sh [--pure | --ultra]
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
# The locked feature so the scan can exercise LockedKey: its integrity tag is a
# hash of the key, and that is the residue this tool now looks for.
xchacha20-blake3-siv = { path = "$ROOT", features = ["locked"] }
# To compute the expected integrity tag (BLAKE3(key)[0..8]) independently, and to
# run the blake3-only attribution control with the same wipe discipline.
blake3 = { version = "1.8", default-features = false, features = ["zeroize"] }
zeroize = "1"
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
/// `LockedKey::new` computes `BLAKE3(key)[0..8]` and `as_bytes()` recomputes it, on every
/// call. Both copies are key material by the crate's own classification, and both are now
/// wiped by their caller — this case is what measures that.
#[inline(never)]
fn do_locked(k: &[u8; 32], _n: &[u8; 24]) {
    use xchacha20_blake3_siv::locked::LockedKey;
    let key = LockedKey::new(k).expect("mlock failed");
    std::hint::black_box(key.as_bytes());
}
/// Attribution control: the *same* BLAKE3 XOF call and the same wipe discipline the crate's
/// `integrity_tag` uses, but with no crate code around it. If the 8-byte tag shows up here
/// too, the residue is a stack temporary inside the `blake3` dependency (`fill`'s output
/// buffer), which this crate cannot reach — and the `locked` case's residue is attributable
/// to it rather than to the crate.
#[inline(never)]
fn do_blake3_only(k: &[u8; 32], _n: &[u8; 24]) {
    use zeroize::Zeroize;
    let mut hasher = blake3::Hasher::new();
    hasher.update(k);
    let mut out = [0u8; 8];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    reader.zeroize();
    hasher.zeroize();
    std::hint::black_box(out);
    out.zeroize();
}

fn main() {
    let key: [u8; 32] = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into().unwrap();
    let nonce: [u8; 24] = hx("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into().unwrap();

    // The caller knows these two; the derived values (k_in, k_out, enc_seed, enc_key,
    // enc_nonce) are not reachable from the public API, which is why the in-tree
    // version of this measurement needed crate internals.
    //
    // The third pattern *is* reachable: the `locked` integrity tag is `BLAKE3(key)[0..8]`,
    // an unkeyed hash of the master key, so it is computable here and (per the crate's
    // classification) is key material. It is 8 bytes, so its threshold is 8 rather than 16.
    let tag8 = blake3::hash(&key).as_bytes()[..8].to_vec();
    let known: [(&str, Vec<u8>); 3] = [
        ("master KEY (must never appear)", key.to_vec()),
        (
            "control (never used, must not appear)",
            hx("deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"),
        ),
        ("locked integrity tag BLAKE3(key)[0..8]", tag8),
    ];

    let cases: [(&str, fn(&[u8; 32], &[u8; 24])); 6] = [
        // First, so it can attribute the tag residue before the crate cases run.
        ("blake3-only control", do_blake3_only),
        ("encrypt", do_encrypt),
        ("encrypt+decrypt", do_decrypt),
        ("encrypt_in_place_detached", do_enc_ip),
        ("decrypt_in_place_detached", do_dec_ip),
        ("locked new+as_bytes", do_locked),
    ];

    let mut failures = 0usize;
    let mut dependency_leaks_tag = false;
    println!("stack-residue scan: {} KiB of call-chain stack per entry point", PAINT / 1024);
    for (name, f) in cases {
        let is_control = name.starts_with("blake3-only");
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
            // The integrity tag is 8 bytes, so its threshold is 8.
            let tag_case = label.starts_with("locked integrity tag");
            let threshold = if tag_case { 8 } else { 16 };
            if label.starts_with("master KEY") && best >= threshold {
                failures += 1;
                line.push_str(&format!(" | KEY RESIDUE: {}-byte run @{}", best, at));
            } else if label.starts_with("control") && best >= threshold {
                failures += 1;
                line.push_str(&format!(" | CONTROL FALSE POSITIVE: {}-byte run @{}", best, at));
            } else if tag_case && best >= threshold {
                if is_control {
                    // The dependency itself leaves the pattern: record it, and exculpate
                    // the crate cases below.
                    dependency_leaks_tag = true;
                    line.push_str(&format!(" | TAG RESIDUE in blake3 itself: {} B @{}", best, at));
                } else if dependency_leaks_tag {
                    line.push_str(&format!(
                        " | TAG RESIDUE ({}-byte run @{}) attributable to blake3",
                        best, at
                    ));
                } else {
                    failures += 1;
                    line.push_str(&format!(" | TAG RESIDUE: {}-byte run @{}", best, at));
                }
            } else {
                line.push_str(&format!(" | {}: {} B", label.split(' ').next().unwrap(), best));
            }
        }
        println!("  {:<28}{}", name, line);
    }

    if failures == 0 {
        println!();
        println!("PASS: this crate leaves neither the master key nor the locked integrity tag");
        println!("      in the call-chain stack region, and the control shows the scan");
        println!("      produces no false positives.");
        if dependency_leaks_tag {
            println!();
            println!("Note: the blake3-only control DOES leave the 8-byte tag, with the same");
            println!("wipe discipline and no crate code -- so the tag residue in the `locked`");
            println!("case is the dependency's XOF output buffer, in a frame this crate cannot");
            println!("wipe (the same finding as the derived values, README 'cannot fix'). The");
            println!("crate's own copies are wiped; this is the residual that is not its code.");
        }
    } else {
        println!();
        println!("FAIL: {} entry point(s) left key material on the stack.", failures);
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
