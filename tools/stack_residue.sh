#!/usr/bin/env bash
# Measure what key material survives in the stack frames of an AEAD call.
#
# This is a *measurement*, not a gate, and it is wired in as an advisory: CI has a
# `stack residue` job that runs it in both configurations under `continue-on-error`, and
# `verify.sh`'s tool stage runs it and reports a change as ADVISORY rather than as a
# failure in a narrow run -- under `--deep`/`--all` (`STRICT=1`) a finding fails the run,
# because a strict run is the one place a measurement this noisy is worth gating on.
# (The header used to say it was not wired into CI at all, which stopped being
# true when that job was added.)
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
#   * the region is then searched **in place**, and that search is the first thing
#     to run once the call under test returns, before anything allocates or calls
#     again: every later call's frame is pushed into the top of the region, which
#     is exactly where the shallowest call-chain frames -- the freshest residue --
#     live. An earlier design snapshotted the region to the heap first; measured
#     with a forced 32-byte key copy in the top frame, that snapshot saw at most 2
#     bytes of it where the in-place read sees all 32, because the allocator's
#     frames and the snapshot function's own frame had already overwritten the
#     evidence.
#     The search itself is reads only and every pattern it compares against is
#     preallocated, so -- unlike the very first version, which allocated its
#     output buffer and then searched through its own frames -- it cannot produce
#     hits that fail to re-verify.
#   * one case is the *scan's* own positive control: it copies the master key into
#     the region and the tool fails if that copy is not found. Without it a scan
#     that read the wrong memory (measured: a throwaway copy whose `paint()`
#     returned a heap region, i.e. a plausible "fix" for the dead-stack-buffer UB)
#     printed the same PASS line as a clean measurement, with every best-run at 0
#     bytes. The false-positive control cannot catch that, because a scan that
#     sees nothing produces no false positives either.
#
# Usage:  tools/stack_residue.sh [--pure | --ultra]
set -euo pipefail

# `cargo run` below is invoked directly, so this tool has to find cargo itself.
# `verify.sh` exports the path, but a direct `tools/stack_residue.sh` used to die
# with "cargo: command not found" on a machine where that is not already on PATH.
export PATH="$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# `--pure` forces BLAKE3's portable Rust backends; `--ultra` runs against the
# feature bundle whose `scrub_stack` is supposed to clear the residue.
FEATURES=""
case "${1:-}" in
  "") ;;
  --pure)  FEATURES="--features=xchacha20-blake3-siv/pure" ;;
  --ultra) FEATURES="--features=xchacha20-blake3-siv/ultra" ;;
  *)
    echo "usage: tools/stack_residue.sh [--pure | --ultra]" >&2
    # Silently ignoring an unknown option ran the default build while the caller thought
    # it had asked for another one.
    exit 1 ;;
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
/// Positive control for the *scan*, not for the crate: the same shape as the cases above,
/// but it copies the whole master key into a stack buffer and takes that buffer's address
/// with `black_box`, so the key is in the region the scan reads. The verdict below requires
/// this copy to be found.
///
/// Without it, a scan that read the wrong memory printed exactly the line a clean
/// measurement prints: measured in a throwaway copy whose `paint()` returned a heap region
/// (a plausible "fix" for the dead-stack-buffer UB), every best-run was 0 bytes -- nothing,
/// anywhere -- and the tool still printed "PASS: this crate leaves neither the master key
/// nor the locked integrity tag in the call-chain stack region". The false-positive control
/// below cannot catch that: a scan that sees nothing produces no false positives either.
/// This probe has already been blind once (the snapshot read the frames only *after* they
/// had been overwritten), and that was found by a manual plant, not by the tool.
#[inline(never)]
fn do_planted_key(k: &[u8; 32], _n: &[u8; 24]) {
    // `&copy` through `black_box` forces the array to exist in memory: a value that is
    // only read cannot be kept in registers and still have its address taken. `copy[0]`
    // is fed through `black_box` too, so nothing can prove the array equals `*k` and
    // rematerialise it from the argument.
    let mut copy = *k;
    copy[0] = core::hint::black_box(copy[0]);
    std::hint::black_box(&copy);
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

    let cases: [(&str, fn(&[u8; 32], &[u8; 24])); 7] = [
        // First, so the scan's own positive control is known before any verdict and the
        // blake3-only attribution below runs on a scan that is known to see this region.
        ("planted key (control, must be found)", do_planted_key),
        // Second, so it can attribute the tag residue before the crate cases run.
        ("blake3-only control", do_blake3_only),
        ("encrypt", do_encrypt),
        ("encrypt+decrypt", do_decrypt),
        ("encrypt_in_place_detached", do_enc_ip),
        ("decrypt_in_place_detached", do_dec_ip),
        ("locked new+as_bytes", do_locked),
    ];

    let mut failures = 0usize;
    let mut dependency_leaks_tag = false;
    let mut planted_found = false;
    println!("stack-residue scan: {} KiB of call-chain stack per entry point", PAINT / 1024);
    for (name, f) in cases {
        let is_control = name.starts_with("blake3-only");
        let is_planted = name.starts_with("planted key");
        let ptr = paint();
        f(&key, &nonce);
        // The region is read *in place*, as the first statement after `f` returns.
        // Nothing between here and the three searches below may allocate or call
        // anything: a call pushes its frame (plus a return address) into the top of
        // the region, which is where a just-returned call leaves its shallowest --
        // freshest -- residues. The snapshot this replaced did exactly that: the
        // `vec![0u8; PAINT]` allocation and `snapshot`'s own frame ran before the
        // copy, so a forced 32-byte key copy in the top frame read 32 bytes in place
        // and at most 2 through the snapshot (measured). The searches are reads only,
        // and `known` was built before `paint()` erased the region, so the analyser
        // cannot overwrite what it is about to read. Results are collected first and
        // formatted afterwards for the same reason: building `line` allocates.
        let region: &[u8] = unsafe { core::slice::from_raw_parts(ptr, PAINT) };
        let mut best = [0usize; 3];
        let mut at = [0usize; 3];
        for (k, (_label, pat)) in known.iter().enumerate() {
            for r in 0..region.len() {
                for s in 0..pat.len() {
                    let mut l = 0usize;
                    while r + l < region.len() && s + l < pat.len() && region[r + l] == pat[s + l] {
                        l += 1;
                    }
                    if l > best[k] {
                        best[k] = l;
                        at[k] = r;
                    }
                }
            }
        }

        let mut line = String::new();
        for (k, (label, _pat)) in known.iter().enumerate() {
            let (best, at) = (best[k], at[k]);
            // The master key is the one thing this scan can check that matters: it
            // is the caller's secret, and it is supposed to reach the cipher only
            // through copies the crate wipes.  The `control` entry is a symbol that
            // is *never* placed on the stack, so a run that "finds" it is a false
            // positive and the scan cannot be trusted — it is counted as a failure
            // too, because the PASS text below claims exactly that control (and,
            // until this branch existed, claimed a check the code did not perform).
            //
            // 8 bytes for every pattern, the 8-byte integrity tag included. The
            // threshold used to be 16 for the 32-byte master key, so a 12-byte
            // prefix *printed* as a `master: N B` line and contributed no failure:
            // the verdict and the line disagreed, and a partial key spill read as
            // clean.
            // There is no false-positive case for 8: an accidental 8-byte run of a
            // 32-byte random key has probability ~2^-64 per position, and the
            // never-used control below is the check that would expose one.
            const THRESHOLD: usize = 8;
            let tag_case = label.starts_with("locked integrity tag");
            if label.starts_with("master KEY") && best >= THRESHOLD {
                if is_planted {
                    // The control's own copy, which is supposed to be found: the check
                    // after the loop fails the run if it was not.
                    planted_found = true;
                    line.push_str(&format!(
                        " | KEY RESIDUE (planted, expected): {}-byte run @{}",
                        best, at
                    ));
                } else {
                    failures += 1;
                    line.push_str(&format!(" | KEY RESIDUE: {}-byte run @{}", best, at));
                }
            } else if label.starts_with("control") && best >= THRESHOLD {
                failures += 1;
                line.push_str(&format!(" | CONTROL FALSE POSITIVE: {}-byte run @{}", best, at));
            } else if tag_case && best >= THRESHOLD {
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

    // The scan's own verdict, and it comes first: a scan that cannot see a key copy placed
    // in its own region has not measured anything, and its "no residue" lines below would
    // be claims about memory it never read.
    if !planted_found {
        println!();
        println!("FAIL: the positive control -- a 32-byte copy of the master key in the scanned");
        println!("      region -- was NOT found (best run shorter than the 8-byte threshold),");
        println!("      so this scan is not reading the frames it claims to read and every");
        println!("      'no residue' line above is vacuous. Fix the probe before trusting a PASS.");
        std::process::exit(1);
    }

    if failures == 0 {
        println!();
        if dependency_leaks_tag {
            println!("PASS: no master key in the call-chain stack region, and no residue of");
            println!("      this crate's own code -- the 8-byte locked integrity tag above IS");
            println!("      left, by the blake3 dependency's XOF buffer, as the note below says.");
        } else {
            println!("PASS: this crate leaves neither the master key nor the locked integrity");
            println!("      tag in the call-chain stack region.");
        }
        println!("      The planted-key control shows the scan reads this region, and the");
        println!("      never-used pattern shows it produces no false positives.");
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
# Exit codes are the repository's convention: 0 = measured, nothing found; 1 = measured,
# residue found -- or the scan's own positive control was not found, which means the
# measurement was vacuous (the probe exits 1 for both); 3 = could not run. The distinction
# matters to verify.sh, which reports 1 as ADVISORY (a change in compiler-chosen layout
# must not fail a `--deep` run) but a *skipped stage* for 3. Nothing produced a 3 here
# before -- so a build failure (cargo exits 101) was reported as "residue changed", which
# is a measurement claim about a run that never happened.
rc=0
# shellcheck disable=SC2086
cargo run --release --quiet $FEATURES || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "SKIPPED: the measurement could not run (cargo exited $rc; see above)" >&2
  exit 3
fi
exit "$rc"
