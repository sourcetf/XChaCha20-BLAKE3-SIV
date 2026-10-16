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
#   * three cases are the *scan's* own positive controls, and the tool fails if any
#     is not found: a full 32-byte master-key copy; the key's first and last four
#     bytes as two separate 4-byte copies (a 4+4 split); and its first seven bytes
#     as one run (one byte short of the old 8-byte threshold). Without them a scan
#     that read the wrong memory (measured: a throwaway copy whose `paint()`
#     returned a heap region, i.e. a plausible "fix" for the dead-stack-buffer UB)
#     printed the same PASS line as a clean measurement, with every best-run at 0
#     bytes. The split and 7-byte controls exist because the single-run threshold
#     used to be 8: an audit planted both shapes and the tool printed PASS (measured
#     on a scratch copy: `master: 4 B` and `master: 7 B`, verdict PASS, exit 0).
#     The false-positive control cannot catch a scan that sees nothing, because
#     such a scan produces no false positives either.
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
/// Positive control for the *split* rule: the key's first four bytes followed by
/// its last four, back to back -- eight bytes of key material with no contiguous
/// run matching more than four pattern bytes, so neither the old 8-byte threshold
/// nor any single-run threshold sees it. The two fragments are 24 bytes apart in
/// the pattern (`k[0..4]`, `k[28..32]`), which is what makes the physical
/// adjacency two *runs* and not one: a merged 8-byte spill cannot be a key
/// substring.
///
/// Two measured details of the *plant*, not of the crate:
///   * the buffer must be deep enough that the caller's first post-return code
///     does not overwrite the fragments. The top ~24 bytes of the callee frame
///     are clobbered (the caller's scratch area reuses them), and versions that
///     planted the two fragments there lost half of the plant before the scan --
///     measured in a scratch copy, both as two 8-byte arrays and as one 16-byte
///     buffer: one 4-byte run survived, the other did not, and the control failed
///     with `master: 4 B`. A 256-byte buffer with the fragments 128 bytes in
///     survives intact (measured, both runs found).
///   * the stores are `write_volatile`: a plain `copy_from_slice` compiles to
///     small stores, the compiler proves the array unread (only its address is
///     black-boxed) and deletes them -- the first version of the 7-byte control
///     read `master: 1 B`, i.e. the plant might as well not have existed.
#[inline(never)]
fn do_planted_split(k: &[u8; 32], _n: &[u8; 24]) {
    let mut a = [0u8; 256];
    for i in 0..4 {
        // SAFETY: pointer into a live local, in bounds for 128 + i < 136.
        unsafe {
            core::ptr::write_volatile(a.as_mut_ptr().add(128 + i), k[i]);
            core::ptr::write_volatile(a.as_mut_ptr().add(132 + i), k[28 + i]);
        }
    }
    std::hint::black_box(&a);
}
/// Positive control for the run threshold: seven contiguous key bytes, one byte
/// short of the old 8. The array is one byte longer than the copy so a widened
/// machine-word store still cannot make the run eight bytes of key (the eighth
/// byte is the zeroed init, not `k[7]`), and the stores are `write_volatile` for
/// the same reason as the split control above.
#[inline(never)]
fn do_planted_seven(k: &[u8; 32], _n: &[u8; 24]) {
    let mut a = [0u8; 8];
    for i in 0..7 {
        // SAFETY: pointer into a live local, in bounds for i < 7.
        unsafe {
            core::ptr::write_volatile(a.as_mut_ptr().add(i), k[i]);
        }
    }
    std::hint::black_box(&a);
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
    // classification) is key material. It is 8 bytes, so it is judged by the same
    // 7-byte single-run and split rules as the two longer patterns.
    let tag8 = blake3::hash(&key).as_bytes()[..8].to_vec();
    let known: [(&str, Vec<u8>); 3] = [
        ("master KEY (must never appear)", key.to_vec()),
        (
            "control (never used, must not appear)",
            hx("deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"),
        ),
        ("locked integrity tag BLAKE3(key)[0..8]", tag8),
    ];

    let cases: [(&str, fn(&[u8; 32], &[u8; 24])); 9] = [
        // First, so the scan's own positive controls are known before any verdict and the
        // blake3-only attribution below runs on a scan that is known to see this region.
        // All three controls (whole key, 4+4 split, 7-byte run) come first, and the
        // verdict below requires each to be found.
        ("planted key (control, must be found)", do_planted_key),
        ("planted split (control, must be found)", do_planted_split),
        ("planted seven (control, must be found)", do_planted_seven),
        // Then, so it can attribute the tag residue before the crate cases run.
        ("blake3-only control", do_blake3_only),
        ("encrypt", do_encrypt),
        ("encrypt+decrypt", do_decrypt),
        ("encrypt_in_place_detached", do_enc_ip),
        ("decrypt_in_place_detached", do_dec_ip),
        ("locked new+as_bytes", do_locked),
    ];

    // The detection thresholds, and the arithmetic they were chosen with. The region
    // is PAINT = 1 MiB, so there are 2^20 windows per case, and the three patterns
    // are 32, 64 and 8 bytes ("master key", "control", "tag").
    //
    //   * SINGLE_RUN = 7 is the old 8-byte single-run threshold one byte lower, so
    //     the 7-byte run the audit planted is caught. For the 32-byte key there are
    //     26 7-grams, so a uniform-random window matches one with probability
    //     ~26 * 2^-56; over 2^20 windows that is ~26 * 2^-36 ~ 4e-10 per
    //     pattern-case, under 1e-8 over the 3 patterns x 7 cases. Effectively no
    //     false positives from this rule at all.
    //   * the split rule -- >= 2 disjoint runs of >= MIN_RUN = 4 bytes totalling
    //     >= SPLIT_TOTAL = 8 -- catches a 4+4 split. A 4-byte match has ~29 * 2^-32
    //     probability per window for the key, i.e. ~0.0071 expected matches over
    //     2^20 windows; P(>= 2 matches) ~ 0.0071^2 / 2 ~ 2.5e-5 per pattern-case,
    //     ~5e-4 over the 21 pattern-cases: one false alarm in ~2000 runs. A false
    //     alarm on the never-used control pattern is itself *reported* as a
    //     failure, so its price is a rare loud error, never a silent PASS.
    //
    // A plain drop to a 4-byte single-run threshold was the simpler candidate and
    // was rejected on the same arithmetic, not on taste: at the 32 KiB frame the
    // audit's sketch assumed that rule would be quiet (~2^-17 per pattern-case),
    // but this region is 1 MiB, 32x larger, and 0.0071 expected 4-byte matches per
    // key-pattern-case means ~4% of runs would see a spurious match in one of the
    // six non-planted cases and ~3% in the control pattern alone -- a false FAIL
    // about once per 12 runs, doubled by CI's two configurations. Hence the split
    // rule for the 4+4 shape and 7, not 4, for a single run.
    const MIN_RUN: usize = 4;
    const SINGLE_RUN: usize = 7;
    const SPLIT_TOTAL: usize = 8;

    let mut failures = 0usize;
    let mut dependency_leaks_tag = false;
    let mut planted_found = false;
    let mut split_found = false;
    let mut seven_found = false;
    println!("stack-residue scan: {} KiB of call-chain stack per entry point", PAINT / 1024);
    for (name, f) in cases {
        let is_control = name.starts_with("blake3-only");
        let is_planted = name.starts_with("planted key");
        let is_split_plant = name.starts_with("planted split");
        let is_seven_plant = name.starts_with("planted seven");
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
        let mut split_runs = [0usize; 3];
        let mut split_bytes = [0usize; 3];
        // Every maximal run of >= MIN_RUN shared bytes is collected, not only the
        // longest, because the split rule below needs the *runs*: a 4+4 split is
        // two runs and no contiguous threshold sees eight bytes in it. `r += l`
        // steps past a match once it is consumed, so each run is emitted once per
        // alignment; the list is then deduplicated (the never-used control pattern
        // repeats a 16-byte substring at two alignments, which would otherwise
        // count one physical run twice) and overlap-merged (a longer match that
        // contains a shorter one). Adjacent runs are deliberately *not* merged --
        // two 4-byte key chunks that happen to land back to back are still two
        // chunks, and merging them would hide exactly the shape being counted.
        for (k, (_label, pat)) in known.iter().enumerate() {
            let mut runs: Vec<(usize, usize)> = Vec::new();
            for s in 0..pat.len() {
                let mut r = 0usize;
                while r < region.len() {
                    if region[r] == pat[s] {
                        let mut l = 1usize;
                        while r + l < region.len() && s + l < pat.len()
                            && region[r + l] == pat[s + l]
                        {
                            l += 1;
                        }
                        if l > best[k] {
                            best[k] = l;
                            at[k] = r;
                        }
                        if l >= MIN_RUN && !runs.contains(&(r, l)) {
                            runs.push((r, l));
                        }
                        r += l;
                    } else {
                        r += 1;
                    }
                }
            }
            runs.sort_unstable();
            let mut merged: Vec<(usize, usize)> = Vec::new();
            for &(start, len) in runs.iter() {
                if let Some(last) = merged.last_mut() {
                    if start < last.0 + last.1 {
                        last.1 = last.1.max(start + len - last.0);
                        continue;
                    }
                }
                merged.push((start, len));
            }
            if merged.len() >= 2 {
                split_runs[k] = merged.len();
                split_bytes[k] = merged.iter().map(|&(_, l)| l).sum();
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
            // A hit is either rule: one run of SINGLE_RUN bytes or more (7, one
            // below the old 8 -- a 7-byte run was the audit's second planted
            // shape), or the split rule (>= 2 runs of >= MIN_RUN bytes totalling
            // >= SPLIT_TOTAL, which is what a 4+4 split looks like). The threshold
            // used to be 16 for the 32-byte master key, so a 12-byte prefix
            // *printed* as a `master: N B` line and contributed no failure: the
            // verdict and the line disagreed, and a partial key spill read as
            // clean. The false-positive arithmetic for 7 and for the split rule is
            // written at MIN_RUN/SINGLE_RUN above.
            let split_hit = split_runs[k] >= 2 && split_bytes[k] >= SPLIT_TOTAL;
            let hit = best >= SINGLE_RUN || split_hit;
            let split_note = if split_hit {
                format!(
                    " (split rule: {} runs totalling {} B)",
                    split_runs[k], split_bytes[k]
                )
            } else {
                String::new()
            };
            let tag_case = label.starts_with("locked integrity tag");
            if label.starts_with("master KEY") && hit {
                if is_split_plant || is_seven_plant {
                    // The two controls that pin the shapes the old threshold
                    // missed. Each is found only by the rule it exists for: the
                    // split control must trip the *split* rule (a single-run hit
                    // on it would mean the plant was compiled into a contiguous
                    // spill, which would not witness the split rule at all), and
                    // the 7-byte control must reach SINGLE_RUN.
                    if is_split_plant && split_hit { split_found = true; }
                    if is_seven_plant && best >= SINGLE_RUN { seven_found = true; }
                    line.push_str(&format!(
                        " | KEY RESIDUE (planted, expected): {}-byte run @{}{}",
                        best, at, split_note
                    ));
                } else if is_planted {
                    // The control's own copy, which is supposed to be found: the check
                    // after the loop fails the run if it was not.
                    planted_found = true;
                    line.push_str(&format!(
                        " | KEY RESIDUE (planted, expected): {}-byte run @{}{}",
                        best, at, split_note
                    ));
                } else {
                    failures += 1;
                    line.push_str(&format!(
                        " | KEY RESIDUE: {}-byte run @{}{}",
                        best, at, split_note
                    ));
                }
            } else if label.starts_with("control") && hit {
                failures += 1;
                line.push_str(&format!(
                    " | CONTROL FALSE POSITIVE: {}-byte run @{}{}",
                    best, at, split_note
                ));
            } else if tag_case && hit {
                if is_control {
                    // The dependency itself leaves the pattern: record it, and exculpate
                    // the crate cases below.
                    dependency_leaks_tag = true;
                    line.push_str(&format!(
                        " | TAG RESIDUE in blake3 itself: {}-byte run @{}{}",
                        best, at, split_note
                    ));
                } else if dependency_leaks_tag {
                    line.push_str(&format!(
                        " | TAG RESIDUE ({}-byte run @{}) attributable to blake3",
                        best, at
                    ));
                } else {
                    failures += 1;
                    line.push_str(&format!(
                        " | TAG RESIDUE: {}-byte run @{}{}",
                        best, at, split_note
                    ));
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
        println!("      region -- was NOT found, so this scan is not reading the frames it");
        println!("      claims to read and every 'no residue' line above is vacuous. Fix the");
        println!("      probe before trusting a PASS.");
        std::process::exit(1);
    }
    // The two controls for the shapes the old single-run threshold could not see.
    // Each must be found by its own rule: a regression of the split rule or of the
    // 7-byte threshold turns into a failure here instead of a PASS over a 4+4 or
    // 7-byte residual -- which is exactly what the audit measured before these
    // controls existed.
    if !split_found {
        println!();
        println!("FAIL: the split positive control -- the key's first and last four bytes as");
        println!("      two separate 4-byte stack copies -- was NOT found by the split rule");
        println!("      (>= 2 runs of >= {MIN_RUN} bytes totalling >= {SPLIT_TOTAL}), so a 4+4 split of");
        println!("      key material would read as clean. Fix the rule before trusting a PASS.");
        std::process::exit(1);
    }
    if !seven_found {
        println!();
        println!("FAIL: the 7-byte positive control -- the key's first seven bytes as one run --");
        println!("      was NOT found by the {SINGLE_RUN}-byte single-run threshold, so a 7-byte");
        println!("      residual would read as clean. Fix the threshold before trusting a PASS.");
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
        println!("      The three planted controls (whole key, 4+4 split, 7-byte run) show the");
        println!("      scan reads this region and sees both of the shapes an 8-byte single-run");
        println!("      threshold used to miss, and the never-used pattern shows it produces no");
        println!("      false positives.");
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
