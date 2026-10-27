#!/usr/bin/env bash
# Measure what key material survives in the stack frames of an AEAD call.
#
# CI's `stack residue` job runs this in the default and `ultra` configurations as a
# **blocking** check and a release gate: a finding, a missing measurement, or a positive
# control that did not fire fails the job. `verify.sh`'s tool stage is narrower: a narrow
# local run reports a change as ADVISORY, while `--deep`/`--all` (`STRICT=1`) fails the
# run. (The header used to say the tool was advisory in CI, which stopped being true when
# the job became blocking.)
# What it finds today is dominated by the `blake3` dependency: its XOF output
# buffer sits in frames this crate cannot name, let alone wipe (the key itself is
# not left -- measured). The derived per-message values are reconstructed from the
# public construction and that reconstruction is checked against the public tag and
# ciphertext before it is scanned; a wrong domain string or field order therefore
# fails this tool instead of making every derived pattern miss. A gate that fails
# for a reason upstream of this crate would be a gate someone eventually deletes,
# so it is a tool instead, and the finding is written down in README's "cannot fix
# for you" list.
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
# Cargo reads manifest paths with the host's path syntax. On Windows Git Bash,
# `$ROOT` is /c/... and would be resolved as C:\c\...; convert for the temp project.
ROOT_MANIFEST="$(cygpath -m "$ROOT" 2>/dev/null || printf %s "$ROOT")"
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
xchacha20-blake3-siv = { path = "$ROOT_MANIFEST", features = ["locked"] }
# To compute the expected integrity tag (BLAKE3(key)[0..8]) independently, and to
# run the blake3-only attribution control with the same wipe discipline. This tool's
# standalone manifest must use the maintained fork directly: it does not inherit the
# parent's path dependency, and there is no crates.io BLAKE3 in the graph.
blake3 = { path = "$ROOT_MANIFEST/blake3", default-features = false, features = ["zeroize"] }
zeroize = "1"
chacha20 = { version = "0.9", default-features = false }
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
EOF

cat > "$WORK/src/main.rs" <<'RS'
use xchacha20_blake3_siv::{
    decrypt, decrypt_in_place_detached, encrypt, encrypt_in_place_detached,
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::cipher::generic_array::GenericArray;

const PAINT: usize = 1 << 20;
const SENTINEL: u8 = 0x5A;

/// Which *known* pattern the painted frame carries, so the scan's positive controls sit
/// where the window is defined to be. They used to write into their own frames: a
/// `#[inline(never)]` function called from the same site usually gets the same frame slot as
/// its neighbours, which is why that worked on the development host -- and CI, on another
/// toolchain, measured the split control *outside* the window (`FAIL: the split positive
/// control ... was NOT found`, while the 32-byte and 7-byte plants were found). A control
/// that cannot run is not the same finding as a scan that cannot see, and writing the plant
/// into the frame `paint` returns a pointer into makes the window's contents a property of
/// the construction rather than of a compiler's frame assignment.
#[derive(Clone, Copy)]
enum Plant {
    None,
    Key,
    Split,
    Seven,
}

/// Store one byte into the frame being painted. `write_volatile` and not a copy, for the
/// reason the old plants documented: the optimiser can prove a plain store into an array
/// whose address is only black-boxed is dead and delete it (measured: the 7-byte plant read
/// `master: 1 B`, i.e. the plant might as well not have existed).
#[inline(always)]
fn plant_byte(buf: &mut [u8; PAINT], at: usize, byte: u8) {
    assert!(at < PAINT, "the plant must land inside the painted frame");
    // SAFETY: `at` is asserted in bounds, and `buf` is a live local of the caller.
    unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(at), byte) };
}

#[inline(never)]
fn paint(plant: Plant, k: &[u8; 32]) -> *const u8 {
    let mut buf = [SENTINEL; PAINT];
    std::hint::black_box(&mut buf);
    match plant {
        Plant::None => {}
        // One 32-byte run: the shape the old 8-byte threshold was written for.
        Plant::Key => {
            for (i, b) in k.iter().enumerate() {
                plant_byte(&mut buf, 16 + i, *b);
            }
        }
        // Two 4-byte runs, 24 pattern bytes apart -- the shape only the split rule sees.
        // The buffer is 1 MiB and the fragments are 128 bytes in, so the caller's post-return
        // scratch area (which clobbers the top ~24 bytes of a callee frame, measured) cannot
        // take half the plant before the scan.
        Plant::Split => {
            for i in 0..4 {
                plant_byte(&mut buf, 128 + i, k[i]);
                plant_byte(&mut buf, 132 + i, k[28 + i]);
            }
        }
        // One 7-byte run, between MIN_RUN and the old 8-byte threshold. The byte after it is
        // the paint sentinel rather than `k[7]`, so a widened store cannot make the run eight
        // bytes of key.
        Plant::Seven => {
            for i in 0..7 {
                plant_byte(&mut buf, 16 + i, k[i]);
            }
        }
    }
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
    use xchacha20_blake3_siv::locked::{LockedKey, SUPPORTED};
    if !SUPPORTED {
        return;
    }
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
/// The 32-byte control's case: the plant itself happens in `paint`'s frame (`Plant::Key`),
/// which is the frame the scan's window is *defined* as; this function only keeps the case
/// list and the report's name for it.
#[inline(never)]
fn do_planted_key(_k: &[u8; 32], _n: &[u8; 24]) {}
/// The split control's case (`Plant::Split`): the key's first four bytes followed by its
/// last four, back to back -- eight bytes of key material with no contiguous run matching
/// more than four pattern bytes, so neither the old 8-byte threshold nor any single-run
/// threshold sees it. The two fragments are 24 bytes apart in the *pattern*
/// (`k[0..4]`, `k[28..32]`), which is what makes the physical adjacency two runs and not
/// one: a merged 8-byte spill cannot be a key substring.
#[inline(never)]
fn do_planted_split(_k: &[u8; 32], _n: &[u8; 24]) {}
/// The 7-byte control's case (`Plant::Seven`): seven contiguous key bytes, one byte short of
/// the old 8-byte threshold.
#[inline(never)]
fn do_planted_seven(_k: &[u8; 32], _n: &[u8; 24]) {}
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
    // `paint` needs a 1 MiB frame; the platform main-thread stack is often 1 MiB
    // (Windows), so run the measurement on a thread with room for it and the scrub.
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("scan thread panicked");
}

fn run() {
    let key: [u8; 32] = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into().unwrap();
    let nonce: [u8; 24] = hx("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into().unwrap();

    // The caller knows these two. The derived values (k_in, k_out, enc_seed, enc_key,
    // enc_nonce) are reconstructed below from the documented construction and checked
    // against the public tag/ciphertext; the in-tree version of this measurement used
    // crate internals, while this one needs the construction to be correct and says so.
    //
    // The third pattern *is* reachable: the `locked` integrity tag is `BLAKE3(key)[0..8]`,
    // an unkeyed hash of the master key, so it is computable here and (per the crate's
    // classification) is key material. It is 8 bytes, so it is judged by the same
    // 7-byte single-run and split rules as the two longer patterns.
    let tag8 = blake3::hash(&key).as_bytes()[..8].to_vec();

    // Derive the per-message values independently, using the public construction:
    // HChaCha20 subkey, the two "XSIV"||N[16..24] ChaCha20 blocks, then the two
    // keyed-BLAKE3 hashes. Scanning for these is what turns "scrub_stack should
    // cover the dependency's by-value temporaries" into a measurement.
    let subkey = chacha20::hchacha::<chacha20::cipher::consts::U10>(
        GenericArray::from_slice(&key),
        GenericArray::from_slice(&nonce[..16]),
    );
    let mut derive_nonce = [0u8; 12];
    derive_nonce[..4].copy_from_slice(b"XSIV");
    derive_nonce[4..].copy_from_slice(&nonce[16..]);
    let mut derive = chacha20::ChaCha20::new(
        GenericArray::from_slice(&subkey),
        GenericArray::from_slice(&derive_nonce),
    );
    let mut material = [0u8; 96];
    derive.apply_keystream(&mut material);
    let k_in: [u8; 32] = material[0..32].try_into().unwrap();
    let k_out: [u8; 32] = material[32..64].try_into().unwrap();
    let enc_seed: [u8; 32] = material[64..96].try_into().unwrap();
    let mut inner = [0u8; 32];
    let mut h = blake3::Hasher::new_keyed(&k_in);
    h.update(b"XSIV-PRE");
    h.update(&nonce);
    h.update(&0u64.to_le_bytes());
    h.update(&64u64.to_le_bytes());
    h.update(&[b'A'; 64]);
    h.finalize_xof().fill(&mut inner);
    let mut tag = [0u8; 65];
    let mut h = blake3::Hasher::new_keyed(&k_out);
    h.update(b"XSIV-TAG");
    h.update(&inner);
    h.finalize_xof().fill(&mut tag);
    let mut enc_material = [0u8; 44];
    let mut h = blake3::Hasher::new_keyed(&enc_seed);
    h.update(b"XSIV-ENC");
    h.update(&tag);
    h.finalize_xof().fill(&mut enc_material);

    // Positive control for the derivation itself, not just for the scan: the values
    // above are computed from the documented construction, and a typo in a domain
    // string, field order or length would make every derived pattern miss without
    // ever failing. Feed the independently derived tag and per-message key back
    // through the public API and require the same bytes. This is also what proves
    // the scan's `tag`/`enc_material` are the crate's values, not merely some
    // self-consistent construction.
    let plaintext = [b'A'; 64];
    let (public_ciphertext, public_tag) = encrypt(&key, &nonce, b"", &plaintext).unwrap();
    assert_eq!(
        tag, public_tag,
        "the independently derived tag does not match the public encrypt output; the scan's derived patterns are not the crate's values"
    );
    let mut independent_plaintext = plaintext;
    let mut independent_ciphertext = [0u8; 64];
    let mut cipher = chacha20::ChaCha20::new(
        GenericArray::from_slice(&enc_material[..32]),
        GenericArray::from_slice(&enc_material[32..44]),
    );
    cipher.apply_keystream(&mut independent_plaintext);
    independent_ciphertext.copy_from_slice(&independent_plaintext);
    assert_eq!(
        &independent_ciphertext[..],
        &public_ciphertext[..],
        "the independently derived per-message key/nonce do not reproduce the public ciphertext"
    );

    let known: Vec<(&str, Vec<u8>)> = vec![
        ("master KEY (must never appear)", key.to_vec()),
        (
            "control (never used, must not appear)",
            hx("deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"),
        ),
        ("locked integrity tag BLAKE3(key)[0..8]", tag8),
        ("k_in (derived, must never appear)", k_in.to_vec()),
        ("k_out (derived, must never appear)", k_out.to_vec()),
        ("enc_seed (derived, must never appear)", enc_seed.to_vec()),
        ("enc_key (derived, must never appear)", enc_material[..32].to_vec()),
        ("enc_nonce (derived, must never appear)", enc_material[32..].to_vec()),
    ];

    let mut cases: Vec<(&str, fn(&[u8; 32], &[u8; 24]))> = vec![
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
    ];
    // `locked` is Linux-only; printing a `0 B` line for a case that returned
    // immediately made an unmeasured entry point read as a clean one. Omit the
    // case and say so, rather than claiming its tag was scanned here.
    let locked_supported = xchacha20_blake3_siv::locked::SUPPORTED;
    if locked_supported {
        cases.push(("locked new+as_bytes", do_locked));
    } else {
        println!("locked new+as_bytes: SKIPPED (the locked module is unsupported on this platform)");
    }

    // The detection thresholds, and the arithmetic they were chosen with. The region
    // is PAINT = 1 MiB, so there are 2^20 windows per case, the eight or nine cases
    // are the `cases` vector below (the `locked` case is omitted where the platform
    // does not support it), and the three patterns are 32, 32 and 8 bytes ("master
    // key", "control", "tag" -- the control is `deadbeef...`, 64 hex digits = 32
    // bytes, not the 64 the earlier revision of this comment claimed).
    //
    // The model, stated so the numbers below can be recomputed: for a pattern of L
    // bytes there are L-k+1 k-grams, a fixed window equals a given k-gram with
    // probability 2^-8k, and the expected number of k-byte matches in one painted
    // region is lambda_k = (L-k+1) * 2^20 / 2^8k; occurrences are treated as
    // independent (Poisson), so a rule firing on >= 1 match has probability
    // ~lambda and one firing on >= 2 has ~lambda^2/2. A spurious hit is a failure
    // in the six non-planted cases (the ones the verdict greps for): the three
    // planted cases expect their own pattern's hit, and a tag-pattern hit is
    // attributed to `blake3` once the blake3-only case has run. The per-run rates
    // below therefore sum the three patterns over those six cases (18
    // pattern-cases, not the 21 this comment used to imply).
    //
    //   * SINGLE_RUN = 7 is the old 8-byte single-run threshold one byte lower, so
    //     the 7-byte run the audit planted is caught. For a 32-byte pattern there
    //     are 26 7-grams: lambda_7 = 26 * 2^20 / 2^56 ~ 3.8e-10 per pattern-case
    //     (2 * 2^-36 ~ 3e-11 for the 8-byte tag), i.e. ~2e-8 over the three
    //     patterns and nine cases, and ~5e-9 over the six non-planted ones.
    //     Effectively no false positives from this rule at all.
    //   * the split rule -- >= 2 disjoint runs of >= MIN_RUN = 4 bytes totalling
    //     >= SPLIT_TOTAL = 8 -- catches a 4+4 split. A 4-byte match has
    //     lambda_4 = 29 * 2^20 / 2^32 ~ 0.0071 expected matches per pattern-case
    //     for either 32-byte pattern (5 * 2^-12 ~ 0.0012 for the tag), so
    //     P(>= 2 matches) ~ lambda^2/2 ~ 2.5e-5 per 32-byte pattern-case (~7e-7
    //     for the tag); summed over the three patterns of the six non-planted
    //     cases that is ~3.1e-4, one false alarm in ~3,200 runs. A false alarm on
    //     the never-used control pattern is itself *reported* as a failure, so its
    //     price is a rare loud error, never a silent PASS.
    //
    // A plain drop to a 4-byte single-run threshold was the simpler candidate and
    // was rejected on the same arithmetic, not on taste: at the 32 KiB frame the
    // audit's sketch assumed that rule would be quiet (~2^-17 per pattern-case),
    // but this region is 1 MiB, 32x larger, and the same sum with P(>= 1) ~ lambda
    // gives 6 * (2 * 0.0071 + 0.0012) ~ 9% of runs seeing a spurious match that
    // counts as a failure -- a false FAIL about once per 11 runs, doubled by CI's
    // two configurations. Hence the split rule for the 4+4 shape and 7, not 4, for
    // a single run.
    const MIN_RUN: usize = 4;
    const SINGLE_RUN: usize = 7;
    const SPLIT_TOTAL: usize = 8;

    let mut failures = 0usize;
    let mut dependency_leaks_tag = false;
    let mut locked_tag_hit = false;
    let mut planted_found = false;
    let mut split_found = false;
    let mut seven_found = false;
    println!("stack-residue scan: {} KiB of call-chain stack per entry point", PAINT / 1024);
    for (name, f) in cases {
        let is_control = name.starts_with("blake3-only");
        let is_planted = name.starts_with("planted key");
        let is_split_plant = name.starts_with("planted split");
        let is_seven_plant = name.starts_with("planted seven");
        let plant = if is_planted {
            Plant::Key
        } else if is_split_plant {
            Plant::Split
        } else if is_seven_plant {
            Plant::Seven
        } else {
            Plant::None
        };
        let ptr = paint(plant, &key);
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
        let mut best = vec![0usize; known.len()];
        let mut at = vec![0usize; known.len()];
        let mut split_runs = vec![0usize; known.len()];
        let mut split_bytes = vec![0usize; known.len()];
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
            let derived_case = *label == "k_in (derived, must never appear)"
                || *label == "k_out (derived, must never appear)"
                || *label == "enc_seed (derived, must never appear)"
                || *label == "enc_key (derived, must never appear)"
                || *label == "enc_nonce (derived, must never appear)";
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
                    locked_tag_hit = true;
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
            } else if derived_case && hit {
                failures += 1;
                line.push_str(&format!(
                    " | DERIVED RESIDUE: {}-byte run @{}{}",
                    best, at, split_note
                ));
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
        if locked_tag_hit {
            println!("PASS: no master key in the call-chain stack region, and no residue of");
            println!("      this crate's own code -- the 8-byte locked integrity tag above IS");
            println!("      left, by the blake3 dependency's XOF buffer, as the note below says.");
        } else if locked_supported {
            println!("PASS: this crate leaves neither the master key, the locked integrity");
            println!("      tag, nor any derived key in the call-chain stack region.");
        } else {
            println!("PASS: this crate leaves neither the master key nor any derived key in");
            println!("      the call-chain stack region; the locked integrity tag was not");
            println!("      measurable because the locked module is unsupported on this platform.");
        }
        println!("      The three planted controls (whole key, 4+4 split, 7-byte run) show the");
        println!("      scan reads this region and sees both of the shapes an 8-byte single-run");
        println!("      threshold used to miss, and the never-used pattern shows it produces no");
        println!("      false positives.");
        if locked_tag_hit {
            println!();
            println!("Note: the blake3-only control DOES leave the 8-byte tag, with the same");
            println!("wipe discipline and no crate code -- so the tag residue in the `locked`");
            println!("case is the dependency's XOF output buffer, in a frame this crate cannot");
            println!("wipe (the same finding as the derived values, README 'cannot fix'). The");
            println!("crate's own copies are wiped; this is the residual that is not its code.");
        } else if dependency_leaks_tag {
            println!();
            if locked_supported {
                println!("The blake3-only control leaves the dependency's 8-byte XOF tag; the");
                println!("crate's `locked` entry point now scrubs that region, so its case is clean.");
            } else {
                println!("The blake3-only control leaves the dependency's 8-byte XOF tag. The");
                println!("`locked` entry point was not run on this platform, so this note makes no");
                println!("claim about it.");
            }
        }
    } else {
        println!();
        println!("FAIL: {} entry point(s) left key material on the stack.", failures);
        std::process::exit(1);
    }
    println!();
    println!("Covered here: the derived k_in/k_out/enc_seed/enc_key/enc_nonce values,");
    println!("computed independently from the public construction and checked against the");
    println!("public tag and ciphertext before scanning. A register or a");
    println!("value outside the 1 MiB painted window is still outside the scan; the");
    println!("entry-point scrub is the mitigation and is measured by these patterns.");
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
# Prefer `--offline` when this standalone project can resolve from the local cargo
# cache: verify.sh --tools runs after the crate has been built, and an offline host
# should not need the network. A cold CI runner has no index yet (this job does not
# build the crate first), so `cargo fetch --offline` fails there and the run falls
# back to the normal online path. Unconditionally passing `--offline` made the job
# fail with "no matching package named `zeroize`" before any measurement ran.
offline_flag=""
if cargo fetch --offline >/dev/null 2>&1; then
  offline_flag=--offline
fi
# shellcheck disable=SC2086
cargo run --release --quiet $offline_flag $FEATURES || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "SKIPPED: the measurement could not run (cargo exited $rc; see above)" >&2
  exit 3
fi
exit "$rc"
