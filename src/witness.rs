//! An independent second implementation of the whole construction, for `ultra`.
//!
//! Every other defence in this crate is a *shape*: two gates, two serial checks, two slots,
//! a fail-closed call site. They all share one property that no amount of restructuring
//! removes — the bytes being compared come from **one** implementation. A fault that makes
//! that implementation produce the attacker's tag, or that corrupts the keystream before the
//! tag is computed, is invisible to every gate, because every gate is looking at the same
//! wrong answer. `tools/fi_check.sh` pins that as a known limit (`computed-tag-replaced`).
//!
//! This module is the software answer: a second implementation of ChaCha20, HChaCha20 and
//! keyed BLAKE3, written here from the specifications, with no shared code and no shared
//! dependency — the crate's normal path goes through the `blake3` crate and its SIMD
//! kernels, this one is scalar Rust written from the BLAKE3 book and the ChaCha20 RFC. Under
//! `ultra` the whole decryption is computed **twice**, once by each, and the two results are
//! required to agree bit for bit before anything is accepted. A single fault must then
//! corrupt *two independent implementations identically* to get through.
//!
//! What that does and does not buy, stated plainly, because "two implementations" invites
//! over-reading:
//!
//! * **It does buy:** any fault confined to one implementation, *on a path the caller
//!   cross-checks in full*. The two decryption entry points compare both the recomputed
//!   keystream (through the plaintext) and the tag, so a compressed keystream, a corrupted
//!   comparison, a skipped round, a wrong constant, a pin on the tag or a fault in the
//!   `blake3` dependency's own state has to land on both implementations, in the same way,
//!   to survive. **Where the comparison is narrower, so is this bullet:** the allocating
//!   `encrypt` cross-checks only the *tag* (`witness::encrypt_tag`; there is no witness
//!   keystream), so a keystream fault there yields a correct tag over a corrupt ciphertext
//!   and is caught by the receiver's `decrypt`, not locally — and
//!   `encrypt_in_place_detached` carries no witness at all. Both asymmetries are
//!   deliberate and stated in the README and `src/lib.rs`'s entry-point docs.
//! * **It does not buy:** two faults, one in each implementation; a fault in the shared
//!   *inputs* (a corrupted key byte corrupts both sides identically); a fault in the
//!   comparison that ANDs the agreement itself; and anything physical — power, EM, a
//!   hypervisor, cold boot. Those are the residual, and the README says so.
//! * **It fails by `assert!`, not by `Result`, and that is deliberate.** The module's three
//!   internal-contract checks — equal buffer lengths in `keystream_xor` and `decrypt`, and
//!   the CV-stack bound in `CvStack::push` — are active in release and panic rather than
//!   return an error. There is no caller to hand one to: the only caller is `src/lib.rs`,
//!   which sizes every buffer it passes and bounds inputs by `MAX_MSG_SIZE`, so none of the
//!   three is reachable from the public API today; and a witness that quietly gave up would
//!   be worse than one that says why (the `CvStack::push` comment makes the same argument
//!   locally).
//!
//! Cost is the point of `ultra`: this doubles the cipher and the MAC and allocates a second
//! plaintext. It is not on unless the feature is, and the crate's default build does not
//! compile this file.
//!
//! # Why it is written the way it is
//!
//! Deliberately *unlike* the main path, in every way that could otherwise be shared:
//!
//! * scalar, no SIMD, no target features, no CPU detection — the main path's AVX2/SSE2/NEON
//!   kernels are where a keystream fault would live;
//! * a different BLAKE3 implementation strategy: this one streams through a chunk state with
//!   an explicit CV stack (the reference structure), while the crate's path hands the whole
//!   input to the `blake3` crate's `Hasher` in one or three `update` calls;
//! * `u32`/`u64` arithmetic written out rather than reusing the crate's helpers, so a fault
//!   in one of those helpers (say the rotate amount in `qr`) cannot affect both sides.
//!
//! The one thing that *must* be shared is the specification: flags, constants, domain
//! strings. The ChaCha20 constant, the BLAKE3 IV/flags/permutation are duplicated as literals
//! here on purpose, so a typo in one copy shows up as a disagreement in the first test rather
//! than as a silent mismatch of behaviour. The domain *strings* and the field widths
//! (`DOM_PRE`, `DOM_TAG`, `DOM_ENC`, `SUBKEY_DOMAIN`, `NONCE_LEN`, `TAG_LEN`) are **imported**
//! from the crate instead — that is what `tests/ultra.rs` requires — so a wrong domain is
//! wrong on both sides and cannot show up here as a disagreement; the external anchor for the
//! wire format is the differential fixture against `tools/ref_impl.py`, not this cross-check.

use crate::{DOM_ENC, DOM_PRE, DOM_TAG, NONCE_LEN, SUBKEY_DOMAIN, TAG_LEN};

/// Volatile-zero a slice.
///
/// The witness wipes every key-derived buffer it names, and `ultra` does not count cost, so
/// this is applied liberally. That includes the primitive-internal state: `block`'s and
/// `hchacha20`'s `s`/`v` (the key words and the permutation state), `compress`'s
/// `state`/`m`, the compression outputs in `Output::chaining_value`/`root_output_bytes`, and
/// the streaming locals in `ChunkState::update`/`Hasher::update`/`add_chunk_cv`/
/// `finalize_xof`. `Output` has a `Drop` that wipes its key CV and its message block, so the
/// node built by `parent_output(..).chaining_value()` — which no caller names — is zeroed on
/// the way out.
///
/// What is still *not* covered, honestly — two classes, and an earlier revision of this
/// comment claimed the first of them was:
///
///   * **By-value return temporaries**, which no wipe in the callee can name: a `[u32; 8]`
///     CV, the `[u8; 32]` from `hchacha20`, and the 65-byte tags `tag`/`decrypt`/
///     `encrypt_tag` return, exactly as `src/lib.rs::derive_enc`'s doc describes for its own
///     44-byte aggregate. The construction buffers are written through caller slices for that
///     reason; the caller (`src/lib.rs`) wipes its own copies of the tags, and `scrub_stack`
///     remains the cover for the return slots themselves.
///   * **Short-lived 4-byte copies inside the primitives**: the `[u8; 4]` built from the key
///     in `Hasher::new_keyed`, the ones `block`/`hchacha20` build from the key and nonce as
///     they unpack them into state words, the one built from a message word in
///     `words_from_le_bytes`, the per-word output copies in `hchacha20`, and `block`'s named
///     `x` — the added keystream word, written into `out` byte-wise. The sentence that
///     used to stand here said these were wiped; they are not — the inline array expressions
///     have no local to name, and the named locals
///     (`Hasher::new_keyed`'s and `words_from_le_bytes`'s `b`, `block`'s `x`) go unwiped for
///     the same cost reason as the
///     inline ones. They are left rather than paid
///     for with a volatile store per word — four bytes of a 32-byte key is not a key, and
///     `tools/stack_residue.sh` searches for the whole value — and `scrub_stack` covers the
///     region afterwards under `ultra`.
///
/// This is also what keeps `tools/ctgrind.sh` quiet: the first version of this module left its
/// BLAKE3 chaining values in a `Vec<[u32; 8]>`, and memcheck reported a conditional jump in
/// glibc's `free` — the freed chunk's payload held poisoned data, and the allocator reads part
/// of it. The CV stack is a fixed array with a length now (`CvStack`), so it is wiped in
/// place and there is nothing to free at all — which also means a keyed call performs **no
/// heap allocation** and cannot abort on an allocation refusal (see `CvStack`'s doc).
#[inline(never)]
fn wipe<T>(value: &mut T) {
    let bytes = core::mem::size_of::<T>();
    let p = value as *mut T as *mut u8;
    for i in 0..bytes {
        // SAFETY: `p` is the base of a live `T`, so `p.add(i)` is in bounds for `i < bytes`,
        // and `T` here is only ever an integer or an array of them.
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Volatile-zero a `u32` array.
#[inline(never)]
fn wipe_words(words: &mut [u32]) {
    for w in words.iter_mut() {
        // SAFETY: `w` is a live `u32`; a volatile store needs no more than that.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ── ChaCha20 (RFC 8439) ───────────────────────────────────────────────

const CHACHA_CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// One ChaCha20 block, written out as the RFC states it.
fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&CHACHA_CONST);
    // The key and nonce words are assembled field by field rather than into a *named*
    // `[u8; 4]` temporary: a named 4-byte copy of key bytes is a thing a wipe can reach, so
    // leaving one here would need a wipe in a loop over the whole message (one block per
    // 64 bytes). No cost figure is quoted for that wipe: it is not reproducible from this
    // repository — the named temporary this replaced was never wiped in any revision, so
    // the saving is unmeasured here. The unnamed `[u8; 4]` that `from_le_bytes` still
    // builds is one of the short-lived copies the module header lists as left; `s`/`v`,
    // which do hold the key words, are wiped below.
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut v = s;
    for _ in 0..10 {
        // Column rounds.
        quarter(&mut v, 0, 4, 8, 12);
        quarter(&mut v, 1, 5, 9, 13);
        quarter(&mut v, 2, 6, 10, 14);
        quarter(&mut v, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter(&mut v, 0, 5, 10, 15);
        quarter(&mut v, 1, 6, 11, 12);
        quarter(&mut v, 2, 7, 8, 13);
        quarter(&mut v, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    // Byte-wise, so no `[u8; 4]` temporary is built for each output word. The word itself
    // is still a named 4-byte local (`x`, below) and is left unwiped, like the other
    // short-lived 4-byte copies the module header lists and for the same reason (a
    // volatile store per word, 16 per block, on this per-block path); the key-bearing
    // `s`/`v` above are what this function is responsible for. (An earlier version of
    // this comment claimed the keystream word "never exists as a named 4-byte
    // temporary", which the `let x` line below contradicts.)
    for i in 0..16 {
        let x = v[i].wrapping_add(s[i]);
        out[i * 4] = x as u8;
        out[i * 4 + 1] = (x >> 8) as u8;
        out[i * 4 + 2] = (x >> 16) as u8;
        out[i * 4 + 3] = (x >> 24) as u8;
    }
    // `s` and `v` hold the key words and the key-dependent permutation state; the crate's
    // own `chacha20_block` wipes its equivalents, so this does too (an earlier version of
    // this module disclosed the omission as a gap).
    wipe(&mut v);
    wipe(&mut s);
    out
}

/// One quarter round, in place — the same arithmetic as the crate's `qr`, written
/// differently (indexing a mutable state rather than returning a tuple).
fn quarter(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] ^= v[a];
    v[d] = v[d].rotate_left(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] ^= v[c];
    v[b] = v[b].rotate_left(12);
    v[a] = v[a].wrapping_add(v[b]);
    v[d] ^= v[a];
    v[d] = v[d].rotate_left(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] ^= v[c];
    v[b] = v[b].rotate_left(7);
}

/// `out = input ^ keystream`, starting at `counter`.
fn keystream_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], input: &[u8], out: &mut [u8]) {
    assert_eq!(input.len(), out.len(), "witness: length mismatch");
    let mut ctr = counter;
    let mut off = 0usize;
    while off < input.len() {
        let mut ks = block(key, ctr, nonce);
        let take = core::cmp::min(64, input.len() - off);
        for i in 0..take {
            out[off + i] = input[off + i] ^ ks[i];
        }
        // The keystream block is secret (it is the key stream), so it is wiped every
        // iteration rather than left for the next one to overwrite.
        wipe(&mut ks);
        ctr = ctr.wrapping_add(1);
        off += take;
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2).
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&CHACHA_CONST);
    // As in `block`: field by field, so no *named* 4-byte key copy exists to wipe.
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in 0..4 {
        s[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut v = s;
    for _ in 0..10 {
        quarter(&mut v, 0, 4, 8, 12);
        quarter(&mut v, 1, 5, 9, 13);
        quarter(&mut v, 2, 6, 10, 14);
        quarter(&mut v, 3, 7, 11, 15);
        quarter(&mut v, 0, 5, 10, 15);
        quarter(&mut v, 1, 6, 11, 12);
        quarter(&mut v, 2, 7, 8, 13);
        quarter(&mut v, 3, 4, 9, 14);
    }

    // No feed-forward: words 0..4 and 12..16.
    let mut out = [0u8; 32];
    for (i, idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v[*idx].to_le_bytes());
    }
    // As in `block`: `s`/`v` carry the key words and the permutation state.
    wipe(&mut v);
    wipe(&mut s);
    out
}

// ── BLAKE3 (keyed, XOF) ───────────────────────────────────────────────
//
// Written from the specification's own structure: a chunk state of 16 blocks, a CV stack
// for the tree, and an `Output` that becomes the root. The crate's path calls the `blake3`
// crate instead, so the two implementations share no code beyond the algorithm.

const BLAKE3_BLOCK: usize = 64;
const BLAKE3_CHUNK: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;

const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn words_from_le_bytes(bytes: &[u8; 64]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for i in 0..16 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        w[i] = u32::from_le_bytes(b);
    }
    w
}

fn mix(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    mix(state, 0, 4, 8, 12, m[0], m[1]);
    mix(state, 1, 5, 9, 13, m[2], m[3]);
    mix(state, 2, 6, 10, 14, m[4], m[5]);
    mix(state, 3, 7, 11, 15, m[6], m[7]);
    mix(state, 0, 5, 10, 15, m[8], m[9]);
    mix(state, 1, 6, 11, 12, m[10], m[11]);
    mix(state, 2, 7, 8, 13, m[12], m[13]);
    mix(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &[u32; 16]) -> [u32; 16] {
    let mut p = [0u32; 16];
    for i in 0..16 {
        p[i] = m[MSG_PERMUTATION[i]];
    }
    p
}

/// Seven rounds, then the feed-forward that makes the first eight words the chaining value
/// and all sixteen the output block.
fn compress(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block_words;
    for _ in 0..7 {
        round(&mut state, &m);
        m = permute(&m);
    }
    let mut out = [0u32; 16];
    for i in 0..8 {
        out[i] = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
    // `state` is the CV followed by the IV, counter, block length and flags, with the
    // message words mixed in by `round`; `m` is the (permuted) message block. Neither is
    // "key-derived" in general -- `m` is AAD or plaintext in the tag's passes and a derived
    // key or the tag in the KDF's -- but message blocks are treated as sensitive here too,
    // so both are wiped (the `blake3` crate's own compression path is a black box with no
    // equivalent hook).
    wipe_words(&mut state);
    wipe_words(&mut m);
    out
}

fn first8(words: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&words[0..8]);
    cv
}

/// The node whose `chaining_value` is the CV of a subtree and whose `root_output_bytes` is
/// the XOF when it happens to be the root.
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Drop for Output {
    /// The node holds the key CV (`input_cv`, which is the key words for the bottom chunk)
    /// and a message block (`block_words`, the two child CVs at a parent) for its whole
    /// life. Wiping on drop covers every node that no call site could wipe itself, including
    /// the unnamed temporary in `parent_output(..).chaining_value()` and the node
    /// `Hasher::finalize_xof` replaces on each merge.
    fn drop(&mut self) {
        wipe_words(&mut self.input_cv);
        wipe_words(&mut self.block_words);
    }
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        // Name the compression output so it can be wiped: `first8(&compress(..))` would
        // leave the other eight key-derived words in an unnamed temporary.
        let mut words = compress(
            &self.input_cv,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let cv = first8(&words);
        wipe_words(&mut words);
        cv
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        // `enumerate` rather than a hand-kept counter: clippy flagged the loop-variable shape,
        // and the output block index *is* the counter, so saying so is clearer anyway.
        for (counter, chunk) in out.chunks_mut(2 * 32).enumerate() {
            let counter = counter as u64;
            let mut words = compress(
                &self.input_cv,
                &self.block_words,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, four) in words.iter().zip(chunk.chunks_mut(4)) {
                // Byte-wise, as in `block`: the word is key-derived, and a named
                // `[u8; 4]` of it would be a copy to wipe (at a per-word cost). The
                // `enumerate` keeps the final chunk's short tail working, which a fixed
                // 0..4 index would not.
                for (k, dst) in four.iter_mut().enumerate() {
                    *dst = (*word >> (8 * k)) as u8;
                }
            }
            // The compression output is the key-derived root block (or a chunk of it).
            wipe_words(&mut words);
        }
    }
}

fn parent_output(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[0..8].copy_from_slice(left);
    block_words[8..16].copy_from_slice(right);
    Output {
        input_cv: *key,
        block_words,
        counter: 0,
        block_len: BLAKE3_BLOCK as u32,
        flags: flags | PARENT,
    }
}

fn parent_cv(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> [u32; 8] {
    parent_output(left, right, key, flags).chaining_value()
}

/// One 1024-byte chunk, filled block by block.
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLAKE3_BLOCK],
    block_len: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            cv: *key,
            chunk_counter,
            block: [0u8; BLAKE3_BLOCK],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        self.blocks_compressed * BLAKE3_BLOCK + self.block_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLAKE3_BLOCK {
                let mut words = words_from_le_bytes(&self.block);
                // Name the compression output rather than writing
                // `first8(&compress(..))`: the unnamed `[u32; 16]` temporary would keep the
                // other eight key-derived words past the statement, where no wipe reaches it.
                let mut full = compress(
                    &self.cv,
                    &words,
                    self.chunk_counter,
                    BLAKE3_BLOCK as u32,
                    self.flags | self.start_flag(),
                );
                self.cv = first8(&full);
                wipe_words(&mut full);
                wipe_words(&mut words);
                self.blocks_compressed += 1;
                self.block = [0u8; BLAKE3_BLOCK];
                self.block_len = 0;
            }
            let want = BLAKE3_BLOCK - self.block_len;
            let take = core::cmp::min(want, input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/// BLAKE3's maximum tree depth: the reference implementation keeps at most one CV per
/// level and 2^64 bytes is 2^54 chunks, so 64 is a safe bound for any input. Reserving the
/// stack up front means it never reallocates -- a reallocating `Vec` frees a block holding
/// the live chaining values it just copied out, which no wipe here could reach.
const CV_STACK_RESERVE: usize = 64;

/// Keyed BLAKE3, streaming, with XOF output.
///
/// `cv_stack` is a fixed array with a length, **not a `Vec`**, and that is a correctness
/// property rather than an optimisation. A keyed call runs *after* the caller has derived
/// `k_in`/`k_out`/`enc_seed` (and, on the decrypt paths, after the recovered plaintext is in
/// a buffer), so an allocation refusal here would abort the process -- skipping every wipe,
/// with the derived keys and the plaintext still in memory. That is the failure class
/// `derive_tag`'s window buffer was fixed for; an audit found the same shape here, in a
/// `Vec::with_capacity`. Sixty-four entries cover every input a 64-bit chunk counter can
/// describe, so nothing is given up by not having a growable stack.
struct CvStack {
    cvs: [[u32; 8]; CV_STACK_RESERVE],
    len: usize,
}

impl CvStack {
    fn new() -> Self {
        CvStack {
            cvs: [[0u32; 8]; CV_STACK_RESERVE],
            len: 0,
        }
    }

    fn push(&mut self, mut cv: [u32; 8]) {
        // Unreachable: the depth is bounded by the counter's width. A panic (rather than a
        // silent drop) is the right failure here -- a witness that forgot a chaining value
        // would disagree with the main path on a huge input instead of saying why.
        assert!(self.len < CV_STACK_RESERVE, "witness: CV stack exhausted");
        self.cvs[self.len] = cv;
        self.len += 1;
        // The parameter is a by-value copy of the key-derived chaining value the caller
        // passes (`add_chunk_cv` wipes its own local after this returns, but a copy that
        // entered through an argument slot is a different place, and nothing else names
        // it). Wipe it here too, so no whole CV copy is left merely because of the ABI.
        wipe_words(&mut cv);
    }
}

pub struct Hasher {
    key_words: [u32; 8],
    chunk: ChunkState,
    cv_stack: CvStack,
    flags: u32,
}

impl Hasher {
    /// Keyed mode: the key words *are* the initial chaining value.
    ///
    /// Worth stating because the first version of this had `key_words = IV ^ key`, which is
    /// the shape BLAKE2's keyed mode has and BLAKE3's does not — and the differential test
    /// below caught it immediately, at the empty input, before any of this was wired
    /// anywhere.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&key[i * 4..i * 4 + 4]);
            key_words[i] = u32::from_le_bytes(b);
        }
        let flags = KEYED_HASH;
        Hasher {
            key_words,
            chunk: ChunkState::new(&key_words, 0, flags),
            cv_stack: CvStack::new(),
            flags,
        }
    }

    fn add_chunk_cv(&mut self, mut new_cv: [u32; 8], total_chunks: u64) {
        let mut chunks = total_chunks;
        while chunks & 1 == 0 {
            // The popped CV is key-derived; wipe the slot it leaves behind as well as the copy
            // this function folds, so nothing in the stack's storage outlives its use.
            //
            // A `Vec::pop` alone would move the value out and shorten the length, leaving the
            // old bytes in storage the stack still owns -- and wiping the returned copy would
            // not touch them. An audit pointed at this comment, which claimed the slot was
            // wiped when it was not. Zero the slot first, then shorten.
            let last = self.cv_stack.len - 1;
            let mut left = self.cv_stack.cvs[last];
            wipe_words(&mut self.cv_stack.cvs[last]);
            self.cv_stack.len = last;
            new_cv = parent_cv(&left, &new_cv, &self.key_words, self.flags);
            wipe_words(&mut left);
            chunks >>= 1;
        }
        self.cv_stack.push(new_cv);
        // `new_cv` is a `Copy` copy of the value the stack now owns; wipe this frame's
        // copy (the caller wipes its own after the call).
        wipe_words(&mut new_cv);
    }

    /// Wipe everything this hasher accumulated, before its buffers are released.
    fn wipe_state(&mut self) {
        for cv in self.cv_stack.cvs[..self.cv_stack.len].iter_mut() {
            wipe_words(cv);
        }
        self.cv_stack.len = 0;
        wipe_words(&mut self.key_words);
        wipe_words(&mut self.chunk.cv);
        wipe(&mut self.chunk.block);
        self.chunk.block_len = 0;
        self.chunk.blocks_compressed = 0;
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk.len() == BLAKE3_CHUNK {
                let mut cv = self.chunk.output().chaining_value();
                let total = self.chunk.chunk_counter + 1;
                self.add_chunk_cv(cv, total);
                // The stack owns a copy now; wipe this frame's.
                wipe_words(&mut cv);
                self.chunk = ChunkState::new(&self.key_words, total, self.flags);
            }
            let want = BLAKE3_CHUNK - self.chunk.len();
            let take = core::cmp::min(want, input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize_xof(&self, out: &mut [u8]) {
        let mut output = self.chunk.output();
        let mut remaining = self.cv_stack.len;
        while remaining > 0 {
            remaining -= 1;
            let mut cv = output.chaining_value();
            output = parent_output(
                &self.cv_stack.cvs[remaining],
                &cv,
                &self.key_words,
                self.flags,
            );
            // `parent_output` copied it into the new node; wipe this frame's copy. The
            // node being replaced is wiped by `Output`'s `Drop`.
            wipe_words(&mut cv);
        }
        output.root_output_bytes(out);
    }
}

fn keyed_xof(key: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    h.finalize_xof(out);
    // Wipe before the hasher's chunk state is released: the chaining values are key-derived,
    // and leaving them is a hygiene gap. (The `Vec` that used to hold them is gone — the CV
    // stack is a fixed array now — and with it the `free` that memcheck used to report a
    // conditional jump inside.)
    h.wipe_state();
}

// ── The construction, independently ───────────────────────────────────

/// `(k_in, k_out, enc_seed)`, recomputed the way the crate specifies it: two
/// ChaCha20 blocks under the subkey nonce, counters 0 (the two tag keys) and 1
/// (the encryption seed).
///
/// Writes through the caller's slices rather than returning a `([u8; 32], [u8; 32],
/// [u8; 32])` tuple: an aggregate return materialises an unnamed temporary holding
/// all three keys, which no `wipe` in this function can name. That is the same
/// defect `src/lib.rs::derive_material`/`derive_enc` were rewritten away from (see
/// `derive_enc`'s doc), and a stack scan found the witness reintroducing it —
/// `k_out` survived as a full 32-byte run after `witness::decrypt`.
fn material(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    k_in: &mut [u8; 32],
    k_out: &mut [u8; 32],
    enc_seed: &mut [u8; 32],
) {
    let mut hch_nonce = [0u8; 16];
    hch_nonce.copy_from_slice(&nonce[0..16]);
    let mut subkey = hchacha20(key, &hch_nonce);

    let mut sub_nonce = [0u8; 12];
    sub_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let mut block0 = [0u8; 64];
    keystream_xor(&subkey, 0, &sub_nonce, &[0u8; 64], &mut block0);
    let mut block1 = [0u8; 64];
    keystream_xor(&subkey, 1, &sub_nonce, &[0u8; 64], &mut block1);

    k_in.copy_from_slice(&block0[0..32]);
    k_out.copy_from_slice(&block0[32..64]);
    enc_seed.copy_from_slice(&block1[0..32]);

    // `subkey` and the two blocks are key-derived and are wiped. `sub_nonce` and `hch_nonce`
    // are public (the domain label and the caller's nonce) — they are wiped too, but for
    // uniformity, not because they are secret; an earlier version of this comment called them
    // "key material", which was wrong.
    wipe(&mut subkey);
    wipe(&mut sub_nonce);
    wipe(&mut hch_nonce);
    wipe(&mut block0);
    wipe(&mut block1);
}

/// The 65-byte tag, recomputed in two levels: an inner keyed hash of the public
/// context under `k_in`, then an outer keyed hash of that digest under `k_out`.
pub fn tag(
    k_in: &[u8; 32],
    k_out: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> [u8; TAG_LEN] {
    // Inner: DOM_PRE || N || le64(|A|) || le64(|M|) || A || M, under k_in.
    let mut head = [0u8; 8 + NONCE_LEN + 16];
    head[0..8].copy_from_slice(&DOM_PRE);
    head[8..8 + NONCE_LEN].copy_from_slice(nonce);
    head[8 + NONCE_LEN..16 + NONCE_LEN].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    head[16 + NONCE_LEN..24 + NONCE_LEN].copy_from_slice(&(msg.len() as u64).to_le_bytes());

    let mut inner = [0u8; 32];
    keyed_xof(k_in, &[&head, aad, msg], &mut inner);

    // Outer: DOM_TAG || X, under k_out.
    let mut outer = [0u8; 8 + 32];
    outer[0..8].copy_from_slice(&DOM_TAG);
    outer[8..].copy_from_slice(&inner);

    let mut out = [0u8; TAG_LEN];
    keyed_xof(k_out, &[&outer], &mut out);

    // `inner` and `outer` are key-derived (a PRF output under `k_in`); `head` is public.
    wipe(&mut inner);
    wipe(&mut outer);
    out
}

/// `(enc_key, enc_nonce)` from the seed and the whole tag.
///
/// Writes through the caller's slices for the same reason [`material`] does: the
/// 44-byte `(enc_key, enc_nonce)` tuple this used to return left an unnamed return
/// temporary, and `src/lib.rs::derive_enc`'s doc records a stack scan finding exactly
/// that tail surviving a round trip.
fn enc_material(
    enc_seed: &[u8; 32],
    tag: &[u8; TAG_LEN],
    enc_key: &mut [u8; 32],
    enc_nonce: &mut [u8; 12],
) {
    let mut input = [0u8; 8 + TAG_LEN];
    input[0..8].copy_from_slice(&DOM_ENC);
    input[8..].copy_from_slice(tag);

    let mut material = [0u8; 44];
    keyed_xof(enc_seed, &[&input], &mut material);

    enc_key.copy_from_slice(&material[0..32]);
    enc_nonce.copy_from_slice(&material[32..44]);

    // The tag is a hash of key material and the 44 bytes are the per-message key and nonce.
    wipe(&mut input);
    wipe(&mut material);
}

/// The whole decryption, independently: writes the plaintext into `plaintext` and returns
/// the recomputed tag.
///
/// Used by `ultra` to cross-check the main path bit for bit. The output is a caller slice
/// rather than a `Vec` on purpose: allocation belongs to `src/lib.rs`, where it is fallible
/// and taken *before* any key material exists. **Nothing in this module allocates** — the
/// chaining-value stack is a fixed array (see `CvStack`) — so no path here can abort on an
/// allocation refusal, which at this point in the call would skip every wipe with the derived
/// keys and the recovered plaintext still in reach. The caller wipes both the slice and the
/// tag when it is done.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    received_tag: &[u8; TAG_LEN],
    plaintext: &mut [u8],
) -> [u8; TAG_LEN] {
    // The parameter is `received_tag`, not `tag`: naming it `tag` shadowed this module's
    // own `tag` function, so the call below resolved to the reference.
    assert_eq!(
        plaintext.len(),
        ciphertext.len(),
        "witness: the output buffer must be the length of the ciphertext"
    );
    let mut k_in = [0u8; 32];
    let mut k_out = [0u8; 32];
    let mut enc_seed = [0u8; 32];
    material(key, nonce, &mut k_in, &mut k_out, &mut enc_seed);
    let mut enc_key = [0u8; 32];
    let mut enc_nonce = [0u8; 12];
    enc_material(&enc_seed, received_tag, &mut enc_key, &mut enc_nonce);

    keystream_xor(&enc_key, 0, &enc_nonce, ciphertext, plaintext);

    let recomputed = tag(&k_in, &k_out, nonce, aad, plaintext);
    // The derived keys are wiped here; the plaintext slice is the caller's to wipe (it is
    // written through its buffer, and under `ultra` the caller wipes it after comparing).
    wipe(&mut k_in);
    wipe(&mut k_out);
    wipe(&mut enc_seed);
    wipe(&mut enc_key);
    wipe(&mut enc_nonce);
    recomputed
}

/// The tag the *encryption* side would produce, independently.
pub fn encrypt_tag(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; TAG_LEN] {
    let mut k_in = [0u8; 32];
    let mut k_out = [0u8; 32];
    let mut enc_seed = [0u8; 32];
    material(key, nonce, &mut k_in, &mut k_out, &mut enc_seed);
    let t = tag(&k_in, &k_out, nonce, aad, plaintext);
    wipe(&mut k_in);
    wipe(&mut k_out);
    wipe(&mut enc_seed);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    // The witness's own code is allocation-free (see `CvStack`); only these tests build
    // `Vec`s, so the import lives here rather than in the module.
    use alloc::vec::Vec;

    /// Locate a disagreement: the ChaCha20 block first, then HChaCha20, then BLAKE3.
    #[test]
    fn chacha20_block_matches_the_crate() {
        let key = [0x37u8; 32];
        let nonce = [0x11u8; 12];
        for ctr in [0u32, 1, 7, u32::MAX] {
            assert_eq!(
                block(&key, ctr, &nonce),
                crate::chacha20_block(&key, ctr, &nonce),
                "ChaCha20 block disagrees at counter {ctr}"
            );
        }
    }

    #[test]
    fn hchacha20_matches_the_crate() {
        let key = [0x42u8; 32];
        let n16 = [0x5Au8; 16];
        assert_eq!(hchacha20(&key, &n16), crate::hchacha20(&key, &n16));
    }

    #[test]
    fn blake3_keyed_xof_matches_the_crate() {
        let key = [0x11u8; 32];
        // Sizes that cross BLAKE3's block (64), chunk (1024) and a few tree levels.
        for len in [
            0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 4096, 100_000,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let mut mine = [0u8; 65];
            let mut theirs = [0u8; 65];
            keyed_xof(&key, &[&data], &mut mine);
            crate::blake3_keyed_xof(&key, &data, &mut theirs);
            assert_eq!(mine, theirs, "keyed BLAKE3 XOF disagrees at length {len}");
        }
    }

    /// The same comparison at *every* length up to four chunks and a bit.
    ///
    /// The list above is enough to catch a wrong key schedule — it did, at the empty input —
    /// but not enough for the tree. This witness keeps a chaining-value stack and merges when
    /// the chunk count's low bits are zero, so the merge *pattern* depends on the number of
    /// trailing zeros of the chunk count: a bug can live at 3072 bytes (three chunks) while
    /// 2048 (two) and 4096 (four) both pass. Enumerating every length to 4200 removes that
    /// whole class where boundaries are dense, and the chunk-count powers of two above it
    /// (up to 200 chunks) cover the deepest merges the stack can perform.
    #[test]
    fn blake3_keyed_xof_agrees_at_every_length() {
        const MAX: usize = 204_807; // 200 chunks and 7 bytes
        let data: Vec<u8> = (0..MAX).map(|i| (i % 251) as u8).collect();
        let mut mine = [0u8; 65];
        let mut theirs = [0u8; 65];

        fn compare(data: &[u8], mine: &mut [u8; 65], theirs: &mut [u8; 65], len: usize) {
            let key = [0x11u8; 32];
            keyed_xof(&key, &[&data[..len]], mine);
            crate::blake3_keyed_xof(&key, &data[..len], theirs);
            assert_eq!(*mine, *theirs, "keyed BLAKE3 XOF disagrees at length {len}");
        }

        for len in 0..=4200 {
            compare(&data, &mut mine, &mut theirs, len);
        }
        // Chunk-count boundaries (1024·k) at the block and chunk edges.
        for chunks in [1usize, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 200] {
            let base = chunks * 1024;
            for delta in [0usize, 1, 63, 64, 65] {
                if base + delta <= MAX {
                    compare(&data, &mut mine, &mut theirs, base + delta);
                }
                if base >= delta {
                    compare(&data, &mut mine, &mut theirs, base - delta);
                }
            }
        }
    }

    /// The cross-checks above feed the primitives **constant-byte** keys and nonces
    /// (`[0x11; 32]`, `[0x37; 32]`, `[0x5A; 24]`, …). With every byte equal, permuting
    /// the words during unpacking leaves the assembled words identical, so those tests
    /// cannot see the order at all. The end-to-end cross-check in `src/lib.rs` *is*
    /// sensitive to it in `block` and `Hasher::new_keyed`, because their inputs are the
    /// derived subkey and `k_in`/`k_out` — not constant-byte. That also reaches
    /// `hchacha20` whenever a composite test uses a non-constant key, so a permuted
    /// `hchacha20` word order does *not* pass every existing test. Permuting its key
    /// words (`s[4 + i]` → `s[4 + (7 - i)]`) leaves the four other tests in this module
    /// green — none of them feeds `hchacha20` distinct bytes — but under the same
    /// mutation `cargo test --release --features ultra --lib` reports 55 passed /
    /// 8 failed. Seven of the eight are composite tests (the three
    /// `test_xchacha20_blake3_siv_kat_*` cases, `test_avalanche_single_bit_flip`,
    /// `test_all_accelerated_paths_agree_on_a_boundary_corpus`,
    /// `test_random_helpers_produce_usable_output`, `test_tag_binds_both_derived_keys`)
    /// that see it as `AuthenticationFailed` from the `ultra` encrypt/decrypt
    /// cross-check rather than as a named site;
    /// `tests/ultra.rs::every_layer_answers_correctly_in_the_ultra_build` fails the same
    /// way. What this test adds is the unit-level witness of the unpacking: the failure
    /// lands on the `hchacha20` comparison itself, with both values, so the word order
    /// is named where it lives instead of surfacing as "the witness disagrees". It runs
    /// the comparisons on distinct bytes, so the unpacking order in every one of the
    /// three sites is actually exercised.
    #[test]
    fn matches_the_crate_on_distinct_key_and_nonce_bytes() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let nonce: [u8; NONCE_LEN] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(5));

        // The two primitives, whose word unpacking the constant-byte tests cannot check.
        let n12: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
        let n16: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(2));
        for ctr in [0u32, 1, 7, 0x1234_5678, u32::MAX] {
            assert_eq!(
                block(&key, ctr, &n12),
                crate::chacha20_block(&key, ctr, &n12),
                "distinct-byte ChaCha20 block disagrees at counter {ctr}"
            );
        }
        assert_eq!(hchacha20(&key, &n16), crate::hchacha20(&key, &n16));

        // The keyed hash, whose key is unpacked into the initial chaining value.
        for len in [0usize, 1, 63, 64, 65, 1024, 1025, 4096] {
            let data: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let mut mine = [0u8; 65];
            let mut theirs = [0u8; 65];
            keyed_xof(&key, &[&data], &mut mine);
            crate::blake3_keyed_xof(&key, &data, &mut theirs);
            assert_eq!(
                mine, theirs,
                "distinct-byte keyed XOF disagrees at length {len}"
            );
        }

        // And the whole construction, so the derivation (which unpacks the key through
        // `hchacha20` and the subkey nonce) is covered end to end, not just the pieces.
        for len in [0usize, 1, 64, 65, 1024, 1025, 4096] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let aad: Vec<u8> = (0..17).map(|i| (i % 241) as u8).collect();
            let (ct, tag) = crate::encrypt(&key, &nonce, &aad, &pt).unwrap();
            assert_eq!(
                encrypt_tag(&key, &nonce, &aad, &pt),
                tag,
                "distinct-byte witness tag disagrees at length {len}"
            );
            let mut w_pt = alloc::vec![0u8; ct.len()];
            let w_tag = decrypt(&key, &nonce, &aad, &ct, &tag, &mut w_pt);
            assert_eq!(w_pt, pt, "distinct-byte witness plaintext at length {len}");
            assert_eq!(w_tag, tag, "distinct-byte witness tag at length {len}");
        }
    }
}
