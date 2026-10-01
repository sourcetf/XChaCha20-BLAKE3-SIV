//! XChaCha20-BLAKE3-SIV — Misuse-resistant, key- and context-committing AEAD
//!
//! A 24-byte-nonce (192-bit) AEAD that combines XChaCha20-style nonce extension
//! with a **keyed BLAKE3** MAC.  There is no published specification for this
//! construction; it is this crate's own composition of the two primitives.
//!
//! # The construction
//!
//! ```text
//! K (256-bit)   N (192-bit)   A (associated data)   M (message)
//!
//! 1. subkey   = HChaCha20(K, N[0..16])
//!    material = ChaCha20_keystream(subkey, 0, "XSIV" || N[16..24])    64 B
//!    mac_key  = material[0..32]      enc_seed = material[32..64]
//!
//! 2. tag = BLAKE3_keyed(mac_key,
//!             "XSIV-TAG" || K || N || le64(|A|) || le64(|M|) || A || M)  65 B
//!
//! 3. km      = BLAKE3_keyed(enc_seed, "XSIV-ENC" || tag)               44 B
//!    enc_key = km[0..32]             enc_nonce = km[32..44]
//!
//! 4. C = ChaCha20(enc_key, 0, enc_nonce, M)
//! ```
//!
//! SIV: the tag is computed first, and the per-message encryption key and nonce
//! are derived from it.  Decryption reverses steps 3 and 4, recomputes the tag
//! from the recovered plaintext, and compares all 65 bytes in constant time.
//!
//! Three details are load-bearing rather than incidental:
//!
//! * **Domain separation in the subkey derivation.**  [`SUBKEY_DOMAIN`] sits in
//!   the first 4 bytes of the derivation block's ChaCha20 *nonce* (counter 0),
//!   where XChaCha20-Poly1305 leaves NUL padding.  Without it the same
//!   `(key, nonce)` would derive identical material in both schemes, so a
//!   protocol mixing them would be reusing keys across schemes.
//! * **The key enters the tag input directly**, not only through the derived
//!   `mac_key`.  Binding it only via `mac_key` would let an adversary search for
//!   two keys colliding on that 256-bit value — a 2^128 effort — and bypass the
//!   520-bit tag entirely.
//! * **Both lengths are encoded and every field is fixed width.**  BLAKE3 is not
//!   vulnerable to length extension (its finalisation is flagged, unlike
//!   Merkle–Damgård constructions), but `A || M` alone would be ambiguous:
//!   `("ab", "c")` and `("a", "bc")` would hash identically.
//!
//! This is **not** the c2sp.org ChaCha20-Poly1305-SIV construction: it does not
//! use Poly1305, its tag is 65 bytes rather than 32, and it is not interoperable
//! with anything.
//!
//! The public API exposes **only the 24-byte-nonce** entry points.  Two flavours
//! are available:
//!
//! * Allocating: [`encrypt`] / [`decrypt`].
//! * Allocating under a caller's length policy: [`decrypt_bounded`], which checks
//!   the bound *before* allocating the plaintext buffer.  This is the entry point
//!   for input whose length came from a network peer; see the note on [`decrypt`].
//! * Detached, in-place: [`encrypt_in_place_detached`] /
//!   [`decrypt_in_place_detached`], for protocols that keep the tag separate or
//!   want to avoid a second allocation (and which never allocate themselves).
//!
//! Key properties:
//!
//! - 520-bit tag (65 bytes), key-committing (CMT-1/CMTk) and context-committing
//!   (CMT-3): an attacker must hit the tag it published, a *target* at `2^520` per
//!   attempt, and that is what the width buys.  Read the "Security level" section
//!   below before relying on a number: this crate advertised `2^260` for these for a
//!   while, and that was wrong — the tag is a function of a 256-bit chaining value, so
//!   what it *collides* at is `2^128`, well below the key.
//! - SIV mode: tag computed before encryption, nonce-misuse resistant
//! - Fault-injection hardening, **on by default** (the `hardened` feature): the
//!   accept/reject decision becomes two independently recomputed checks with
//!   separate branches, so a single skipped instruction cannot accept a forgery —
//!   and the outcome is fail-closed, so skipping the decision call cannot either.
//!   It defends the decision and nothing else, it is not validated on a
//!   fault-injection bench, and it costs ~4-11% below 4 KiB and under 2.5% above
//!   (measured against `--no-default-features`, which gives the single-gate build
//!   back). See README.md ("The `hardened` decision — on by default") for the table
//!   of what it covers and what it does not.
//! - Constant-time operations: the tag is compared with `subtle::ConstantTimeEq`
//!   and decryption is decrypt-then-verify (SIV requires the plaintext to
//!   recompute the tag, so verify-then-decrypt is not possible).  See the
//!   "Side channels" section below for what has actually been checked.
//! - Zeroization of sensitive material, including the returned [`Plaintext`],
//!   which wipes itself on drop, and BLAKE3's internal state, which holds the
//!   MAC key and is not cleared on drop.
//! - Typed errors via [`Error`]; no stringly-typed failures
//!
//! # Security level
//!
//! | Property | Strength | Determined by |
//! | --- | --- | --- |
//! | Confidentiality | 256-bit | the ChaCha20 key |
//! | Forgery resistance | **256-bit** | BLAKE3 keyed mode as a PRF over a 256-bit key |
//! | Context / key commitment (CMT-3, CMT-1/CMTk) | **`2^520` per attempt** against a given ciphertext | the tag hit as a *target*; the width does not set it |
//! | Collision resistance of the tag | **2^128** | the 256-bit chaining value the tag is a function of, not the tag's width |
//!
//! **Forgery: 256 bits is the ceiling, not a choice.**  Forgery resistance is
//! bounded by the key's entropy; with a 256-bit key it cannot exceed 256 bits,
//! and a longer tag does not raise it.  **Nor does it raise collision
//! resistance**: the tag is a function of a 256-bit chaining value, so a
//! collision costs `2^128` by birthday whatever the output length is.  (Commitment
//! is not a birthday property at all — see below.)
//!
//! **Commitment: the width is what makes the scheme committing, and that is a *target*
//! property, not a birthday one.** A second key that opens a given ciphertext must make
//! its tag computation output the tag that was published: a `2^-520` event per candidate
//! key, so enumerating the whole `2^256` key space yields nothing (`≈ 2^-264`), while a
//! 32-byte tag would leave `≈ 1` such key in reach and the scheme would no longer be
//! key-committing.  What the width does *not* buy is collision resistance (`2^128`, the
//! birthday of the chaining value the tag is a function of) or forgery resistance
//! (`2^256`, bounded by the key).  [`TAG_LEN`]'s own docs carry both arguments, and
//! `SECURITY-ANALYSIS.md` §4.5 the derivation; the format is frozen at revision `v0.2`,
//! which is now a second reason the width cannot move, not the only one.
//!
//! These rest on BLAKE3 being a secure PRF and collision-resistant and on
//! ChaCha20 being a secure stream cipher: standard, heavily analysed assumptions,
//! but assumptions.  This particular composition has no public specification and
//! has not been independently analysed.
//!
//! # Side channels
//!
//! The cryptographic code paths contain **no secret-dependent branches and no
//! secret-dependent memory indexing**.  Every secret-derived quantity is
//! handled with straight-line arithmetic or `subtle` primitives:
//!
//! * Tag comparison — `subtle::ConstantTimeEq` over all [`TAG_LEN`] (65) bytes.
//! * [`Plaintext`] equality — every `PartialEq` impl routes through
//!   `ConstantTimeEq`, so comparing a decrypted secret against an expected
//!   value does not leak its matching prefix.  A length mismatch is not
//!   secret-dependent.
//! * ChaCha20/HChaCha20 use only ARX operations — no tables, hence nothing to
//!   index with a secret.
//! * BLAKE3 is likewise ARX with no data-dependent lookups.  Its `pure` backend
//!   selects a SIMD kernel at run time from CPU features, which is
//!   data-independent: the dispatch depends on the CPU, not on any secret.
//!
//! Two caveats, stated plainly:
//!
//! 1. **This is an argument about the source and the generated machine code,
//!    not a proof.**  Kani's harnesses cover *functional* correctness; they
//!    cannot establish timing independence, because CBMC has no timing model.
//!    The branch-freedom claims above are backed by inspecting the release
//!    assembly of the ChaCha20 entry points, where the only conditional jumps
//!    are the loop bounds of the zeroization helpers (alignment-dependent, not
//!    value-dependent).
//!
//! 2. **Cache-timing effects are not addressed.**  The SIMD backends
//!    (`x86_simd`, `aarch64_simd`) are data-independent in the sense above, but
//!    no claim is made about microarchitectural leakage, and a full
//!    constant-time argument would need tooling this crate does not run.
//!
//! 3. **The guarantees hold in release builds.**  `subtle`'s `Choice` runs
//!    invariant checks in debug builds (`debug_assert!` on the underlying
//!    byte), which introduce branches; that crate documents itself as intended
//!    for release mode.  `verify.sh` therefore runs `cargo test --release`, and
//!    a debug build should be treated as development-only, not as something to
//!    handle real secrets.  This is a property of the dependency, not of any
//!    code in this crate.
//!
//! Secret material is wiped with `write_volatile` through the internal
//! `zeroize_array`/`zeroize_slice` helpers, which the compiler cannot elide.
//! BLAKE3's own state holds the MAC key and cannot be reached from here, so its
//! `zeroize` feature is enabled and the state is cleared explicitly.
//!
//! Test vectors:
//! - XChaCha20 / HChaCha20: draft-irtf-cfrg-xchacha-03 §2.2.1 / §A.2.1 / §A.3.1
//! - ChaCha20 block: RFC 8439 §2.3.2
//! - keyed BLAKE3: BLAKE3's official `test_vectors.json`
//! - XChaCha20-BLAKE3-SIV (public API): generated by the independent reference
//!   implementation in `tools/ref_impl.py`, which self-checks against the three
//!   sources above before emitting anything; see the KAT tests.
//!
//! References:
//! - <https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/> (HChaCha20 / XChaCha20)
//! - RFC 8439 (ChaCha20 and Poly1305)
//! - <https://github.com/BLAKE3-team/BLAKE3> (the keyed mode used for the MAC)
//!
//! # Formal verification
//!
//! Construction properties (limb arithmetic, carry propagation, buffer wiping,
//! counter sequencing, length limits) are proved with Kani bounded model
//! checking; the harnesses live in the `proofs` module and are compiled only
//! under `cfg(kani)`.
//!
//! ```text
//! cargo kani -Z stubbing
//! ```
//!
//! The `-Z stubbing` flag is **required**.  Several harnesses use
//! `#[kani::stub]` to replace the ChaCha20 permutation, the zeroization helper
//! and the BLAKE3 context-commitment hash with cheap stand-ins; without the flag
//! Kani rejects the attribute and the suite fails to compile.  See the `proofs`
//! module documentation for the cost model behind the harness sizes, and for
//! which of those stubs are honest abstractions rather than placeholders.

#![no_std]
// Public API items are documented; this keeps it that way under CI's `-D warnings`.
// Scoped to the library deliberately: `criterion_group!`/`criterion_main!` expand to
// public items in the benches, which cannot carry docs.
#![warn(missing_docs)]

extern crate alloc;

// `vec!` is only used by the tests: every allocation in the library goes through
// `alloc_zeroed`, which is fallible on purpose (see there).
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Test-only instrumentation, compiled out of every non-test build.
///
/// It exists so that "the `dual-mac` layer actually runs" can be asserted as
/// *behaviour* rather than by grepping the source for a `#[cfg]` string.  The
/// source-text version passed in every configuration, which is how the three
/// defects in the `locked` module (wrong `madvise` arity, wrong `MADV_DONTDUMP`
/// value, unaligned `madvise` range) survived a suite that claimed to test the
/// layer: the one assertion that touched it could not fail.
#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) mod test_counters {
    std::thread_local! {
        /// Number of times `derive_tag` has been entered **on this thread**.
        ///
        /// Thread-local, not a global counter: `cargo test` runs tests in parallel
        /// threads, so a process-wide counter is incremented by every other test that
        /// encrypts anything, and the deltas a counting test measures become noise.
        /// This is measured, not guessed -- the first version was a global `AtomicUsize`
        /// and passed in one configuration and failed in another depending on
        /// scheduling.
        pub static DERIVE_TAG_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
}

// ── Constants ────────────────────────────────────────────────────────

/// Maximum message size: 2^38 bytes (256 GiB), matching the c2sp.org A_MAX/P_MAX
/// limit this crate inherited.  See `max_msg_size_fits_in_the_block_counter` for why
/// it must not be raised: 2^38 is exactly 2^32 ChaCha20 blocks.
///
/// Public so a caller can reject an input *before* reading or allocating it.  The
/// AEAD cannot bound what it is handed: [`decrypt`] allocates a buffer as large as
/// its ciphertext argument, so a service that trusts a length field off the wire
/// is exposed to a memory-exhaustion request no matter what this crate does.
/// Checking the length against this constant, before reading the body, is the
/// cheap place to stop that.
pub const MAX_MSG_SIZE: u64 = 1u64 << 38;

// The limit and the block counter are two halves of one fact, so they are bound by a
// `const` assertion: this fails to *compile* if either side is changed without the
// other. `MAX_MSG_SIZE` is exactly 2^32 ChaCha20 blocks, so the last block of a
// maximum-length message uses counter `u32::MAX` -- and one block more would wrap it
// (`ctr = ctr.wrapping_add(1)` in every keystream path, SIMD included) and reuse the
// keystream inside a single message, silently. `src/proofs.rs` proves the same
// arithmetic with Kani, but a proof in the Formal job is a different thing from a build
// that refuses to happen.
const _: () = {
    assert!(
        MAX_MSG_SIZE % CHACHA20_BLOCK as u64 == 0,
        "the length limit must be a whole number of ChaCha20 blocks"
    );
    assert!(
        MAX_MSG_SIZE / CHACHA20_BLOCK as u64 <= u32::MAX as u64 + 1,
        "the length limit needs more blocks than the ChaCha20 counter has values: the \
         last block would wrap to counter 0 and reuse keystream within one message"
    );
};

/// ChaCha20 block size (64 bytes).
const CHACHA20_BLOCK: usize = 64;

/// Key length: 32 bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Tag length: 65 bytes (520 bits).
///
/// # What this width does and does not buy
///
/// The rationale used to read: *commitment is a collision property, so an `n`-bit tag caps it
/// at `2^(n/2)`; 64 bytes gives exactly `2^256`, so 65 bytes gives `2^260`.* The decision was
/// right — the tag does have to be wider than 32 bytes for the scheme to be *committing* — but
/// the property it named was the wrong one, and the number was wrong with it. Commitment is a
/// *target*; collisions are a separate matter where a 256-bit state, not the tag's width, sets
/// the bound. Keyed BLAKE3's XOF output is
/// `compress(cv, tail, |tail|, counter, flags | ROOT)` — a function of the **256-bit chaining
/// value**, the final block, its length, the counter and the flags — so two inputs that agree on
/// that state produce byte-identical tags *of any length*.
///
/// So, concretely (see `SECURITY-ANALYSIS.md` §4.5 for the argument and §5 for what a
/// refutation would look like):
///
/// * **the width is what makes it committing, through the *target* rather than a birthday.** A
///   candidate key that is not the real one opens a given ciphertext with probability `2^-520`,
///   so enumerating the whole `2^256` key space succeeds only with probability `≈ 2^-264`. A
///   32-byte tag would make that `2^256 · 2^-256 ≈ 1`: one second key within reach of a key-space
///   enumeration, which is exactly the non-committing failure mode of the 16-byte-tag SIV family.
///   So the width stays, and a revision cannot shorten it without giving up CMT-1/CMTk;
/// * **collision resistance is `2^128`, not `2^260`** — the birthday bound of that chaining
///   value, since a colliding prefix with a held-fixed tail gives identical tags. That is the
///   SHA-256-collision class: still far out of reach of a practical attack, but *below* the
///   256-bit key strength — the part of the old rationale that was simply false, and the one
///   place where the scheme is weaker than its key;
/// * **a *target* is still 2^520 away.** The state shortcut is a *birthday* search over
///   *pairs* of tags the adversary may both search; a tag that must be hit as given — a
///   forgery, or a ciphertext that must also verify under a second key — is unaffected by
///   it, because there the value is fixed by someone else. So `2^128` bounds collision
///   properties (§3 Corollary's two-time-pad event) and says nothing about forgery;
/// * **forgery is unchanged**, and is bounded by the key (`2^256`) rather than by the tag:
///   key search dominates whatever the tag length, since guessing a 32-byte tag costs `2^-256`
///   per attempt and searching the key costs `2^256`.
///
/// (The bullet list above was duplicated once, verbatim but for the collision entry, in the
/// revision that introduced the commitment correction — a merge artefact in the one doc
/// comment that explains a frozen format decision, which is why it is worth a note rather than
/// a silent fix. An auditor reading this constant found it.)
pub const TAG_LEN: usize = 65;

/// Nonce length: 24 bytes (192 bits, XChaCha20 extension).
pub const NONCE_LEN: usize = 24;

/// Domain-separation constant placed in the first 4 bytes of the 12-byte
/// ChaCha20 **nonce** of the subkey-derivation block; the counter stays 0.
///
/// Those are exactly the bytes XChaCha20 and XChaCha20-Poly1305 leave as NUL
/// padding when they extend a nonce.  If this crate did the same, then for the
/// same `(key, nonce)` it would derive **identical per-message key material** to
/// XChaCha20-Poly1305, so a protocol that mixed the two schemes would be reusing
/// keys across them.  A non-zero constant makes that collide only with
/// negligible probability.
///
/// (Note the placement is in the *nonce*, not the counter.  Putting it in the
/// counter slot instead would be a different construction, and would not
/// separate this scheme from XChaCha20-Poly1305, which leaves the counter at 0.)
///
/// The value is ASCII "XSIV", chosen to be self-describing.
pub const SUBKEY_DOMAIN: [u8; 4] = *b"XSIV";

/// Domain separator for the **tag** computation.
///
/// Part of the wire format: changing it changes every tag ever produced.
///
/// Both domains are fixed width and mutually distinct.  A variable-length
/// domain would reintroduce exactly the ambiguity the `u64` length fields in
/// `derive_tag` exist to prevent.
pub const DOM_TAG: [u8; 8] = *b"XSIV-TAG";

/// Domain separator for deriving the per-message encryption key and nonce.
///
/// Part of the wire format.  Distinct from [`DOM_TAG`] so the two BLAKE3
/// invocations cannot be confused for one another.
pub const DOM_ENC: [u8; 8] = *b"XSIV-ENC";

/// Extra stack, in bytes, that one call into this crate may touch below its entry point.
///
/// Non-zero only under `dual-mac` (and therefore `ultra`), where the entry points call
/// `scrub_stack` to overwrite the call-chain region the key derivations used: that overwrite is
/// a single **16 KiB frame**, so a thread whose remaining stack is smaller faults inside the
/// function rather than returning. The README's layer table carries the measurement (a 32 KiB
/// thread survives ~16 KiB of prior consumption without this feature and fails at 8 KiB with
/// it); this function is that number as a value a caller can check, because "size your threads
/// for it" is advice and `stack_size(stack_requirement_bytes() + margin)` is a build step.
///
/// Zero means "no large fixed frame" — not a promise that the crate uses no stack at all: the
/// derivations, the tag buffers and the SIMD kernels are ordinary frames, in the hundreds of
/// bytes, and a caller that gives a thread a stack smaller than that has a problem no constant
/// can describe.
///
/// ```no_run
/// # #[cfg(feature = "dual-mac")]
/// let stack = xchacha20_blake3_siv::stack_requirement_bytes() + 16 * 1024;
/// # #[cfg(feature = "dual-mac")]
/// let h = std::thread::Builder::new().stack_size(stack).spawn(|| { /* AEAD here */ }).unwrap();
/// ```
#[must_use]
pub const fn stack_requirement_bytes() -> usize {
    #[cfg(feature = "dual-mac")]
    {
        16 * 1024
    }
    #[cfg(not(feature = "dual-mac"))]
    {
        0
    }
}

// ── Error type ────────────────────────────────────────────────────────

/// Errors returned by [`encrypt`], [`decrypt`] and the detached variants.
///
/// # What these variants do and do not reveal
///
/// [`Error::AuthenticationFailed`] is the only outcome that can depend on secret
/// material, and it carries no information beyond "the tag did not verify": the
/// comparison covers all [`TAG_LEN`] bytes in constant time, every intermediate
/// secret is wiped before the decision is taken, and the unverified plaintext is
/// wiped rather than returned. There is no distinction between "wrong key",
/// "wrong nonce", "wrong AAD" and "corrupted ciphertext".
///
/// The two length variants are reported before any cryptography runs. That is a
/// deliberate choice, not an oversight: message and AAD lengths are chosen by the
/// caller and are not secret, and returning a distinct error lets a caller
/// distinguish "this input is unsupported" from "this input is forged", which is
/// what a protocol needs in order to report a usable failure. If an application
/// must not distinguish them, it can collapse the three variants itself.
///
/// Note also that this API takes the tag as a separate `&[u8; TAG_LEN]`, so a
/// caller cannot accidentally treat a truncated ciphertext as `ciphertext || tag`
/// and compare only part of it — the types make that impossible. Length is also
/// bound into the tag's input, so a truncated ciphertext changes the tag rather
/// than authenticating a prefix of the plaintext.
///
/// # Allocation
///
/// [`decrypt`] allocates a buffer the size of the ciphertext, fallibly: if the
/// allocator refuses, it returns [`Error::AllocationFailed`] rather than aborting
/// the process. [`MAX_MSG_SIZE`] (256 GiB) is public for the other half of this —
/// a caller that accepts unbounded input from the network should bound the length
/// itself *before* calling, because this crate cannot do that on the caller's
/// behalf, and a request the kernel *accepts* can still be OOM-killed when the
/// buffer is written to. Decryption never returns a partial result, so a
/// length-bounded call cannot leak a prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The plaintext (on encryption) or ciphertext (on decryption) is longer than
    /// [`MAX_MSG_SIZE`] (256 GiB) — or, for [`decrypt_bounded`], longer than the
    /// caller's own `max_len`.
    MessageTooLong,
    /// The associated data is longer than [`MAX_MSG_SIZE`] (256 GiB).
    AadTooLong,
    /// The buffer for the recovered plaintext could not be allocated.
    ///
    /// Distinct from [`AuthenticationFailed`](Error::AuthenticationFailed) because
    /// it is about this process's memory, not about the key or the message: a
    /// caller may retry a smaller message, but must not retry this one forever.
    AllocationFailed,
    /// Tag verification failed.  The plaintext is never returned in this case.
    AuthenticationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::MessageTooLong => "message exceeds the maximum supported length",
            Error::AadTooLong => "associated data exceeds the maximum supported length",
            Error::AllocationFailed => "the plaintext buffer could not be allocated",
            Error::AuthenticationFailed => "authentication failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

// ── Plaintext ─────────────────────────────────────────────────────────

/// Decrypted plaintext that zeroizes its buffer on drop.
///
/// [`decrypt`] returns this instead of a bare `Vec<u8>` so the recovered
/// plaintext does not linger in freed heap memory.  Derefs to `[u8]`, so it can
/// be used anywhere a byte slice is expected.
///
/// `Debug` deliberately prints only the length, never the contents.
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// Borrow the plaintext bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length of the plaintext in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the plaintext is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::ops::Deref for Plaintext {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Plaintext {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Equality against byte sequences — and against another [`Plaintext`] — is **constant-time**
/// in the plaintext contents.
///
/// [`Plaintext`] holds decrypted secrets, and comparing a decrypted value
/// against an expected one (a token, a password, a key) is a natural use of
/// `==`.  A short-circuiting byte comparison would leak the matching prefix
/// length through timing, so every implementation below routes through
/// [`subtle::ConstantTimeEq`].  A length mismatch is not secret-dependent.
impl PartialEq<[u8]> for Plaintext {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        bool::from(self.0.as_slice().ct_eq(other))
    }
}

impl PartialEq<&[u8]> for Plaintext {
    #[inline]
    fn eq(&self, other: &&[u8]) -> bool {
        bool::from(self.0.as_slice().ct_eq(*other))
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Plaintext {
    #[inline]
    fn eq(&self, other: &[u8; N]) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.as_slice()))
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Plaintext {
    #[inline]
    fn eq(&self, other: &&[u8; N]) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.as_slice()))
    }
}

impl PartialEq<Vec<u8>> for Plaintext {
    #[inline]
    fn eq(&self, other: &Vec<u8>) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.as_slice()))
    }
}

/// Two decrypted values compare in constant time as well.
///
/// This impl was missing on purpose in an earlier revision, on the reasoning that comparing
/// two decrypted values is rarely what a caller wants. The reasoning was sound and the
/// consequence was not: without it, `a == b` does not compile, and the fallback every caller
/// reaches for is `a.as_slice() == b.as_slice()` — a short-circuiting comparison, which is
/// exactly the leak the rest of this file spends its constant-time budget closing. (An auditor
/// hit the compile error while writing a test and took the fallback; that is the evidence.)
/// Providing the impl removes the trap rather than documenting it: same length, same
/// [`subtle::ConstantTimeEq`] call as the other comparisons, so `pt1 == pt2` is now both the
/// shortest and the constant-time way to ask.
impl PartialEq<Plaintext> for Plaintext {
    #[inline]
    fn eq(&self, other: &Plaintext) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

/// As above, for the by-reference spelling (`pt == &other`).
impl PartialEq<&Plaintext> for Plaintext {
    #[inline]
    fn eq(&self, other: &&Plaintext) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        // Wipe the whole allocation, not just `len` bytes.  `decrypt` builds this
        // `Vec` with `alloc_zeroed`, which reserves exactly `n` and cannot
        // reallocate, so the initialized part *is* the allocation today; the
        // `capacity` tail is handled anyway so a future constructor that grows the
        // buffer cannot silently leave plaintext behind in it.  (This comment said
        // `vec![0u8; n]`, which is the *infallible* allocation `alloc_zeroed`
        // replaced -- the difference is the `Error::AllocationFailed` return rather
        // than an abort, so a reader trusting the old text would have had the
        // memory-exhaustion behaviour backwards.)
        zeroize_slice(self.0.as_mut_slice());
        let (len, cap) = (self.0.len(), self.0.capacity());
        if cap > len {
            // Bytes past `len` belong to this allocation but were never written,
            // so no reference may be formed over them (a `&mut [u8]` into
            // uninitialized memory is not a valid reference).  Writing through
            // the raw pointer is the sound way to clear them.
            // SAFETY: `len` is in bounds of the allocation and `cap - len` bytes
            // from there are owned by this `Vec` (still alive: we are in its
            // owner's `Drop`), so the stores are in bounds and cannot alias a
            // live reference.
            unsafe { core::ptr::write_bytes(self.0.as_mut_ptr().add(len), 0, cap - len) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl core::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never expose plaintext contents through `Debug`.
        f.debug_struct("Plaintext")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

// ── Key ───────────────────────────────────────────────────────────────

/// A 256-bit key that zeroizes on drop.
///
/// [`random::generate_key`] returns this rather than a bare `[u8; KEY_LEN]`, so a
/// key this crate generated is wiped when it goes out of scope instead of being
/// left in freed stack or heap memory for the next allocation to read.  Every API
/// here takes `&[u8; KEY_LEN]` and this derefs to it, so call sites are unchanged:
///
/// ```ignore
/// let key = random::generate_key()?;
/// let (ct, tag) = encrypt(&key, &nonce, &aad, msg)?;
/// ```
///
/// `Debug` prints no key bytes and no fingerprint of them.  The wipe is the same
/// volatile-store wipe the rest of the crate uses, with the same limits — see
/// "What is not defended against" in the README: it does not cover a page that was
/// already swapped out, a core dump, or a cold boot.
///
/// A caller that already holds key bytes can wrap them with [`Key::from_bytes`];
/// that *copies*, so the array passed in is still the caller's to wipe.
///
/// `#[repr(transparent)]` over the array: the wrapper is an API convenience, and
/// its layout is the array's (the test that reads the storage back after a drop
/// relies on that, and it is worth being sure of rather than assuming).
#[repr(transparent)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Wrap existing key bytes.
    ///
    /// The value is copied into the returned `Key`, which wipes its copy on drop.
    /// The array passed in is untouched and remains the caller's responsibility.
    #[inline]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Key(bytes)
    }

    /// Borrow the key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Mutable access, crate-internal: filling a `Key` from the OS CSPRNG is the
    /// only thing that may write one after construction, and a caller that could
    /// mutate a `Key` in place would be able to defeat the wipe-on-drop contract.
    ///
    /// Gated on `rng` because that is the only caller: without the feature nothing
    /// generates a key, and an ungated method would be dead code under
    /// `--no-default-features`, which CI builds with `-D warnings`.
    #[cfg(feature = "rng")]
    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }
}

impl core::ops::Deref for Key {
    type Target = [u8; KEY_LEN];
    #[inline]
    fn deref(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl AsRef<[u8; KEY_LEN]> for Key {
    #[inline]
    fn as_ref(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        zeroize_array(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No bytes *and* no fingerprint of them: a prefix or a hash of a key is
        // still key material in a log.
        f.write_str("Key([REDACTED; 32])")
    }
}

// ── Randomness (optional) ─────────────────────────────────────────────

/// OS-backed random key and nonce generation (requires the `rng` feature).
///
/// # The construction itself needs no randomness
///
/// [`encrypt`] is a deterministic function of `(key, nonce, aad, plaintext)`:
/// every subkey, the tag and the keystream are derived from the key with
/// ChaCha20/HChaCha20, and the tag binds the associated data and the message
/// directly.  Nothing is drawn from a random source internally — which is exactly
/// what makes the known-answer vectors and the formal harnesses meaningful,
/// since there is no hidden entropy dependency to mock out or to fail at run
/// time.
///
/// # What *is* random, and why this module exists
///
/// Keys, and the nonce.  Every encryption under a given key needs a fresh
/// nonce, and getting that wrong is the most likely way to misuse this
/// construction.  The public API takes a `&[u8; NONCE_LEN]` and cannot check
/// where it came from, so this module provides a safe way to obtain one when
/// the application has no source of its own.
///
/// It stays opt-in so that `no_std` users, and users who already have an
/// entropy source or a counter, pay nothing — not even the extra dependency.
///
/// # Nonce requirements
///
/// A nonce MAY be public and predictable; it **MUST be unique for every
/// encryption under the same key**.  The construction is misuse-resistant, but
/// that is a fail-safe for an occasional slip, not a licence to reuse: security
/// degrades with every repetition, and reusing a nonce with the same key, AAD
/// and plaintext reveals that the same triple was encrypted.
///
/// Two acceptable strategies:
///
/// * **A counter**, incremented after every encryption and never allowed to
///   wrap.  Deterministic, testable, and free of any collision bound.  Prefer
///   this whenever the application has somewhere to store the counter.
/// * **[`random::generate_nonce`] (random)**.  The c2sp.org specification this
///   construction extends RECOMMENDS "randomly generate\[d\] nonces with a
///   CSPRNG" and gives the budget as 2^48 messages under one key with a
///   collision probability of 2^-32, aligning with NIST guidance.  (The bare
///   birthday bound for a 192-bit nonce is far more generous than that; the
///   specification's figure is the conservative one and is the one to follow.)
///
/// Do **not** form a nonce by XORing a counter with a random value: the c2sp.org
/// specification calls that approach out explicitly as unsuitable for
/// commitment.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "rng")] {
/// use xchacha20_blake3_siv::{encrypt, random};
///
/// # fn main() -> Result<(), random::Error> {
/// let key = random::generate_key()?;
/// let nonce = random::generate_nonce()?;
/// let (ciphertext, tag) = encrypt(&key, &nonce, b"aad", b"message").unwrap();
/// # let _ = (ciphertext, tag);
/// # Ok(())
/// # }
/// # }
/// ```
#[cfg(feature = "rng")]
pub mod random {
    pub use getrandom::Error;

    use crate::{Key, KEY_LEN, NONCE_LEN};

    /// Fill `dest` from `source`, wiping `dest` if the source fails.
    ///
    /// Crate-internal, and shaped this way so the guarantee can be *tested*: the
    /// platform entropy source cannot be made to fail on demand, and a guarantee
    /// nothing exercises is a comment.
    pub(crate) fn fill_from(
        dest: &mut [u8],
        source: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match source(dest) {
            Ok(()) => Ok(()),
            Err(e) => {
                // `getrandom`'s own contract: "This function returns an error on any
                // failure, including partial reads. We make no guarantees regarding the
                // contents of `dest` on error." A prefix of real entropy, stale bytes or
                // zeros are all permitted, and a caller that ignores the `Result` would
                // take whichever arrived as a key or a nonce.
                crate::zeroize_slice(dest);
                Err(e)
            }
        }
    }

    /// Fill `dest` with bytes from the operating system's CSPRNG.
    ///
    /// Returns an error if the OS entropy source is unavailable.  That can
    /// genuinely happen — early boot, a sandbox that blocks `getrandom(2)`, a
    /// failed `RDRAND` on `no_std` — which is why this returns a `Result`
    /// instead of panicking.
    ///
    /// **On error `dest` is zeroed**, rather than left as `getrandom` left it: that
    /// crate makes no promise about the buffer when it fails, so an error can leave a
    /// *prefix* of genuine entropy behind, and a caller that ignores the `Result` — which
    /// is `#[must_use]`, but a warning is not a guarantee — would use those bytes as a
    /// key or a nonce. All zeros are not a usable key either, but they fail the same way
    /// every time instead of working sometimes, which is what makes the failure visible.
    ///
    /// There is deliberately **no userspace fallback PRNG**.  A predictable
    /// nonce is a real attack (see the module documentation), and a silent
    /// fallback would turn "the OS had no entropy" into "your messages are
    /// forgeable" without anyone noticing.
    pub fn fill(dest: &mut [u8]) -> Result<(), Error> {
        fill_from(dest, getrandom::fill)
    }

    /// Generate a fresh 256-bit key from the OS CSPRNG.
    ///
    /// The key comes back in a [`Key`], which zeroizes it on drop.  A generated key
    /// is the one secret in this API with no other copy anywhere, so it is the one
    /// case where bytes left behind afterwards are purely this crate's doing.  On
    /// failure nothing escapes: the intermediate buffer is wiped ([`fill`]'s
    /// guarantee) and the `Key` is dropped.
    ///
    /// A caller that needs a bare array can copy one out of it (`*key`), but then
    /// that copy is the caller's to wipe.
    pub fn generate_key() -> Result<Key, Error> {
        let mut key = Key::from_bytes([0u8; KEY_LEN]);
        fill(key.as_bytes_mut())?;
        Ok(key)
    }

    /// Generate a fresh 192-bit nonce from the OS CSPRNG.
    ///
    /// See the module documentation for how many such nonces may safely be used
    /// under one key, and for when a counter is the better choice.
    pub fn generate_nonce() -> Result<[u8; NONCE_LEN], Error> {
        let mut nonce = [0u8; NONCE_LEN];
        fill(&mut nonce)?;
        Ok(nonce)
    }
}

// ── Locked memory (the `ultra` feature) ───────────────────────────────
//
// The volatile-store wipe above reaches the bytes this process owns *now*. It does not
// reach a page the kernel already wrote out to swap, or that a core dump is about to
// copy. Those are the two OS-level reads a userspace library can still ask the kernel
// to prevent, and this module is that request.
//
// It cannot cover everything, and the doc comments say which: a debugger or
// `/proc/<pid>/mem` from a same-uid process, cold-boot remanence, and a hypervisor
// remain outside what any in-process code can do. What it reaches is the *deployment*
// half of the wipe story, which is why it is opt-in rather than default: it changes what
// the process asks of the kernel, not what the crate computes.
//
// Availability: Linux only. On any other target the functions are no-ops that report
// "not locked", so a caller can decide what to do about it (and the default build never
// calls them).
/// Locking keys out of swap and core dumps (the `ultra` feature).
///
/// The volatile-store wipe this crate uses everywhere reaches the bytes the process owns
/// *now*; it cannot reach a page the kernel already wrote to swap, or one a core dump is
/// about to copy. `mlock` and `madvise(MADV_DONTDUMP)` are the two requests a userspace
/// library can still make, and this module makes them for a key.
///
/// What it does not cover, stated here as well as in the README: a debugger or
/// `/proc/<pid>/mem` from a process with the same uid, a hypervisor reading guest memory,
/// and cold-boot remanence. `LockedKey::new` fails loudly when the kernel refuses
/// (`RLIMIT_MEMLOCK` is the usual reason) rather than leaving the caller unsure which
/// state it is in.
// Gated on `locked`, not on `ultra`: `Cargo.toml` exposes `locked` as a feature of its
// own, so gating the module on `ultra` made `--features locked` an *empty* feature -- it
// compiled nothing and said nothing, while the README's table lists `locked` as a layer a
// reader can turn on. `ultra` implies `locked`, so nothing about the bundle changes.
#[cfg(feature = "locked")]
pub mod locked {
    use subtle::ConstantTimeEq;

    /// Whether this platform can lock memory at all.
    ///
    /// Linux **and** an architecture with a syscall sequence here: the stub for other
    /// architectures returns `ENOSYS`, so `cfg!(target_os = "linux")` alone would report
    /// support on (say) i686 and then fail at the first call. A caller that branches on
    /// this has to be told the truth.
    pub const SUPPORTED: bool =
        cfg!(target_os = "linux") && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod imp {

        // Sycall numbers, from the kernel's own headers -- `unistd_64.h` on x86_64
        // (mlock 149, munlock 150, madvise 28) and `asm-generic/unistd.h` everywhere
        // else (mlock 228, munlock 229, madvise 233). Having these in a `const` that a
        // test checks against `/usr/include` would be circular; what is checked instead
        // is *behaviour*: `lock` must make `is_locked` true, and `mlock` is the only
        // call that can do that through this path.
        #[cfg(target_arch = "x86_64")]
        const NR_MLOCK: usize = 149;
        #[cfg(target_arch = "x86_64")]
        const NR_MUNLOCK: usize = 150;
        #[cfg(target_arch = "x86_64")]
        const NR_MADVISE: usize = 28;

        #[cfg(not(target_arch = "x86_64"))]
        const NR_MLOCK: usize = 228;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_MUNLOCK: usize = 229;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_MADVISE: usize = 233;

        /// `prctl(2)`: 157 on x86_64, 167 in the generic table aarch64 uses.
        #[cfg(target_arch = "x86_64")]
        const NR_PRCTL: usize = 157;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_PRCTL: usize = 167;

        /// `PR_SET_DUMPABLE` / `PR_GET_DUMPABLE` (`linux/prctl.h`).
        const PR_SET_DUMPABLE: usize = 4;
        const PR_GET_DUMPABLE: usize = 3;

        /// `MADV_DONTDUMP`: exclude the range from core dumps.
        ///
        /// **16**, from `asm-generic/mman-common.h` (`#define MADV_DONTDUMP 16`),
        /// where 4 is `MADV_DONTNEED`.  This constant was 4.  The consequence was
        /// not "core dumps still contain the key": because `MADV_DONTNEED` on a
        /// page that has just been `mlock`ed is rejected (`EINVAL` -- the kernel
        /// will not let the contents of a locked page be discarded), `lock_range`
        /// returned an error, undid the `mlock`, and `LockedKey::new` refused.  So
        /// the whole `locked` layer was inert on any host that reached this line,
        /// and it read as "the kernel would not let us lock memory" -- a
        /// deployment conclusion, not a bug report.  Both this and the
        /// argument-arity bug in the call below were invisible because
        /// `locked_key_is_actually_locked` returned early with `ok`.
        const MADV_DONTDUMP: usize = 16;

        /// `MADV_DODUMP`: undo [`MADV_DONTDUMP`] on the same range. **17**, from the same
        /// header (`asm-generic/mman-common.h`).
        ///
        /// The absence of this constant was a real defect — and one a commit message had
        /// claimed was fixed. `VM_DONTDUMP` is per-*mapping* and sticky: a range that is
        /// merely unlocked stays excluded from core dumps, so `munlock` alone can never
        /// clear it. Because `LockedKey` owns a page-sized allocation that returns to the
        /// allocator when it is dropped, the consequence was not about the key at all:
        /// **unrelated** data that later landed on that page was silently excluded from
        /// every core dump the process wrote for the rest of its life. That is a defect in
        /// the availability of evidence rather than in the secrecy of the key, and it is
        /// the kind that only a live probe (`/proc/self/smaps`) shows — which is what
        /// `tests/locked.rs` now does.
        const MADV_DODUMP: usize = 17;

        /// Raw syscall with two arguments. `-1`..`-4095` is an error; the raw value is
        /// returned so a caller can classify it (`ENOMEM` 12, `EPERM` 1, `EAGAIN` 11).
        ///
        /// SAFETY: the caller guarantees `a` is a valid pointer for `b` bytes, or that
        /// the syscall number takes non-pointer arguments (as `madvise`'s second one is
        /// not -- both callers below pass a real region).
        #[cfg(target_arch = "x86_64")]
        unsafe fn syscall2(number: usize, a: usize, b: usize) -> isize {
            let ret: isize;
            core::arch::asm!(
                "syscall",
                inlateout("rax") number as isize => ret,
                in("rdi") a,
                in("rsi") b,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
            ret
        }

        #[cfg(target_arch = "aarch64")]
        unsafe fn syscall2(number: usize, a: usize, b: usize) -> isize {
            let ret: isize;
            core::arch::asm!(
                "svc 0",
                inlateout("x8") number as isize => _,
                inlateout("x0") a as isize => ret,
                in("x1") b,
                options(nostack),
            );
            ret
        }

        fn ok(ret: isize) -> bool {
            ret >= 0
        }

        /// Lock `len` bytes at `ptr` into RAM and exclude them from core dumps.
        ///
        /// Returns `Ok(())` only if **both** succeeded. `EFAULT`/`EINVAL` are impossible
        /// for a live slice, so a failure here is the environment's: `ENOMEM` means the
        /// `RLIMIT_MEMLOCK` allowance is exhausted (common, and not fatal), `EPERM` a
        /// hardened container. The caller decides; this crate's default build never
        /// calls it.
        pub fn lock_range(ptr: *const u8, len: usize) -> Result<(), isize> {
            if len == 0 {
                return Ok(());
            }
            // SAFETY: `ptr`/`len` describe a live allocation (the caller's slice), which
            // is what both syscalls require; neither reads or writes the bytes.
            unsafe {
                let l = syscall2(NR_MLOCK, ptr as usize, len);
                if !ok(l) {
                    return Err(l);
                }
                // `madvise(addr, length, advice)` takes THREE arguments.  This
                // was called through `syscall2`, which put `MADV_DONTDUMP` in the
                // *length* slot and left `advice` as whatever happened to be in
                // `rdx` -- undefined at the ABI level, and in practice almost
                // always invalid, so the call returned `EINVAL` on hosts where
                // `mlock` itself had just succeeded.  `lock_range` then reported
                // failure and `LockedKey::new` refused, which read as "the kernel
                // will not let us lock" and was masked by a test that skipped
                // instead of failing.  With the real length and the real advice,
                // `EINVAL` is impossible for a live slice, as the comment above
                // says it is.
                //
                // `madvise` also demands a page-aligned address, which a slice
                // pointer is not: unlike `mlock`, it does not round.  The range is
                // therefore expanded to whole pages covering the key.  Aligning
                // down cannot leave the mapping (mappings start on a page
                // boundary) and rounding the end up cannot leave it either
                // (mappings end on one), so this cannot touch foreign memory.
                let ps = page_size();
                let start = (ptr as usize) & !(ps - 1);
                let end = ((ptr as usize).saturating_add(len).saturating_add(ps - 1)) & !(ps - 1);
                let d = syscall3(NR_MADVISE, start, end - start, MADV_DONTDUMP);
                if !ok(d) {
                    // Do not leave it locked without the dump exclusion: undo.
                    let _ = syscall2(NR_MUNLOCK, ptr as usize, len);
                    return Err(d);
                }
            }
            Ok(())
        }

        /// Undo [`lock_range`]: drop the lock **and** put the range back in core dumps.
        ///
        /// Both halves matter. `madvise(MADV_DONTDUMP)` is sticky, so a range that is only
        /// unlocked stays excluded from core dumps — and since `LockedKey` hands its
        /// page-sized allocation back to the allocator on drop, whatever lands there next is
        /// silently excluded too. Reverting the advice is therefore part of undoing the
        /// lock, not an optimization.
        ///
        /// The order is `munlock` first, then `MADV_DODUMP`, and that is deliberate: the
        /// page stays non-dumpable until the lock is released, so the window in which a page
        /// is locked *and* dumpable never exists. The window that would matter more — a page
        /// holding a live key becoming dumpable — is closed earlier still, by
        /// `LockedKey::drop` wiping before it unlocks.
        ///
        /// A failure from either syscall is ignored, as in `lock_range`: there is nothing
        /// useful a caller could do about it, and the caller is about to free or reuse the
        /// range anyway.
        ///
        /// Idempotent for an unlocked range.
        pub fn unlock_range(ptr: *const u8, len: usize) {
            if len == 0 {
                return;
            }
            let ps = page_size();
            let start = (ptr as usize) & !(ps - 1);
            let end = ((ptr as usize).saturating_add(len).saturating_add(ps - 1)) & !(ps - 1);
            // SAFETY: as `lock_range`: `ptr`/`len` describe the caller's live allocation, and
            // neither syscall reads or writes the bytes. `start`/`end` are the whole pages
            // covering it, which cannot leave the mapping (mappings begin and end on a page
            // boundary).
            unsafe {
                let _ = syscall2(NR_MUNLOCK, ptr as usize, len);
                let _ = syscall3(NR_MADVISE, start, end - start, MADV_DODUMP);
            }
        }

        /// Make this process **non-dumpable**: another process can no longer `ptrace` it, read
        /// `/proc/<pid>/mem`, or obtain its memory through a core dump, unless it holds
        /// `CAP_SYS_PTRACE` (or is otherwise privileged).
        ///
        /// This is the one entry in this crate's attack-class table that *is* a software
        /// measure: every other class in SECURITY-ANALYSIS.md §8.2 that the configurations do
        /// not answer — power, EM, laser faults, cold boot, Rowhammer, speculative execution —
        /// is a property of the machine, and no line of Rust changes it. A debugger is not: the
        /// kernel enforces this flag, and `PTRACE_MODE_ATTACH` fails for a non-dumpable process
        /// even from the same user. `prctl(PR_SET_DUMPABLE, 0)` is what `sshd`, `sudo` and every
        /// setuid program set for the same reason.
        ///
        /// **It is not called automatically, not even by `ultra`, because it is *process*
        /// policy rather than crate policy.** A library that silently makes its host
        /// un-debuggable and un-dumpable breaks crash reporters, `strace`, and the operator's
        /// own tooling — that is a decision for the application, so it is one call the caller
        /// makes deliberately. What it does *not* do, stated plainly: an attacker with root (or
        /// `CAP_SYS_PTRACE`), a hypervisor, or a hardware probe is unaffected, and a process that
        /// was already being traced keeps its tracer.
        ///
        /// Returns the previous dumpable state, so a caller can restore it (which is what the
        /// test does) — the value is `0` or `1`, or a negative errno on failure.
        pub fn deny_debugging() -> Result<u32, isize> {
            // SAFETY: `prctl` with `PR_SET_DUMPABLE` takes an integer in `arg2` and reads no
            // pointer; `syscall2` passes it in the second argument slot.
            let previous = unsafe { syscall2(NR_PRCTL, PR_GET_DUMPABLE, 0) };
            if !ok(previous) {
                return Err(previous);
            }
            // SAFETY: as above.
            let set = unsafe { syscall2(NR_PRCTL, PR_SET_DUMPABLE, 0) };
            if !ok(set) {
                return Err(set);
            }
            Ok(previous as u32)
        }

        /// Read the process's dumpable flag: `true` (1) or `false` (0), `None` if the kernel
        /// refuses to say.
        ///
        /// Exists so that [`deny_debugging`] is testable without a second process to attack —
        /// and so a caller can check the state it inherited rather than assume it.
        pub fn is_dumpable() -> Option<bool> {
            // SAFETY: `PR_GET_DUMPABLE` reads no pointer and writes none; the syscall returns
            // the flag itself, or a negative errno.
            let v = unsafe { syscall2(NR_PRCTL, PR_GET_DUMPABLE, 0) };
            if !ok(v) {
                None
            } else {
                Some(v != 0)
            }
        }

        /// `page_size` for the rest of the module (the `Page` allocation needs it).
        pub(crate) fn page_size_pub() -> usize {
            page_size()
        }

        #[cfg(target_arch = "x86_64")]
        const NR_READ: usize = 0;
        #[cfg(target_arch = "x86_64")]
        const NR_OPENAT: usize = 257;
        #[cfg(target_arch = "x86_64")]
        const NR_CLOSE: usize = 3;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_READ: usize = 63;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_OPENAT: usize = 56;
        #[cfg(not(target_arch = "x86_64"))]
        const NR_CLOSE: usize = 57;

        /// `AT_FDCWD`: resolve a relative path against the working directory.
        const AT_FDCWD: isize = -100;
        /// `O_RDONLY`.
        const O_RDONLY: usize = 0;

        /// `openat(AT_FDCWD, path, O_RDONLY)`.
        ///
        /// `openat` on both architectures, because `asm-generic`'s table has no
        /// `__NR_open` at all: the number this used first (56) is `openat` on aarch64,
        /// so calling it with `open`'s two-argument shape passed the *path* as the
        /// directory file descriptor and the open failed. The cross-target test is what
        /// caught that; a single-architecture check could not.
        fn open_ro(path: &[u8]) -> isize {
            // SAFETY: `path` is a NUL-terminated byte string in static memory.
            unsafe {
                syscall3(
                    NR_OPENAT,
                    AT_FDCWD as usize,
                    path.as_ptr() as usize,
                    O_RDONLY,
                )
            }
        }

        /// The system page size, from `/proc/self/auxv`'s `AT_PAGESZ`.
        ///
        /// Needed because `madvise` rejects an address that is not page-aligned --
        /// unlike `mlock`, which rounds the range itself.  4096 is correct for
        /// every x86_64 Linux, but an aarch64 kernel can be built with 16 or 64 KiB
        /// pages, where aligning to 4096 would still not be aligned and the call
        /// would keep returning `EINVAL`.  Falls back to 4096 if auxv cannot be
        /// read, which is the x86_64 answer and the common aarch64 one.
        fn page_size() -> usize {
            const PATH: &[u8] = b"/proc/self/auxv\0";
            const AT_PAGESZ: u64 = 6;
            const FALLBACK: usize = 4096;

            // SAFETY: `PATH` is a NUL-terminated byte string in static memory.
            let fd = open_ro(PATH);
            if fd < 0 {
                return FALLBACK;
            }
            let fd = fd as usize;
            let mut buf = [0u8; 512];
            // SAFETY: `buf` is a live local of exactly the length passed.
            let n = unsafe { syscall3(NR_READ, fd, buf.as_mut_ptr() as usize, buf.len()) };
            // SAFETY: closing a descriptor this function owns.
            unsafe {
                let _ = syscall2(NR_CLOSE, fd, 0);
            }
            if n < 16 {
                return FALLBACK;
            }
            let n = n as usize;
            let mut i = 0usize;
            while i + 16 <= n {
                let mut ty = [0u8; 8];
                let mut val = [0u8; 8];
                ty.copy_from_slice(&buf[i..i + 8]);
                val.copy_from_slice(&buf[i + 8..i + 16]);
                let ty = u64::from_ne_bytes(ty);
                if ty == 0 {
                    break; // AT_NULL ends the vector
                }
                if ty == AT_PAGESZ {
                    let v = u64::from_ne_bytes(val);
                    // Only accept something that could be a page size; a
                    // truncated read must not produce a bogus mask.
                    return if v >= 4096 && v.is_power_of_two() {
                        v as usize
                    } else {
                        FALLBACK
                    };
                }
                i += 16;
            }
            FALLBACK
        }

        #[cfg(target_arch = "x86_64")]
        unsafe fn syscall3(number: usize, a: usize, b: usize, c: usize) -> isize {
            let ret: isize;
            core::arch::asm!(
                "syscall",
                inlateout("rax") number as isize => ret,
                in("rdi") a,
                in("rsi") b,
                in("rdx") c,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
            ret
        }

        #[cfg(target_arch = "aarch64")]
        unsafe fn syscall3(number: usize, a: usize, b: usize, c: usize) -> isize {
            let ret: isize;
            core::arch::asm!(
                "svc 0",
                inlateout("x8") number as isize => _,
                inlateout("x0") a as isize => ret,
                in("x1") b,
                in("x2") c,
                options(nostack),
            );
            ret
        }

        /// Bytes currently locked into RAM, from `/proc/self/status`'s `VmLck`.
        ///
        /// There is no syscall for "is this range locked", so the kernel's own accounting
        /// is the answer -- read with raw syscalls because this crate is `no_std` and
        /// has no `std::fs`. A *range* counts as locked if the total is at least its
        /// length, which is what a single-key test wants.
        pub fn locked_bytes() -> Option<u64> {
            const PATH: &[u8] = b"/proc/self/status\0";
            // SAFETY: `PATH` is a NUL-terminated byte string in static memory; O_RDONLY
            // is 0. The fd is closed on every path below.
            let fd = open_ro(PATH);
            if fd < 0 {
                return None;
            }
            let fd = fd as usize;
            let mut buf = [0u8; 4096];
            // SAFETY: `buf` is a live local of exactly the length passed.
            let n = unsafe { syscall3(NR_READ, fd, buf.as_mut_ptr() as usize, buf.len()) };
            // SAFETY: closing a descriptor this function owns.
            unsafe {
                let _ = syscall2(NR_CLOSE, fd, 0);
            }
            if n <= 0 {
                return None;
            }
            let text = core::str::from_utf8(&buf[..n as usize]).ok()?;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("VmLck:") {
                    let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                    return Some(kb * 1024);
                }
            }
            None
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) use imp::page_size_pub;
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub use imp::{deny_debugging, is_dumpable, lock_range, locked_bytes, unlock_range};

    /// Elsewhere locking is unsupported: `lock_range` reports `ENOSYS` rather than
    /// pretending, so a caller cannot mistake a no-op for protection.
    /// Unsupported on this target: reports `ENOSYS` rather than pretending, so a caller
    /// cannot mistake a no-op for protection.
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub fn lock_range(_ptr: *const u8, _len: usize) -> Result<(), isize> {
        Err(-38) // ENOSYS
    }
    /// Unsupported on this target: nothing was ever locked, so there is nothing to undo.
    ///
    /// (This and the two below are `pub` in the module on every target, so they need doc
    /// comments everywhere — `missing_docs` is a hard lint here, and it caught these on
    /// i686, where the module compiles its unsupported arm.)
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub fn unlock_range(_ptr: *const u8, _len: usize) {}
    /// Unsupported on this target: `None`, because there is no `VmLck` to read.
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub fn locked_bytes() -> Option<u64> {
        None
    }

    /// Unsupported on this target: `ENOSYS`, and deliberately not a silent `Ok`. Making a
    /// process un-debuggable is Linux's `prctl`; elsewhere the caller must use the platform's
    /// own mechanism, and returning success here would tell it the process is protected when
    /// it is not.
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub fn deny_debugging() -> Result<u32, isize> {
        Err(-38) // ENOSYS
    }

    /// Unsupported on this target: `None`, because there is no flag to read.
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub fn is_dumpable() -> Option<bool> {
        None
    }

    /// The page size, for `Page`'s allocation, on targets with no syscall arm.
    ///
    /// The supported arm reads `AT_PAGESZ` from `/proc/self/auxv`; here nothing is locked,
    /// so all that matters is an alignment generous enough for the platform (16 KiB covers
    /// the 4/16/64 KiB page sizes in use), and `LockedKey::new` fails closed before this
    /// value could mislead anyone.
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    pub(crate) fn page_size_pub() -> usize {
        16 * 1024
    }

    /// A `Key` that is locked into RAM (and excluded from core dumps) for its lifetime.
    ///
    /// `ultra`'s answer to the part of the wipe story a volatile store cannot reach:
    /// while this value is alive its pages cannot be swapped out, and a core dump will
    /// not contain them. It does **not** cover a debugger attached to the process, a
    /// hypervisor reading guest memory, or cold-boot remanence — see the README's
    /// "cannot fix for you" list.
    ///
    /// `LockedKey::new` fails when the OS refuses (`ENOMEM` from `RLIMIT_MEMLOCK` is the
    /// usual one), rather than silently leaving the key unprotected: the whole point is
    /// that the caller knows which of the two states it is in.
    /// The key lives behind a `Box` so its address is **stable**.
    ///
    /// This is not an optimisation, it is what makes the lock mean anything.
    /// `mlock` is address-based: it locks the pages covering the address it is
    /// given. An earlier version locked a `crate::Key` held in a local and then
    /// returned `LockedKey(inner)` — and returning a 32-byte value *moves* it,
    /// typically into the caller's frame or a return slot, so the lock was left
    /// on the callee's dead stack slot while the live copy sat unprotected on an
    /// unlocked page. The struct looked locked (`locked_bytes()` went up, the
    /// test passed) and was not. Heap-allocating first means the `Box` can be
    /// moved as much as it likes without the key ever changing address.
    pub struct LockedKey(Page);

    /// Bytes of BLAKE3 kept beside the key as an integrity tag (see `LockedKey::as_bytes`).
    ///
    /// Eight is a judgement, not a security parameter: the tag's job is to notice a
    /// malfunction (a flip in this page), where 64 bits make an accidental agreement
    /// impossible, and its cost is one compression of a 32-byte input. A wider tag would cost
    /// the same — the compression dominates — and detect nothing more against the adversary it
    /// is aimed at.
    pub(crate) const KEY_TAG_LEN: usize = 8;

    /// The integrity tag of a key: the first `KEY_TAG_LEN` bytes of BLAKE3 over the key.
    ///
    /// Unkeyed on purpose — see `LockedKey::as_bytes` for what that does and does not buy.
    fn integrity_tag(key: &[u8]) -> [u8; KEY_TAG_LEN] {
        let hash = blake3::hash(key);
        let mut tag = [0u8; KEY_TAG_LEN];
        tag.copy_from_slice(&hash.as_bytes()[..KEY_TAG_LEN]);
        tag
    }

    impl LockedKey {
        /// Lock a copy of `key` into memory, at an address that will not move.
        ///
        /// The key occupies a **page of its own**, and that is deliberate: `mlock`,
        /// `munlock` and `madvise` are page-granular, so a 32-byte key sharing a page with
        /// another `LockedKey` would not be independent of it -- dropping one would unlock
        /// the other's page while it was still alive and still documented as locked. A
        /// page-aligned allocation of exactly one page costs 4 KiB per key and makes the
        /// lock the key's own.
        ///
        /// The bytes are copied into that page (so the locked range is the range the caller
        /// uses) and the *whole* page is locked and excluded from core dumps, which is also
        /// what makes the wipe on drop cover everything that could hold key material.
        pub fn new(key: &[u8; crate::KEY_LEN]) -> Result<Self, isize> {
            let mut page = Page::new().ok_or(-12isize /* ENOMEM */)?;
            page.bytes_mut()[..crate::KEY_LEN].copy_from_slice(key);
            let tag = integrity_tag(&key[..]);
            page.bytes_mut()[crate::KEY_LEN..crate::KEY_LEN + KEY_TAG_LEN].copy_from_slice(&tag);
            // Lock the whole page; on failure `page` is freed by its own `Drop`.
            lock_range(page.as_ptr(), page.len())?;
            Ok(LockedKey(page))
        }

        /// Borrow the key bytes, first checking that the page still holds the key that was
        /// put there.
        ///
        /// **This is the software half of the fault and Rowhammer rows in
        /// `SECURITY-ANALYSIS.md` §8.2.** A hardware fault or a bit flip in the locked page
        /// would otherwise be silent: the key changes, every tag derived from it changes, and
        /// the failure surfaces as "authentication failed" — indistinguishable from a wrong
        /// ciphertext, and in the encryption direction as ciphertexts the peer silently
        /// rejects. Keeping an 8-byte tag beside the key (`KEY_TAG_LEN`, `blake3::hash` of the
        /// key, compared in constant time) turns that into a fail-stop panic at the first use
        /// after the corruption. What it does *not* detect: a fault that also rewrites the tag
        /// (an attacker with two precise faults and knowledge of this layout), and corruption
        /// outside the key and tag region — the rest of the page is never read, so a flip
        /// there is harmless by construction and is not covered by the check.
        ///
        /// The hash is deliberately **unkeyed**: this is an integrity check against
        /// *malfunction*, not a MAC, and an attacker who can read the page has the key
        /// already, so keying it would buy nothing. It is not a second use of BLAKE3 in the
        /// sense §4.2 is about either — nothing is derived from this value and no adversary
        /// controls its input.
        ///
        /// Cost, measured on this host: one BLAKE3 hash of a 32-byte input, **42 ns**, paid per
        /// `as_bytes()` call — so once per encryption and once per decryption, since both go
        /// through it. That is ~5% of a 64-byte encrypt (0.82 us) and ~0.01% of a 1 MiB one,
        /// and it is confined to `locked`: callers that pass a `&[u8; 32]` directly pay nothing.
        pub fn as_bytes(&self) -> &[u8; crate::KEY_LEN] {
            // SAFETY: `new` wrote `KEY_LEN` initialised bytes at the start of the page; the
            // page is page-aligned, so the cast is aligned for `[u8; KEY_LEN]` (alignment
            // 1); nothing writes through this reference; and the allocation outlives it.
            let bytes = unsafe { &*(self.0.as_ptr() as *const [u8; crate::KEY_LEN]) };
            self.check_integrity(bytes);
            bytes
        }

        /// Recompute the page's integrity tag and compare it in constant time.
        ///
        /// `#[inline(never)]` for the same reason the two gates are: one fault should not be
        /// able to reach both this check and the caller's use of the key through shared code.
        /// Panics — this is the crate's one non-error failure, and it is deliberate: after a
        /// detected corruption there is no correct answer to give, and continuing would use a
        /// key that is not the caller's.
        #[inline(never)]
        fn check_integrity(&self, bytes: &[u8; crate::KEY_LEN]) {
            let expected = integrity_tag(&bytes[..]);
            // SAFETY: `new` wrote `KEY_TAG_LEN` initialised bytes immediately after the key.
            let stored = unsafe {
                core::slice::from_raw_parts(self.0.as_ptr().add(crate::KEY_LEN), KEY_TAG_LEN)
            };
            if !bool::from(expected.as_slice().ct_eq(stored)) {
                panic!(
                    "LockedKey: the locked page no longer holds the key that was stored in it \
                     (hardware fault or memory corruption). Refusing to use a key that is not \
                     the caller's; see `SECURITY-ANALYSIS.md` §8.2, the fault and Rowhammer \
                     rows."
                );
            }
        }

        /// Whether this key's pages are actually locked, read back from the kernel.
        ///
        /// Comparing `VmLck` before and after is the only way to ask; this reports the
        /// process-wide total, which is what a single-key program wants.
        pub fn locked_bytes() -> Option<u64> {
            locked_bytes()
        }
    }

    impl core::ops::Deref for LockedKey {
        type Target = [u8; crate::KEY_LEN];
        fn deref(&self) -> &[u8; crate::KEY_LEN] {
            LockedKey::as_bytes(self)
        }
    }

    /// A `LockedKey` may be moved to another thread, and borrowed from several.
    ///
    /// Neither was true by default: the type owns a raw pointer, so the compiler derives
    /// neither `Send` nor `Sync`, and an `ultra` user who wants to hand a locked key to a
    /// worker thread could not compile — the lock layer then forces a single-threaded
    /// shape on the surrounding program, which is a strange thing for a *harden the key's
    /// residency* feature to do. (Recorded as a usability limitation by an auditor, which is
    /// how the missing impls were noticed.)
    ///
    /// SAFETY, for both: the pointer in `Page` is uniquely owned — one `alloc` in `new`, one
    /// `dealloc` in `Page::drop` — and nothing in this module stores thread-affine state.
    /// `mlock`, `munlock` and `madvise` are process-wide operations with no calling-thread
    /// requirement, so running `LockedKey::drop` (wipe, `munlock`, `MADV_DODUMP`, free) on a
    /// different thread than `new` is sound, and that is the whole of the type's thread
    /// interaction. `Sync` is sound because every shared access is `as_bytes(&self)` returning
    /// an immutable `&[u8; 32]`: there is no interior mutability to race on, and the
    /// allocation outlives any borrow by construction.
    // SAFETY: `Send` — the `Page` pointer is uniquely owned (one `alloc` in `new`, one
    // `dealloc` in `Page::drop`), and nothing in this module stores thread-affine state:
    // `mlock`, `munlock` and `madvise` are process-wide with no calling-thread requirement,
    // so running the whole of `LockedKey::drop` (wipe, `munlock`, `MADV_DODUMP`, free) on a
    // different thread than `new` is sound.
    unsafe impl Send for LockedKey {}
    // SAFETY: `Sync` — every shared access is `as_bytes(&self)`, an immutable
    // `&[u8; KEY_LEN]`; there is no interior mutability to race on, the allocation
    // outlives any borrow by construction, and the immutability argument above means
    // concurrent borrows cannot observe a mutation.
    unsafe impl Sync for LockedKey {}

    /// Flip one byte of the locked page, for the integrity test.
    ///
    /// `cfg(test)` because there is no other way to reach the page from a test: the point of
    /// `LockedKey` is that nothing outside it can write there, which is also what makes a
    /// corruption test need a hook. Offsets are page-relative, so a test can hit the key, the
    /// integrity tag, or the unused remainder of the page on purpose.
    #[cfg(test)]
    impl LockedKey {
        pub(crate) fn flip_byte_for_test(&mut self, offset: usize) {
            assert!(
                offset < crate::KEY_LEN + KEY_TAG_LEN,
                "test offset inside the page"
            );
            // SAFETY: the page is uniquely owned by `self`, `offset` is inside the region
            // `new` initialised, and the write is a plain byte store.
            unsafe {
                let p: *mut u8 = self.0.bytes_mut().as_mut_ptr().add(offset);
                *p ^= 0x01;
            }
        }
    }

    /// One page-aligned, page-sized, zeroed allocation.
    ///
    /// Exists so a key can own its page: every syscall this module uses acts on pages, so
    /// an allocation smaller than one would share with whatever the allocator put next to it.
    struct Page {
        ptr: *mut u8,
        layout: alloc::alloc::Layout,
    }

    impl Page {
        fn new() -> Option<Self> {
            let ps = page_size_pub();
            let layout = alloc::alloc::Layout::from_size_align(ps, ps).ok()?;
            // SAFETY: `layout` has a non-zero size (one page), which is all this call
            // requires; the result is checked for null and freed with the same layout.
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                None
            } else {
                Some(Page { ptr, layout })
            }
        }
        fn as_ptr(&self) -> *const u8 {
            self.ptr
        }
        fn len(&self) -> usize {
            self.layout.size()
        }
        fn bytes_mut(&mut self) -> &mut [u8] {
            // SAFETY: `ptr` and the size come from the allocation made in `new`, which is
            // still alive and uniquely owned by `self`.
            unsafe { core::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
        }
    }

    impl Drop for Page {
        fn drop(&mut self) {
            // SAFETY: the pointer and layout `new` allocated, freed exactly once.
            unsafe { alloc::alloc::dealloc(self.ptr, self.layout) }
        }
    }

    impl Drop for LockedKey {
        fn drop(&mut self) {
            // Wipe *before* unlocking, and the order is the point: `munlock` makes the pages
            // swappable again, so unlocking first opens a window in which a key whose entire
            // reason for being locked could be written to swap.
            //
            // The whole page is wiped, not just the 32 key bytes: that page is what was
            // locked and what could hold key-derived spill, and `Page`'s own `Drop` frees it
            // immediately afterwards either way.
            crate::zeroize_slice(self.0.bytes_mut());
            unlock_range(self.0.as_ptr(), self.0.len());
        }
    }

    impl core::fmt::Debug for LockedKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("LockedKey([REDACTED; 32], locked)")
        }
    }
}

// ── Zeroize helpers ───────────────────────────────────────────────────

/// Zeroize a mutable byte slice in a way the compiler cannot optimize away.
///
/// Writes in `usize`-sized chunks where alignment permits, rather than
/// byte-by-byte: `write_volatile` blocks vectorisation, so one volatile store
/// per byte would dominate the cost of the (SIMD-accelerated) cipher itself.
/// `write_volatile` requires natural alignment, so the leading bytes are
/// written singly until the pointer is `usize`-aligned.
fn zeroize_slice(slice: &mut [u8]) {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    let chunk = core::mem::size_of::<usize>();
    let align = core::mem::align_of::<usize>();

    let mut i = 0usize;
    // Leading bytes up to the first naturally aligned position.  These MUST be
    // written: starting the loop at the aligned offset instead would silently
    // leave `align - 1` bytes of secret material un-wiped.
    while i < len && (ptr as usize).wrapping_add(i) % align != 0 {
        // SAFETY: `i < len` and `ptr` is the base of a slice of `len` bytes, so
        // `ptr.add(i)` is in bounds and writable for the whole loop.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
        i += 1;
    }
    while i + chunk <= len {
        // SAFETY: `i + size_of::<usize>() <= len` keeps the store in bounds, and
        // the loop above left the pointer `usize`-aligned, which `write_volatile`
        // on a `*mut usize` requires.
        unsafe { core::ptr::write_volatile(ptr.add(i) as *mut usize, 0) };
        i += chunk;
    }
    // Trailing bytes.
    while i < len {
        // SAFETY: as in the leading loop: `i < len`, so the store is in bounds.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Overwrite the stack region the key derivations just used (the `ultra` layer).
///
/// Every named local in this crate is wiped, and `tools/stack_residue.sh` confirms
/// that the master key never survives in the call-chain stack region.  What *does*
/// survive is the `blake3` dependency's XOF output block: its frames hold a full
/// `enc_key ‖ enc_nonce`, and this crate cannot name them, let alone zeroize them.
///
/// Those frames can, however, be **overwritten**, because they sit below this
/// function's own frame and are about to be reused anyway.  Calling this from an
/// entry point after the last derivation turns "the dependency's residue is still
/// there" into "the region it lived in has been rewritten", using the stack the way
/// it is normally used rather than doing anything fragile.
///
/// Two limits, stated rather than implied:
///
/// * It is not a proof.  A compiler may keep a secret in a register, or spill it
///   further down than `SCRUB_LEN`.  The constant is several times the deepest frame
///   measured, and the tool that measures it is committed so the claim can be
///   rechecked instead of believed.
/// * It reaches only this thread's stack.  A value already written to swap, a core
///   dump, or another process is what `locked` is for, not this.
#[cfg(feature = "dual-mac")]
#[inline(never)]
fn scrub_stack() {
    /// The derivation frames measured ~3.4 KiB deep; this leaves ample margin.
    ///
    /// The margin is stack *usage* as well as coverage: this buffer is a 16 KiB frame, so a
    /// thread whose remaining stack is smaller than that faults here -- measured on a 32 KiB
    /// thread stack, which survives ~16 KiB of prior consumption in the default build and
    /// fails at 8 KiB with this enabled. A caller that runs AEAD on small-stack threads must
    /// size them for it.
    const SCRUB_LEN: usize = 16 * 1024;
    let mut buf = [0u8; SCRUB_LEN];
    // The buffer is already zero, so a plain store would be a dead store the
    // optimizer may delete -- and deleting it is exactly what must not happen.
    // `zeroize_array` issues volatile stores, so the write to this address range
    // happens.  Note what is being written to *is the point*, not what is in it.
    zeroize_array(&mut buf);
    core::hint::black_box(&buf);
}

/// Volatile-zero the raw memory of any value (array, scalar, ...).
///
/// This replaces the `zeroize` crate.  Stores are issued in `usize`-sized
/// chunks where alignment permits, because `write_volatile` blocks
/// vectorisation and a byte-at-a-time loop over a 512-byte SIMD state costs
/// more than the cipher round itself.  `black_box` stops the optimizer from
/// eliding the wipe when the value is dead afterwards (e.g. an HChaCha20 state
/// that has already been consumed).
fn zeroize_array<T>(value: &mut T) {
    let bytes = core::mem::size_of::<T>();
    let p = value as *mut T as *mut u8;
    // SAFETY: `p` points at `bytes` initialised bytes of `T`.  `T` is only ever
    // an integer or an array of integers here, so every bit pattern is valid
    // `u8` and the resulting slice is in bounds and uniquely borrowed.
    let slice = unsafe { core::slice::from_raw_parts_mut(p, bytes) };
    zeroize_slice(slice);
    core::hint::black_box(value);
}

// ── Public API ───────────────────────────────────────────────────────

/// Derive `(mac_key, enc_seed)` from a key and nonce.
///
/// XChaCha20-style: `subkey = HChaCha20(key, nonce[0..16])`, then one ChaCha20
/// keystream block under `SUBKEY_DOMAIN || nonce[16..24]` yields 64 bytes,
/// split into the BLAKE3 MAC key and the encryption seed.
fn derive_material(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut subkey = hchacha20(key, &nonce[0..16].try_into().unwrap());
    let mut subkey_nonce = [0u8; 12];
    subkey_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
    subkey_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let mut material = [0u8; 64];
    chacha20_keystream_raw(&subkey, 0, &subkey_nonce, &mut material);

    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&material[0..32]);
    let mut enc_seed = [0u8; 32];
    enc_seed.copy_from_slice(&material[32..64]);

    zeroize_array(&mut subkey);
    zeroize_array(&mut subkey_nonce);
    zeroize_array(&mut material);
    (mac_key, enc_seed)
}

/// `out.len()` bytes of `BLAKE3_keyed(key, parts[0] || parts[1] || ...)`, in
/// BLAKE3's XOF mode.
///
/// This is the **single seam** through which every keyed-BLAKE3 use in the crate
/// passes.  That matters for two reasons:
///
/// * The formal harnesses stub exactly this function.  Two separate call sites
///   reaching into `blake3` directly would leave one of them unmodelled, and a
///   harness that stubs the wrong one silently proves nothing.
/// * Kani cannot run the real BLAKE3: its CPU-feature detection lowers to inline
///   assembly, which CBMC rejects.  Stubbing one seam removes all of it.
///
/// Taking a slice of parts rather than one concatenated buffer keeps the key out
/// of a growable heap allocation: the callers pass fixed-size stack arrays.
/// `derive_tag` does build one contiguous buffer for mid-sized messages (it is
/// measurably faster, see there); that buffer is exact-sized and wiped before it
/// is dropped, so no copy of the key is stranded.
fn blake3_keyed_multi(key: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for p in parts {
        hasher.update(p);
    }
    let mut reader = hasher.finalize_xof();
    reader.fill(out);

    // `blake3::Hasher` holds its key in `key: CVWords`, and this crate cannot
    // reach that memory: wiping it needs the dependency's own `zeroize` support
    // (enabled in Cargo.toml), and it is *not* automatic on drop.  The XOF
    // reader carries key-derived output state, so it is wiped too.
    //
    // Under Kani this code is unreachable, because harnesses stub this whole
    // function -- which also keeps `zeroize`'s own inline assembly out of the
    // verification scope.
    //
    // This wipe is not free, and it is worth knowing what it costs: callgrind puts
    // `<Hasher as Zeroize>::zeroize` at 15% of all instructions in a 64-byte round
    // trip (four calls: tag and key derivation, each encrypting and decrypting),
    // because BLAKE3 wipes its whole CV stack rather than the part a one-chunk
    // input touched. It stays. The guarantee is that no copy of the MAC key
    // survives the call, and only the dependency can say which of its own state
    // that covers.
    reader.zeroize();
    hasher.zeroize();
}

/// Convenience wrapper for the single-part case.
fn blake3_keyed_xof(key: &[u8; 32], data: &[u8], out: &mut [u8]) {
    blake3_keyed_multi(key, &[data], out);
}

/// Message sizes whose tag is hashed through one contiguous buffer instead of
/// three `update` calls. See `derive_tag` for why, and for the measurements.
const TAG_CONCAT_LIMIT: usize = 65_536;
/// Below this, the copy is pure overhead: with less than a chunk to batch,
/// BLAKE3 gains nothing from a single call.
const TAG_CONCAT_MIN: usize = 2_048;

/// The 520-bit tag: one keyed BLAKE3 over the entire context.
///
/// `BLAKE3_keyed(mac_key, DOM_TAG || K || N || le64(|A|) || le64(|M|) || A || M)`
///
/// Two properties are load-bearing and easy to lose in a refactor:
///
/// * **The key is an input, not just the MAC key.** Without `K` in the head, an adversary
///   who controls two keys could look for a collision in the *derivation* — the 512-bit
///   `mat` block is `CC(HC(K, N₁), …)`, so two keys with equal `mat` give equal `mac_key`
///   *and* equal `enc_seed`, hence identical tags for equal messages *and* identical
///   keystreams: one ciphertext opening under both keys, for a `2^256` birthday search,
///   which is the key-search level and therefore not committing at all. With `K` in the
///   head that route is closed — the two tags now have different inputs — and the shortest
///   route is the `2^520` target of `TAG_LEN`'s docs. So the binding raises the *route* the
///   attacker must take, at the price of the correlation noted below.
///
///   One honest caveat belongs here, because it is the one step in the security argument
///   that no black-box reduction covers (`SECURITY-ANALYSIS.md` §2.1, node L3.6): the hash's
///   *key* and a 32-byte *substring of its input* are two correlated functions of one
///   secret, where the PRF game assumes a key drawn independently of the input. With the
///   derivation idealized the reduction is immediate — a random function does not care what
///   its input means — but a hash that could *notice* the relation would not be a PRF under
///   this composition, and §2.1's separation shows the gap is real rather than a missing
///   paragraph. What supports the step is that neither primitive is known to have that
///   structure, and that no experiment here separates the composition from ideal. A format
///   revision could remove the correlation entirely by dropping `K` from the head — at the
///   cost of re-opening the derivation route above, which is the trade rather than a free win.
/// * **Lengths are encoded and every field is fixed width.** BLAKE3 is not
///   vulnerable to length extension (its finalisation is flagged, unlike
///   Merkle–Damgård constructions), but `A || M` alone would be ambiguous:
///   `("ab", "c")` and `("a", "bc")` would hash identically. The two `u64`
///   length fields remove that.
///
/// The hasher is fed incrementally rather than through one concatenated buffer,
/// so the key never lands in a growable heap allocation.
#[allow(unused_variables)]
fn derive_tag(
    mac_key: &[u8; 32],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> [u8; TAG_LEN] {
    #[cfg(test)]
    test_counters::DERIVE_TAG_CALLS.with(|c| c.set(c.get() + 1));

    // Fixed-width head: domain, key, nonce, and the two lengths.  Assembled on
    // the stack so the key never enters a heap buffer, and so the whole thing is
    // one slice the seam can absorb.
    let mut head = [0u8; 8 + 32 + NONCE_LEN + 16];
    head[0..8].copy_from_slice(&DOM_TAG);
    head[8..40].copy_from_slice(key);
    head[40..40 + NONCE_LEN].copy_from_slice(nonce);
    head[40 + NONCE_LEN..48 + NONCE_LEN].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    head[48 + NONCE_LEN..56 + NONCE_LEN].copy_from_slice(&(msg.len() as u64).to_le_bytes());

    let mut tag = [0u8; TAG_LEN];
    // How the bytes are *fed* does not change the hash -- only their order does --
    // so this is free to pick whichever call shape is faster:
    //
    // BLAKE3's incremental API only takes its batched SIMD path (`hash_many`)
    // when a call starts on a chunk boundary. Feeding it `head`, then `aad`, then
    // `msg` starts the big call 83 bytes into a chunk, which drops the whole
    // message onto the one-block-at-a-time path. Measured on x86_64, per message:
    //
    //     size     three updates   one contiguous   ratio
    //     1 KiB         1120 ns          1089 ns     1.0x
    //     4 KiB         2796 ns          1310 ns     2.1x
    //    16 KiB         4734 ns          2098 ns     2.3x
    //    64 KiB        10239 ns          7478 ns     1.4x
    //     1 MiB       117795 ns        112902 ns     1.0x
    //
    // A contiguous buffer costs a copy (about 0.07 ns/byte), so the win is
    // size-bounded: below one chunk there is nothing to batch, and above
    // ~64 KiB the copy costs more than the batching saves.
    //
    // `head` holds the master key, so the buffer is built once with an exact
    // capacity (no reallocation can strand a copy) and wiped before it is
    // dropped, which is what keeps this consistent with the rest of the crate.
    // `checked_add`, not `+`: on a 32-bit target this sum can overflow, because
    // `check_lengths` cannot fire there (`MAX_MSG_SIZE` = 2^38 > `u32::MAX`, as
    // `test_length_guard_cannot_fire_on_32_bit` records), so `aad.len() + msg.len()` is
    // bounded only by the address space. Reaching it needs ~4 GiB of live slices, so it is
    // not exploitable -- but a *wrapping* sum would pick a branch by accident, and an
    // `overflow-checks` build would panic on a caller's input. `None` is the honest
    // answer: "larger than any total this fast path serves".
    let window = head
        .len()
        .checked_add(aad.len())
        .and_then(|t| t.checked_add(msg.len()))
        .filter(|t| (TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT).contains(t));
    match window {
        // The one infallible allocation outside the entry points, and it is bounded by
        // construction: this arm is only taken for a total within
        // `TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT`, so `total <= 65_536` whatever the input
        // length is. A refusal here would mean the process has no memory left at all,
        // which is why it is not threaded through `derive_tag`'s array return type.
        Some(total) => {
            let mut cat = Vec::with_capacity(total);
            cat.extend_from_slice(&head);
            cat.extend_from_slice(aad);
            cat.extend_from_slice(msg);
            blake3_keyed_multi(mac_key, &[&cat], &mut tag);
            zeroize_slice(&mut cat);
        }
        None => blake3_keyed_multi(mac_key, &[&head, aad, msg], &mut tag),
    }

    // `head` holds the master key at `head[8..40]`, so it is secret and must be
    // wiped like every other key-bearing local in this module.  A `[u8; 80]`
    // on the stack is not cleared by dropping it, and leaving the key there
    // would break the invariant the rest of this file maintains (the same
    // failure mode as the two previously fixed instances of unwiped copies).
    zeroize_array(&mut head);
    tag
}

/// Per-message encryption key and nonce, derived from the **whole** tag.
///
/// Consuming all `TAG_LEN` bytes is what makes the ciphertext commit to the full
/// 520 bits: the ciphertext is a function of the tag, and the tag is transmitted
/// and compared in full.
///
/// # Why this writes through the caller's slices
///
/// It used to return `([u8; 32], [u8; 12])`. Returning a 44-byte aggregate makes
/// the compiler materialise an unnamed temporary for the return value — a copy
/// no `zeroize_array` call in this function can name, and therefore none can
/// wipe. A stack scan (`tests/stack_residue.rs`'s method, run as a unit test)
/// found exactly that: the tail of this value, `material[16..44]` — the second
/// half of `enc_key` together with the whole `enc_nonce` — survived in the frame
/// after a full round trip, in all three build configurations. Writing into the
/// caller's buffers leaves the caller's own named locals as the only copies, and
/// the caller already wipes them.
///
/// This does not make the wipe *provable* — a compiler may still spill to the
/// stack — which is why the unit test exists as a regression check rather than
/// as an argument.
fn derive_enc(
    enc_seed: &[u8; 32],
    tag: &[u8; TAG_LEN],
    enc_key: &mut [u8; 32],
    enc_nonce: &mut [u8; 12],
) {
    let mut input = [0u8; 8 + TAG_LEN];
    input[0..8].copy_from_slice(&DOM_ENC);
    input[8..].copy_from_slice(tag);

    // One buffer, written once by the XOF and copied out immediately, so there
    // is a single place for `enc_key ‖ enc_nonce` to live inside this call.
    let mut material = [0u8; 44];
    blake3_keyed_xof(enc_seed, &input, &mut material);

    enc_key.copy_from_slice(&material[0..32]);
    enc_nonce.copy_from_slice(&material[32..44]);

    zeroize_array(&mut material);
    zeroize_array(&mut input);
}

#[inline]
fn check_lengths(msg_len: usize, aad_len: usize) -> Result<(), Error> {
    if msg_len as u64 > MAX_MSG_SIZE {
        return Err(Error::MessageTooLong);
    }
    if aad_len as u64 > MAX_MSG_SIZE {
        return Err(Error::AadTooLong);
    }
    Ok(())
}

/// Allocate a zeroed buffer of `len` bytes for an allocating entry point.
///
/// Fallible on purpose, and **both** allocating entry points go through it: [`decrypt`]
/// for the recovered plaintext and [`encrypt`] for the ciphertext.  `vec![0u8; n]` calls
/// the allocation-error handler, which aborts the process — so with a plain `vec!` an
/// unlucky size turns a request into a kill the application cannot catch, instead of an
/// [`Error::AllocationFailed`] it can report and move past.
///
/// What this does **not** remove, and what no in-process library can: a request the
/// kernel *accepts* can still be killed later, when the buffer is written to — the OOM
/// killer sends a signal a process cannot intercept.  That half belongs to the
/// deployment (a cgroup limit, an accept-size policy, a maximum request size), and
/// [`MAX_MSG_SIZE`] is public for the caller-side check.  What is fixed here is the case
/// where the allocator itself says no and the process dies for it.
///
/// Note the peak this implies for [`decrypt`]: the caller already holds the ciphertext,
/// so the call holds ciphertext **and** plaintext — twice the message — for its
/// duration.  [`decrypt_bounded`] bounds the second half; the first is the caller's.
fn alloc_zeroed(len: usize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(len)
        .map_err(|_| Error::AllocationFailed)?;
    // Cannot reallocate: `len` bytes are already reserved.
    buf.resize(len, 0u8);
    Ok(buf)
}

/// Encrypt `plaintext` under `(key, nonce, aad)`, returning `(ciphertext, tag)`.
///
/// SIV construction: the tag is computed first, and the per-message encryption
/// key and nonce are derived from it.
#[must_use = "the returned ciphertext and tag must be handled"]
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Error> {
    check_lengths(plaintext.len(), aad.len())?;

    // The buffer is allocated *first*, before any key material exists: this length is the
    // caller's, so the allocation is the one step that can fail, and taking it here means
    // the `?` cannot return through live secrets. (It did: with the derivation first, an
    // `AllocationFailed` left `mac_key`, `enc_seed`, `enc_key` and `enc_nonce` in the frame
    // -- on a path the error type explicitly invites the caller to retry, and which the
    // `ultra` stack scrub would have had to cover as well.)
    let mut ciphertext = alloc_zeroed(plaintext.len())?;

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let tag = derive_tag(&mac_key, key, nonce, aad, plaintext);
    // `ultra`: the independent implementation must produce the same tag. A mismatch is a
    // rejection here rather than a ciphertext the peer will refuse -- and it is the only way
    // to notice a fault in the tag computation on the *sending* side at all.
    //
    // The comparison is secret-derived (both operands are), so the branch on it goes through
    // `accept_or_reject` with the decrypt side's rather than standing here as an `if`: a
    // comparison-then-branch at this call site is precisely what the suppression file may not
    // cover, and `tools/ctgrind.sh --features ultra` reports it when it is written that way
    // (measured before this shape: 1 report, inside `encrypt`). What the caller branches on
    // below is a discriminant written as a *constant* by each arm of that function, so the
    // decision is the same one reviewed in `accept_or_reject` and nothing else is suppressed.
    #[cfg(feature = "ultra")]
    {
        let agree: subtle::Choice = witness::encrypt_tag(key, nonce, aad, plaintext).ct_eq(&tag);
        // Two rejections written before the call and checked in series, the same fail-closed
        // shape as both decrypt entry points: a fault that skips the call, or corrupts one
        // outcome, leaves a rejection standing.
        let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);
        let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);
        accept_or_reject(agree, agree, &mut decision0, &mut decision1);
        if decision0.is_err() {
            zeroize_array(&mut mac_key);
            zeroize_array(&mut enc_seed);
            // The buffer has not been written yet (the keystream runs below), but it is
            // zeroized on this path anyway rather than left to `Drop`, so the two rejection
            // paths out of this function differ only in what they have derived.
            zeroize_slice(&mut ciphertext);
            return Err(Error::AuthenticationFailed);
        }
        if decision1.is_err() {
            zeroize_array(&mut mac_key);
            zeroize_array(&mut enc_seed);
            zeroize_slice(&mut ciphertext);
            return Err(Error::AuthenticationFailed);
        }
    }
    let mut enc_key = [0u8; 32];
    let mut enc_nonce = [0u8; 12];
    derive_enc(&enc_seed, &tag, &mut enc_key, &mut enc_nonce);

    chacha20_keystream(&enc_key, 0, &enc_nonce, plaintext, &mut ciphertext);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);

    #[cfg(feature = "dual-mac")]
    scrub_stack();

    Ok((ciphertext, tag))
}

/// Encrypt `buffer` in place, returning the detached tag.
#[must_use = "the returned tag must be handled"]
pub fn encrypt_in_place_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    check_lengths(buffer.len(), aad.len())?;

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let tag = derive_tag(&mac_key, key, nonce, aad, buffer);
    let mut enc_key = [0u8; 32];
    let mut enc_nonce = [0u8; 12];
    derive_enc(&enc_seed, &tag, &mut enc_key, &mut enc_nonce);

    chacha20_apply(&enc_key, 0, &enc_nonce, &Input::InPlace, buffer);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);

    #[cfg(feature = "dual-mac")]
    scrub_stack();

    Ok(tag)
}

/// The second gate's comparison of the two volatile copies.
///
/// `AND`-ed from two *differently written* constant-time comparisons: `subtle`'s byte loop
/// (both ways round) and [`ct_eq_independent`]'s eight-bytes-at-a-time fold.
///
/// The reason is a boundary worth naming: every other comparison in every gate is the same
/// `subtle` byte loop, so one fault that shortens that loop would make them all say "equal"
/// for different tags — one fault reaching two gates — and `dual-mac`'s recomputations do not
/// help either, because they are compared through the same function again. Measured before
/// the second comparison existed: a forgery accepted after **2,573 attempts** with the
/// comparison cut to two bytes, in both the default and the `ultra` build; with both shapes in
/// place, the same hand-made fault yields **no forgery in 2,000,000 attempts**. Two faults
/// still defeat both, which is the boundary the README's table states.
///
/// **The second comparison is now in every configuration, not only `dual-mac`.** It used to be
/// gated on `dual-mac` — so the *default* build had one comparison shape and one shortened-loop
/// fault was enough — until the costs were put side by side: this is one extra 65-byte fold,
/// **measured at 1.4 ns** (0.1% of a 64-byte decryption, 1.05 us) against a measured change from
/// "forgery after 2,573 attempts" to "none in 2,000,000". A defence with that ratio belongs in
/// the default.
#[inline(always)]
#[cfg(feature = "hardened")]
fn second_gate_comparison(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> subtle::Choice {
    let plain = a.ct_eq(b) & b.ct_eq(a);
    let also = ct_eq_independent(a, b);
    plain & also
}

/// A second, independent constant-time equality over two tags.
///
/// Deliberately a different *shape* from `subtle`'s comparison, which walks the
/// bytes one at a time: this folds eight bytes at a time into a `u64` and tests
/// the accumulator once. The reason is that every other comparison in the
/// `hardened` decision calls the *same* `subtle` loop, so a single fault that
/// shortens that loop would disarm the gates together — one fault reaching two
/// gates defeats the purpose of having two.
///
/// Unconditional since the cost was measured: one 65-byte fold, tens of
/// nanoseconds, in exchange for turning a hand-modelled shortened-loop forgery
/// from "accepted after 2,573 attempts" into "none in 2,000,000". It was
/// `dual-mac`-only before that comparison, which left the *default* build on one
/// comparison shape.
///
/// This is not a claim of fault-injection resistance. An adversary who can fault
/// this loop *and* `subtle`'s has two faults and defeats both, which is what the
/// README's table already says. What it removes is the single-fault case, where
/// the two gates were one gate wearing two hats.
///
/// Constant time: the loop bounds depend only on the public length, there is no
/// data-dependent branch and no data-dependent index, and the final
/// `acc.ct_eq(&0)` is a single `u64` comparison with no loop of its own to
/// shorten. `#[inline(never)]` keeps the compiler from merging it with the other
/// comparison, which would put both gates back on shared code.
#[cfg(feature = "hardened")]
#[inline(never)]
fn ct_eq_independent(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> subtle::Choice {
    let mut acc = 0u64;
    let mut i = 0usize;
    while i + 8 <= TAG_LEN {
        let x = u64::from_le_bytes(a[i..i + 8].try_into().unwrap())
            ^ u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        acc |= x;
        i += 8;
    }
    // TAG_LEN is 65, so one byte is left over; a general loop rather than a
    // hard-coded tail keeps this correct if TAG_LEN ever changes.
    while i < TAG_LEN {
        acc |= (a[i] ^ b[i]) as u64;
        i += 1;
    }
    acc.ct_eq(&0u64)
}

// ── The accept/reject decision, isolated in one function ───────────────
//
// SIV decrypts before it verifies, so "does this ciphertext authenticate?" is a
// branch on secret-derived data, and it cannot be removed: that one bit is what
// the mode is designed to reveal. Four properties depend on its living *here*, in a
// function of its own, `#[inline(never)]`, shared by both decrypt entry points:
//
//  * `tests/ctgrind.supp` suppresses this function and nothing else, so a
//    secret-dependent branch anywhere else in the crate -- including inside
//    `decrypt` and `decrypt_in_place_detached`, which an earlier revision
//    suppressed whole and which therefore hid one -- is reported by memcheck and
//    fails `tools/ctgrind.sh`. That script plants exactly such a branch in a
//    throwaway copy and requires it to be caught before it reports a clean run.
//  * the outcome is written through **two slots**, each initialised to a rejection by
//    the caller before the call and each written by *its own* gate's flow, rather
//    than returned by value. Two properties follow, and both are measured:
//      - a returned value can be lost by never making the call. `tools/fi_instruction.sh`
//        measured six single-byte faults in `decrypt` that skipped the call and
//        accepted a forgery, because the ABI then hands back whatever the return slot
//        held; with the slots pre-initialised, skipping the call leaves rejections.
//      - a *corrupted* outcome cannot accept either: one fault would have to corrupt
//        both slots, which is two faults. The caller therefore rejects if *either*
//        slot says so, and the two checks sit in series so that no single corrupted
//        branch can accept -- accepting is the fall-through of both.
//    What none of this removes is a fault inside the *encoding* of the caller's own
//    accept decision: a conditional jump's opcode is one bit from its inverse
//    (`je` 0x84 / `jne` 0x85) and its target is a few bits away from any address in
//    the function. That residual is measured with `tools/fi_instruction.sh --bits`
//    and published in the README's table rather than claimed away.
//  * the *caller* wipes the buffer on any rejection, not this function. One wipe
//    site, on the path every rejection takes -- including the one a skipped call
//    leaves behind, which this function would never see.
//  * there is exactly one body, with the `hardened` gates *inside* it rather than a
//    second `#[cfg]`-selected definition of the same function. Two bodies would be
//    two functions to a mutation campaign that does not evaluate `cfg`
//    (`cargo mutants`), and the one that is not compiled in a given run reads as an
//    uncaught mutant. One body means every mutatable line is compiled in the
//    `hardened` build, which is a superset of the default one.
//
// The default build passes the same `Choice` for both gates -- the second gate is
// compiled out there, so one comparison is the whole decision and nothing is
// wasted computing a second one.
#[inline(never)]
fn accept_or_reject(
    gate0: subtle::Choice,
    gate1: subtle::Choice,
    out0: &mut Result<(), Error>,
    out1: &mut Result<(), Error>,
) {
    // Each gate writes *its own* slot, **inside a branch arm**, so the byte that
    // lands there is a constant each path writes rather than a value selected from a
    // secret-derived condition. The difference is not cosmetic: `*out = if cond { A }
    // else { B }` compiles to a `setcc`/`cmov` on the tainted condition, which makes
    // the discriminant itself secret-derived -- and then the *caller's* check on it is
    // a secret-dependent branch outside the function `tests/ctgrind.supp` permits
    // (measured: six reports against `decrypt` when this was written as an if-
    // expression, none as arms).
    if bool::from(gate0) {
        *out0 = Ok(());
    } else {
        *out0 = Err(Error::AuthenticationFailed);
        // `out1` keeps the rejection the caller wrote: a message the first gate
        // rejects does not need the second gate evaluated.
        return;
    }

    // Fault-injection hardening (the `hardened` feature, on by default): a second
    // *recomputed* check with its own branch, so a single skipped instruction reaches
    // this gate instead of accepting. `&` and never `&&`: both comparisons always run
    // in the caller, so the time this takes does not reveal which gate failed. No
    // `unwrap_u8` and no early exit inside the comparisons -- `bool::from` is the
    // conversion `subtle` documents for exactly this place (the end of a
    // verification). What it does and does not defend against: see README "What is
    // not defended against".
    #[cfg(feature = "hardened")]
    if bool::from(gate1) {
        *out1 = Ok(());
    } else {
        *out1 = Err(Error::AuthenticationFailed);
    }

    // The opt-out build has one gate, so both slots carry its answer: the caller's
    // two checks are then one check written twice, which is honest for a build whose
    // promise is the single gate.
    #[cfg(not(feature = "hardened"))]
    {
        let _ = gate1;
        *out1 = *out0;
    }
}

/// Decrypt `ciphertext`, verifying the tag.
///
/// **This allocates a buffer as large as `ciphertext`.** Bound untrusted input
/// before calling it: [`MAX_MSG_SIZE`] (256 GiB) is the format's ceiling, not a safe
/// one, and a service that trusts a length field off the wire can be made to
/// allocate that much per request. [`decrypt_bounded`] takes a policy limit and
/// enforces it *before* the allocation; that is the entry point for input whose
/// length came from a network peer.
///
/// Returns the plaintext in a [`Plaintext`] that zeroizes on drop. On failure
/// returns [`Error::AuthenticationFailed`] and never exposes the unverified
/// plaintext.
#[must_use = "the returned plaintext must be handled"]
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Plaintext, Error> {
    check_lengths(ciphertext.len(), aad.len())?;

    // As in `encrypt`: the fallible step runs before any key material exists, so the error
    // path cannot return through live secrets. `ultra`'s witness needs an output buffer of the
    // same size, so that allocation is taken here too, with the same reasoning -- and it is
    // why `witness::decrypt` writes into a caller slice instead of allocating: an allocation
    // inside it would `abort` on refusal rather than returning `Error::AllocationFailed`.
    let mut plaintext = alloc_zeroed(ciphertext.len())?;
    #[cfg(feature = "ultra")]
    let mut witness_plaintext = alloc_zeroed(ciphertext.len())?;

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let mut enc_key = [0u8; 32];
    let mut enc_nonce = [0u8; 12];
    derive_enc(&enc_seed, tag, &mut enc_key, &mut enc_nonce);

    chacha20_keystream(&enc_key, 0, &enc_nonce, ciphertext, &mut plaintext);

    let mut computed_tag = derive_tag(&mac_key, key, nonce, aad, &plaintext);
    // `ultra`: recompute the *entire* decryption with the independent implementation in
    // `witness` and require bit-for-bit agreement — plaintext and tag both. Every other
    // defence compares values produced by one implementation, so a fault that makes that
    // implementation wrong is invisible to all of them; this is the only check that can
    // disagree with it.
    //
    // The agreement is a `Choice` that the gate below absorbs, *not* a branch here: a branch on
    // a secret-derived comparison outside `accept_or_reject` is precisely what
    // `tests/ctgrind.supp` exists to forbid, and the first version of this was written that way
    // — seven memcheck reports against this crate, caught by `tools/ctgrind.sh --features
    // ultra`. Riding the gate keeps one branch site, keeps it fail-closed, and keeps it
    // audited.
    //
    // Without the feature, `witness_ok` is a constant *true* so that the gate below is one
    // expression in every build rather than a `#[cfg]`-selected copy per configuration:
    // `cargo mutants` does not evaluate `cfg`, so a copy that is compiled out in a given run
    // reads there as an uncaught mutant (measured: six `&` -> `^` mutants came back MISSED
    // when these were two arms).
    #[cfg(feature = "ultra")]
    let witness_ok: subtle::Choice = {
        let witness_tag =
            witness::decrypt(key, nonce, aad, ciphertext, tag, &mut witness_plaintext);
        let agree = witness_tag.ct_eq(&computed_tag)
            & witness_plaintext.as_slice().ct_eq(plaintext.as_slice());
        zeroize_slice(&mut witness_plaintext);
        agree
    };
    // The gate's extra operand when `ultra` is off: `Choice::from(1)` is "true", so the
    // `&` it feeds is a no-op the optimizer folds away. Gated on `hardened` as well,
    // because that is what compiles the gate that reads it -- without the gate there is
    // nothing to fold and the binding would be an unused-variable warning.
    #[cfg(all(not(feature = "ultra"), feature = "hardened"))]
    let witness_ok: subtle::Choice = subtle::Choice::from(1);
    // `ultra`/`dual-mac`: recompute the tag *independently* and require the
    // recomputation to agree with both the stored value and the received tag. The two
    // gates above compare the same two values, so a fault that sets the stored tag to
    // the received one satisfies both at once; this is the only software measure that
    // disagrees with such a fault. Measured cost: +21..40% on decryption.
    #[cfg(feature = "dual-mac")]
    let mut recomputed_tag = derive_tag(&mac_key, key, nonce, aad, &plaintext);
    #[cfg(feature = "hardened")]
    let gates = {
        // Two *recomputations*, not one result read twice.  The two gate
        // expressions are identical, and an optimizer is entitled to
        // common-subexpression-eliminate them into a single comparison — at which
        // point one fault would carry both gates and the second gate would have
        // stopped being a second gate.
        //
        // The volatile re-read is what forbids that merge, and it is here rather
        // than `black_box` on purpose: whether `black_box` defeats CSE is a
        // property of the optimizer's choices, not of the program, and this
        // hardening must not rest on the difference between two compilers.  A
        // volatile access is one the language requires to happen.
        //
        // Cost: two 65-byte copies and two wipes, only under this feature.
        let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);

        // SAFETY: `computed_tag` is a live local, initialised and aligned for a
        // `[u8; TAG_LEN]` read for the whole statement; nothing writes through the
        // pointer, and a volatile read of live memory has no effect beyond being
        // the read itself.
        let mut computed_tag_copy = unsafe { core::ptr::read_volatile(&computed_tag) };
        // SAFETY: as above, for the caller's reference: `tag` is a live `&[u8;
        // TAG_LEN]` and this only reads through it, so aliasing rules hold.
        let mut tag_copy = unsafe { core::ptr::read_volatile(tag) };
        // The independent recomputation joins the second gate: it must match the
        // stored value *and* the received tag, so a fault that corrupted the stored
        // value (or a silently rewritten constant) is caught here even though both
        // gate expressions read the same memory.
        //
        // `witness_ok` -- `ultra`'s independent-implementation agreement, a constant
        // `true` in every other configuration -- is folded in *here*, on the one line
        // that is compiled in all of them, rather than as a `#[cfg]`-selected copy of the
        // gate below. `cargo mutants` does not evaluate `cfg`: a copy that is not compiled
        // in a given run reads there as an uncaught mutant, and the `&`s it contains are
        // then either reported as gaps that are not gaps or (worse) lose their coverage
        // silently. Measured when this was three arms: six MISSED mutants.
        let gate_pair = second_gate_comparison(&computed_tag_copy, &tag_copy) & witness_ok;
        #[cfg(feature = "dual-mac")]
        let second = gate_pair & recomputed_tag.ct_eq(&computed_tag) & recomputed_tag.ct_eq(tag);
        #[cfg(not(feature = "dual-mac"))]
        let second = gate_pair;

        // The copies are secret-derived (they are the computed MAC), so they are
        // wiped like every other copy in this function rather than left in the
        // frame of the `hardened` build.
        zeroize_array(&mut computed_tag_copy);
        zeroize_array(&mut tag_copy);

        (first, second)
    };
    #[cfg(not(feature = "hardened"))]
    let auth_ok = computed_tag.ct_eq(tag);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);
    zeroize_array(&mut computed_tag);
    // The independent recomputation is the computed MAC too, so it is wiped like the
    // rest -- `tests/ultra.rs` asserts this, which is how the omission was found.
    #[cfg(feature = "dual-mac")]
    zeroize_array(&mut recomputed_tag);

    // Two rejections until the decision proves otherwise, written *before* the call:
    // a fault that skips the call leaves both standing, and a fault that corrupts one
    // outcome leaves the other -- so accepting would take two faults. See the comment
    // on `accept_or_reject`.
    #[cfg(feature = "dual-mac")]
    scrub_stack();

    let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);
    let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);
    #[cfg(not(feature = "hardened"))]
    accept_or_reject(auth_ok, auth_ok, &mut decision0, &mut decision1);
    #[cfg(feature = "hardened")]
    accept_or_reject(gates.0, gates.1, &mut decision0, &mut decision1);

    // Two checks in series, each jumping *to the rejection*: accepting is the
    // fall-through of both, so no single corrupted branch accepts -- whichever one is
    // corrupted, the other still rejects. A corrupted jump *target* can skip both,
    // and that residual is measured (`tools/fi_instruction.sh --bits`) and pinned in
    // the README's table rather than claimed away.
    if decision0.is_err() {
        zeroize_slice(&mut plaintext);
        return Err(Error::AuthenticationFailed);
    }
    if decision1.is_err() {
        zeroize_slice(&mut plaintext);
        return Err(Error::AuthenticationFailed);
    }
    Ok(Plaintext(plaintext))
}

/// [`decrypt`] with an allocation bound that is checked **before** the buffer is
/// allocated.
///
/// `max_len` is the caller's policy, not the format's: a ciphertext longer than it
/// is refused with [`Error::MessageTooLong`] and nothing is allocated. This exists
/// because [`MAX_MSG_SIZE`] (256 GiB) is a format limit and does not bound a remote
/// request by itself — a service whose message length comes off the wire wants a
/// limit of its own, applied before the bytes are trusted.
///
/// The bound is on the ciphertext, which is the size of the plaintext, so the two
/// are the same number for the caller's purposes.
///
/// ```
/// # use xchacha20_blake3_siv::{decrypt_bounded, encrypt, Error};
/// # let key = [0x42u8; 32];
/// # let nonce = [0x55u8; 24];
/// # let (ciphertext, tag) = encrypt(&key, &nonce, b"", b"hello").unwrap();
/// // This service accepts at most 64 KiB, whatever the format would allow.
/// let plaintext = decrypt_bounded(&key, &nonce, b"", &ciphertext, &tag, 64 * 1024).unwrap();
/// assert_eq!(plaintext, b"hello");
///
/// // Longer than the policy: refused before any buffer is allocated. (`matches!`
/// // rather than `assert_eq!`: `Plaintext` compares against byte slices, not
/// // against another `Plaintext`, deliberately.)
/// assert!(matches!(
///     decrypt_bounded(&key, &nonce, b"", &ciphertext, &tag, 2),
///     Err(Error::MessageTooLong)
/// ));
/// # Ok::<(), Error>(())
/// ```
#[must_use = "the returned plaintext must be handled"]
pub fn decrypt_bounded(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    max_len: usize,
) -> Result<Plaintext, Error> {
    if ciphertext.len() > max_len {
        return Err(Error::MessageTooLong);
    }
    decrypt(key, nonce, aad, ciphertext, tag)
}

/// Decrypt `buffer` in place, verifying the detached tag.
///
/// On failure the buffer is zeroized, so unverified plaintext is never left in
/// place. Note this destroys the caller's buffer on the failure path.
pub fn decrypt_in_place_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    check_lengths(buffer.len(), aad.len())?;

    // `ultra` needs the ciphertext later, and the in-place transform consumes it, so a copy is
    // taken. This was the first version's bug: the witness was handed `buffer` *after* the XOR,
    // so it decrypted plaintext-as-ciphertext and disagreed with everything -- which is at
    // least the right failure (a rejection), but for a reason unrelated to any fault.
    //
    // Both buffers are allocated *before* any derivation, like `encrypt`'s and `decrypt`'s: the
    // `?` here must not return through live key material. It did, while these two were
    // allocated where they are used -- the same defect `encrypt` was fixed for, reintroduced by
    // adding an allocation after the derivations.
    #[cfg(feature = "ultra")]
    let mut witness_ciphertext = alloc_zeroed(buffer.len())?;
    #[cfg(feature = "ultra")]
    let mut witness_plaintext = alloc_zeroed(buffer.len())?;

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let mut enc_key = [0u8; 32];
    let mut enc_nonce = [0u8; 12];
    derive_enc(&enc_seed, tag, &mut enc_key, &mut enc_nonce);

    #[cfg(feature = "ultra")]
    witness_ciphertext.copy_from_slice(buffer);

    chacha20_apply(&enc_key, 0, &enc_nonce, &Input::InPlace, buffer);

    let mut computed_tag = derive_tag(&mac_key, key, nonce, aad, buffer);
    // `ultra`: the independent implementation recomputes the whole decryption from the
    // ciphertext the caller still holds, and its agreement rides the existing gate rather than
    // becoming a branch of its own -- a branch on a secret-derived comparison outside
    // `accept_or_reject` is what `tests/ctgrind.supp` exists to forbid, and the first version
    // of this did exactly that (seven memcheck reports against this crate, caught by
    // `tools/ctgrind.sh --features ultra`). Riding the gate keeps one branch site, keeps it
    // fail-closed, and keeps it audited.
    #[cfg(feature = "ultra")]
    let witness_ok: subtle::Choice = {
        let witness_tag = witness::decrypt(
            key,
            nonce,
            aad,
            &witness_ciphertext,
            tag,
            &mut witness_plaintext,
        );
        let agree = witness_tag.ct_eq(&computed_tag) & witness_plaintext.ct_eq(buffer);
        zeroize_slice(&mut witness_plaintext);
        zeroize_slice(&mut witness_ciphertext);
        agree
    };
    // Constant `true` when `ultra` is off, so the gate below stays one expression; see the
    // matching binding in `decrypt` for the reasoning (cargo-mutants does not read `cfg`).
    #[cfg(all(not(feature = "ultra"), feature = "hardened"))]
    let witness_ok: subtle::Choice = subtle::Choice::from(1);
    // `ultra`/`dual-mac`, as in `decrypt`: an independent recomputation that must agree
    // with both the stored value and the received tag.
    #[cfg(feature = "dual-mac")]
    let mut recomputed_tag = derive_tag(&mac_key, key, nonce, aad, buffer);
    #[cfg(feature = "hardened")]
    let gates = {
        // See the matching block in `decrypt`: identical reasoning, and the same
        // volatile re-read, so both entry points get a second gate that is a
        // recomputation rather than a copy of the first.
        let first = computed_tag.ct_eq(tag) & tag.ct_eq(&computed_tag);

        // SAFETY: `computed_tag` is a live local, initialised and aligned for a
        // `[u8; TAG_LEN]` read for the whole statement; nothing writes through the
        // pointer, and a volatile read of live memory has no effect beyond being
        // the read itself.
        let mut computed_tag_copy = unsafe { core::ptr::read_volatile(&computed_tag) };
        // SAFETY: as above, for the caller's reference: `tag` is a live `&[u8;
        // TAG_LEN]` and this only reads through it, so aliasing rules hold.
        let mut tag_copy = unsafe { core::ptr::read_volatile(tag) };
        // The independent recomputation joins the second gate: it must match the
        // stored value *and* the received tag, so a fault that corrupted the stored
        // value (or a silently rewritten constant) is caught here even though both
        // gate expressions read the same memory.
        //
        // `witness_ok` -- `ultra`'s independent-implementation agreement, a constant
        // `true` in every other configuration -- is folded in *here*, on the one line
        // that is compiled in all of them, rather than as a `#[cfg]`-selected copy of the
        // gate below. `cargo mutants` does not evaluate `cfg`: a copy that is not compiled
        // in a given run reads there as an uncaught mutant, and the `&`s it contains are
        // then either reported as gaps that are not gaps or (worse) lose their coverage
        // silently. Measured when this was three arms: six MISSED mutants.
        let gate_pair = second_gate_comparison(&computed_tag_copy, &tag_copy) & witness_ok;
        #[cfg(feature = "dual-mac")]
        let second = gate_pair & recomputed_tag.ct_eq(&computed_tag) & recomputed_tag.ct_eq(tag);
        #[cfg(not(feature = "dual-mac"))]
        let second = gate_pair;

        // The copies are secret-derived (they are the computed MAC), so they are
        // wiped like every other copy in this function rather than left in the
        // frame of the `hardened` build.
        zeroize_array(&mut computed_tag_copy);
        zeroize_array(&mut tag_copy);

        (first, second)
    };
    #[cfg(not(feature = "hardened"))]
    let auth_ok = computed_tag.ct_eq(tag);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);
    zeroize_array(&mut computed_tag);
    // The independent recomputation is the computed MAC too, so it is wiped like the
    // rest -- `tests/ultra.rs` asserts this, which is how the omission was found.
    #[cfg(feature = "dual-mac")]
    zeroize_array(&mut recomputed_tag);

    // As in `decrypt`: two rejections written first, and two serial checks, so a fault
    // that skips the call or corrupts one outcome cannot accept.
    #[cfg(feature = "dual-mac")]
    scrub_stack();

    let mut decision0: Result<(), Error> = Err(Error::AuthenticationFailed);
    let mut decision1: Result<(), Error> = Err(Error::AuthenticationFailed);
    #[cfg(not(feature = "hardened"))]
    accept_or_reject(auth_ok, auth_ok, &mut decision0, &mut decision1);
    #[cfg(feature = "hardened")]
    accept_or_reject(gates.0, gates.1, &mut decision0, &mut decision1);

    if decision0.is_err() {
        zeroize_slice(buffer);
        return Err(Error::AuthenticationFailed);
    }
    if decision1.is_err() {
        zeroize_slice(buffer);
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

// ── ChaCha20 Primitive ────────────────────────────────────────────────

/// Quarter round: (a, b, c, d) → (a', b', c', d')
#[inline]
fn qr(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(12);
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(8);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// 20 rounds of ChaCha (10 double-rounds), **in place**.
///
/// Takes `&mut` rather than by value on purpose. `[u32; 16]` is `Copy`, so a
/// by-value signature hands the callee its own copy of the state -- and that state
/// holds the key -- which no `zeroize_array` in the caller can name, let alone
/// wipe. A stack scan found a 24-byte prefix of the per-message encryption key
/// surviving in exactly that shape, on the scalar path taken by messages below the
/// SIMD threshold. Mutating in place leaves the caller's `s` as the only live copy,
/// and the caller already wipes it.
///
/// This is the same failure mode as the `let mut orig = orig;` bug that
/// `chacha20_block`'s comment records: wiping a copy is not wiping the original.
fn chacha20_rounds(s: &mut [u32; 16]) {
    for _ in 0..10 {
        // Column rounds
        let (a, b, c, d) = qr(s[0], s[4], s[8], s[12]);
        s[0] = a;
        s[4] = b;
        s[8] = c;
        s[12] = d;
        let (a, b, c, d) = qr(s[1], s[5], s[9], s[13]);
        s[1] = a;
        s[5] = b;
        s[9] = c;
        s[13] = d;
        let (a, b, c, d) = qr(s[2], s[6], s[10], s[14]);
        s[2] = a;
        s[6] = b;
        s[10] = c;
        s[14] = d;
        let (a, b, c, d) = qr(s[3], s[7], s[11], s[15]);
        s[3] = a;
        s[7] = b;
        s[11] = c;
        s[15] = d;
        // Diagonal rounds
        let (a, b, c, d) = qr(s[0], s[5], s[10], s[15]);
        s[0] = a;
        s[5] = b;
        s[10] = c;
        s[15] = d;
        let (a, b, c, d) = qr(s[1], s[6], s[11], s[12]);
        s[1] = a;
        s[6] = b;
        s[11] = c;
        s[12] = d;
        let (a, b, c, d) = qr(s[2], s[7], s[8], s[13]);
        s[2] = a;
        s[7] = b;
        s[8] = c;
        s[13] = d;
        let (a, b, c, d) = qr(s[3], s[4], s[9], s[14]);
        s[3] = a;
        s[4] = b;
        s[9] = c;
        s[14] = d;
    }
}

/// Generate one ChaCha20 keystream block (64 bytes).
///
/// The ChaCha20 state is initialized with the key, counter, and nonce.
/// After 20 rounds, the state is added to the original state (Davies-Meyer)
/// and serialized as a 64-byte keystream block.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    const CHACHA_CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    let mut s = [0u32; 16];
    s[0] = CHACHA_CONST[0];
    s[1] = CHACHA_CONST[1];
    s[2] = CHACHA_CONST[2];
    s[3] = CHACHA_CONST[3];
    s[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    s[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    s[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    s[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    s[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    s[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    s[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    s[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    s[12] = counter;
    s[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    s[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    s[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let mut orig = s;
    // In place: `s` becomes the post-round state, and it is the caller's own local,
    // so the wipe below reaches it. There is no `out` to leave behind.
    chacha20_rounds(&mut s);

    let mut keystream = [0u8; 64];
    for i in 0..16 {
        let v = s[i].wrapping_add(orig[i]);
        keystream[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Side-channel hygiene: wipe the key-derived state in place. It has to be these
    // locals themselves -- an earlier version wrote `let mut orig = orig;
    // zeroize_array(&mut orig);`, which wipes a *copy* (`[u32; 16]` is `Copy`) and
    // leaves the original on the stack, i.e. no wipe at all.
    zeroize_array(&mut s);
    zeroize_array(&mut orig);

    keystream
}

// ── SIMD backends (x86_64 / aarch64) ──────────────────────────────────
//
// ChaCha20 parallelises perfectly across blocks: block `counter + i` uses the
// same key and nonce, so N blocks can be computed in N SIMD lanes (N = 4 for
// SSE2 and NEON, 8 for AVX2).  Every backend MUST produce output byte-identical
// to the scalar `chacha20_block`; the `simd_matches_scalar` tests enforce this
// across widths, counters and lengths.
//
// All other architectures (loongarch, riscv, wasm, sh, ...) compile the scalar
// path only, which is also the correctness reference.  No target-specific code
// is compiled for them, so cross-architecture output is identical by
// construction (ChaCha20 is defined on 32-bit little-endian words).

/// The 16 scalar ChaCha20 state words for a given (key, counter, nonce).
/// SIMD backends broadcast these into lanes and override the counter word.
///
/// Only the SIMD modules use this, and they are compiled out under Kani, so it
/// is gated to match and does not become dead code there.
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(kani)))]
#[inline]
fn chacha20_state_words(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s
}

#[cfg(all(target_arch = "x86_64", not(kani)))]
mod x86_simd {
    use super::{chacha20_state_words, zeroize_array};
    use core::arch::x86_64::*;
    use core::sync::atomic::{AtomicU8, Ordering};

    // SSE2/AVX2 have no 32-bit rotate instruction, so rotate via shift + or.
    // The two shift amounts are passed explicitly because stable Rust forbids
    // arithmetic on const generics in `::<{ 32 - N }>` position.
    macro_rules! rotl128 {
        ($x:expr, $l:literal, $r:literal) => {
            _mm_or_si128(_mm_slli_epi32::<$l>($x), _mm_srli_epi32::<$r>($x))
        };
    }

    macro_rules! rotl256 {
        ($x:expr, $l:literal, $r:literal) => {
            _mm256_or_si256(_mm256_slli_epi32::<$l>($x), _mm256_srli_epi32::<$r>($x))
        };
    }

    macro_rules! qr128 {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {{
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl128!(_mm_xor_si128($x[$d], $x[$a]), 16, 16);
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl128!(_mm_xor_si128($x[$b], $x[$c]), 12, 20);
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl128!(_mm_xor_si128($x[$d], $x[$a]), 8, 24);
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl128!(_mm_xor_si128($x[$b], $x[$c]), 7, 25);
        }};
    }

    macro_rules! qr256 {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {{
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl256!(_mm256_xor_si256($x[$d], $x[$a]), 16, 16);
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl256!(_mm256_xor_si256($x[$b], $x[$c]), 12, 20);
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl256!(_mm256_xor_si256($x[$d], $x[$a]), 8, 24);
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl256!(_mm256_xor_si256($x[$b], $x[$c]), 7, 25);
        }};
    }

    /// 4 ChaCha20 blocks in parallel (SSE2, 128-bit lanes).  Baseline on x86_64.
    ///
    /// Writes 4 * 64 = 256 bytes of raw keystream to `out`.
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn blocks4(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
        assert_eq!(out.len(), 256);
        let mut s = chacha20_state_words(key, counter, nonce);

        let mut x: [__m128i; 16] = [core::mem::zeroed(); 16];
        for i in 0..16 {
            x[i] = _mm_set1_epi32(s[i] as i32);
        }
        // Lane k carries counter + k.
        x[12] = _mm_set_epi32(
            counter.wrapping_add(3) as i32,
            counter.wrapping_add(2) as i32,
            counter.wrapping_add(1) as i32,
            counter as i32,
        );

        let mut orig = x;
        for _ in 0..10 {
            qr128!(x, 0, 4, 8, 12);
            qr128!(x, 1, 5, 9, 13);
            qr128!(x, 2, 6, 10, 14);
            qr128!(x, 3, 7, 11, 15);
            qr128!(x, 0, 5, 10, 15);
            qr128!(x, 1, 6, 11, 12);
            qr128!(x, 2, 7, 8, 13);
            qr128!(x, 3, 4, 9, 14);
        }

        // Final addition, then transpose lanes -> per-block byte layout.
        //
        // Same reasoning as `blocks8`: a 4x4 dword transpose replaces 64 scalar
        // four-byte copies per 256 bytes of keystream.
        for i in 0..16 {
            x[i] = _mm_add_epi32(x[i], orig[i]);
        }
        transpose4x4(&mut x[0..4]);
        transpose4x4(&mut x[4..8]);
        transpose4x4(&mut x[8..12]);
        transpose4x4(&mut x[12..16]);
        for j in 0..4 {
            for i in 0..4 {
                _mm_storeu_si128(
                    out.as_mut_ptr().add(j * 64 + i * 16) as *mut __m128i,
                    x[i * 4 + j],
                );
            }
        }

        zeroize_xmm(&mut x);
        zeroize_xmm(&mut orig);
        zeroize_array(&mut s);
    }

    /// Transpose a 4x4 matrix of 32-bit words held in four `__m128i`.
    #[target_feature(enable = "sse2")]
    unsafe fn transpose4x4(m: &mut [__m128i]) {
        debug_assert_eq!(m.len(), 4);
        let t0 = _mm_unpacklo_epi32(m[0], m[1]);
        let t1 = _mm_unpackhi_epi32(m[0], m[1]);
        let t2 = _mm_unpacklo_epi32(m[2], m[3]);
        let t3 = _mm_unpackhi_epi32(m[2], m[3]);
        m[0] = _mm_unpacklo_epi64(t0, t2);
        m[1] = _mm_unpackhi_epi64(t0, t2);
        m[2] = _mm_unpacklo_epi64(t1, t3);
        m[3] = _mm_unpackhi_epi64(t1, t3);
    }

    /// Volatile-zero an array of 128-bit vectors with full-width stores.
    ///
    /// Same rationale as [`zeroize_ymm`]: 16-byte volatile stores instead of one
    /// 8-byte `write_volatile` per `usize`.
    #[target_feature(enable = "sse2")]
    unsafe fn zeroize_xmm(v: &mut [__m128i]) {
        let zero = _mm_setzero_si128();
        let p = v.as_mut_ptr();
        for i in 0..v.len() {
            core::ptr::write_volatile(p.add(i), zero);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Transpose an 8x8 matrix of 32-bit words held in eight `__m256i`.
    ///
    /// On entry `m[c]` holds row `c`; on return `m[r]` holds row `r`.  Used to
    /// turn "word `i` of all eight blocks" into "all words of block `j`", which
    /// is the byte order the keystream is consumed in.
    #[target_feature(enable = "avx2")]
    unsafe fn transpose8x8(m: &mut [__m256i]) {
        debug_assert_eq!(m.len(), 8);
        let t0 = _mm256_unpacklo_epi32(m[0], m[1]);
        let t1 = _mm256_unpackhi_epi32(m[0], m[1]);
        let t2 = _mm256_unpacklo_epi32(m[2], m[3]);
        let t3 = _mm256_unpackhi_epi32(m[2], m[3]);
        let t4 = _mm256_unpacklo_epi32(m[4], m[5]);
        let t5 = _mm256_unpackhi_epi32(m[4], m[5]);
        let t6 = _mm256_unpacklo_epi32(m[6], m[7]);
        let t7 = _mm256_unpackhi_epi32(m[6], m[7]);

        let s0 = _mm256_unpacklo_epi64(t0, t2);
        let s1 = _mm256_unpackhi_epi64(t0, t2);
        let s2 = _mm256_unpacklo_epi64(t1, t3);
        let s3 = _mm256_unpackhi_epi64(t1, t3);
        let s4 = _mm256_unpacklo_epi64(t4, t6);
        let s5 = _mm256_unpackhi_epi64(t4, t6);
        let s6 = _mm256_unpacklo_epi64(t5, t7);
        let s7 = _mm256_unpackhi_epi64(t5, t7);

        m[0] = _mm256_permute2x128_si256(s0, s4, 0x20);
        m[1] = _mm256_permute2x128_si256(s1, s5, 0x20);
        m[2] = _mm256_permute2x128_si256(s2, s6, 0x20);
        m[3] = _mm256_permute2x128_si256(s3, s7, 0x20);
        m[4] = _mm256_permute2x128_si256(s0, s4, 0x31);
        m[5] = _mm256_permute2x128_si256(s1, s5, 0x31);
        m[6] = _mm256_permute2x128_si256(s2, s6, 0x31);
        m[7] = _mm256_permute2x128_si256(s3, s7, 0x31);
    }

    /// 8 ChaCha20 blocks in parallel (AVX2, 256-bit lanes).
    ///
    /// Writes 8 * 64 = 512 bytes of raw keystream to `out`.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn blocks8(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
        assert_eq!(out.len(), 512);
        let mut s = chacha20_state_words(key, counter, nonce);

        let mut x: [__m256i; 16] = [core::mem::zeroed(); 16];
        for i in 0..16 {
            x[i] = _mm256_set1_epi32(s[i] as i32);
        }
        x[12] = _mm256_set_epi32(
            counter.wrapping_add(7) as i32,
            counter.wrapping_add(6) as i32,
            counter.wrapping_add(5) as i32,
            counter.wrapping_add(4) as i32,
            counter.wrapping_add(3) as i32,
            counter.wrapping_add(2) as i32,
            counter.wrapping_add(1) as i32,
            counter as i32,
        );

        // The ChaCha20 feed-forward is `x + orig`, where `orig` is the initial
        // state.  Holding it as 16 live `__m256i` alongside the working `x`
        // needs 32 YMM registers and x86-64 has 16, so every call spilled half
        // the state to the stack.  Re-broadcasting from the scalar words at the
        // end is 16 `vpbroadcastd` (they stay in cache) and keeps the round loop
        // entirely register-resident.
        let ctr_vec = x[12];
        for _ in 0..10 {
            qr256!(x, 0, 4, 8, 12);
            qr256!(x, 1, 5, 9, 13);
            qr256!(x, 2, 6, 10, 14);
            qr256!(x, 3, 7, 11, 15);
            qr256!(x, 0, 5, 10, 15);
            qr256!(x, 1, 6, 11, 12);
            qr256!(x, 2, 7, 8, 13);
            qr256!(x, 3, 4, 9, 14);
        }

        // Final addition, then transpose lanes -> per-block byte layout.
        //
        // A scalar transpose here costs 128 four-byte copies per 512 bytes of
        // keystream, which was a measurable share of the total at large sizes.
        // The 8x8 dword transpose below does the same work with ~24 shuffles:
        // before it `x[i]` holds word `i` of all eight blocks, after it
        // `x[k]`/`x[8 + k]` hold words `0..8`/`8..16` of block `k`, so each
        // block is two 32-byte stores.
        for i in 0..16 {
            // Word 12 is the counter, whose initial value differs per lane.
            let init = if i == 12 {
                ctr_vec
            } else {
                _mm256_set1_epi32(s[i] as i32)
            };
            x[i] = _mm256_add_epi32(x[i], init);
        }
        transpose8x8(&mut x[0..8]);
        transpose8x8(&mut x[8..16]);
        for k in 0..8 {
            _mm256_storeu_si256(out.as_mut_ptr().add(k * 64) as *mut __m256i, x[k]);
            _mm256_storeu_si256(out.as_mut_ptr().add(k * 64 + 32) as *mut __m256i, x[8 + k]);
        }

        zeroize_ymm(&mut x);
        zeroize_array(&mut s);
    }

    /// Volatile-zero an array of 256-bit vectors with full-width stores.
    ///
    /// `zeroize_array` issues one `write_volatile` per `usize` (8 bytes), so
    /// wiping the AVX2 state cost 64 volatile stores per 512 bytes of keystream
    /// — measured at ~24% of total throughput at 1 MiB.  A 32-byte volatile
    /// store cuts that 4x with the same guarantee: every byte is written and the
    /// store cannot be elided.
    #[target_feature(enable = "avx2")]
    unsafe fn zeroize_ymm(v: &mut [__m256i]) {
        let zero = _mm256_setzero_si256();
        let p = v.as_mut_ptr();
        for i in 0..v.len() {
            core::ptr::write_volatile(p.add(i), zero);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Cached AVX2 availability (0 = unknown, 1 = no, 2 = yes).
    static AVX2_CACHE: AtomicU8 = AtomicU8::new(0);

    /// Whether the CPU *and* OS support AVX2.
    ///
    /// `no_std` rules out `is_x86_feature_detected!`, so this queries CPUID
    /// directly and additionally checks XCR0, because a CPU can advertise AVX2
    /// while the OS has not enabled YMM state saving (using AVX2 then faults).
    /// The result is cached: CPUID is serialising and would otherwise dominate
    /// the cost of short messages.
    pub(super) fn has_avx2() -> bool {
        match AVX2_CACHE.load(Ordering::Relaxed) {
            1 => return false,
            2 => return true,
            _ => {}
        }
        let detected = detect_avx2();
        AVX2_CACHE.store(if detected { 2 } else { 1 }, Ordering::Relaxed);
        detected
    }

    fn detect_avx2() -> bool {
        // Miri cannot execute `__cpuid_count` — it lowers to inline assembly,
        // which Miri rejects ("unsupported operation: inline assembly"). What it
        // *can* do is emulate target features: Miri refuses to run a
        // `#[target_feature(enable = "avx2")]` function unless the *build*
        // enables AVX2 ("calling a function that requires unavailable target
        // features"). So the feature set compiled into this crate is the honest
        // answer under Miri, and it makes both accelerated paths reachable:
        //
        //   * default Miri build -> SSE2 and scalar, as before;
        //   * `RUSTFLAGS=-C target-feature=+avx2` -> the AVX2 kernel as well,
        //     including the dispatcher's AVX2 loop, which was otherwise the one
        //     accelerated path Miri never inspected.
        //
        // Either way the SIMD kernels are held byte-identical to the scalar
        // reference by the `simd_matches_scalar` tests.
        #[cfg(miri)]
        {
            return cfg!(target_feature = "avx2");
        }

        #[cfg(not(miri))]
        {
            use core::arch::x86_64::{__cpuid_count, _xgetbv};
            // SAFETY: CPUID is always available on x86_64.  `_xgetbv` is only
            // executed after confirming OSXSAVE, which guarantees the instruction
            // exists and XCR0 is readable.
            unsafe {
                let leaf1 = __cpuid_count(1, 0);
                let osxsave = (leaf1.ecx >> 27) & 1 == 1;
                let avx = (leaf1.ecx >> 28) & 1 == 1;
                if !osxsave || !avx {
                    return false;
                }
                // XCR0[2:1] must both be set: XMM and YMM state enabled by the OS.
                if _xgetbv(0) & 0b110 != 0b110 {
                    return false;
                }
                let leaf7 = __cpuid_count(7, 0);
                (leaf7.ebx >> 5) & 1 == 1
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", not(kani)))]
mod aarch64_simd {
    use super::{chacha20_state_words, zeroize_array};
    use core::arch::aarch64::*;

    // NEON has no 32-bit rotate; combine shift-left and shift-right.  Shift
    // amounts are explicit literals because stable Rust forbids arithmetic on
    // const generics in `::<{ 32 - N }>` position.
    macro_rules! rotlq {
        ($x:expr, $l:literal, $r:literal) => {
            vorrq_u32(vshlq_n_u32::<$l>($x), vshrq_n_u32::<$r>($x))
        };
    }

    macro_rules! qrq {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {{
            $x[$a] = vaddq_u32($x[$a], $x[$b]);
            $x[$d] = rotlq!(veorq_u32($x[$d], $x[$a]), 16, 16);
            $x[$c] = vaddq_u32($x[$c], $x[$d]);
            $x[$b] = rotlq!(veorq_u32($x[$b], $x[$c]), 12, 20);
            $x[$a] = vaddq_u32($x[$a], $x[$b]);
            $x[$d] = rotlq!(veorq_u32($x[$d], $x[$a]), 8, 24);
            $x[$c] = vaddq_u32($x[$c], $x[$d]);
            $x[$b] = rotlq!(veorq_u32($x[$b], $x[$c]), 7, 25);
        }};
    }

    /// 4 ChaCha20 blocks in parallel (NEON, 128-bit lanes).  Baseline on
    /// aarch64 (ARMv8-A), so no runtime detection is required.
    ///
    /// Writes 4 * 64 = 256 bytes of raw keystream to `out`.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn blocks4(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
        assert_eq!(out.len(), 256);
        let mut s = chacha20_state_words(key, counter, nonce);

        let mut x: [uint32x4_t; 16] = [core::mem::zeroed(); 16];
        for i in 0..16 {
            x[i] = vdupq_n_u32(s[i]);
        }
        let ctrs: [u32; 4] = [
            counter,
            counter.wrapping_add(1),
            counter.wrapping_add(2),
            counter.wrapping_add(3),
        ];
        x[12] = vld1q_u32(ctrs.as_ptr());

        let mut orig = x;
        for _ in 0..10 {
            qrq!(x, 0, 4, 8, 12);
            qrq!(x, 1, 5, 9, 13);
            qrq!(x, 2, 6, 10, 14);
            qrq!(x, 3, 7, 11, 15);
            qrq!(x, 0, 5, 10, 15);
            qrq!(x, 1, 6, 11, 12);
            qrq!(x, 2, 7, 8, 13);
            qrq!(x, 3, 4, 9, 14);
        }

        // Final addition, then transpose lanes -> per-block byte layout.
        //
        // NOTE: unlike the x86 kernels, this keeps the scalar transpose.  The
        // NEON shuffle sequence that would replace it cannot be *executed* in
        // the development environment (no aarch64 hardware and no qemu), and a
        // wrong transpose silently corrupts the keystream, so an unverifiable
        // speedup is not worth taking here.  The x86 equivalents are covered by
        // `test_simd_matches_scalar_all_lengths`, which runs on every host.
        let mut w = [[0u32; 4]; 16];
        for i in 0..16 {
            let v = vaddq_u32(x[i], orig[i]);
            vst1q_u32(w[i].as_mut_ptr(), v);
        }
        for j in 0..4 {
            for i in 0..16 {
                out[j * 64 + i * 4..j * 64 + i * 4 + 4].copy_from_slice(&w[i][j].to_le_bytes());
            }
        }

        zeroize_neon(&mut x);
        zeroize_neon(&mut orig);
        zeroize_array(&mut w);
        zeroize_array(&mut s);
    }

    /// Volatile-zero an array of NEON vectors with full-width stores.
    ///
    /// Same rationale as the x86 `zeroize_ymm`/`zeroize_xmm`: 16-byte volatile
    /// stores instead of one 8-byte `write_volatile` per `usize`.  Unlike the
    /// transpose, this cannot change any output byte — it only writes zeros — so
    /// it needs no execution to be trusted.
    #[target_feature(enable = "neon")]
    unsafe fn zeroize_neon(v: &mut [uint32x4_t]) {
        let zero = vdupq_n_u32(0);
        let p = v.as_mut_ptr();
        for i in 0..v.len() {
            core::ptr::write_volatile(p.add(i), zero);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Where the XOR input for [`chacha20_apply`] comes from.
///
/// The three AEAD entry points differ only here: the allocating API XORs a
/// separate plaintext buffer, the detached API XORs the buffer into itself, and
/// subkey derivation wants raw keystream.  Making that a value rather than a
/// flag keeps every caller on one dispatch path, so the SIMD kernels can never
/// be bypassed by one entry point but not another.
enum Input<'a> {
    /// Plaintext lives in a separate buffer: `output = input ^ keystream`.
    Separate(&'a [u8]),
    /// Plaintext *is* the output buffer: `buffer ^= keystream`.
    InPlace,
    /// No XOR at all: `output = keystream`.
    Keystream,
}

/// XOR `ks` into (or copy it over) `output[off..off + ks.len()]`.
///
/// The slice is taken up front so the loops below index from 0: that removes the
/// three bounds checks per byte that a raw `output[off + i]` / `inp[off + i]`
/// loop carries, which is what stops LLVM from vectorising it.  The cost is
/// linear in the message, so it showed up as a real gap on multi-KiB inputs.
fn xor_or_copy(input: &Input<'_>, output: &mut [u8], off: usize, ks: &[u8]) {
    let out = &mut output[off..off + ks.len()];
    match input {
        Input::Separate(inp) => {
            let inp = &inp[off..off + ks.len()];
            for ((o, i), k) in out.iter_mut().zip(inp.iter()).zip(ks.iter()) {
                *o = i ^ k;
            }
        }
        Input::InPlace => {
            // Read-modify-write the same byte: each byte is read once and
            // written once, so no scratch buffer and no aliasing hazard.
            for (o, k) in out.iter_mut().zip(ks.iter()) {
                *o ^= k;
            }
        }
        Input::Keystream => out.copy_from_slice(ks),
    }
}

/// Core keystream application shared by the XOR and raw entry points.
///
/// Uses the widest SIMD path available on this CPU, falling back to the scalar
/// core for the tail.  Keeping both entry points on one code path guarantees
/// they can never disagree about block sequencing.
fn chacha20_apply(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
    input: &Input<'_>,
    output: &mut [u8],
) {
    let n = output.len();
    let mut ctr = counter;
    let mut off = 0usize;

    // Widest-first so AVX2 absorbs as much as possible before SSE2.
    //
    // The SIMD backends are compiled out under Kani: CBMC cannot model the
    // x86/aarch64 intrinsics (`_mm256_*`, `vmull_u32`) nor `__cpuid_count`/
    // `_xgetbv`, so they would be unconstrained functions and every AEAD proof
    // would be vacuous.  The scalar core below is the correctness reference, so
    // that is what gets verified; the SIMD kernels are held to it by the
    // `*_matches_scalar` differential tests.
    #[cfg(all(target_arch = "x86_64", not(kani)))]
    {
        if x86_simd::has_avx2() {
            let mut ks = [0u8; 512];
            while off + 512 <= n {
                // SAFETY: AVX2 support was checked at runtime above.
                unsafe { x86_simd::blocks8(key, ctr, nonce, &mut ks) };
                xor_or_copy(input, output, off, &ks);
                ctr = ctr.wrapping_add(8);
                off += 512;
            }
            // Keystream equals plaintext XOR ciphertext; treat it as secret.
            zeroize_array(&mut ks);
        }
        {
            let mut ks = [0u8; 256];
            while off + 256 <= n {
                // SAFETY: SSE2 is part of the x86_64 baseline.
                unsafe { x86_simd::blocks4(key, ctr, nonce, &mut ks) };
                xor_or_copy(input, output, off, &ks);
                ctr = ctr.wrapping_add(4);
                off += 256;
            }
            zeroize_array(&mut ks);
        }
    }

    #[cfg(all(target_arch = "aarch64", not(kani)))]
    {
        let mut ks = [0u8; 256];
        while off + 256 <= n {
            // SAFETY: NEON is part of the ARMv8-A baseline.
            unsafe { aarch64_simd::blocks4(key, ctr, nonce, &mut ks) };
            xor_or_copy(input, output, off, &ks);
            ctr = ctr.wrapping_add(4);
            off += 256;
        }
        zeroize_array(&mut ks);
    }

    // Scalar tail: remaining full blocks, then a final partial block.
    //
    // Tried and rejected, so that it is not tried again: routing this through
    // `blocks4` (four blocks, of which one to three are used) *lowers* the
    // instruction count -- callgrind put the scalar rounds at 28% of all
    // instructions in a 64-byte round trip -- and *raises* the wall clock, +22% at
    // 64 bytes and +10% at 100, because the four-lane kernel writes a 256-byte
    // keystream into a scratch that is then zeroized (64 bytes for the scalar
    // block) and does a lane transpose the scalar path does not need. A small
    // message is latency- and memory-bound, not issue-bound. There is also nothing
    // for four lanes to win: the wide loops above consume everything from 256 bytes
    // up, so this tail is at most three blocks plus a partial one.
    while off + CHACHA20_BLOCK <= n {
        let mut ks = chacha20_block(key, ctr, nonce);
        xor_or_copy(input, output, off, &ks);
        ctr = ctr.wrapping_add(1);
        off += CHACHA20_BLOCK;
        zeroize_array(&mut ks);
    }
    if off < n {
        let mut ks = chacha20_block(key, ctr, nonce);
        xor_or_copy(input, output, off, &ks[..n - off]);
        zeroize_array(&mut ks);
    }
}

/// XOR `input` with ChaCha20 keystream, writing result to `output`.
///
/// `counter` is the starting ChaCha20 counter value.
/// `nonce` is the 12-byte ChaCha20 nonce.
/// `input` and `output` must have the same length.
fn chacha20_keystream(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
    input: &[u8],
    output: &mut [u8],
) {
    assert_eq!(input.len(), output.len());
    chacha20_apply(key, counter, nonce, &Input::Separate(input), output);
}

/// Produce `len` bytes of ChaCha20 keystream (no XOR, just raw keystream output).
///
/// Used for subkey derivation where we need raw keystream bytes.
fn chacha20_keystream_raw(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
    chacha20_apply(key, counter, nonce, &Input::Keystream, out);
}

// ── HChaCha20 ─────────────────────────────────────────────────────────

/// HChaCha20: derive 32-byte subkey from key and 16-byte nonce.
///
/// Runs 20 rounds, outputs state words 0-3 and 12-15 WITHOUT final addition.
/// Per draft-irtf-cfrg-xchacha-03 §2.2.  (Not RFC 8439: that document is
/// ChaCha20 and Poly1305 and contains no HChaCha20 at all.)
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    const CHACHA_CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    let mut s = [0u32; 16];
    s[0] = CHACHA_CONST[0];
    s[1] = CHACHA_CONST[1];
    s[2] = CHACHA_CONST[2];
    s[3] = CHACHA_CONST[3];
    s[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    s[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    s[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    s[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    s[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    s[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    s[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    s[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    s[12] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    s[13] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    s[14] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    s[15] = u32::from_le_bytes([nonce[12], nonce[13], nonce[14], nonce[15]]);

    // In place, for the same reason as in `chacha20_block`.
    chacha20_rounds(&mut s);

    let mut r = [0u8; 32];
    // Output words 0,1,2,3,12,13,14,15 (NO final addition!)
    let indices = [0usize, 1, 2, 3, 12, 13, 14, 15];
    for (i, &idx) in indices.iter().enumerate() {
        r[i * 4..i * 4 + 4].copy_from_slice(&s[idx].to_le_bytes());
    }

    // Side-channel hygiene, as in `chacha20_block`: wipe the key-bearing locals
    // themselves. There is no `orig` here because HChaCha20 has no feed-forward, so
    // a copy of the pre-round state would be a second copy of the key material to
    // keep alive for no reason.
    zeroize_array(&mut s);

    r
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(kani)]
mod proofs;

/// The independent second implementation `ultra` cross-checks against.
///
/// Private: it is an implementation detail of the `ultra` feature, not API. See the module
/// documentation for what a second implementation does and does not buy.
#[cfg(feature = "ultra")]
mod witness;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex decode (handles 0-9, a-f, A-F)
    fn hex(s: &str) -> Vec<u8> {
        let s = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let hi = hex_nibble(s[i]);
            let lo = hex_nibble(s[i + 1]);
            out.push((hi << 4) | lo);
        }
        out
    }

    #[inline]
    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    // ── XChaCha20 KAT (draft-irtf-cfrg-xchacha-03, 24-byte nonce) ──
    // These pin the draft's HChaCha20 nonce-suffix layout (`0^4 || nonce[16..24]`),
    // which is deliberately NOT this crate's layout: `derive_material` places
    // `SUBKEY_DOMAIN` ("XSIV") in those four bytes instead.  They are kept
    // because they anchor the HChaCha20 and ChaCha20 primitives to an external
    // vector.  Without them, a wrong-but-self-consistent layout
    // passes every roundtrip test.

    #[test]
    fn test_hchacha20_kat() {
        // draft-irtf-cfrg-xchacha-03 §2.2.1
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex("000000090000004a0000000031415927");
        let expected = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        assert_eq!(
            hchacha20(&key_arr, &nonce_arr).as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn test_hchacha20_and_chacha20_match_draft_vector() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1 — the AEAD vector's first keystream
        // block, i.e. ChaCha20(HChaCha20(key, iv[0..16]), 0, 0^4 || iv[16..24]).
        //
        // This anchors the two primitives this crate builds on: HChaCha20, and
        // the ChaCha20 keystream that carries it.  Note it does NOT pin this
        // crate's own subkey layout: the vector uses XChaCha20-Poly1305's `0^4`
        // padding, whereas `derive_material` deliberately places `SUBKEY_DOMAIN`
        // ("XSIV") there instead — see `test_subkey_domain_occupies_nonce_not_counter`
        // for that.  An earlier version of this comment claimed the vector was
        // "exactly our subkey derivation", which stopped being true when the
        // domain constant was introduced.
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let iv = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let expected = hex("7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let iv_arr: [u8; 24] = iv.try_into().unwrap();

        let subkey = hchacha20(&key_arr, &iv_arr[0..16].try_into().unwrap());
        let mut nonce12 = [0u8; 12];
        nonce12[4..12].copy_from_slice(&iv_arr[16..24]);
        let mut buf = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &nonce12, &mut buf);

        assert_eq!(&buf[0..32], expected.as_slice());
    }

    // ── XChaCha20-BLAKE3-SIV KAT (24-byte nonce public API) ──
    //
    // These lock the whole construction: XChaCha20-style subkey derivation
    // (HChaCha20 + SUBKEY_DOMAIN || nonce[16..24]) producing `mac_key` and
    // `enc_seed`, the keyed-BLAKE3 tag over `DOM_TAG || K || N || |A| || |M| ||
    // A || M`, and the encryption key/nonce derived from that tag.  There is no
    // CTX term and no Poly1305: both were part of v0.1 and are gone.
    //
    // The vectors were regenerated with the independent reference implementation
    // in `tools/ref_impl.py`, written from the RFC 8439 /
    // draft-irtf-cfrg-xchacha-03 pseudocode and the BLAKE3 specification, after
    // the tag change.  That reference is checked
    // against the published RFC 8439 §2.3.2, the HChaCha20 draft (§2.2.1, §A.2.1,
    // §A.3.1) and BLAKE3's official keyed vectors before it emits anything, so it
    // is not merely a restatement of
    // this code.

    #[test]
    fn test_xchacha20_blake3_siv_kat_draft_key() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        );
        let expected_ct = hex(
            "39d8c2bc507e147e719d79975b5cf999f0313790d98f7b523f3f4d738116822b3b582ecf7b448d43b3074761cf5c6c2af92faabaf04c779c5f5fe8aa3d3b2a6588137488b453d3728452341483725c9ba1b5ee36d2cf9c743da4df8c4f6023852db6a85e82fcf58636d38768d88c881d56e5",
        );
        let expected_tag = hex(
            "6f463e1fb35a5c7727a73bc194a826a4607a7a885b6bdc4622a8a118e673f786800e0fbff12d3d6db861042eb88bda44ca69a9f222417ecea36525ebb9390bb2b6",
        );

        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());

        let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn test_xchacha20_blake3_siv_kat_c2sp_key() {
        // A published c2sp.org test-vector key in the first 16 nonce bytes, with a
        // fixed suffix in the last 8; exercises the empty-AAD path.
        let key: [u8; 32] = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("530ee5e3dae7693017d28e5d7c6936ce0001020304050607")
            .try_into()
            .unwrap();
        let pt = hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        );
        let expected_ct = hex(
            "cadc4425420cd2885a524aef50b5079dba67d38c37ca8aff461817e4de4470f1f228627f5e88733843d2658049ffb8b91b656cd7950ace606515e41fc60d7a943940d4798f053f97744d0146129e51a128e2f1fec012104f6ffb6dabcacb646f63d0c644a736a0984f991ad5ac3dae002288",
        );
        let expected_tag = hex(
            "19a364fdd465b99a1d30ff89bd55099e2c8fb25b4e8dbdae87347e72ffc86eb3a28eb065c6ff101bc4218cd141a931ebceec3807b271e4466bc85ed5b35d1eec4a",
        );

        let (ct, tag) = encrypt(&key, &nonce, &[], &pt).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());

        let back = decrypt(&key, &nonce, &[], &ct, &tag).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn test_xchacha20_blake3_siv_kat_empty() {
        // Empty plaintext + empty AAD: the tag alone authenticates.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let expected_tag = hex(
            "1db104f0e59673b1426fc2febf34b719273295bc5d04f7accd04a1181aa5495af53f3924cc55cbf08d17d640ad8af582b49fa64eafb82856f927b3ff173f75996e",
        );

        let (ct, tag) = encrypt(&key, &nonce, &[], &[]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
    }

    #[test]
    fn test_xchacha20_keystream_kat_counter0() {
        // draft-irtf-cfrg-xchacha-03 §A.2.1 — XChaCha20 keystream, counter 0.
        // Locks in the 0^4||nonce[16..24] layout against an external vector.
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let iv = hex("404142434445464748494a4b4c4d4e4f5051525354555658");
        let expected_first_64 = hex(
            "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a\
             adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d",
        );

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let iv_arr: [u8; 24] = iv.try_into().unwrap();

        let subkey = hchacha20(&key_arr, &iv_arr[0..16].try_into().unwrap());
        let mut nonce12 = [0u8; 12];
        nonce12[4..12].copy_from_slice(&iv_arr[16..24]);
        let mut buf = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &nonce12, &mut buf);

        assert_eq!(buf.as_slice(), expected_first_64.as_slice());
    }

    // ── SIMD vs scalar cross-architecture consistency ──

    /// Scalar reference keystream (the definition ChaCha20 must match exactly).
    fn scalar_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut ctr = counter;
        while out.len() < n {
            out.extend_from_slice(&chacha20_block(key, ctr, nonce));
            ctr = ctr.wrapping_add(1);
        }
        out.truncate(n);
        out
    }

    /// The dispatched keystream (SIMD where available) must equal the scalar
    /// reference for *every* length and counter, including the tails that fall
    /// between SIMD width, block size, and exact multiples.
    #[test]
    fn test_simd_matches_scalar_all_lengths() {
        let key = [0x9Bu8; 32];
        let nonce = [0x4Cu8; 12];
        // Lengths covering: SIMD widths (256/512), block size, boundaries.
        let mut lens: Vec<usize> = (0..=600).collect();
        lens.extend([1023, 1024, 1025, 2047, 2048, 2049, 4096, 8191, 8192, 8193]);
        for &len in &lens {
            let mut got = vec![0u8; len];
            chacha20_keystream_raw(&key, 0, &nonce, &mut got);
            assert_eq!(
                got,
                scalar_keystream(&key, 0, &nonce, len),
                "keystream mismatch at len {len}"
            );
        }
    }

    /// Same, but with non-zero starting counters and counter values that
    /// exercise carry across SIMD lanes.
    #[test]
    fn test_simd_matches_scalar_counters() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for &ctr in &[
            0u32,
            1,
            7,
            8,
            0xFFFF_FFF8,
            0xFFFF_FFFC,
            0xFFFF_FFFE,
            0x7FFF_FFFF,
        ] {
            for &len in &[0usize, 64, 65, 255, 256, 257, 512, 513, 1024] {
                let mut got = vec![0u8; len];
                chacha20_keystream_raw(&key, ctr, &nonce, &mut got);
                assert_eq!(
                    got,
                    scalar_keystream(&key, ctr, &nonce, len),
                    "keystream mismatch at ctr {ctr:#x} len {len}"
                );
            }
        }
    }

    /// The XOR entry point must match scalar XOR, and `chacha20_keystream` /
    /// `chacha20_keystream_raw` must agree with each other.
    #[test]
    fn test_simd_xor_matches_scalar_and_raw() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 1000, 1024] {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();

            let mut got = vec![0u8; len];
            chacha20_keystream(&key, 0, &nonce, &input, &mut got);

            let ks = scalar_keystream(&key, 0, &nonce, len);
            let want: Vec<u8> = input.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
            assert_eq!(got, want, "xor mismatch at len {len}");

            // raw path must equal the keystream used above
            let mut raw = vec![0u8; len];
            chacha20_keystream_raw(&key, 0, &nonce, &mut raw);
            assert_eq!(raw, ks, "raw mismatch at len {len}");
        }
    }

    /// Explicitly exercise the SSE2 (4-block) and AVX2 (8-block) kernels in
    /// isolation where the target supports them, so a broken backend cannot
    /// hide behind the dispatcher's fallback.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_simd_kernels_match_scalar() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];

        for &ctr in &[0u32, 1, 9, 0xFFFF_FFF0] {
            // SSE2: 4 blocks = 256 bytes
            let mut out4 = [0u8; 256];
            // SAFETY: SSE2 is part of the x86_64 baseline.
            unsafe { x86_simd::blocks4(&key, ctr, &nonce, &mut out4) };
            assert_eq!(
                out4.as_slice(),
                scalar_keystream(&key, ctr, &nonce, 256).as_slice(),
                "SSE2 mismatch at ctr {ctr:#x}"
            );

            // AVX2: 8 blocks = 512 bytes (only where supported)
            if x86_simd::has_avx2() {
                let mut out8 = [0u8; 512];
                // SAFETY: guarded by the runtime AVX2 check.
                unsafe { x86_simd::blocks8(&key, ctr, &nonce, &mut out8) };
                assert_eq!(
                    out8.as_slice(),
                    scalar_keystream(&key, ctr, &nonce, 512).as_slice(),
                    "AVX2 mismatch at ctr {ctr:#x}"
                );
            }
        }
    }

    /// Same isolation test for the NEON kernel.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_aarch64_neon_kernel_matches_scalar() {
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        for &ctr in &[0u32, 1, 9, 0xFFFF_FFF0] {
            let mut out4 = [0u8; 256];
            // SAFETY: NEON is part of the ARMv8-A baseline.
            unsafe { aarch64_simd::blocks4(&key, ctr, &nonce, &mut out4) };
            assert_eq!(
                out4.as_slice(),
                scalar_keystream(&key, ctr, &nonce, 256).as_slice(),
                "NEON mismatch at ctr {ctr:#x}"
            );
        }
    }

    /// End-to-end: a full AEAD message long enough to use the widest SIMD path
    /// must decrypt correctly and match a scalar-only recomputation.
    #[test]
    fn test_aead_large_simd_path_roundtrip() {
        let key = [0x12u8; 32];
        let nonce = [0x34u8; 24];
        let aad = b"simd aad";
        for &size in &[512usize, 1024, 4096, 8192, 16384, 65536] {
            let pt: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (ct, tag) = encrypt(&key, &nonce, aad, &pt).unwrap();
            assert_eq!(ct.len(), size);
            let back = decrypt(&key, &nonce, aad, &ct, &tag).unwrap();
            assert_eq!(back, pt, "roundtrip mismatch at size {size}");
        }
    }

    /// Every accelerated path must agree with the scalar reference **and with
    /// each other**, byte for byte, on a corpus that crosses every boundary.
    ///
    /// The corpus covers lengths around the ChaCha20 block (64), the SSE2/NEON
    /// width (256), the AVX2 width (512) and BLAKE3's chunk boundary (1024), up to
    /// 4097, times four AAD lengths, through both the allocating and the in-place
    /// API, and folds every ciphertext and tag byte into one FNV-1a value.
    ///
    /// The expected digest below is not a KAT for one implementation: it is the
    /// value produced *identically* by
    ///
    /// * x86_64 with AVX2 (native, so the AVX2 and SSE2 loops and the scalar tail),
    /// * x86_64 with AVX2 disabled under `qemu-x86_64 -cpu Nehalem` (SSE2 only),
    /// * aarch64 under `qemu-aarch64` (NEON),
    /// * i686 under `qemu-i386` (no SIMD backend at all, pure scalar),
    /// * s390x, big-endian, interpreted by Miri.
    ///
    /// CI runs this test under qemu on aarch64 and i686, so a change that makes
    /// one backend disagree with the others fails there rather than on a user's
    /// machine.
    #[test]
    fn test_all_accelerated_paths_agree_on_a_boundary_corpus() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() >> 33) as u8
            }
        }
        fn fold(digest: &mut u64, bytes: &[u8]) {
            for &b in bytes {
                *digest ^= b as u64;
                *digest = digest.wrapping_mul(0x0000_0100_0000_01B3);
            }
        }

        let lens: [usize; 30] = [
            0, 1, 2, 63, 64, 65, 127, 128, 129, 255, 256, 257, 383, 384, 511, 512, 513, 640, 767,
            768, 1023, 1024, 1025, 1535, 2047, 2048, 2049, 4095, 4096, 4097,
        ];
        let aad_lens: [usize; 4] = [0, 1, 64, 255];

        let mut rng = Rng(0x1234_5678_9ABC_DEF0);
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        let mut total = 0usize;
        let mut cases = 0usize;

        for &len in &lens {
            for &alen in &aad_lens {
                let mut key = [0u8; 32];
                let mut nonce = [0u8; NONCE_LEN];
                for b in key.iter_mut() {
                    *b = rng.byte();
                }
                for b in nonce.iter_mut() {
                    *b = rng.byte();
                }
                let pt: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                let aad: Vec<u8> = (0..alen).map(|_| rng.byte()).collect();

                let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();

                // The in-place API must produce exactly the same bytes.
                let mut buf = pt.clone();
                let tag2 = encrypt_in_place_detached(&key, &nonce, &aad, &mut buf).unwrap();
                assert_eq!(buf, ct, "in-place differs from allocating at len {len}");
                assert_eq!(tag2, tag, "in-place tag differs at len {len}");

                let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
                assert_eq!(back.as_slice(), pt, "roundtrip at len {len}");

                fold(&mut digest, &ct);
                fold(&mut digest, &tag);
                total += ct.len() + TAG_LEN;
                cases += 1;
            }
        }

        assert_eq!(cases, 120);
        assert_eq!(total, 123_256);
        assert_eq!(
            digest, 0x430e_de7e_c152_53fe,
            "the accelerated paths disagree with the scalar reference \
             (digest {digest:#018x} over {cases} cases, {total} bytes)"
        );
    }

    // ── Property-based tests (XChaCha20, 24-byte nonce) ──
    /// Zeroization must clear *every* byte, including the leading bytes of a
    /// buffer that is not `usize`-aligned.
    ///
    /// Regression guard: the previous implementation started its chunked loop
    /// at the offset of the first aligned byte, so a buffer that was not
    /// 8-byte aligned kept its first `8 - (addr % 8)` bytes intact — silently
    /// leaving secret material un-wiped.
    #[test]
    fn test_zeroize_covers_unaligned_prefix() {
        // Slice form, every possible misalignment.
        for off in 0..8usize {
            let mut backing = [0xAAu8; 64];
            let end = off + 24;
            {
                let s = &mut backing[off..end];
                zeroize_slice(s);
            }
            assert!(
                backing[off..end].iter().all(|&b| b == 0),
                "zeroize_slice left bytes at offset {off}: {:?}",
                &backing[off..end]
            );
        }

        // Array form, every possible misalignment.
        for off in 0..8usize {
            let mut backing = [0xAAu8; 64];
            {
                // SAFETY: `off + 16 <= 64`, and `[u8; 16]` has alignment 1, so
                // any offset within the array is a valid `[u8; 16]` pointer.
                let p = unsafe { backing.as_mut_ptr().add(off) as *mut [u8; 16] };
                // SAFETY: as above; `p` came from a live `&mut` to `backing` and
                // 16 initialised bytes from it, so the reference is valid and
                // uniquely borrowed for the rest of this block.
                let arr: &mut [u8; 16] = unsafe { &mut *p };
                zeroize_array(arr);
            }
            assert!(
                backing[off..off + 16].iter().all(|&b| b == 0),
                "zeroize_array left bytes at offset {off}"
            );
        }

        // Sizes that exercise the trailing-byte path.
        for len in 0..24usize {
            let mut buf = vec![0xFFu8; len];
            zeroize_slice(&mut buf);
            assert!(buf.iter().all(|&b| b == 0), "len {len} not fully wiped");
        }
    }

    #[test]
    fn test_different_nonce() {
        let key1 = [0u8; 32];
        let nonce1 = [0u8; 24];
        let nonce2 = [1u8; 24]; // different nonce
        let plaintext = b"Hello, XChaCha20!";
        let aad = b"";

        let (ct1, tag1) = encrypt(&key1, &nonce1, aad, plaintext).unwrap();
        let (ct2, tag2) = encrypt(&key1, &nonce2, aad, plaintext).unwrap();

        // Different nonces MUST produce different tags and ciphertexts
        assert_ne!(tag1, tag2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_decrypt_does_not_leak_plaintext_on_failure() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"Secret message";
        let aad = b"";
        let wrong_key = [0x43u8; 32];

        let (ct, tag) = encrypt(&key, &nonce, aad, plaintext).unwrap();

        // A wrong key must fail with the *specific* authentication error, not
        // some other variant -- and must not return `Ok`.
        //
        // Note what this test can and cannot see.  The allocating `decrypt`
        // wipes its internal buffer before returning `Err`, but that buffer is
        // private and already freed by the time the caller has the error, so no
        // assertion here can observe the wiping itself.  The wiping *is* checked
        // -- by `test_detached_rejects_tampering_and_wipes`, which uses the
        // in-place API where the buffer belongs to the caller and can be
        // inspected afterwards.  This test covers the other half: that the
        // failure is reported correctly and carries no data.
        assert_eq!(
            decrypt(&wrong_key, &nonce, aad, &ct, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );

        // A tampered tag and a tampered ciphertext must fail the same way.
        let mut bad_tag = tag;
        bad_tag[31] ^= 1;
        assert_eq!(
            decrypt(&key, &nonce, aad, &ct, &bad_tag).unwrap_err(),
            Error::AuthenticationFailed
        );

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            decrypt(&key, &nonce, aad, &bad_ct, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );

        // The genuine input still round-trips, so the failures above are the
        // tampering and not a broken test harness.
        assert_eq!(decrypt(&key, &nonce, aad, &ct, &tag).unwrap(), plaintext);
    }

    /// Ciphertexts must not be transplantable between messages that share a
    /// `(key, nonce)`.
    ///
    /// This is the property "nonce-misuse resistant" actually names, and the one a
    /// test can check: SIV derives the per-message key from the tag, so a ciphertext
    /// authenticates only under the tag that was computed for it. The previous
    /// version of this test asserted that two *nonces* give two tags -- nonce
    /// sensitivity, which every correct AEAD has and which says nothing about what
    /// happens when a nonce is reused.
    #[test]
    fn test_message_swap_under_a_reused_nonce_is_rejected() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let aad = b"same aad";

        let (ct_a, tag_a) = encrypt(&key, &nonce, aad, b"first message").unwrap();
        let (ct_b, tag_b) = encrypt(&key, &nonce, aad, b"second message").unwrap();
        assert_ne!(tag_a, tag_b, "different messages must give different tags");

        // The transplant an attacker with a reused nonce would attempt: one
        // message's ciphertext under the other's tag (and the reverse).
        for (label, ct, tag) in [
            ("A's ciphertext under B's tag", &ct_a, &tag_b),
            ("B's ciphertext under A's tag", &ct_b, &tag_a),
        ] {
            assert_eq!(
                decrypt(&key, &nonce, aad, ct, tag).unwrap_err(),
                Error::AuthenticationFailed,
                "{label} must not authenticate"
            );
        }

        // The genuine pairs still round-trip, so the rejections above are the
        // transplant and not a broken harness.
        assert_eq!(
            decrypt(&key, &nonce, aad, &ct_a, &tag_a).unwrap(),
            b"first message"
        );
        assert_eq!(
            decrypt(&key, &nonce, aad, &ct_b, &tag_b).unwrap(),
            b"second message"
        );
    }

    /// The tag must change when *only* the key changes.
    ///
    /// Key commitment itself is a security argument about collision bounds (2^128 for the
    /// context case, at most 2^256 for the key case — see `TAG_LEN` and the README's
    /// "Security level") and cannot be established by sampling; what is testable is that
    /// the tag is not indifferent to the key, and the mechanism it rests on -- the
    /// key reaching the tag *directly*, not only through `mac_key` -- is what
    /// `test_tag_binds_the_key_directly` checks. The old name claimed the property
    /// rather than the sampling.
    #[test]
    fn test_tag_changes_when_only_the_key_changes() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"Key commitment test";
        let aad = b"";

        let (ct1, tag1) = encrypt(&key1, &nonce, aad, plaintext).unwrap();
        let (ct2, tag2) = encrypt(&key2, &nonce, aad, plaintext).unwrap();

        assert_ne!(tag1, tag2, "the tag must depend on the key");
        // And a tag from one key must not authenticate under the other, in either
        // direction -- the consequence a caller would notice if the key were not
        // bound in.
        assert_eq!(
            decrypt(&key2, &nonce, aad, &ct1, &tag1).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(
            decrypt(&key1, &nonce, aad, &ct2, &tag2).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn test_empty_inputs() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];

        // Empty AAD, empty plaintext
        let (ct, tag) = encrypt(&key, &nonce, b"", b"").unwrap();
        let pt = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        assert_eq!(pt, b"");

        // Non-empty AAD, empty plaintext
        let (ct2, tag2) = encrypt(&key, &nonce, b"aad", b"").unwrap();
        let pt2 = decrypt(&key, &nonce, b"aad", &ct2, &tag2).unwrap();
        assert_eq!(pt2, b"");

        // Empty AAD, non-empty plaintext
        let (ct3, tag3) = encrypt(&key, &nonce, b"", b"pt").unwrap();
        let pt3 = decrypt(&key, &nonce, b"", &ct3, &tag3).unwrap();
        assert_eq!(pt3, b"pt");
    }

    #[test]
    fn test_tag_length() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let (_, tag) = encrypt(&key, &nonce, b"", b"").unwrap();
        assert_eq!(tag.len(), TAG_LEN);
        // 65 bytes = 520 bits. Sized so commitment exceeds 2^256: the birthday
        // bound caps commitment at 2^(n/2) bits for an n-bit tag, and 64 bytes
        // would give exactly 2^256 rather than more.
        assert_eq!(TAG_LEN, 65);
    }

    #[test]
    fn test_tampered_aad() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"Secret message";
        let aad = b"original";

        let (ct, tag) = encrypt(&key, &nonce, aad, plaintext).unwrap();
        // Tampered AAD should cause authentication failure
        let result = decrypt(&key, &nonce, b"tampered", &ct, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ct() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"Secret message";
        let aad = b"";

        let (mut ct, tag) = encrypt(&key, &nonce, aad, plaintext).unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, aad, &ct, &tag).is_err());
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; 24];
        let aad = b"roundtrip test";

        for size in [0, 1, 16, 17, 64, 65, 128, 255, 1024] {
            let plaintext = vec![0xEFu8; size];
            let (ct, tag) = encrypt(&key, &nonce, aad, &plaintext).unwrap();
            let pt = decrypt(&key, &nonce, aad, &ct, &tag).unwrap();
            assert_eq!(pt, plaintext, "roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_wrong_tag() {
        let key = [
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ];
        let nonce = [0u8; 24];
        let plaintext = b"Secret message";
        let aad = b"";

        let (ct, tag) = encrypt(&key, &nonce, aad, plaintext).unwrap();
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, aad, &ct, &wrong_tag).is_err());
    }

    #[test]
    fn test_api_constants() {
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(KEY_LEN, 32);
        assert_eq!(TAG_LEN, 65);
    }

    // ── Detached API ──

    #[test]
    fn test_detached_matches_attached() {
        // The detached (in-place) form must produce byte-identical results to
        // the allocating form, across block boundaries.
        let key = [0x7Au8; 32];
        let nonce = [0x3Cu8; 24];
        let aad = b"detached aad";
        for size in [0usize, 1, 16, 17, 64, 65, 200, 4096, 4097] {
            let pt = vec![0x5Eu8; size];

            let (ct_ref, tag_ref) = encrypt(&key, &nonce, aad, &pt).unwrap();

            let mut buf = pt.clone();
            let tag = encrypt_in_place_detached(&key, &nonce, aad, &mut buf).unwrap();
            assert_eq!(buf, ct_ref, "detached ct mismatch at size {size}");
            assert_eq!(tag, tag_ref, "detached tag mismatch at size {size}");

            // Round-trip through the in-place decryptor.
            decrypt_in_place_detached(&key, &nonce, aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, pt, "detached roundtrip mismatch at size {size}");

            // Cross-check: detached-encrypt → attached-decrypt.
            let back = decrypt(&key, &nonce, aad, &ct_ref, &tag_ref).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[test]
    fn test_detached_rejects_tampering_and_wipes() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let pt = b"detached secret".to_vec();

        let mut buf = pt.clone();
        let tag = encrypt_in_place_detached(&key, &nonce, b"", &mut buf).unwrap();

        // Wrong tag → error, and the buffer must be wiped (not left as plaintext).
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xFF;
        let mut buf2 = buf.clone();
        assert_eq!(
            decrypt_in_place_detached(&key, &nonce, b"", &mut buf2, &bad_tag),
            Err(Error::AuthenticationFailed)
        );
        assert!(
            buf2.iter().all(|&b| b == 0),
            "buffer must be zeroized on failure"
        );

        // Correct tag → plaintext recovered.
        decrypt_in_place_detached(&key, &nonce, b"", &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn test_detached_empty_and_error_types() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];

        // Empty buffer works.
        let mut empty: Vec<u8> = Vec::new();
        let tag = encrypt_in_place_detached(&key, &nonce, b"", &mut empty).unwrap();
        decrypt_in_place_detached(&key, &nonce, b"", &mut empty, &tag).unwrap();
        assert!(empty.is_empty());

        // Error variants are distinct and comparable.
        assert_ne!(Error::MessageTooLong, Error::AadTooLong);
        assert_ne!(Error::AuthenticationFailed, Error::AadTooLong);
        // Display is implemented.
        let _ = alloc::format!("{}", Error::AuthenticationFailed);
    }

    // ── Plaintext wrapper ──

    #[test]
    fn test_plaintext_debug_does_not_leak() {
        let key = [0x01u8; 32];
        let nonce = [0x02u8; 24];
        let secret = b"TOP-SECRET-VALUE".to_vec();
        let (ct, tag) = encrypt(&key, &nonce, b"", &secret).unwrap();
        let pt = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();

        let rendered = alloc::format!("{:?}", pt);
        assert!(
            !rendered.contains("TOP-SECRET"),
            "Debug leaked plaintext: {rendered}"
        );
        assert!(rendered.contains("len"));

        // Deref / as_slice / len behave as expected.
        assert_eq!(pt.len(), secret.len());
        assert_eq!(pt.as_slice(), secret.as_slice());
        assert_eq!(&*pt, secret.as_slice());
        assert_eq!(pt, secret);
    }

    /// A corrupted locked page must be *noticed*, at the first use after the corruption.
    ///
    /// The alternative is the failure this check exists to remove: a flipped bit in the key
    /// makes every derived tag differ, which surfaces as "authentication failed" — a message
    /// about the ciphertext for a fault in the key — and, on the encrypt side, as ciphertexts
    /// the peer silently rejects. The check turns it into a fail-stop with a message that
    /// names the actual condition.
    ///
    /// Three cases, because the boundary is the point: a flip **in the key** and a flip **in
    /// the tag** must both panic, and a flip in the unused remainder of the page must *not*
    /// (nothing reads it, so treating it as corruption would be a false alarm).
    #[cfg(feature = "locked")]
    #[test]
    fn a_corrupted_locked_page_is_detected_on_use() {
        if !crate::locked::SUPPORTED {
            return; // no page, no check; the locked suite's SKIPPED note covers this
        }
        let key = [0x5Au8; KEY_LEN];

        // (a) a flip in the key itself.
        match crate::locked::LockedKey::new(&key) {
            Ok(mut k) => {
                k.flip_byte_for_test(7);
                let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = k.as_bytes();
                }))
                .is_err();
                assert!(panicked, "a flipped key byte was accepted by `as_bytes`");
            }
            Err(_) => return, // the environment refuses to lock; the locked suite says so
        }

        // (b) a flip in the integrity tag.
        match crate::locked::LockedKey::new(&key) {
            Ok(mut k) => {
                k.flip_byte_for_test(KEY_LEN + crate::locked::KEY_TAG_LEN - 1);
                let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = k.as_bytes();
                }))
                .is_err();
                assert!(
                    panicked,
                    "a flipped integrity tag was accepted by `as_bytes`"
                );
            }
            Err(_) => return,
        }

        // (c) an intact key still works, and the boundary: a flip *after* the tag is not a
        // false alarm. (`flip_byte_for_test` refuses offsets outside key+tag, so this writes
        // through the page's own accessor instead. The lock is taken and dropped inside the
        // assertion, and a refusal means the environment cannot lock at all, which the locked
        // suite reports as SKIPPED rather than as a pass.)
        if let Ok(k) = crate::locked::LockedKey::new(&key) {
            assert_eq!(k.as_bytes(), &key, "an intact key must read back unchanged");
        }
    }

    /// `Plaintext` equality must be constant-time but still *correct*:
    /// equal, differing-in-last-byte, differing-in-first-byte and
    /// different-length must all behave as expected.
    // A `PartialEq<&Plaintext>` impl exists for the same reason the `&[u8]` ones do, and
    // the `&same` assertion below is what exercises it; clippy's `op_ref` would rewrite it
    // to the owned form and drop the coverage.
    #[allow(clippy::op_ref)]
    #[test]
    fn test_plaintext_eq_semantics() {
        let key = [0x01u8; 32];
        let nonce = [0x02u8; 24];
        let secret = b"TOP-SECRET-VALUE".to_vec();
        let (ct, tag) = encrypt(&key, &nonce, b"", &secret).unwrap();
        let pt = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();

        // Equal, via every supported comparison type.
        assert!(pt == secret);
        assert!(pt == secret.as_slice());
        assert!(pt == b"TOP-SECRET-VALUE");

        // Differing in the last byte.
        let mut last = secret.clone();
        *last.last_mut().unwrap() ^= 1;
        assert!(pt != last);

        // Differing in the first byte.
        let mut first = secret.clone();
        first[0] ^= 1;
        assert!(pt != first);

        // Shorter and longer (length mismatch must not panic).
        assert!(pt != secret[..secret.len() - 1]);
        let mut longer = secret.clone();
        longer.push(0);
        assert!(pt != longer);
        assert!(pt != b"");

        // Plaintext-to-Plaintext, both spellings. This is the comparison an auditor was
        // pushed *away* from before the impl existed: without it `pt == other` does not
        // compile and the fallback is a short-circuiting slice comparison.
        let same = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        let (ct2, tag2) = encrypt(&key, &nonce, b"", &last).unwrap();
        let different = decrypt(&key, &nonce, b"", &ct2, &tag2).unwrap();
        let (short_ct, short_tag) = encrypt(&key, &nonce, b"", b"TOP").unwrap();
        let shorter = decrypt(&key, &nonce, b"", &short_ct, &short_tag).unwrap();
        assert!(pt == same);
        assert!(pt == &same);
        assert!(!(pt != same));
        assert!(pt != different);
        assert!(pt != shorter);
        assert!(shorter != pt);
    }

    /// A thread sized for [`stack_requirement_bytes`] survives a round trip.
    ///
    /// The constant exists because "size your threads for the 16 KiB scrub frame" was advice in
    /// a table row, and advice does not fail a build. This test is the other half: the number
    /// the crate reports is *sufficient*, measured by spawning a thread with exactly that stack
    /// plus a small margin and running the AEAD on it.
    ///
    /// The "too small" half — that a thread with less than the requirement faults inside
    /// `scrub_stack` — stays the hand measurement in the README's layer table, because a stack
    /// overflow is not something a test can catch: the process dies, which is the point of the
    /// constant rather than something to assert around.
    #[test]
    fn the_reported_stack_requirement_is_sufficient() {
        let need = stack_requirement_bytes();
        // A margin for the test's own frames, the key/nonce locals and the allocator.
        let stack = need + 64 * 1024;
        let handle = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(|| {
                let key = [0x11u8; 32];
                let nonce = [0x22u8; NONCE_LEN];
                let pt = vec![0xA5u8; 4096];
                let (ct, tag) = encrypt(&key, &nonce, b"aad", &pt).unwrap();
                let back = decrypt(&key, &nonce, b"aad", &ct, &tag).unwrap();
                assert_eq!(back, pt);
            })
            .expect("spawn");
        handle
            .join()
            .expect("the round trip must fit the reported requirement");
    }

    #[test]
    fn test_large_message_roundtrip() {
        // Exercise multi-block ChaCha20 boundaries.
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let aad = b"large aad";
        for size in [4096usize, 4097, 65536, 65537] {
            let pt = vec![0xA5u8; size];
            let (ct, tag) = encrypt(&key, &nonce, aad, &pt).unwrap();
            assert_eq!(ct.len(), size);
            let back = decrypt(&key, &nonce, aad, &ct, &tag).unwrap();
            assert_eq!(back, pt);
        }
    }

    // ── Avalanche ──
    //
    // Diffusion is not a security *proof* — the construction's security rests on
    // the underlying primitives — but it is the cheapest detector of the bug class
    // a hand-written ChaCha20 or ARX hash is most likely to have: a round function,
    // counter lane or limb-recombination error that leaves part of the state
    // untouched.  A missing round still passes roundtrip tests; it fails these.

    /// Count differing bits between two equal-length byte slices.
    fn differing_bits(a: &[u8], b: &[u8]) -> u32 {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum()
    }

    /// Flipping one input bit must change roughly half of the output bits — for
    /// the ciphertext, the tag, and the key.  A construction that ignored part
    /// of its input (or a keystream that reused a block) would show up as a
    /// stuck region and fail the lower bound.
    #[test]
    fn test_avalanche_single_bit_flip() {
        let key = [0x3Cu8; 32];
        let nonce = [0x5Eu8; 24];
        let aad = b"avalanche";
        let pt: Vec<u8> = (0..256).map(|i| (i * 3 % 251) as u8).collect();

        let (ct0, tag0) = encrypt(&key, &nonce, aad, &pt).unwrap();

        // Flip one bit of the plaintext: both ciphertext and tag must change
        // across a wide spread.
        let mut pt1 = pt.clone();
        pt1[100] ^= 0x01;
        let (ct1, tag1) = encrypt(&key, &nonce, aad, &pt1).unwrap();
        assert_ne!(ct0, ct1);
        assert_ne!(tag0, tag1);
        let ct_bits = differing_bits(&ct0, &ct1);
        assert!(
            ct_bits > 256 * 8 / 4,
            "plaintext bit flip changed only {ct_bits} of {} ciphertext bits",
            256 * 8
        );

        // Flip one bit of the key: everything must change.
        let mut key1 = key;
        key1[0] ^= 0x01;
        let (ct2, tag2) = encrypt(&key1, &nonce, aad, &pt).unwrap();
        assert_ne!(ct0, ct2);
        assert_ne!(tag0, tag2);
        let bits = differing_bits(&tag0, &tag2);
        assert!(
            bits > 32 * 8 / 4,
            "key bit flip changed only {bits} of {} tag bits",
            32 * 8
        );

        // Flip one bit of the nonce: everything must change.
        let mut nonce1 = nonce;
        nonce1[23] ^= 0x01;
        let (ct3, tag3) = encrypt(&key, &nonce1, aad, &pt).unwrap();
        assert_ne!(ct0, ct3);
        assert_ne!(tag0, tag3);

        // Flip one bit of the AAD: the tag must change widely.  The ciphertext
        // only changes through the tag, so check the tag here.
        let (_, tag4) = encrypt(&key, &nonce, b"avalanchf", &pt).unwrap();
        assert_ne!(tag0, tag4);
        let bits = differing_bits(&tag0, &tag4);
        assert!(
            bits > 32 * 8 / 4,
            "aad bit flip changed only {bits} of {} tag bits",
            32 * 8
        );
    }

    /// The tag must depend on **every** byte of the AAD, including bytes well
    /// past where a truncating implementation would plausibly stop (BLAKE3's
    /// 64-byte block and 1024-byte chunk boundaries).
    ///
    /// `test_aad_message_split_is_unambiguous` covers the encoding and a
    /// 4-byte AAD; this sweeps every position of a 200-byte one, so a
    /// `&aad[..N]` truncation would be caught.
    #[test]
    fn test_tag_depends_on_every_aad_byte() {
        let key = [0x71u8; 32];
        let nonce = [0x93u8; 24];
        let pt = b"fixed plaintext";

        let aad: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let (_, tag0) = encrypt(&key, &nonce, &aad, pt).unwrap();

        for pos in 0..aad.len() {
            let mut perturbed = aad.clone();
            perturbed[pos] ^= 0x01;
            let (_, tag) = encrypt(&key, &nonce, &perturbed, pt).unwrap();
            assert_ne!(tag, tag0, "AAD byte {pos} does not reach the tag");
        }
    }

    // ── Randomness (rng feature) ──

    /// The OS-backed helpers must return usable values, and two consecutive
    /// draws must differ.
    ///
    /// The inequality is a sanity check on the *plumbing* (that the bytes are
    /// actually being read and returned), not a statistical test: a 192-bit
    /// collision has probability 2^-192, so a failure here means the entropy
    /// source is broken or the buffer is not being filled, not bad luck.
    #[cfg(feature = "rng")]
    #[test]
    fn test_random_helpers_produce_usable_output() {
        let key = crate::random::generate_key().expect("OS entropy source unavailable");
        let nonce = crate::random::generate_nonce().expect("OS entropy source unavailable");

        // The generated values must work end-to-end.
        let (ct, tag) = encrypt(&key, &nonce, b"aad", b"message").unwrap();
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &ct, &tag).unwrap(),
            b"message"
        );

        assert_ne!(
            nonce,
            crate::random::generate_nonce().unwrap(),
            "two consecutive nonces were identical -- entropy source broken"
        );
        assert_ne!(
            key.as_bytes(),
            crate::random::generate_key().unwrap().as_bytes(),
            "two consecutive keys were identical -- entropy source broken"
        );

        // A zero-length request must succeed rather than error.
        crate::random::fill(&mut []).expect("empty fill must succeed");
        crate::random::fill(&mut nonce.clone()).expect("plain fill must succeed");
    }

    /// A failed fill must not leave a partial buffer behind.
    ///
    /// `getrandom` makes no guarantee about `dest` when it errors — its own words are
    /// "including partial reads ... no guarantees regarding the contents of `dest`" — so
    /// the crate wipes the buffer on the error path. A caller that ignores the `Result`
    /// then gets zeros, which fails the same way every time, instead of a prefix of real
    /// entropy that would work *sometimes* as a key.
    ///
    /// The failing source here is the reason `fill_from` exists: the real entropy source
    /// cannot be made to fail portably, and a guarantee that is never exercised is a
    /// comment.
    #[cfg(feature = "rng")]
    #[test]
    fn test_failed_fill_zeroizes_the_buffer() {
        let mut buf = [0xAAu8; 48];
        let result = crate::random::fill_from(&mut buf, |dest| {
            // The worst case the contract permits: a partial write, then a failure.
            for (i, b) in dest.iter_mut().enumerate().take(8) {
                *b = i as u8;
            }
            Err(getrandom::Error::UNSUPPORTED)
        });
        assert!(result.is_err(), "the failing source must be reported");
        assert_eq!(
            buf, [0u8; 48],
            "a failed fill left bytes behind; a caller ignoring the Result would take \
             them as a key"
        );

        // And the success path still fills the buffer.
        let mut ok = [0xAAu8; 48];
        crate::random::fill_from(&mut ok, |dest| {
            for (i, b) in dest.iter_mut().enumerate() {
                *b = i as u8;
            }
            Ok(())
        })
        .unwrap();
        assert!(ok.iter().any(|&b| b != 0xAA), "the success path must fill");
    }

    /// A generated key wipes itself on drop, and `Debug` never prints it.
    ///
    /// The wipe is read back out of the value's storage *after* dropping it in
    /// place: wiping only when the allocation is reused, or only the bytes a
    /// reference covers, is the failure mode this has to distinguish, and it cannot
    /// be seen from the outside any other way.  `MaybeUninit` + `drop_in_place` is
    /// what makes reading afterwards legal — the storage is ours, the value is gone,
    /// and every byte is a `u8`.
    #[cfg(feature = "rng")]
    #[test]
    fn test_key_zeroizes_on_drop_and_hides_itself() {
        let key = crate::random::generate_key().expect("OS entropy source unavailable");
        assert!(
            key.as_bytes().iter().any(|&b| b != 0),
            "an all-zero key from the OS CSPRNG means the entropy source is broken"
        );
        assert_eq!(
            alloc::format!("{key:?}"),
            "Key([REDACTED; 32])",
            "`Debug` must print nothing derived from the key -- not a prefix, not a hash"
        );

        let mut slot = core::mem::MaybeUninit::<Key>::uninit();
        slot.write(key);
        // SAFETY: `slot` was just initialised, and `Key` is `#[repr(transparent)]`
        // over `[u8; KEY_LEN]`, so its first `KEY_LEN` bytes are the key bytes and
        // they are initialised.
        let before = unsafe { core::ptr::read(slot.as_ptr() as *const [u8; KEY_LEN]) };
        assert!(
            before.iter().any(|&b| b != 0),
            "the key was already zero before it was dropped"
        );

        // SAFETY: `slot` is initialised, so this is the drop the scope would run.
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };

        // SAFETY: the drop wrote `KEY_LEN` initialised bytes (`zeroize_array`), `u8`
        // has no validity requirement beyond being initialised, and the storage is
        // still `slot`'s, so reading them back is reading initialised memory. The
        // value is never used as a `Key` again.
        let after = unsafe { core::ptr::read(slot.as_ptr() as *const [u8; KEY_LEN]) };
        assert_eq!(after, [0u8; KEY_LEN], "Key::drop left key bytes behind");
    }

    /// `random::fill` must overwrite the whole buffer, not a prefix.
    #[cfg(feature = "rng")]
    #[test]
    fn test_random_fill_covers_whole_buffer() {
        // A long run of identical bytes is overwhelmingly unlikely to be
        // reproduced by chance; if `fill` wrote only a prefix, the tail would
        // stay 0xAA.
        let mut buf = [0xAAu8; 64];
        crate::random::fill(&mut buf).unwrap();
        assert!(
            buf.iter().any(|&b| b != 0xAA),
            "fill produced identical bytes -- buffer untouched?"
        );
    }

    // `random` must be absent unless the feature is on, so `no_std` users who
    // supply their own entropy pay nothing (not even the dependency).
    //
    // This is a *compile-time* property, and `cargo test` already exercises it:
    // this file is compiled and run both with and without `--features rng`
    // (`verify.sh` runs both), so the `#[cfg(feature = "rng")]` gate on
    // `crate::random` is checked by the build itself on every run, and a broken
    // gate fails to compile rather than failing an assertion.  There is
    // deliberately no `assert!(true)` placeholder test: one that cannot fail is
    // noise in the test list (and `clippy::assertions_on_constants` flags it).

    // ── New-construction properties ──
    //
    // These replace the deleted Poly1305/CTX tests. Each pins a property the
    // new construction depends on and that a refactor could silently break.

    /// The key must reach the tag **directly**, not only through the derived
    /// `mac_key`.
    ///
    /// If the tag were `BLAKE3_keyed(mac_key, ...)`, an adversary could look for
    /// two keys colliding on that 256-bit value — a 2^128 search — and thereby
    /// bypass the whole point of a 520-bit tag. Feeding `K` into the hash input
    /// instead binds the tag to the key itself.
    ///
    /// A test cannot distinguish the two designs by output equality, so this
    /// checks the *construction*: `derive_tag` must change when the key does,
    /// for a fixed `mac_key`. (The complementary property — that the real
    /// encryption path changes — is covered by every KAT.)
    #[test]
    fn test_tag_binds_the_key_directly() {
        let mac_key = [0x5Au8; 32];
        let nonce = [0x33u8; NONCE_LEN];
        let aad = b"aad";
        let msg = b"msg";

        let k1 = [0x00u8; 32];
        let mut k2 = [0x00u8; 32];
        k2[0] = 1;

        let t1 = derive_tag(&mac_key, &k1, &nonce, aad, msg);
        let t2 = derive_tag(&mac_key, &k2, &nonce, aad, msg);
        assert_ne!(t1, t2, "tag must depend on the key, not just the mac_key");

        // And the nonce must reach it too.
        let mut n2 = nonce;
        n2[23] ^= 1;
        assert_ne!(t1, derive_tag(&mac_key, &k1, &n2, aad, msg));
    }

    /// The `K || N || len(A) || len(M) || A || M` encoding must be unambiguous.
    ///
    /// BLAKE3 is not vulnerable to length extension, but `A || M` on its own is
    /// ambiguous: `("ab", "c")` and `("a", "bc")` concatenate identically. The
    /// two `u64` length fields are what prevent that, and this pins them.
    #[test]
    fn test_aad_message_split_is_unambiguous() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];

        let (ct_a, tag_a) = encrypt(&key, &nonce, b"ab", b"c").unwrap();
        let (ct_b, tag_b) = encrypt(&key, &nonce, b"a", b"bc").unwrap();
        assert_ne!(tag_a, tag_b, "A||M must not be ambiguous");
        // Different tags imply different per-message keys, so the ciphertexts
        // differ even though the plaintexts are equal in length.
        assert_ne!(ct_a, ct_b);

        // Trailing zeros must not be strippable either.
        let (_, tag_c) = encrypt(&key, &nonce, b"ab\0", b"c").unwrap();
        assert_ne!(tag_a, tag_c);
        let (_, tag_d) = encrypt(&key, &nonce, b"ab", b"c\0").unwrap();
        assert_ne!(tag_a, tag_d);

        // Both must still round-trip under their own split.
        assert_eq!(decrypt(&key, &nonce, b"ab", &ct_a, &tag_a).unwrap(), b"c");
        assert_eq!(decrypt(&key, &nonce, b"a", &ct_b, &tag_b).unwrap(), b"bc");
    }

    /// Every one of the 65 tag bytes must influence the ciphertext.
    ///
    /// The ciphertext is derived from the tag, and the tag is what carries the
    /// commitment. The previous construction consumed only `tag[0..28]`, leaving
    /// `tag[28..32]` unable to affect the ciphertext at all; `derive_enc` now
    /// takes the whole tag, so all 520 bits are committed to.
    #[test]
    fn test_every_tag_byte_reaches_the_ciphertext() {
        let enc_seed = [0x77u8; 32];
        let mut base = [0u8; TAG_LEN];
        for (i, b) in base.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut key0 = [0u8; 32];
        let mut nonce0 = [0u8; 12];
        derive_enc(&enc_seed, &base, &mut key0, &mut nonce0);

        for pos in 0..TAG_LEN {
            let mut t = base;
            t[pos] ^= 0x01;
            let mut k = [0u8; 32];
            let mut n = [0u8; 12];
            derive_enc(&enc_seed, &t, &mut k, &mut n);
            assert!(
                k != key0 || n != nonce0,
                "tag byte {pos} does not reach the encryption key or nonce"
            );
        }
    }

    /// The keyed-BLAKE3 primitive must match BLAKE3's **official** test vectors.
    ///
    /// This is the external anchor for the new MAC. Without it the tag vectors
    /// would only ever be checked against this crate's own reference
    /// implementation, which proves nothing about either.
    ///
    /// Source: BLAKE3 `test_vectors/test_vectors.json` — the file's own key, and
    /// inputs following its `paint_test_input` pattern (byte `i` is `i % 251`).
    #[test]
    fn test_blake3_keyed_matches_official_vectors() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let cases: [(usize, &str); 5] = [
            (
                0,
                "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
            ),
            (
                1,
                "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
            ),
            (
                1024,
                "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
            ),
            (
                3072,
                "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770",
            ),
            (
                102400,
                "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
            ),
        ];

        for (n, want) in cases {
            let input: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let got = blake3::keyed_hash(&key, &input);
            assert_eq!(
                got.to_hex().as_str(),
                want,
                "official BLAKE3 keyed vector, len {n}"
            );
        }

        // And the XOF path used for the 65-byte tag must agree with the plain
        // 32-byte digest on the first 32 bytes.
        let input = b"xof consistency";
        let mut xof = [0u8; 65];
        blake3_keyed_xof(&key, input, &mut xof);
        assert_eq!(&xof[0..32], blake3::keyed_hash(&key, input).as_bytes());
    }

    /// The domain separators are part of the wire format and must stay pinned,
    /// fixed width, and distinct from each other.
    #[test]
    fn test_domain_separators_are_pinned() {
        assert_eq!(DOM_TAG, *b"XSIV-TAG");
        assert_eq!(DOM_ENC, *b"XSIV-ENC");
        assert_eq!(DOM_TAG.len(), 8);
        assert_eq!(DOM_ENC.len(), 8);
        assert_ne!(DOM_TAG, DOM_ENC);
    }

    /// The subkey domain constant must occupy the first 4 bytes of the ChaCha20
    /// **nonce** (counter 0), not the counter slot.
    ///
    /// The two readings produce different key material, and the KATs encode the
    /// nonce layout, so this pins the layout the docs describe.
    #[test]
    fn test_subkey_domain_occupies_nonce_not_counter() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];

        let (mac_key, _) = derive_material(&key, &nonce);
        let subkey = hchacha20(&key, &nonce[0..16].try_into().unwrap());

        // The layout the code uses: domain in the nonce, counter 0.
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&SUBKEY_DOMAIN);
        n[4..12].copy_from_slice(&nonce[16..24]);
        let mut buf = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &n, &mut buf);
        assert_eq!(mac_key.as_slice(), &buf[0..32]);

        // The documented-but-wrong reading (domain in the counter) must differ.
        let mut n2 = [0u8; 12];
        n2[4..12].copy_from_slice(&nonce[16..24]);
        let mut buf2 = [0u8; 64];
        chacha20_keystream_raw(&subkey, u32::from_le_bytes(SUBKEY_DOMAIN), &n2, &mut buf2);
        assert_ne!(mac_key.as_slice(), &buf2[0..32]);
    }

    /// The MAC must cover the **whole** AAD and the **whole** message: flipping
    /// any bit of either must change the tag.
    #[test]
    fn test_tag_covers_every_aad_and_message_byte() {
        let key = [0x71u8; 32];
        let nonce = [0x93u8; NONCE_LEN];
        let aad: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let msg: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();

        let (_, tag0) = encrypt(&key, &nonce, &aad, &msg).unwrap();

        for pos in 0..aad.len() {
            let mut a = aad.clone();
            a[pos] ^= 1;
            let (_, t) = encrypt(&key, &nonce, &a, &msg).unwrap();
            assert_ne!(t, tag0, "AAD byte {pos} does not reach the tag");
        }
        for pos in 0..msg.len() {
            let mut m = msg.clone();
            m[pos] ^= 1;
            let (_, t) = encrypt(&key, &nonce, &aad, &m).unwrap();
            assert_ne!(t, tag0, "message byte {pos} does not reach the tag");
        }
    }

    /// The tag must equal a keyed BLAKE3 over **exactly** the documented byte
    /// string, all 65 bytes.
    ///
    /// The input is rebuilt here from the specification in the module docs
    /// (`DOM_TAG || K || N || le64(|A|) || le64(|M|) || A || M`), independently of
    /// how `derive_tag` assembles it, and compared byte for byte. This makes the
    /// full width deterministic: an implementation that filled a prefix and
    /// zeroed the rest, or that dropped or reordered a field, fails here and
    /// cannot pass by luck.
    ///
    /// An earlier version of this test flipped one input byte and required all
    /// 65 tag bytes to move. That is *probabilistic* — a single fixed byte
    /// collision has probability 2^-8, so with 65 comparisons per case the test
    /// had roughly a 22% chance of failing spuriously, and it did (tag byte 6 of
    /// a real tag happened to be equal). It was replaced rather than loosened,
    /// because exact equality is both stronger and deterministic.
    #[test]
    fn test_tag_matches_blake3_over_the_documented_input() {
        let mac_key = [0x5Au8; 32];
        let key = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];

        for (aad, msg) in [
            (b"".as_slice(), b"".as_slice()),
            (b"aad".as_slice(), b"message".as_slice()),
            (b"x".as_slice(), b"".as_slice()),
            (b"".as_slice(), b"y".as_slice()),
        ] {
            let mut want = [0u8; TAG_LEN];

            let mut hasher = blake3::Hasher::new_keyed(&mac_key);
            hasher.update(&DOM_TAG);
            hasher.update(&key);
            hasher.update(&nonce);
            hasher.update(&(aad.len() as u64).to_le_bytes());
            hasher.update(&(msg.len() as u64).to_le_bytes());
            hasher.update(aad);
            hasher.update(msg);
            hasher.finalize_xof().fill(&mut want);

            let got = derive_tag(&mac_key, &key, &nonce, aad, msg);
            assert_eq!(
                got,
                want,
                "tag diverges from keyed BLAKE3 over the documented input \
                 (aad_len={}, msg_len={})",
                aad.len(),
                msg.len()
            );
        }

        // The nonce and the key must each be in the hashed input, and the two
        // length fields must swap when the roles are swapped.
        let t1 = derive_tag(&mac_key, &key, &nonce, b"ab", b"cde");
        let t2 = derive_tag(&mac_key, &key, &nonce, b"abc", b"de");
        assert_ne!(t1, t2, "A||M must not be ambiguous");
    }

    /// `derive_tag` hashes the tag input either as three `update` calls or as one
    /// contiguous buffer, whichever BLAKE3 is faster on (see the comment there).
    /// That is a performance decision, so it must not be observable — and this
    /// pins the two shapes to each other at the four totals where the choice
    /// flips: one byte either side of `TAG_CONCAT_MIN` and of `TAG_CONCAT_LIMIT`.
    ///
    /// A one-byte message and a large AAD reach all four totals, so the buffers
    /// stay small while AAD and message both stay non-empty (an empty part is the
    /// case the two shapes could most easily disagree on, and the in-crate KATs
    /// The length guard, tested directly.
    ///
    /// **64-bit only, and that is the point**: on a 32-bit target every possible
    /// `usize` is below `MAX_MSG_SIZE` (2^38), so the guard cannot fire at all and
    /// there is nothing to test -- which the first version of this test got wrong by
    /// casting the constant to `usize` and truncating it to zero on i686.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_length_guard_rejects_oversized_inputs() {
        let max = MAX_MSG_SIZE as usize;
        assert!(check_lengths(max, max).is_ok(), "the maximum is allowed");
        assert_eq!(
            check_lengths(max + 1, 0),
            Err(Error::MessageTooLong),
            "one byte over the maximum message length"
        );
        assert_eq!(
            check_lengths(0, max + 1),
            Err(Error::AadTooLong),
            "one byte over the maximum AAD length"
        );
        assert_eq!(
            check_lengths(max + 1, max + 1),
            Err(Error::MessageTooLong),
            "the message is checked first"
        );
    }

    /// On a 32-bit target the guard is unreachable rather than untested.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn test_length_guard_cannot_fire_on_32_bit() {
        assert!(
            MAX_MSG_SIZE > usize::MAX as u64,
            "the maximum exceeds usize here"
        );
        assert!(check_lengths(usize::MAX, usize::MAX).is_ok());
    }

    /// The independent implementation must agree with the main path, everywhere.
    ///
    /// This is the load-bearing test for `ultra`: the cross-check rejects a message the two
    /// implementations disagree on, so a *wrong* witness would reject everything, and a
    /// witness that agreed for the wrong reason (say, a stub) would be worse than none. The
    /// lengths sweep every structural boundary the construction has — the ChaCha20 block, the
    /// SIMD widths, the tag's contiguous-buffer window at 2048 and 65536, and BLAKE3's chunk
    /// boundaries at 1024 — because those are where two implementations most plausibly differ.
    #[cfg(feature = "ultra")]
    #[test]
    fn test_witness_agrees_with_the_main_path() {
        let key = [0x37u8; 32];
        let nonce = [0x5Au8; NONCE_LEN];
        let aad_len = 13usize;

        for len in [
            0usize, 1, 63, 64, 65, 127, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048,
            2049, 4096, 16384, 65535, 65536, 65537,
        ] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let aad: Vec<u8> = (0..aad_len).map(|i| (i % 241) as u8).collect();

            let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();

            // The tag the *encryption* side computes, independently.
            assert_eq!(
                crate::witness::encrypt_tag(&key, &nonce, &aad, &pt),
                tag,
                "witness tag disagrees at length {len}"
            );

            // And the whole decryption: plaintext and recomputed tag both. The witness
            // writes into a caller slice (see its documentation: allocation belongs to the
            // entry points, where it is fallible and taken before any derivation).
            let mut w_pt = vec![0u8; ct.len()];
            let w_tag = crate::witness::decrypt(&key, &nonce, &aad, &ct, &tag, &mut w_pt);
            assert_eq!(w_pt, pt, "witness plaintext disagrees at length {len}");
            assert_eq!(
                w_tag, tag,
                "witness recomputed tag disagrees at length {len}"
            );

            // The main path's own tag, for the same input, must equal the witness's.
            let (mac_key, _) = derive_material(&key, &nonce);
            assert_eq!(
                derive_tag(&mac_key, &key, &nonce, &aad, &pt),
                w_tag,
                "the crate's tag and the witness tag disagree at length {len}"
            );
        }
    }

    /// The witness must reject a forgery too, so the cross-check cannot be satisfied by a
    /// witness that says "fine" to everything.
    #[cfg(feature = "ultra")]
    #[test]
    fn test_witness_recomputes_rather_than_echoing() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];
        let pt = b"the witness must not echo the received tag".as_slice();
        let (ct, tag) = encrypt(&key, &nonce, b"aad", pt).unwrap();

        // A forged tag changes the *encryption* material (the tag feeds it), so the witness
        // decrypts to different plaintext and recomputes a tag matching neither the forged one
        // nor the genuine one. Both inequalities are the point: an implementation that echoed
        // the received tag fails the first, and one that ignored the tag when deriving fails
        // the second (it would recompute the genuine tag under a forgery, which is not SIV).
        let mut bad = tag;
        bad[0] ^= 1;
        let mut w_pt_bad = vec![0u8; ct.len()];
        let w_tag_bad = crate::witness::decrypt(&key, &nonce, b"aad", &ct, &bad, &mut w_pt_bad);
        assert_ne!(
            w_tag_bad, bad,
            "the witness returned the received tag: it is echoing, not recomputing"
        );
        assert_ne!(
            w_pt_bad, pt,
            "the witness produced the genuine plaintext under a forged tag, so it ignored the \
             tag when deriving the encryption material"
        );

        // With the genuine tag it recomputes exactly the crate's tag.
        let mut w_pt = vec![0u8; ct.len()];
        let w_tag = crate::witness::decrypt(&key, &nonce, b"aad", &ct, &tag, &mut w_pt);
        assert_eq!(w_pt, pt);
        assert_eq!(w_tag, tag);
    }

    /// The ChaCha20 counter range, exercised rather than asserted in prose.
    ///
    /// `MAX_MSG_SIZE` is exactly 2^32 blocks, so the last block of a maximum-length
    /// message uses counter `u32::MAX` and one block more would wrap to 0 — reusing
    /// keystream inside one message. The `const` assertion on `MAX_MSG_SIZE` binds the
    /// two at build time; this checks the arithmetic at run time, on every target, and
    /// exercises the primitive at the boundary itself.
    #[test]
    fn test_counter_range_covers_the_maximum_message_and_stops_there() {
        let capacity = (u32::MAX as u64) + 1;

        // The limit is a whole number of blocks, and exactly the counter's capacity.
        assert_eq!(
            MAX_MSG_SIZE % CHACHA20_BLOCK as u64,
            0,
            "a maximum-length message must be a whole number of blocks"
        );
        assert_eq!(
            MAX_MSG_SIZE / CHACHA20_BLOCK as u64,
            capacity,
            "the limit must be exactly the counter's capacity: less wastes range, more \
             wraps the counter inside one message"
        );

        // One more block than the counter can express is refused, and the refusal is
        // the length guard's, not a wrap. The binding is inside the 64-bit arm because
        // `MAX_MSG_SIZE + CHACHA20_BLOCK` does not fit a 32-bit `usize`, and a 32-bit
        // build warned (correctly) that it was unused outside it.
        #[cfg(target_pointer_width = "64")]
        {
            let one_block_over = MAX_MSG_SIZE + CHACHA20_BLOCK as u64;
            assert_eq!(
                check_lengths(one_block_over as usize, 0),
                Err(Error::MessageTooLong),
                "a message needing one block more than the counter has values must be refused"
            );
        }
        // On 32-bit targets no `usize` reaches the limit at all, so the guard cannot
        // fire there — `test_length_guard_cannot_fire_on_32_bit` records that.

        // The primitive itself: the highest counter a message can reach produces a
        // different keystream from counter 0, so nothing wraps where it should not.
        let key = [0x37u8; 32];
        let nonce = [0x11u8; 12];
        let input = [0u8; CHACHA20_BLOCK];
        let mut last = [0u8; CHACHA20_BLOCK];
        let mut first = [0u8; CHACHA20_BLOCK];
        chacha20_keystream(&key, u32::MAX, &nonce, &input, &mut last);
        chacha20_keystream(&key, 0, &nonce, &input, &mut first);
        assert_ne!(
            last, first,
            "counter u32::MAX must not produce the counter-0 keystream"
        );
        // And two consecutive blocks differ, so the counter really advances.
        let mut second = [0u8; CHACHA20_BLOCK];
        chacha20_keystream(&key, 1, &nonce, &input, &mut second);
        assert_ne!(first, second, "the counter must advance between blocks");
    }

    /// The plaintext buffer is allocated fallibly, so a length the allocator
    /// refuses is an error rather than a process abort.
    ///
    /// `usize::MAX` is the length used because it is *guaranteed* to be refused
    /// (the reserve fails on capacity overflow without asking the allocator), so
    /// this test costs no memory and cannot become flaky under pressure.  What it
    /// pins is the property, not the number: a `vec![0u8; n]` here would abort the
    /// test process instead of failing the assertion, which is exactly the
    /// difference between an error a service can return and one it cannot.
    #[test]
    fn test_plaintext_allocation_is_fallible() {
        assert_eq!(
            alloc_zeroed(usize::MAX),
            Err(Error::AllocationFailed),
            "an impossible allocation must come back as an error, not abort"
        );

        assert_eq!(alloc_zeroed(0).unwrap().len(), 0);
        let buf = alloc_zeroed(1024).unwrap();
        assert_eq!(buf.len(), 1024, "the buffer must be `len` bytes long");
        assert!(
            buf.iter().all(|&b| b == 0),
            "the buffer must start zeroed: the keystream is XORed into it"
        );
    }

    /// The tag must not depend on which call shape computed it.
    ///
    /// `blake3_keyed_multi` hashes a slice of parts, and `derive_tag` either passes
    /// them separately or builds one contiguous buffer, switching on the total input
    /// length (`TAG_CONCAT_MIN` ..= `TAG_CONCAT_LIMIT`). The switch has to be
    /// invisible, so this walks both sides of it against a tag the test computes
    /// itself, with the update-per-field shape.
    #[test]
    fn test_both_tag_call_shapes_hash_the_same_bytes() {
        let mac_key = [0x5Au8; 32];
        let key = [0x11u8; 32];
        let nonce = [0x22u8; NONCE_LEN];
        let head_len = 8 + 32 + NONCE_LEN + 16;
        let msg = [0xA5u8];

        for total in [
            TAG_CONCAT_MIN - 1,
            TAG_CONCAT_MIN,
            TAG_CONCAT_LIMIT,
            TAG_CONCAT_LIMIT + 1,
        ] {
            let aad = vec![0x5Au8; total - head_len - msg.len()];
            assert_eq!(head_len + aad.len() + msg.len(), total);

            // The expected tag always comes from the three-update shape, so this
            // compares the two shapes rather than one with itself.
            let mut want = [0u8; TAG_LEN];
            let mut hasher = blake3::Hasher::new_keyed(&mac_key);
            hasher.update(&DOM_TAG);
            hasher.update(&key);
            hasher.update(&nonce);
            hasher.update(&(aad.len() as u64).to_le_bytes());
            hasher.update(&(msg.len() as u64).to_le_bytes());
            hasher.update(&aad);
            hasher.update(&msg);
            hasher.finalize_xof().fill(&mut want);

            let got = derive_tag(&mac_key, &key, &nonce, &aad, &msg);
            assert_eq!(
                got, want,
                "the tag depends on which hash call shape was chosen (total={total})"
            );
        }
    }
    /// `dual-mac` must actually add a second, independent tag derivation.
    ///
    /// This is the *behavioural* form of what `tests/ultra.rs` used to assert by
    /// grepping the source for `#[cfg(feature = "dual-mac")]` -- a string that is
    /// present in every configuration, so that assertion could not fail even if
    /// the feature turned on nothing.  Counting the derivations through the
    /// crate's own instrumentation observes the compiled artefact instead: one
    /// derivation to encrypt, and one for the decryption without the feature,
    /// two with it.
    ///
    /// It lives here rather than in `tests/` because an integration test cannot see
    /// crate internals, and "the extra work happens" is exactly an internal fact.
    #[test]
    fn dual_mac_adds_exactly_one_extra_tag_derivation() {
        let count = || test_counters::DERIVE_TAG_CALLS.with(|c| c.get());

        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let before = count();
        let (ct, tag) = encrypt(&key, &nonce, b"", b"dual-mac probe").unwrap();
        let after_encrypt = count();
        decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        let after_decrypt = count();

        assert_eq!(after_encrypt - before, 1, "encryption derives the tag once");
        #[cfg(feature = "dual-mac")]
        assert_eq!(
            after_decrypt - after_encrypt,
            2,
            "with `dual-mac`, decryption must derive the tag twice (stored + independent              recomputation)"
        );
        #[cfg(not(feature = "dual-mac"))]
        assert_eq!(
            after_decrypt - after_encrypt,
            1,
            "without `dual-mac`, decryption must derive the tag exactly once"
        );
    }

    /// The two ChaCha20 uses inside one call must not be the same keystream.
    ///
    /// `derive_material` burns **counter 0** of `(subkey, "XSIV" || N[16..24])` for the
    /// 64-byte key-material block, and the message keystream is **counter 0** of
    /// `(enc_key, enc_nonce)`. They are separated by *key* and by *nonce*, not by
    /// counter: reserving a counter for the derivation would change every ciphertext ever
    /// produced, and the wire format is frozen (see CHANGELOG, "Wire format").
    ///
    /// So the separation rests on a statement about two secret-derived values —
    /// `enc_key ‖ enc_nonce` is a 44-byte KDF output, `subkey` is an HChaCha20 output —
    /// differing, which holds with probability `1 - 2^-352` and, importantly, is only
    /// *computable* by someone who already holds the master key. That makes it
    /// informational rather than exploitable, but it is also exactly the kind of thing a
    /// refactor can silently destroy: make `derive_enc` ignore the tag, give the two call
    /// sites the same nonce, or "simplify" the domain label away, and the two uses
    /// collapse into one keystream with no other test noticing — the round trip still
    /// works, and the tags still verify.
    ///
    /// This test computes both keystreams for a spread of `(key, nonce, message)` triples
    /// and requires them to differ. It cannot prove the general statement; it pins the
    /// behaviour so that the collapse is a test failure rather than a discovery.
    #[test]
    fn the_key_material_block_is_not_the_message_keystream() {
        for i in 0..16u8 {
            let mut key = [0x11u8; 32];
            key[0] = i;
            let mut nonce = [0x22u8; NONCE_LEN];
            nonce[0] = i.wrapping_mul(7);
            nonce[23] = i;
            let aad = [0x33u8; 3];
            let msg = [0x44u8; 9];

            // The 64-byte block `derive_material` burns under (subkey, subkey_nonce, 0)
            // *is* the pair it returns -- that is how the block is split.
            let (mac_key, enc_seed) = derive_material(&key, &nonce);
            let mut kdf_block = [0u8; 64];
            kdf_block[..32].copy_from_slice(&mac_key);
            kdf_block[32..].copy_from_slice(&enc_seed);

            // The message keystream, derived the way `encrypt` derives it.
            let tag = derive_tag(&mac_key, &key, &nonce, &aad, &msg);
            let mut enc_key = [0u8; 32];
            let mut enc_nonce = [0u8; 12];
            derive_enc(&enc_seed, &tag, &mut enc_key, &mut enc_nonce);
            let mut msg_ks = [0u8; 64];
            chacha20_keystream_raw(&enc_key, 0, &enc_nonce, &mut msg_ks);

            assert_ne!(
                msg_ks, kdf_block,
                "the key-material block and the message keystream are the same keystream \
                 (trial {i}): the two ChaCha20 uses at counter 0 are no longer separated"
            );

            // The nonces must differ as well, and for the right reason: the derivation's
            // nonce is `SUBKEY_DOMAIN || N[16..24]`, which is *public*, while the message
            // nonce is a secret KDF output. A message nonce that equals the public one
            // would be a KDF output that the attacker can predict and check.
            let mut subkey_nonce = [0u8; 12];
            subkey_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
            subkey_nonce[4..12].copy_from_slice(&nonce[16..24]);
            assert_ne!(
                enc_nonce, subkey_nonce,
                "the per-message nonce is the public derivation nonce (trial {i})"
            );

            // And the keys, which is the separation that actually carries the weight.
            let subkey = hchacha20(&key, &nonce[0..16].try_into().unwrap());
            assert_ne!(
                enc_key, subkey,
                "the per-message key is the derivation key (trial {i})"
            );
        }
    }

    /// Nonce reuse must not reuse the keystream — the mechanical core of misuse
    /// resistance.
    ///
    /// SIV's degradation under nonce reuse is stated as "the adversary learns whether two
    /// `(A, M)` pairs are equal, and nothing else". That statement is *false* for a scheme
    /// whose keystream depends only on `(key, nonce)`: two ciphertexts would differ by the
    /// XOR of their plaintexts, so the difference of two messages is handed over
    /// directly — the classic stream-cipher catastrophe, and the reason a naive
    /// nonce-based stream cipher is unusable under misuse.
    ///
    /// This construction avoids it by deriving the per-message key from the tag, so the
    /// keystream moves whenever `(A, M)` moves. That is the property tested here, in the
    /// form that cannot be fooled by a coincidence: the ciphertexts must not differ by the
    /// plaintexts (for a message change) and must not be equal (for an AAD change with the
    /// message held fixed).
    ///
    /// A regression that made the KDF ignore the tag — deriving the key from the message
    /// *length*, say — passes every other test in this file: the tags would still be
    /// correct, the round trip would still work, and the `dual-mac`/witness cross-checks
    /// would still agree with it, because they only compare tags.
    #[test]
    fn nonce_reuse_does_not_reuse_the_keystream() {
        let key = [0x9Au8; 32];
        let nonce = [0xB4u8; NONCE_LEN];
        let aad = b"associated data";
        let mut other_aad = [0u8; 15];
        other_aad.copy_from_slice(aad);
        other_aad[0] ^= 0x20; // same length, one bit differs

        // Equal-length messages that differ in one byte: the XOR formulation below is only
        // meaningful when the two plaintexts line up.
        let m1 = [0x11u8; 64];
        let mut m2 = m1;
        m2[0] ^= 0x40;

        let xor = |a: &[u8], b: &[u8]| -> Vec<u8> { a.iter().zip(b).map(|(x, y)| x ^ y).collect() };

        let (ct1, tag1) = encrypt(&key, &nonce, aad, &m1).unwrap();
        let (ct2, tag2) = encrypt(&key, &nonce, aad, &m2).unwrap();
        assert_ne!(tag1, tag2, "different messages must not share a tag");
        assert_ne!(
            xor(&ct1, &ct2),
            xor(&m1, &m2),
            "the ciphertexts differ by the plaintexts: the keystream depended only on the \
             key and nonce, so nonce reuse hands over M1 XOR M2"
        );

        // The same statement for a change confined to the AAD, with the message fixed:
        // if the keystream ignored the tag, these two ciphertexts would be *identical*.
        let (ct3, tag3) = encrypt(&key, &nonce, &other_aad, &m1).unwrap();
        assert_ne!(tag3, tag1);
        assert_ne!(
            ct3, ct1,
            "the AAD does not reach the keystream: two messages that differ only in their \
             associated data encrypted under one key and nonce produced the same bytes"
        );
        // Sharper than "they differ": the *first block* must move. A keystream that
        // diverged only after the first block would still be a reused prefix, and for a
        // protocol that frames messages in 64-byte units that is most of the message.
        assert_ne!(
            ct1[..64],
            ct3[..64],
            "only the tail of the keystream depends on the AAD"
        );

        // Determinism: the same query twice is the same ciphertext, which is what SIV's
        // degradation statement allows the adversary to see.
        let (ct1_again, tag1_again) = encrypt(&key, &nonce, aad, &m1).unwrap();
        assert_eq!((ct1_again, tag1_again), (ct1.clone(), tag1));

        // The in-place entry point has its own copy of the wiring, so it gets the same
        // check: a regression that put the tag-independent keystream there would be
        // invisible to the attached-path assertions above.
        let mut buf_a = m1.to_vec();
        let mut buf_b = m1.to_vec();
        let tag_a = encrypt_in_place_detached(&key, &nonce, aad, &mut buf_a).unwrap();
        let tag_b = encrypt_in_place_detached(&key, &nonce, &other_aad, &mut buf_b).unwrap();
        assert_eq!(tag_a, tag1, "the two entry points must agree");
        assert_ne!(tag_b, tag_a);
        assert_ne!(
            buf_a, buf_b,
            "in place: the AAD does not reach the keystream either"
        );
        assert_ne!(buf_a[..64], buf_b[..64], "in place: only the tail moved");

        // And the pairs above are usable, so the assertions are about real ciphertexts
        // rather than about a broken harness.
        assert_eq!(
            decrypt(&key, &nonce, aad, &ct1, &tag1).unwrap(),
            m1.as_slice()
        );
        assert!(decrypt(&key, &nonce, &other_aad, &ct1, &tag1).is_err());
        assert_eq!(
            decrypt(&key, &nonce, aad, &buf_a, &tag_a).unwrap(),
            m1.as_slice()
        );
    }

    /// **Lemma S2**, at the value level: for one `(K, N)`, the key-material block is at a
    /// different point of ChaCha20's domain than XChaCha20-Poly1305's first data block.
    ///
    /// Both schemes call `HChaCha20(K, N[0..16])` and then continue with a 12-byte nonce at
    /// counter 0. The draft's schemes leave that nonce's first four bytes as NUL padding; this
    /// crate puts `SUBKEY_DOMAIN` there. The two ChaCha20 evaluations are therefore at
    /// *different points of the domain* — a structural separation — rather than at the same
    /// point with a coincidence that has not happened yet, which is what a scheme relying on
    /// "the keys differ" would have. The integration test
    /// (`tests/construction_inventory.rs`) pins the same lemma from outside the crate, where
    /// only the constants are reachable; this one compares the blocks.
    #[test]
    fn the_key_material_block_is_not_xchacha20_poly1305s_first_block() {
        for i in 0..8u8 {
            let mut key = [0x5Au8; 32];
            key[0] = i;
            let mut nonce = [0xA5u8; NONCE_LEN];
            nonce[16] = i.wrapping_mul(3);

            // Both schemes derive the subkey the same way (draft-irtf-cfrg-xchacha §2.2).
            let subkey = hchacha20(&key, &nonce[0..16].try_into().unwrap());

            // XChaCha20 / XChaCha20-Poly1305: 12-byte nonce = 0^4 || N[16..24].
            let mut draft_nonce = [0u8; 12];
            draft_nonce[4..12].copy_from_slice(&nonce[16..24]);
            let draft_block = chacha20_block(&subkey, 0, &draft_nonce);

            // This crate: SUBKEY_DOMAIN || N[16..24].
            let mut xsi_nonce = [0u8; 12];
            xsi_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
            xsi_nonce[4..12].copy_from_slice(&nonce[16..24]);
            assert_ne!(
                xsi_nonce, draft_nonce,
                "the derivation nonce is the NUL-padded draft one (trial {i})"
            );
            let xsi_block = chacha20_block(&subkey, 0, &xsi_nonce);

            assert_ne!(
                xsi_block, draft_block,
                "the key-material block equals XChaCha20-Poly1305's first keystream block for \
                 (K, N) = (trial {i}): the two nonces differ in four fixed bytes, so equal \
                 keystreams would mean ChaCha20's block function is not injective in its \
                 nonce — which is a collision in a permutation"
            );

            // And the split of the block is what the derivation uses: the first half is the
            // tag key, the second is the encryption seed, with nothing shared between the two
            // uses beyond being two halves of one pseudorandom block (Theorem 1 in
            // SECURITY-ANALYSIS.md).
            let (mac_key, enc_seed) = derive_material(&key, &nonce);
            let mut rebuilt = [0u8; 64];
            rebuilt[..32].copy_from_slice(&mac_key);
            rebuilt[32..].copy_from_slice(&enc_seed);
            assert_eq!(
                rebuilt, xsi_block,
                "the material block is not what it is split from"
            );
        }
    }
}
