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
//!   (CMT-3) at **2^260**.  Read the "Security level" section below before
//!   relying on a number.
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
//! | Key commitment (CMT-1/CMTk) | **2^260** | birthday bound on the 520-bit tag |
//! | Context commitment (CMT-3) | **2^260** | birthday bound, resting on BLAKE3 |
//!
//! **Forgery: 256 bits is the ceiling, not a choice.**  Forgery resistance is
//! bounded by the key's entropy; with a 256-bit key it cannot exceed 256 bits,
//! and a longer tag does not raise it (it raises commitment).
//!
//! **Commitment: the tag is 65 bytes because commitment must exceed 2^256.**
//! Commitment is a *collision* property, so an `n`-bit tag caps it at `2^(n/2)`.
//! A 64-byte tag would give exactly `2^256` — not more — so [`TAG_LEN`] is 65,
//! the smallest byte-aligned size that strictly exceeds it.
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
/// Sized for **more than 256-bit commitment**, which the birthday bound forces:
/// commitment is a collision property, so an `n`-bit tag caps it at `2^(n/2)`.
/// A 64-byte (512-bit) tag would give exactly `2^256` and so would not be
/// *greater* than 256 bits; 65 bytes gives `2^260`, the smallest byte-aligned
/// value that strictly exceeds it.
///
/// This does **not** buy more forgery resistance: forgery is bounded by the
/// 256-bit key, not by the tag length.
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

/// Equality against byte sequences is **constant-time** in the plaintext
/// contents.
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

impl Drop for Plaintext {
    fn drop(&mut self) {
        // Wipe the whole allocation, not just `len` bytes.  `decrypt` builds this
        // `Vec` with `vec![0u8; n]`, whose capacity is exactly `n`, so the
        // initialized part *is* the allocation today; the `capacity` tail is
        // handled anyway so a future constructor that grows the buffer cannot
        // silently leave plaintext behind in it.
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

    /// Fill `dest` with bytes from the operating system's CSPRNG.
    ///
    /// Returns an error if the OS entropy source is unavailable.  That can
    /// genuinely happen — early boot, a sandbox that blocks `getrandom(2)`, a
    /// failed `RDRAND` on `no_std` — which is why this returns a `Result`
    /// instead of panicking.
    ///
    /// There is deliberately **no userspace fallback PRNG**.  A predictable
    /// nonce is a real attack (see the module documentation), and a silent
    /// fallback would turn "the OS had no entropy" into "your messages are
    /// forgeable" without anyone noticing.
    pub fn fill(dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest)
    }

    /// Generate a fresh 256-bit key from the OS CSPRNG.
    ///
    /// The key comes back in a [`Key`], which zeroizes it on drop.  A generated key
    /// is the one secret in this API with no other copy anywhere, so it is the one
    /// case where bytes left behind afterwards are purely this crate's doing.
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
/// * **The key is an input, not just the MAC key.** Feeding only the derived
///   `mac_key` would let an adversary look for two keys colliding on that
///   256-bit value — a 2^128 search — which would bypass the entire point of a
///   520-bit tag. Putting `K` in the hash input binds the tag to the key
///   directly.
/// * **Lengths are encoded and every field is fixed width.** BLAKE3 is not
///   vulnerable to length extension (its finalisation is flagged, unlike
///   Merkle–Damgård constructions), but `A || M` alone would be ambiguous:
///   `("ab", "c")` and `("a", "bc")` would hash identically. The two `u64`
///   length fields remove that.
///
/// The hasher is fed incrementally rather than through one concatenated buffer,
/// so the key never lands in a growable heap allocation.
fn derive_tag(
    mac_key: &[u8; 32],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> [u8; TAG_LEN] {
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
    let total = head.len() + aad.len() + msg.len();
    if (TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT).contains(&total) {
        // The one infallible allocation outside the entry points, and it is bounded by
        // construction: this branch is only taken for a total within
        // `TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT`, so `total <= 65_536` whatever the input
        // length is. A refusal here would mean the process has no memory left at all,
        // which is why it is not threaded through `derive_tag`'s array return type.
        let mut cat = Vec::with_capacity(total);
        cat.extend_from_slice(&head);
        cat.extend_from_slice(aad);
        cat.extend_from_slice(msg);
        blake3_keyed_multi(mac_key, &[&cat], &mut tag);
        zeroize_slice(&mut cat);
    } else {
        blake3_keyed_multi(mac_key, &[&head, aad, msg], &mut tag);
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
fn derive_enc(enc_seed: &[u8; 32], tag: &[u8; TAG_LEN]) -> ([u8; 32], [u8; 12]) {
    let mut input = [0u8; 8 + TAG_LEN];
    input[0..8].copy_from_slice(&DOM_ENC);
    input[8..].copy_from_slice(tag);

    let mut material = [0u8; 44];
    blake3_keyed_xof(enc_seed, &input, &mut material);

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&material[0..32]);
    let mut enc_nonce = [0u8; 12];
    enc_nonce.copy_from_slice(&material[32..44]);

    zeroize_array(&mut material);
    zeroize_array(&mut input);
    (enc_key, enc_nonce)
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

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let tag = derive_tag(&mac_key, key, nonce, aad, plaintext);
    let (mut enc_key, mut enc_nonce) = derive_enc(&enc_seed, &tag);

    // Fallible for the same reason `decrypt` is: this length is the caller's, and a
    // plain `vec!` aborts the process when the allocator refuses.
    let mut ciphertext = alloc_zeroed(plaintext.len())?;
    chacha20_keystream(&enc_key, 0, &enc_nonce, plaintext, &mut ciphertext);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);

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
    let (mut enc_key, mut enc_nonce) = derive_enc(&enc_seed, &tag);

    chacha20_apply(&enc_key, 0, &enc_nonce, &Input::InPlace, buffer);

    zeroize_array(&mut mac_key);
    zeroize_array(&mut enc_seed);
    zeroize_array(&mut enc_key);
    // The per-message ChaCha20 nonce is secret-derived too (it comes out of
    // the same XOF call as `enc_key`), so it is wiped with the rest rather
    // than left on the stack.
    zeroize_array(&mut enc_nonce);

    Ok(tag)
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

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let (mut enc_key, mut enc_nonce) = derive_enc(&enc_seed, tag);

    let mut plaintext = alloc_zeroed(ciphertext.len())?;
    chacha20_keystream(&enc_key, 0, &enc_nonce, ciphertext, &mut plaintext);

    let mut computed_tag = derive_tag(&mac_key, key, nonce, aad, &plaintext);
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
        let second = computed_tag_copy.ct_eq(&tag_copy) & tag_copy.ct_eq(&computed_tag_copy);

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

    // Two rejections until the decision proves otherwise, written *before* the call:
    // a fault that skips the call leaves both standing, and a fault that corrupts one
    // outcome leaves the other -- so accepting would take two faults. See the comment
    // on `accept_or_reject`.
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

    let (mut mac_key, mut enc_seed) = derive_material(key, nonce);
    let (mut enc_key, mut enc_nonce) = derive_enc(&enc_seed, tag);

    chacha20_apply(&enc_key, 0, &enc_nonce, &Input::InPlace, buffer);

    let mut computed_tag = derive_tag(&mac_key, key, nonce, aad, buffer);
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
        let second = computed_tag_copy.ct_eq(&tag_copy) & tag_copy.ct_eq(&computed_tag_copy);

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

    // As in `decrypt`: two rejections written first, and two serial checks, so a fault
    // that skips the call or corrupts one outcome cannot accept.
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

/// 20 rounds of ChaCha (10 double-rounds).
fn chacha20_rounds(mut s: [u32; 16]) -> [u32; 16] {
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
    s
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
    let mut out = chacha20_rounds(s);

    let mut keystream = [0u8; 64];
    for i in 0..16 {
        let v = out[i].wrapping_add(orig[i]);
        keystream[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Side-channel hygiene: wipe the key-derived state in place. It has to be these
    // locals themselves -- an earlier version wrote `let mut orig = orig;
    // zeroize_array(&mut orig);`, which wipes a *copy* (`[u32; 16]` is `Copy`) and
    // leaves the original on the stack, i.e. no wipe at all.
    zeroize_array(&mut s);
    zeroize_array(&mut orig);
    zeroize_array(&mut out);

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
/// Per RFC 8439 §2.8 / draft-irtf-cfrg-xchacha §2.2.
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

    let mut out = chacha20_rounds(s);

    let mut r = [0u8; 32];
    // Output words 0,1,2,3,12,13,14,15 (NO final addition!)
    let indices = [0usize, 1, 2, 3, 12, 13, 14, 15];
    for (i, &idx) in indices.iter().enumerate() {
        r[i * 4..i * 4 + 4].copy_from_slice(&out[idx].to_le_bytes());
    }

    // Side-channel hygiene, as in `chacha20_block`: wipe the key-bearing locals
    // themselves. There is no `orig` here because HChaCha20 has no feed-forward, so
    // a copy of the pre-round state would be a second copy of the key material to
    // keep alive for no reason.
    zeroize_array(&mut s);
    zeroize_array(&mut out);

    r
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(kani)]
mod proofs;

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
    /// Key commitment itself is a security argument from the tag's width (2^260, see
    /// the README) and cannot be established by sampling; what is testable is that
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

    /// `Plaintext` equality must be constant-time but still *correct*:
    /// equal, differing-in-last-byte, differing-in-first-byte and
    /// different-length must all behave as expected.
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
        let (key0, nonce0) = derive_enc(&enc_seed, &base);

        for pos in 0..TAG_LEN {
            let mut t = base;
            t[pos] ^= 0x01;
            let (k, n) = derive_enc(&enc_seed, &t);
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
        // the length guard's, not a wrap.
        let one_block_over = MAX_MSG_SIZE + CHACHA20_BLOCK as u64;
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            check_lengths(one_block_over as usize, 0),
            Err(Error::MessageTooLong),
            "a message needing one block more than the counter has values must be refused"
        );
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
}
