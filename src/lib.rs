//! XChaCha20-Poly1305-SIV — Misuse-resistant, key- and context-committing AEAD
//!
//! A 24-byte-nonce (192-bit) AEAD obtained by lifting the c2sp.org
//! ChaCha20-Poly1305-SIV construction onto the XChaCha20 nonce-extension
//! mechanism (HChaCha20).  There is no published specification for this
//! composition; it is a direct fusion of the two:
//!
//! * Subkey derivation is XChaCha20-style: `HChaCha20(key, nonce[0..16])`
//!   produces a subkey, which is then used with the remaining 8 nonce bytes.
//!   Unlike XChaCha20, the first 4 bytes of the subkey-derivation block's
//!   12-byte *nonce* hold a domain-separation constant ([`SUBKEY_DOMAIN`])
//!   where XChaCha20 leaves NUL padding, so this scheme and
//!   XChaCha20-Poly1305 never derive the same one-time Poly1305 key even under
//!   cross-scheme nonce reuse.  (The counter stays 0.  Putting the constant in
//!   the counter slot instead would be a different construction.)
//! * The AEAD itself is the SIV construction from c2sp.org
//!   ChaCha20-Poly1305-SIV (Poly1305 tag → tag-key-derived encryption key),
//!   which supplies nonce-misuse resistance and key commitment.
//!
//! # Context commitment (beyond c2sp.org)
//!
//! The c2sp.org base construction is key-committing but **not**
//! context-committing: its specification says so explicitly ("there is no
//! context commitment (CMT-3)"), because CMT-3's adversary chooses the key and
//! therefore knows Poly1305's `r`, making the Poly1305 tag solvable rather than
//! collision resistant.
//!
//! This crate closes that gap with the **CTX** transform (Chan and Rogaway,
//! *On Committing Authenticated-Encryption*, ESORICS 2022): the tag is
//! `c2sp_tag XOR BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`.  Costs one hash
//! of the AAD — independent of the message length — and does not lengthen the
//! tag.  Since the tag is transmitted in full and verified in full, the
//! commitment holds over the tag itself: a collision requires a collision in
//! the BLAKE3 term or in the c2sp.org tag, both 2^128 for a 256-bit tag.  See
//! `derive_tag` for why the argument must run through the tag rather than the
//! ciphertext.
//!
//! This is therefore **not** byte-compatible with c2sp.org
//! ChaCha20-Poly1305-SIV.  The unmodified construction remains available
//! internally as `encrypt16`/`decrypt16`, which is what the c2sp.org
//! known-answer vectors are checked against.
//!
//! The public API exposes **only the 24-byte-nonce** entry points.  Two
//! flavours are available:
//!
//! * Allocating: [`encrypt`] / [`decrypt`].
//! * Detached, in-place: [`encrypt_in_place_detached`] /
//!   [`decrypt_in_place_detached`], for protocols that keep the tag separate or
//!   want to avoid a second allocation.
//!
//! Key properties:
//!
//! - 256-bit tag, key-committing (CMT-1/CMTk) and context-committing (CMT-3) at
//!   **128-bit** strength.  Read the "Security level" section below before
//!   relying on a number: the tag is 256 bits, but forgery resistance is
//!   ≈103-bit and commitment is 2^128.
//! - SIV mode: tag computed before encryption, nonce-misuse resistant
//! - Constant-time operations: the tag is compared with `subtle::ConstantTimeEq`
//!   and decryption is decrypt-then-verify (SIV requires the plaintext to
//!   recompute the tag, so verify-then-decrypt is not possible).  See the
//!   "Side channels" section below for what has actually been checked.
//! - Zeroization of sensitive material, including the returned [`Plaintext`],
//!   which wipes itself on drop
//! - Typed errors via [`Error`]; no stringly-typed failures
//!
//! # Security level
//!
//! **The 256-bit tag does not mean 256-bit security.**  The numbers, and what
//! each is bounded by:
//!
//! | Property | Strength | Determined by |
//! | --- | --- | --- |
//! | Confidentiality | 256-bit | the ChaCha20 key |
//! | Forgery resistance | **≈103-bit**, degrading with length | Poly1305's `r` (106 bits of entropy) |
//! | Key commitment (CMT-1/CMTk) | **2^128** | birthday bound on the 256-bit tag |
//! | Context commitment (CMT-3) | **2^128** | birthday bound, resting on BLAKE3 |
//!
//! Both weaker figures are the construction's documented design parameters, not
//! shortcomings of this implementation: the c2sp.org specification states them
//! itself ("256-bit security against plaintext recovery and 103-bit security
//! against forgery"; "the 256-bit tag should provide 128-bit key-committing
//! security (CMT-1/CMTk) due to the birthday bound").
//!
//! * **Forgery** is capped by Poly1305: a single forgery succeeds with
//!   probability `≲ ℓ/2^106` for `ℓ` 16-byte blocks — about `2^-100` for 1 KiB
//!   but only `2^-72` at the `2^38`-byte maximum.  A longer tag does not help;
//!   it raises commitment, never forgery resistance.
//! * **Commitment** is a collision property, so an `n`-bit tag caps it at
//!   `2^(n/2)`.  The CTX XOR takes the *weaker* of its two sides rather than
//!   adding them, so the binding here equals BLAKE3's differential collision
//!   resistance.
//!
//! Do not use this where more than 128-bit commitment or more than 103-bit
//! forgery resistance is required.
//!
//! # Side channels
//!
//! The cryptographic code paths contain **no secret-dependent branches and no
//! secret-dependent memory indexing**.  Every secret-derived quantity is
//! handled with straight-line arithmetic or `subtle` primitives:
//!
//! * Tag comparison — `subtle::ConstantTimeEq` over all 32 bytes.
//! * [`Plaintext`] equality — every `PartialEq` impl routes through
//!   `ConstantTimeEq`, so comparing a decrypted secret against an expected
//!   value does not leak its matching prefix.  A length mismatch is not
//!   secret-dependent.
//! * Poly1305's reduction in `Poly1305State::finalize` uses a mask select
//!   (`shr`/`dec`/`and`/`or`) rather than a branch on the comparison result.
//! * The 26-bit limb arithmetic (`process_block`, `poly1305_mul_wide`,
//!   `poly1305_reduce_wide`, `Poly1305Powers::new`) is branch-free.
//! * ChaCha20/HChaCha20 use only ARX operations — no tables, hence nothing to
//!   index with a secret.
//!
//! Two caveats, stated plainly:
//!
//! 1. **This is an argument about the source and the generated machine code,
//!    not a proof.**  Kani's harnesses cover *functional* correctness; they
//!    cannot establish timing independence, because CBMC has no timing model.
//!    The branch-freedom claims above are backed by inspecting the release
//!    assembly of the Poly1305 and ChaCha20 entry points, where the only
//!    conditional jumps are the loop bounds of the zeroization helpers
//!    (alignment-dependent, not value-dependent).
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
//!
//! Test vectors:
//! - XChaCha20 (24-byte nonce): draft-irtf-cfrg-xchacha-03 §2.2.1 / §A.2.1 / §A.3.1
//! - ChaCha20-Poly1305-SIV (16-byte nonce, internal `encrypt16`/`decrypt16`):
//!   <https://c2sp.org/chacha20-poly1305-siv>
//! - XChaCha20-Poly1305-SIV (public API): generated by an independent reference
//!   implementation derived from the RFC pseudocode; see the KAT tests.
//!
//! References:
//! - <https://c2sp.org/chacha20-poly1305-siv>
//! - <https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/> (HChaCha20 / XChaCha20)
//! - RFC 8439 (ChaCha20 and Poly1305)
//! - Chan, Rogaway. *On Committing Authenticated-Encryption*. ESORICS 2022. (CTX)
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

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

// ── Constants ────────────────────────────────────────────────────────

/// Maximum message size: 2^38 bytes (256 GiB), per c2sp.org A_MAX/P_MAX.
const MAX_MSG_SIZE: u64 = 1u64 << 38;

/// ChaCha20 block size (64 bytes).
const CHACHA20_BLOCK: usize = 64;

/// Poly1305 block size (16 bytes).
const POLY1305_BLOCK_SIZE: usize = 16;

/// Key length: 32 bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Tag length: 32 bytes (256 bits).  Key-committing.
pub const TAG_LEN: usize = 32;

/// Nonce length: 24 bytes (192 bits, XChaCha20 extension).
pub const NONCE_LEN: usize = 24;

/// Domain-separation constant placed in the 4-byte ChaCha20 counter position of
/// the subkey-derivation block.
///
/// XChaCha20-Poly1305 (and plain XChaCha20) derive their keystream with the
/// 12-byte ChaCha20 nonce set to `0x00000000 || nonce[16..24]`.  If this crate
/// did the same, then for the *same* `(key, nonce)` both schemes would derive
/// the **same one-time Poly1305 key**, and a protocol that ever mixed the two
/// would reuse that one-time key — which immediately leaks Poly1305's `r`/`s`
/// and breaks authentication.
///
/// Placing a non-zero constant in the first 4 bytes of the ChaCha20 nonce makes
/// the two derivations collide only with negligible probability, so the schemes
/// stay independent even under nonce reuse across them.
///
/// The value is ASCII "XSIV" (XChaCha20-SIV), chosen to be self-describing.
pub const SUBKEY_DOMAIN: [u8; 4] = *b"XSIV";

/// BLAKE3 `derive_key` context string for the CTX commitment term.
///
/// This string is **part of the wire format**: changing it changes every tag
/// ever produced.  It is hardcoded and application-specific, which is what
/// BLAKE3 requires of a `derive_key` context.
///
/// The commitment term is produced by `blake3::derive_key(COMMITMENT_CONTEXT,
/// aad)` rather than by a bare `blake3::hash(aad)`.  Both are collision
/// resistant, but the bare hash is a *fixed, public* function: any other
/// protocol that XORs `BLAKE3(aad)` into a value of its own would be using the
/// same function, so the two uses could cancel against each other.  BLAKE3's
/// `derive_key` mode gives this use a domain of its own (the context key is
/// folded into the root and the block is flagged `DERIVE_KEY_MATERIAL`), which
/// is exactly what a commitment term embedded in a wire format needs.
pub const COMMITMENT_CONTEXT: &str = "XChaCha20-Poly1305-SIV context commitment v1";

// ── Error type ────────────────────────────────────────────────────────

/// Errors returned by [`encrypt`], [`decrypt`] and the detached variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The plaintext (on encryption) or ciphertext (on decryption) is longer
    /// than `MAX_MSG_SIZE` (256 GiB).
    MessageTooLong,
    /// The associated data is longer than `MAX_MSG_SIZE` (256 GiB).
    AadTooLong,
    /// Tag verification failed.  The plaintext is never returned in this case.
    AuthenticationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::MessageTooLong => "message exceeds the maximum supported length",
            Error::AadTooLong => "associated data exceeds the maximum supported length",
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
        // Wipe the whole allocation, not just `len` bytes.
        zeroize_slice(self.0.as_mut_slice());
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

// ── Randomness (optional) ─────────────────────────────────────────────

/// OS-backed random key and nonce generation (requires the `rng` feature).
///
/// # The construction itself needs no randomness
///
/// [`encrypt`] is a deterministic function of `(key, nonce, aad, plaintext)`:
/// every subkey, the tag and the keystream are derived from the key with
/// ChaCha20/HChaCha20, and the commitment term is a hash of the associated
/// data.  Nothing is drawn from a random source internally — which is exactly
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
/// use xchacha20_poly1305_siv::{encrypt, random};
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

    use crate::{KEY_LEN, NONCE_LEN};

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
    /// The returned array is **not** zeroized on drop: it is a plain
    /// `[u8; 32]`, like every other key in this API, so that it can be used
    /// without unwrapping.  Treat it as secret for its whole lifetime and wipe
    /// it when it is no longer needed.
    pub fn generate_key() -> Result<[u8; KEY_LEN], Error> {
        let mut key = [0u8; KEY_LEN];
        fill(&mut key)?;
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
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
        i += 1;
    }
    while i + chunk <= len {
        unsafe { core::ptr::write_volatile(ptr.add(i) as *mut usize, 0) };
        i += chunk;
    }
    // Trailing bytes.
    while i < len {
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

/// Derive the `(poly1305_key, tag_key)` pair for the 24-byte-nonce construction.
///
/// `subkey = HChaCha20(key, nonce[0..16])`, then one ChaCha20 block under
/// `SUBKEY_DOMAIN || nonce[16..24]` yields 64 bytes:
/// `[0..32]` is the Poly1305 key, `[32..64]` the tag/encryption-derivation key.
fn derive_subkeys(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut hchacha_out = hchacha20(key, &nonce[0..16].try_into().unwrap());
    let mut subkey_nonce = [0u8; 12];
    subkey_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
    subkey_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let mut subkeys_buf = [0u8; 64];
    chacha20_keystream_raw(&hchacha_out, 0, &subkey_nonce, &mut subkeys_buf);

    let poly1305_key: [u8; 32] = subkeys_buf[0..32].try_into().unwrap();
    let tag_key: [u8; 32] = subkeys_buf[32..64].try_into().unwrap();

    zeroize_array(&mut hchacha_out);
    zeroize_array(&mut subkeys_buf);
    (poly1305_key, tag_key)
}

/// Derive the 32-byte tag from the Poly1305 tag, the tag key, and the AAD.
///
/// Two halves, XORed together:
///
/// 1. `ChaCha20(tag_key, LE32(p[0..4]), p[4..16], 64 zeros)[0..32]` — the
///    c2sp.org CCP-SIV tag, which already commits to `(key, nonce)` because
///    `tag_key` is derived from them and `p` covers `(aad, plaintext)`.
/// 2. `BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)` — the context-commitment half.
///
/// # Why the XOR (the CTX transform)
///
/// The c2sp.org construction deliberately omits associated-data commitment: its
/// own specification states "there is no context commitment (CMT-3)".  The
/// reason is that CMT-3's adversary *chooses the key*, and therefore knows the
/// Poly1305 `r`; the Poly1305 tag is then a polynomial evaluation the adversary
/// can solve, so it commits to the AAD only up to a 2^64 birthday bound.
///
/// This is the CTX transform of Chan and Rogaway (*On Committing
/// Authenticated-Encryption*, ESORICS 2022): XOR a hash of the context into the
/// tag.  It costs one hash of the AAD — independent of the plaintext length —
/// and does not lengthen the tag.
///
/// # How the commitment is argued (read this before touching the layout)
///
/// The tag is `inner(K, N, A, M) XOR H(A)`, where `inner` is the c2sp.org tag
/// (a PRF under the key the adversary may know) and `H` is BLAKE3 in
/// `derive_key` mode.  A CMT-3 adversary wins by producing two distinct
/// contexts `(K, N, A, M) != (K', N', A', M')` whose tags are both accepted —
/// that is, whose tags are **equal**, since `decrypt` compares all 32 bytes.
/// Solving `inner XOR H(A) = inner' XOR H(A')` requires a collision in `H` or
/// in `inner`; the `H` term is what forces the AAD to be committed, and `inner`
/// supplies no barrier at all for a known key.  Both are 2^128 for a 256-bit
/// tag.
///
/// **The argument runs through the tag, not through the ciphertext.**  It would
/// be wrong to say "the ciphertext is a function of the tag, so equal
/// ciphertext implies equal tag": encryption consumes only `tag[0..16]` (as
/// `enc_key` material) and `tag[16..28]` (as the encryption nonce), so
/// `tag[28..32]` does **not** influence the ciphertext at all, and two
/// different tags can share one ciphertext.  That is harmless — the tag is
/// transmitted (`ciphertext || tag` is the spec's combined encoding) and is
/// verified in full — but it means any future refactor must keep the
/// commitment on the transmitted-and-compared tag.  `tag_tail_does_not_reach_
/// the_ciphertext` pins the property so a change to it is deliberate.
///
/// Hashing only the AAD is sufficient: the key and nonce are already committed
/// through `tag_key`.
fn derive_tag(tag_key: &[u8; 32], poly1305_tag: &[u8; 16], aad: &[u8]) -> [u8; TAG_LEN] {
    let ctr = u32::from_le_bytes([
        poly1305_tag[0],
        poly1305_tag[1],
        poly1305_tag[2],
        poly1305_tag[3],
    ]);
    let nonce: [u8; 12] = poly1305_tag[4..16].try_into().unwrap();
    let mut buf = [0u8; 64];
    chacha20_keystream_raw(tag_key, ctr, &nonce, &mut buf);
    let mut tag: [u8; TAG_LEN] = buf[0..TAG_LEN].try_into().unwrap();
    zeroize_array(&mut buf);

    // XOR, not assignment: the c2sp.org tag must remain the base value so that
    // the two halves are independent and a collision needs to break one of them.
    let commitment = context_commitment(aad);
    for (t, c) in tag.iter_mut().zip(commitment.iter()) {
        *t ^= *c;
    }
    tag
}

/// The context-commitment term over the associated data.
///
/// `blake3::derive_key(COMMITMENT_CONTEXT, aad)`, **not** `blake3::hash(aad)`.
///
/// Both are collision resistant, so either would make the tag commit to the AAD
/// up to `2^128`.  The difference is domain separation: `BLAKE3(aad)` is one
/// fixed public function, and a protocol that separately XORs `BLAKE3(aad)` into
/// something else would be using the *same* value, so the two uses can cancel.
/// `derive_key` keys the hash with [`COMMITMENT_CONTEXT`], giving this use of
/// BLAKE3 a domain that no other protocol shares by accident.
///
/// Split out so the formal-verification harnesses can stub it cheaply and pin
/// the fact that the tag depends on the *whole* AAD.
fn context_commitment(aad: &[u8]) -> [u8; TAG_LEN] {
    blake3::derive_key(COMMITMENT_CONTEXT, aad)
}

/// Derive the encryption key from the tag and the tag key.
/// `encKey = ChaCha20(tag_key, LE32(tag[0..4]), tag[4..16], 64 zeros)[32..64]`
fn derive_enc_key(tag_key: &[u8; 32], tag: &[u8; TAG_LEN]) -> [u8; 32] {
    let ctr = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]);
    let nonce: [u8; 12] = tag[4..16].try_into().unwrap();
    let mut buf = [0u8; 64];
    chacha20_keystream_raw(tag_key, ctr, &nonce, &mut buf);
    let enc_key: [u8; 32] = buf[32..64].try_into().unwrap();
    zeroize_array(&mut buf);
    enc_key
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

/// Encrypt `plaintext` under `(key, nonce, aad)`, returning `(ciphertext, tag)`.
///
/// The tag is 32 bytes, the nonce 24 bytes (XChaCha20 extension).  This is a SIV
/// construction: the tag is computed first, then encryption uses the tag as
/// additional key material.
///
/// Subkey derivation (XChaCha20-style, with domain separation):
/// `subkey = HChaCha20(key, nonce[0..16])`, then
/// `ChaCha20(subkey, 0, SUBKEY_DOMAIN || nonce[16..24], 64 bytes)` →
/// `[0..32] = Poly1305 key`, `[32..64] = tag-derivation key`.
#[must_use = "the returned ciphertext and tag must be handled"]
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Error> {
    check_lengths(plaintext.len(), aad.len())?;

    let (mut poly1305_key, mut tag_key) = derive_subkeys(key, nonce);

    let mut poly1305_tag = poly1305(&poly1305_key, aad, plaintext);
    let tag = derive_tag(&tag_key, &poly1305_tag, aad);
    let mut enc_key = derive_enc_key(&tag_key, &tag);

    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    chacha20_keystream(&enc_key, 0, &enc_data_nonce, plaintext, &mut ciphertext);

    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut poly1305_tag);
    zeroize_array(&mut enc_key);

    Ok((ciphertext, tag))
}

/// Encrypt `buffer` in place, returning the 32-byte tag (detached form).
///
/// On return `buffer` holds the ciphertext.  This avoids allocating a second
/// buffer and is useful for protocols that store the tag separately.
#[must_use = "the returned tag must be handled"]
pub fn encrypt_in_place_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    check_lengths(buffer.len(), aad.len())?;

    let (mut poly1305_key, mut tag_key) = derive_subkeys(key, nonce);

    let mut poly1305_tag = poly1305(&poly1305_key, aad, buffer);
    let tag = derive_tag(&tag_key, &poly1305_tag, aad);
    let mut enc_key = derive_enc_key(&tag_key, &tag);

    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    // XOR in place: read the plaintext into the same buffer we write.  Goes
    // through the same SIMD dispatch as the allocating API — calling
    // `chacha20_block` directly here cost ~3x on large messages.
    chacha20_apply(&enc_key, 0, &enc_data_nonce, &Input::InPlace, buffer);

    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut poly1305_tag);
    zeroize_array(&mut enc_key);

    Ok(tag)
}

/// Decrypt `ciphertext` under `(key, nonce, aad)`, verifying the 32-byte `tag`.
///
/// Returns the plaintext in a [`Plaintext`] wrapper that zeroizes on drop.
/// On authentication failure returns [`Error::AuthenticationFailed`] and never
/// exposes the unverified plaintext.
#[must_use = "the returned plaintext must be handled"]
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Plaintext, Error> {
    check_lengths(ciphertext.len(), aad.len())?;

    let (mut poly1305_key, mut tag_key) = derive_subkeys(key, nonce);
    let mut enc_key = derive_enc_key(&tag_key, tag);

    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    let mut plaintext = vec![0u8; ciphertext.len()];
    chacha20_keystream(&enc_key, 0, &enc_data_nonce, ciphertext, &mut plaintext);

    let mut poly1305_tag = poly1305(&poly1305_key, aad, &plaintext);
    let mut computed_tag = derive_tag(&tag_key, &poly1305_tag, aad);

    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);
    let auth_ok = computed_tag.ct_eq(&tag_arr);

    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut enc_key);
    zeroize_array(&mut poly1305_tag);
    zeroize_array(&mut tag_arr);
    // `computed_tag` is a deterministic function of `tag_key` and the derived
    // Poly1305 tag, i.e. it is as sensitive as the tag key itself.  It was
    // previously left unwiped here while the test-only `decrypt16` did wipe its
    // equivalent (`computed_tag_buf`), so this was a production-path regression
    // against the crate's own invariant.
    zeroize_array(&mut computed_tag);

    if bool::from(auth_ok) {
        Ok(Plaintext(plaintext))
    } else {
        // Wipe plaintext — per spec, MUST NOT expose unverified plaintext
        zeroize_slice(&mut plaintext);
        Err(Error::AuthenticationFailed)
    }
}

/// Decrypt `buffer` in place, verifying the 32-byte `tag` (detached form).
///
/// On success `buffer` holds the plaintext.  On failure the buffer is zeroized
/// and [`Error::AuthenticationFailed`] is returned, so unverified plaintext is
/// never left in place.
pub fn decrypt_in_place_detached(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    check_lengths(buffer.len(), aad.len())?;

    let (mut poly1305_key, mut tag_key) = derive_subkeys(key, nonce);
    let mut enc_key = derive_enc_key(&tag_key, tag);

    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    chacha20_apply(&enc_key, 0, &enc_data_nonce, &Input::InPlace, buffer);

    let mut poly1305_tag = poly1305(&poly1305_key, aad, buffer);
    let mut computed_tag = derive_tag(&tag_key, &poly1305_tag, aad);

    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);
    let auth_ok = computed_tag.ct_eq(&tag_arr);

    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut enc_key);
    zeroize_array(&mut poly1305_tag);
    zeroize_array(&mut tag_arr);
    // Same reasoning as in `decrypt`: `computed_tag` is key-derived material and
    // must not be left in the frame on either the success or the failure path.
    zeroize_array(&mut computed_tag);

    if bool::from(auth_ok) {
        Ok(())
    } else {
        zeroize_slice(buffer);
        Err(Error::AuthenticationFailed)
    }
}

/// Encrypt plaintext under (key, nonce, aad) with a 16-byte nonce.
///
/// **Internal only.**  This is the base c2sp.org ChaCha20-Poly1305-SIV
/// construction (direct ChaCha20 subkey derivation, no HChaCha20).  It exists
/// so the c2sp.org known-answer test vectors can be verified; it is NOT part
/// of the public API, which is 24-byte-nonce only (see `encrypt`).
///
/// `subkeys = ChaCha20(key, ReadLE32(nonce[0..4]), nonce[4..16], allZeros)`
#[cfg(test)]
pub(crate) fn encrypt16(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), &'static str> {
    if plaintext.len() as u64 > MAX_MSG_SIZE {
        return Err("plaintext too long");
    }
    if aad.len() as u64 > MAX_MSG_SIZE {
        return Err("AAD too long");
    }

    // Per c2sp.org: subkeys = ChaCha20(key, ReadLE32(nonce[0..4]), nonce[4..16], allZeros)
    // nonce[0..4] → counter, nonce[4..16] → 12-byte nonce
    let sub_ctr = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    let chacha_nonce: [u8; 12] = nonce[4..16].try_into().unwrap();

    let mut subkeys_buf = chacha20_block(key, sub_ctr, &chacha_nonce);

    let mut poly1305_key: [u8; 32] = [0; 32];
    poly1305_key.copy_from_slice(&subkeys_buf[0..32]);
    let mut tag_key: [u8; 32] = [0; 32];
    tag_key.copy_from_slice(&subkeys_buf[32..64]);
    zeroize_array(&mut subkeys_buf);

    let mut poly1305_tag = poly1305(&poly1305_key, aad, plaintext);

    let tag_ctr = u32::from_le_bytes([
        poly1305_tag[0],
        poly1305_tag[1],
        poly1305_tag[2],
        poly1305_tag[3],
    ]);
    let tag_nonce: [u8; 12] = poly1305_tag[4..16].try_into().unwrap();
    let mut tag_buf = [0u8; 64];
    chacha20_keystream_raw(&tag_key, tag_ctr, &tag_nonce, &mut tag_buf);
    let tag: [u8; TAG_LEN] = tag_buf[0..TAG_LEN].try_into().unwrap();

    let enc_ctr = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]);
    let enc_nonce: [u8; 12] = tag[4..16].try_into().unwrap();
    let mut enc_key_buf = [0u8; 64];
    chacha20_keystream_raw(&tag_key, enc_ctr, &enc_nonce, &mut enc_key_buf);
    let mut enc_key: [u8; 32] = [0; 32];
    enc_key.copy_from_slice(&enc_key_buf[32..64]);

    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    chacha20_keystream(&enc_key, 0, &enc_data_nonce, plaintext, &mut ciphertext);

    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut tag_buf);
    zeroize_array(&mut enc_key_buf);
    zeroize_array(&mut enc_key);
    zeroize_array(&mut poly1305_tag);

    Ok((ciphertext, tag))
}

/// Decrypt ciphertext under (key, nonce, aad) with a 16-byte nonce.
///
/// **Internal only.**  Counterpart of `encrypt16`; kept solely to validate
/// the c2sp.org ChaCha20-Poly1305-SIV KAT vectors.  Not part of the public API.
#[cfg(test)]
pub(crate) fn decrypt16(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() as u64 > MAX_MSG_SIZE {
        return Err("ciphertext too long");
    }
    if aad.len() as u64 > MAX_MSG_SIZE {
        return Err("AAD too long");
    }

    // Per c2sp.org: subkeys = ChaCha20(key, ReadLE32(nonce[0..4]), nonce[4..16], allZeros)
    let sub_ctr = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    let chacha_nonce: [u8; 12] = nonce[4..16].try_into().unwrap();

    // Generate ONE 64-byte ChaCha20 block (matching spec's "allZeros" input)
    let mut subkeys_buf = chacha20_block(key, sub_ctr, &chacha_nonce);

    let mut poly1305_key: [u8; 32] = [0; 32];
    poly1305_key.copy_from_slice(&subkeys_buf[0..32]);
    let mut tag_key: [u8; 32] = [0; 32];
    tag_key.copy_from_slice(&subkeys_buf[32..64]);
    zeroize_array(&mut subkeys_buf);

    // Step 2: Derive encryption key
    let enc_ctr = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]);
    let enc_nonce: [u8; 12] = tag[4..16].try_into().unwrap();
    let mut enc_key_buf = [0u8; 64];
    chacha20_keystream_raw(&tag_key, enc_ctr, &enc_nonce, &mut enc_key_buf);
    let mut enc_key: [u8; 32] = [0; 32];
    enc_key.copy_from_slice(&enc_key_buf[32..64]);

    // Decrypt ciphertext
    let enc_data_nonce: [u8; 12] = tag[16..28].try_into().unwrap();
    let mut plaintext = vec![0u8; ciphertext.len()];
    chacha20_keystream(&enc_key, 0, &enc_data_nonce, ciphertext, &mut plaintext);

    // Step 3: Compute Poly1305 tag over plaintext
    let mut poly1305_tag = poly1305(&poly1305_key, aad, &plaintext);

    // Step 4: Compute expected tag
    let computed_ctr = u32::from_le_bytes([
        poly1305_tag[0],
        poly1305_tag[1],
        poly1305_tag[2],
        poly1305_tag[3],
    ]);
    let computed_nonce: [u8; 12] = poly1305_tag[4..16].try_into().unwrap();
    let mut computed_tag_buf = [0u8; 64];
    chacha20_keystream_raw(
        &tag_key,
        computed_ctr,
        &computed_nonce,
        &mut computed_tag_buf,
    );
    let computed_tag: [u8; TAG_LEN] = computed_tag_buf[0..TAG_LEN].try_into().unwrap();

    // Step 5: Constant-time tag comparison
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);

    let auth_ok = computed_tag.ct_eq(&tag_arr);

    // Zeroize ALL intermediate secrets before branching on auth result
    zeroize_array(&mut poly1305_key);
    zeroize_array(&mut tag_key);
    zeroize_array(&mut enc_key_buf);
    zeroize_array(&mut enc_key);
    zeroize_array(&mut poly1305_tag);
    zeroize_array(&mut computed_tag_buf);
    zeroize_array(&mut tag_arr);

    if bool::from(auth_ok) {
        Ok(plaintext)
    } else {
        // Wipe plaintext — per spec, MUST NOT expose unverified plaintext
        zeroize_slice(&mut plaintext);
        Err("Authentication failed")
    }
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

    // 【侧信道防护】就地清除含密钥派生中间值的状态。
    // 注意：必须直接清零 `s`/`orig`/`out` 这些局部变量本身。此前写成
    // `let mut orig = orig; zeroize_array(&mut orig);` 只会清零一份**副本**
    // （`[u32; 16]` 是 `Copy`），原始值仍留在栈内存中，等于没有擦除。
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

    /// Four-block Poly1305 batch (AVX2).
    ///
    /// Poly1305 is serial across blocks, so four blocks are instead expressed as
    /// the polynomial `(h+m₀)·r⁴ + m₁·r³ + m₂·r² + m₃·r`; the four products are
    /// then independent and run in four 64-bit lanes.  Limb `j` of the four
    /// blocks is held in one `__m256i` (lane k = block k), so a lane-wise
    /// multiply-accumulate covers all four blocks at once.  The result is the
    /// five wide accumulators, identical to `poly1305_accumulate4_scalar`.
    ///
    /// The powers of `r` are broadcast once per *message* by
    /// `poly1305_absorb_bulk`, not per four-block group.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn poly1305_absorb_bulk(
        h: &mut [u32; 5],
        data: &[u8],
        p: &super::Poly1305Powers,
    ) {
        // Limb values are < 2^27 and the pre-scaled `s` limbs < 2^29, so
        // `_mm256_mul_epu32` (which multiplies the low 32 bits of each 64-bit
        // lane) is exact.
        let mut rr = [_mm256_setzero_si256(); 5];
        let mut ss = [_mm256_setzero_si256(); 5];
        for j in 0..5 {
            rr[j] = _mm256_set_epi64x(
                p.r[3][j] as i64,
                p.r[2][j] as i64,
                p.r[1][j] as i64,
                p.r[0][j] as i64,
            );
            ss[j] = _mm256_set_epi64x(
                p.s[3][j] as i64,
                p.s[2][j] as i64,
                p.s[1][j] as i64,
                p.s[0][j] as i64,
            );
        }

        for g in 0..data.len() / (4 * 16) {
            let group = &data[g * 64..g * 64 + 64];
            // v[k] = limbs of block k, with the running accumulator folded into
            // lane 0 only (the other lanes start from zero).
            let mut v = [[0u32; 5]; 4];
            for (k, vk) in v.iter_mut().enumerate() {
                let block: &[u8; 16] = group[k * 16..k * 16 + 16].try_into().unwrap();
                *vk = super::poly1305_block_limbs(block, true);
            }
            for i in 0..5 {
                v[0][i] = v[0][i].wrapping_add(h[i]);
            }

            let mut vv = [_mm256_setzero_si256(); 5];
            for (j, vvj) in vv.iter_mut().enumerate() {
                *vvj = _mm256_set_epi64x(
                    v[3][j] as i64,
                    v[2][j] as i64,
                    v[1][j] as i64,
                    v[0][j] as i64,
                );
            }

            let mut acc = [0u64; 5];
            for (i, a) in acc.iter_mut().enumerate() {
                let mut sum = _mm256_setzero_si256();
                for (j, vvj) in vv.iter().enumerate() {
                    // Output limb i takes v[j] * r[(i-j) mod 5]; the wrap past
                    // limb 4 folds in the 2^130 ≡ 5 factor via the pre-scaled `s`.
                    let (idx, use_scaled) = if j <= i {
                        (i - j, false)
                    } else {
                        (i + 5 - j, true)
                    };
                    let rv = if use_scaled { ss[idx] } else { rr[idx] };
                    sum = _mm256_add_epi64(sum, _mm256_mul_epu32(*vvj, rv));
                }
                // Horizontal sum of the four 64-bit lanes.
                let lo = _mm256_castsi256_si128(sum);
                let hi = _mm256_extracti128_si256(sum, 1);
                let pair = _mm_add_epi64(lo, hi);
                let total = _mm_add_epi64(pair, _mm_srli_si128(pair, 8));
                *a = _mm_cvtsi128_si64(total) as u64;
            }

            super::poly1305_reduce_wide(h, &acc);
        }

        // `rr`/`ss` are register copies of the secret powers of `r`; wipe them
        // once per message.  (The message limbs in `vv` are not secret.)
        super::zeroize_array(&mut rr);
        super::zeroize_array(&mut ss);
    }

    /// Four-block Poly1305 batch (AVX2), single group.  Used by the tests that
    /// compare each backend against the scalar reference in isolation.
    #[cfg(test)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn poly1305_accumulate4(
        h: &[u32; 5],
        m: &[[u8; 16]; 4],
        r: &[[u32; 5]; 4],
        s: &[[u32; 5]; 4],
    ) -> [u64; 5] {
        // v[k] = limbs of block k, with the running accumulator folded into
        // lane 0 only (the other lanes start from zero).
        let mut v = [[0u32; 5]; 4];
        for k in 0..4 {
            v[k] = super::poly1305_block_limbs(&m[k], true);
        }
        for i in 0..5 {
            v[0][i] = v[0][i].wrapping_add(h[i]);
        }

        // Broadcast limb j across the four blocks into 64-bit lanes.  Limb
        // values are < 2^27, so `_mm256_mul_epu32` (which multiplies the low 32
        // bits of each 64-bit lane) is exact.
        let mut vv = [_mm256_setzero_si256(); 5];
        let mut rr = [_mm256_setzero_si256(); 5];
        let mut ss = [_mm256_setzero_si256(); 5];
        for j in 0..5 {
            vv[j] = _mm256_set_epi64x(
                v[3][j] as i64,
                v[2][j] as i64,
                v[1][j] as i64,
                v[0][j] as i64,
            );
            rr[j] = _mm256_set_epi64x(
                r[3][j] as i64,
                r[2][j] as i64,
                r[1][j] as i64,
                r[0][j] as i64,
            );
            ss[j] = _mm256_set_epi64x(
                s[3][j] as i64,
                s[2][j] as i64,
                s[1][j] as i64,
                s[0][j] as i64,
            );
        }

        let mut out = [0u64; 5];
        for (i, o) in out.iter_mut().enumerate() {
            let mut acc = _mm256_setzero_si256();
            for (j, vvj) in vv.iter().enumerate() {
                // Output limb i takes v[j] * r[(i-j) mod 5]; the wrap past limb
                // 4 folds in the 2^130 ≡ 5 factor via the pre-scaled `s`.
                let (idx, use_scaled) = if j <= i {
                    (i - j, false)
                } else {
                    (i + 5 - j, true)
                };
                let rv = if use_scaled { ss[idx] } else { rr[idx] };
                acc = _mm256_add_epi64(acc, _mm256_mul_epu32(*vvj, rv));
            }
            // Horizontal sum of the four 64-bit lanes.
            let lo = _mm256_castsi256_si128(acc);
            let hi = _mm256_extracti128_si256(acc, 1);
            let pair = _mm_add_epi64(lo, hi);
            let total = _mm_add_epi64(pair, _mm_srli_si128(pair, 8));
            *o = _mm_cvtsi128_si64(total) as u64;
        }
        out
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

    /// Four-block Poly1305 batch (NEON).
    ///
    /// Same polynomial trick as the AVX2 kernel: four blocks become
    /// `(h+m₀)·r⁴ + m₁·r³ + m₂·r² + m₃·r`, so the four products are independent
    /// and fill four 64-bit lanes (two `uint64x2_t` registers).
    ///
    /// NEON has no 64-bit vector multiply on the AArch64 baseline, so the
    /// products use `vmull_u32` (32x32 -> 64).  That is exact here because limbs
    /// are < 2^27 and the pre-scaled `s` limbs are < 2^29.
    ///
    /// The powers of `r` are packed once per *message* by
    /// `poly1305_absorb_bulk`, not per four-block group.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn poly1305_absorb_bulk(
        h: &mut [u32; 5],
        data: &[u8],
        p: &super::Poly1305Powers,
    ) {
        // Pack lanes [0,1] and [2,3] into two 32-bit-lane registers per limb;
        // `vmull_u32` widens each product to a 64-bit lane.
        let mut rr_lo = [vdup_n_u32(0); 5];
        let mut rr_hi = [vdup_n_u32(0); 5];
        let mut ss_lo = [vdup_n_u32(0); 5];
        let mut ss_hi = [vdup_n_u32(0); 5];
        for j in 0..5 {
            let rlanes: [u32; 4] = [p.r[0][j], p.r[1][j], p.r[2][j], p.r[3][j]];
            let slanes: [u32; 4] = [p.s[0][j], p.s[1][j], p.s[2][j], p.s[3][j]];
            rr_lo[j] = vld1_u32(rlanes.as_ptr());
            rr_hi[j] = vld1_u32(rlanes.as_ptr().add(2));
            ss_lo[j] = vld1_u32(slanes.as_ptr());
            ss_hi[j] = vld1_u32(slanes.as_ptr().add(2));
        }

        for g in 0..data.len() / (4 * 16) {
            let group = &data[g * 64..g * 64 + 64];
            let mut v = [[0u32; 5]; 4];
            for (k, vk) in v.iter_mut().enumerate() {
                let block: &[u8; 16] = group[k * 16..k * 16 + 16].try_into().unwrap();
                *vk = super::poly1305_block_limbs(block, true);
            }
            for i in 0..5 {
                v[0][i] = v[0][i].wrapping_add(h[i]);
            }

            let mut vv_lo = [vdup_n_u32(0); 5];
            let mut vv_hi = [vdup_n_u32(0); 5];
            for j in 0..5 {
                let vlanes: [u32; 4] = [v[0][j], v[1][j], v[2][j], v[3][j]];
                vv_lo[j] = vld1_u32(vlanes.as_ptr());
                vv_hi[j] = vld1_u32(vlanes.as_ptr().add(2));
            }

            let mut acc = [0u64; 5];
            for (i, a) in acc.iter_mut().enumerate() {
                let mut acc_lo = vdupq_n_u64(0);
                let mut acc_hi = vdupq_n_u64(0);
                for j in 0..5 {
                    // Output limb i takes v[j] * r[(i-j) mod 5]; the wrap past
                    // limb 4 folds in the 2^130 ≡ 5 factor via the pre-scaled `s`.
                    let (idx, use_scaled) = if j <= i {
                        (i - j, false)
                    } else {
                        (i + 5 - j, true)
                    };
                    let (rv_lo, rv_hi) = if use_scaled {
                        (ss_lo[idx], ss_hi[idx])
                    } else {
                        (rr_lo[idx], rr_hi[idx])
                    };
                    acc_lo = vaddq_u64(acc_lo, vmull_u32(vv_lo[j], rv_lo));
                    acc_hi = vaddq_u64(acc_hi, vmull_u32(vv_hi[j], rv_hi));
                }
                let total = vaddq_u64(acc_lo, acc_hi);
                let mut lanes = [0u64; 2];
                vst1q_u64(lanes.as_mut_ptr(), total);
                *a = lanes[0].wrapping_add(lanes[1]);
            }

            super::poly1305_reduce_wide(h, &acc);
        }

        // `rr_lo`/`rr_hi`/`ss_lo`/`ss_hi` are register copies of the secret
        // powers of `r`; wipe them once per message.  (The message limbs in
        // `vv` are not secret.)
        super::zeroize_array(&mut rr_lo);
        super::zeroize_array(&mut rr_hi);
        super::zeroize_array(&mut ss_lo);
        super::zeroize_array(&mut ss_hi);
    }

    /// Four-block Poly1305 batch (NEON), single group.  Used by the tests that
    /// compare each backend against the scalar reference in isolation.
    #[cfg(test)]
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn poly1305_accumulate4(
        h: &[u32; 5],
        m: &[[u8; 16]; 4],
        r: &[[u32; 5]; 4],
        s: &[[u32; 5]; 4],
    ) -> [u64; 5] {
        let mut v = [[0u32; 5]; 4];
        for k in 0..4 {
            v[k] = super::poly1305_block_limbs(&m[k], true);
        }
        for i in 0..5 {
            v[0][i] = v[0][i].wrapping_add(h[i]);
        }

        let mut vv_lo = [vdup_n_u32(0); 5];
        let mut vv_hi = [vdup_n_u32(0); 5];
        let mut rr_lo = [vdup_n_u32(0); 5];
        let mut rr_hi = [vdup_n_u32(0); 5];
        let mut ss_lo = [vdup_n_u32(0); 5];
        let mut ss_hi = [vdup_n_u32(0); 5];
        for j in 0..5 {
            let vlanes: [u32; 4] = [v[0][j], v[1][j], v[2][j], v[3][j]];
            let rlanes: [u32; 4] = [r[0][j], r[1][j], r[2][j], r[3][j]];
            let slanes: [u32; 4] = [s[0][j], s[1][j], s[2][j], s[3][j]];
            vv_lo[j] = vld1_u32(vlanes.as_ptr());
            vv_hi[j] = vld1_u32(vlanes.as_ptr().add(2));
            rr_lo[j] = vld1_u32(rlanes.as_ptr());
            rr_hi[j] = vld1_u32(rlanes.as_ptr().add(2));
            ss_lo[j] = vld1_u32(slanes.as_ptr());
            ss_hi[j] = vld1_u32(slanes.as_ptr().add(2));
        }

        let mut out = [0u64; 5];
        for (i, o) in out.iter_mut().enumerate() {
            let mut acc_lo = vdupq_n_u64(0);
            let mut acc_hi = vdupq_n_u64(0);
            for j in 0..5 {
                // Output limb i takes v[j] * r[(i-j) mod 5]; the wrap past limb
                // 4 folds in the 2^130 ≡ 5 factor via the pre-scaled `s`.
                let (idx, use_scaled) = if j <= i {
                    (i - j, false)
                } else {
                    (i + 5 - j, true)
                };
                let (rv_lo, rv_hi) = if use_scaled {
                    (ss_lo[idx], ss_hi[idx])
                } else {
                    (rr_lo[idx], rr_hi[idx])
                };
                acc_lo = vaddq_u64(acc_lo, vmull_u32(vv_lo[j], rv_lo));
                acc_hi = vaddq_u64(acc_hi, vmull_u32(vv_hi[j], rv_hi));
            }
            let total = vaddq_u64(acc_lo, acc_hi);
            let mut lanes = [0u64; 2];
            vst1q_u64(lanes.as_mut_ptr(), total);
            *o = lanes[0].wrapping_add(lanes[1]);
        }
        out
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

    let mut orig = s;
    let mut out = chacha20_rounds(s);

    let mut r = [0u8; 32];
    // Output words 0,1,2,3,12,13,14,15 (NO final addition!)
    let indices = [0usize, 1, 2, 3, 12, 13, 14, 15];
    for (i, &idx) in indices.iter().enumerate() {
        r[i * 4..i * 4 + 4].copy_from_slice(&out[idx].to_le_bytes());
    }

    // 【侧信道防护】就地清除 HChaCha20 内部状态（含主密钥材料）。
    // 必须直接清零局部变量本身；若先 `let mut x = x;` 再清零，只会擦掉
    // `[u32; 16]` 的副本，原值仍残留在栈上。
    zeroize_array(&mut s);
    zeroize_array(&mut orig);
    zeroize_array(&mut out);

    r
}

// ── Poly1305 ─────────────────────────────────────────────────────────

/// Poly1305 one-time MAC.
///
/// Per RFC 8439 §2.8 (with the ciphertext replaced by the plaintext):
/// MAC input = aad || pad16(aad) || plaintext || pad16(plaintext)
///             || le64(aad length in bytes) || le64(plaintext length in bytes)
/// where pad16 appends the minimum number of ZERO bytes to reach a 16-byte
/// boundary. Since every component is zero-padded to a multiple of 16 bytes,
/// the whole MAC input is always a multiple of 16 — every block is a FULL
/// block and receives the 2^128 high bit (standard Poly1305 block handling).
/// Returns a 16-byte tag.
fn poly1305(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> [u8; 16] {
    let mut state = Poly1305State::new(key);

    // AAD and plaintext, each zero-padded to a 16-byte boundary (pad16)
    state.absorb_padded(aad);
    state.absorb_padded(plaintext);

    // Single 16-byte length block: le64(aad length in bytes) || le64(pt length in bytes)
    // Per RFC 8439 AEAD pad16 semantics, the length block is a full 16-byte block
    // and MUST be processed with hibit=1 (add 2^128), like all other blocks.
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
    state.process_block(&len_block, true);

    state.finalize(key)
}

/// Convert a 16-byte block into five 26-bit limbs.
///
/// `hibit` adds 2^128 (bit 24 of the fifth limb).  RFC 8439 requires it for
/// every block this construction feeds to Poly1305, since all inputs are whole
/// blocks after pad16 (including the length block).
#[inline]
fn poly1305_block_limbs(block: &[u8; 16], hibit: bool) -> [u32; 5] {
    // RFC 8439 §2.8.1 block decomposition.  Each 26-bit number straddles byte
    // boundaries; the overlapping reads must be assembled bit-by-bit, NOT via
    // `u32::from_le_bytes(..) >> N`.
    let mut b = [0u32; 5];

    b[0] = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff;

    b[1] = ((block[3] as u32) >> 2)
        | ((block[4] as u32) << 6)
        | ((block[5] as u32) << 14)
        | ((block[6] as u32) << 22);
    b[1] &= 0x3ffffff;

    b[2] = ((block[6] as u32) >> 4)
        | ((block[7] as u32) << 4)
        | ((block[8] as u32) << 12)
        | ((block[9] as u32) << 20);
    b[2] &= 0x3ffffff;

    b[3] = ((block[9] as u32) >> 6)
        | ((block[10] as u32) << 2)
        | ((block[11] as u32) << 10)
        | ((block[12] as u32) << 18);
    b[3] &= 0x3ffffff;

    b[4] = ((block[12] as u32) >> 8)
        | (block[13] as u32)
        | ((block[14] as u32) << 8)
        | ((block[15] as u32) << 16);
    if hibit {
        b[4] |= 1 << 24;
    }
    b
}

/// Multiply two 5-limb values modulo 2^130-5, returning the five *unreduced*
/// 64-bit accumulators `d_i = Σ_j a[j]·b[(i-j) mod 5]`.
///
/// Limbs must be < 2^27 on entry so every `d_i` stays below 2^58 and cannot
/// overflow; the `2^130 ≡ 5` fold is applied by using `5·b` for the wrapped
/// terms.  This is the exact quantity both the scalar and the SIMD four-block
/// kernels must agree on.
#[inline]
fn poly1305_mul_wide(a: &[u32; 5], b: &[u32; 5]) -> [u64; 5] {
    // s_i = b_i * 5, encoding 2^130 ≡ 5 (mod 2^130-5).
    let s1 = (b[1] as u64) * 5;
    let s2 = (b[2] as u64) * 5;
    let s3 = (b[3] as u64) * 5;
    let s4 = (b[4] as u64) * 5;

    let a0 = a[0] as u64;
    let a1 = a[1] as u64;
    let a2 = a[2] as u64;
    let a3 = a[3] as u64;
    let a4 = a[4] as u64;
    let b0 = b[0] as u64;
    let b1 = b[1] as u64;
    let b2 = b[2] as u64;
    let b3 = b[3] as u64;
    let b4 = b[4] as u64;

    [
        a0 * b0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1,
        a0 * b1 + a1 * b0 + a2 * s4 + a3 * s3 + a4 * s2,
        a0 * b2 + a1 * b1 + a2 * b0 + a3 * s4 + a4 * s3,
        a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * s4,
        a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0,
    ]
}

/// Multiply two 5-limb values modulo 2^130-5, returning five reduced limbs.
///
/// Limbs must be < 2^26 on entry.  Only used to precompute the powers of `r`;
/// the same carry convention as `Poly1305State::process_block` is applied so the
/// results stay in the representation the main loop expects.
fn poly1305_mul(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
    let d = poly1305_mul_wide(a, b);

    let mut h = [0u32; 5];
    let mut c = d[0] >> 26;
    h[0] = (d[0] as u32) & 0x3ffffff;
    let d1 = d[1] + c;
    c = d1 >> 26;
    h[1] = (d1 as u32) & 0x3ffffff;
    let d2 = d[2] + c;
    c = d2 >> 26;
    h[2] = (d2 as u32) & 0x3ffffff;
    let d3 = d[3] + c;
    c = d3 >> 26;
    h[3] = (d3 as u32) & 0x3ffffff;
    let d4 = d[4] + c;
    c = d4 >> 26;
    h[4] = (d4 as u32) & 0x3ffffff;
    h[0] = h[0].wrapping_add((c as u32) * 5);
    c = (h[0] >> 26) as u64;
    h[0] &= 0x3ffffff;
    h[1] = h[1].wrapping_add(c as u32);
    h
}

/// Powers of `r` for 4-way batched Poly1305.
///
/// Batch index `k` (0..4) is multiplied by `r^(4-k)`, i.e. `r[0] = r⁴`,
/// `r[1] = r³`, `r[2] = r²`, `r[3] = r¹`.
struct Poly1305Powers {
    r: [[u32; 5]; 4],
    /// `r[k]` with every limb multiplied by 5 (the 2^130 ≡ 5 reduction).
    s: [[u32; 5]; 4],
}

impl Poly1305Powers {
    fn new(r: &[u32; 5]) -> Self {
        let r2 = poly1305_mul(r, r);
        let r3 = poly1305_mul(&r2, r);
        let r4 = poly1305_mul(&r2, &r2);

        let rp = [r4, r3, r2, *r];
        let mut sp = [[0u32; 5]; 4];
        for k in 0..4 {
            for i in 0..5 {
                sp[k][i] = rp[k][i] * 5;
            }
        }
        Self { r: rp, s: sp }
    }
}

/// Zeroize the secret powers of `r` once the message is done.
impl Drop for Poly1305Powers {
    fn drop(&mut self) {
        zeroize_array(&mut self.r);
        zeroize_array(&mut self.s);
    }
}

/// Reduce five wide accumulators back to the 26-bit limb representation.
///
/// Shared by the scalar and SIMD 4-block batches so both must produce identical
/// limbs.  Accepts accumulators up to `< 2^62` (both kernels sum raw products
/// rather than pre-reduced limbs), so the carry propagation is done in `u64` and
/// the `2^130 ≡ 5` fold is applied twice.
///
/// # What this function does and does not guarantee
///
/// It guarantees the **residue**: the returned limbs represent a value
/// congruent to `Σ acc[i]·2^(26i)` modulo `2^130 - 5`.
///
/// It does **not** guarantee a canonical limb representation.  Two accumulator
/// vectors that are congruent modulo `2^130 - 5` can reduce to *different*
/// limb vectors — for example `[0,0,0,0,0]` and `[P,0,0,0,0]` (with
/// `P = 2^130-5`) both reduce to residue 0 but produce different limbs.  That is
/// fine here because the only consumer is `finalize`, which reduces the residue
/// modulo `2^130-5` again before adding the pad, so a non-canonical input still
/// yields the correct tag.  It does mean the batched and serial paths legitimately
/// hold different limb values for the same message; they agree on the final tag,
/// which is what the tests pin (`test_poly1305_batch_matches_serial`).
///
/// The second fold pass is **load-bearing, not a no-op**: the accumulators reach
/// roughly `2^58`, so a single pass can leave a carry in limb 4 that the second
/// pass has to propagate.
#[inline]
fn poly1305_reduce_wide(h: &mut [u32; 5], acc: &[u64; 5]) {
    const M: u64 = 0x3ffffff;
    let mut r = [0u64; 5];

    let mut c = acc[0] >> 26;
    r[0] = acc[0] & M;
    for i in 1..5 {
        let t = acc[i] + c;
        c = t >> 26;
        r[i] = t & M;
    }

    // Fold the overflow out of the top limb: 2^130 ≡ 5 (mod 2^130-5).
    let t0 = r[0] + c * 5;
    c = t0 >> 26;
    r[0] = t0 & M;
    for ri in r.iter_mut().skip(1) {
        let t = *ri + c;
        c = t >> 26;
        *ri = t & M;
    }

    // `c` is now 0 or 1; one last fold restores the invariant.  Limb 1 may end
    // up exactly 2^26, which the rest of the code tolerates.
    let t0 = r[0] + c * 5;
    r[0] = t0 & M;
    r[1] += t0 >> 26;

    for (hi, ri) in h.iter_mut().zip(r.iter()) {
        *hi = *ri as u32;
    }
}

/// Scalar accumulation for the four-block batch: returns the five wide
/// accumulators of `(h + m₀)·r⁴ + m₁·r³ + m₂·r² + m₃·r`.
///
/// This is both the correctness reference and the fallback for architectures
/// without a SIMD backend.  The SIMD kernels must return identical values.
fn poly1305_accumulate4_scalar(h: &[u32; 5], m: &[[u8; 16]; 4], r: &[[u32; 5]; 4]) -> [u64; 5] {
    let mut v = [[0u32; 5]; 4];
    for k in 0..4 {
        v[k] = poly1305_block_limbs(&m[k], true);
    }
    // Only lane 0 carries the running accumulator; the others start from zero.
    for i in 0..5 {
        v[0][i] = v[0][i].wrapping_add(h[i]);
    }

    let mut acc = [0u64; 5];
    for k in 0..4 {
        let prod = poly1305_mul_wide(&v[k], &r[k]);
        for i in 0..5 {
            acc[i] += prod[i];
        }
    }
    acc
}

/// Four-block Poly1305 batch, using SIMD where available.
///
/// Computes `h = (h + m₀)·r⁴ + m₁·r³ + m₂·r² + m₃·r  (mod 2^130-5)`.
/// Poly1305 is inherently serial across blocks; expressing four blocks as a
/// polynomial in `r` makes the four multiplications independent so they can run
/// in parallel lanes.  Falls back to `poly1305_accumulate4_scalar`.
#[cfg(test)]
fn poly1305_batch4(h: &mut [u32; 5], m: &[[u8; 16]; 4], p: &Poly1305Powers) {
    let acc = poly1305_accumulate4(h, m, &p.r, &p.s);
    poly1305_reduce_wide(h, &acc);
}

/// Absorb `data` (a multiple of 64 bytes) in four-block groups, using the
/// widest available kernel.  The powers of `r` are broadcast once for the whole
/// call, so the per-group cost is the arithmetic alone.
///
/// # Why this asserts rather than `debug_assert!`s
///
/// Every kernel iterates `for g in 0..data.len() / (4 * POLY1305_BLOCK_SIZE)`,
/// so a `data` length that is *not* a multiple of 64 leaves the trailing bytes
/// unabsorbed.  With a `debug_assert_eq!` that truncation was silent in release
/// builds: the MAC would cover less input than the caller passed, producing a
/// self-consistent but **wrong tag** — the failure mode that no roundtrip test
/// can detect, because encrypt and decrypt would both skip the same bytes.
///
/// The check is therefore a hard `assert!`.  It is an internal invariant (the
/// only caller passes a length it computed as a multiple in
/// `Poly1305State::absorb_padded`), so a violation means a bug in this crate,
/// and failing loudly is strictly better than truncating the MAC input.
fn poly1305_absorb_bulk(h: &mut [u32; 5], data: &[u8], p: &Poly1305Powers) {
    assert_eq!(
        data.len() % (4 * POLY1305_BLOCK_SIZE),
        0,
        "poly1305_absorb_bulk requires a whole number of four-block groups"
    );

    // SIMD kernels are compiled out under Kani: CBMC has no model for the
    // intrinsics and would treat them as unconstrained, making the proofs
    // vacuous.  The scalar loop below is the reference the kernels are tested
    // against.
    #[cfg(all(target_arch = "x86_64", not(kani)))]
    {
        if x86_simd::has_avx2() {
            // SAFETY: AVX2 was confirmed available at runtime.
            unsafe { x86_simd::poly1305_absorb_bulk(h, data, p) };
            return;
        }
    }
    #[cfg(all(target_arch = "aarch64", not(kani)))]
    {
        // SAFETY: NEON is part of the ARMv8-A baseline.
        unsafe { aarch64_simd::poly1305_absorb_bulk(h, data, p) };
        return;
    }
    #[allow(unreachable_code)]
    for g in 0..data.len() / (4 * 16) {
        let group = &data[g * 64..g * 64 + 64];
        let mut m = [[0u8; 16]; 4];
        for (k, blk) in m.iter_mut().enumerate() {
            blk.copy_from_slice(&group[k * 16..k * 16 + 16]);
        }
        let acc = poly1305_accumulate4_scalar(h, &m, &p.r);
        poly1305_reduce_wide(h, &acc);
    }
}

/// Dispatch to the widest available 4-block Poly1305 kernel (single group).
///
/// `s` (the pre-scaled `5·r` limbs) is only consumed by the SIMD kernels; the
/// scalar fallback derives them from `r` itself.  On a target with neither
/// backend it is therefore unused, which is expected rather than a mistake, so
/// the allowance is scoped to exactly that configuration instead of applying
/// blanket-wide.
#[cfg(test)]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(unused_variables)
)]
fn poly1305_accumulate4(
    h: &[u32; 5],
    m: &[[u8; 16]; 4],
    r: &[[u32; 5]; 4],
    s: &[[u32; 5]; 4],
) -> [u64; 5] {
    #[cfg(target_arch = "x86_64")]
    {
        if x86_simd::has_avx2() {
            // SAFETY: AVX2 was confirmed available at runtime.
            return unsafe { x86_simd::poly1305_accumulate4(h, m, r, s) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is part of the ARMv8-A baseline.
        return unsafe { aarch64_simd::poly1305_accumulate4(h, m, r, s) };
    }
    #[allow(unreachable_code)]
    poly1305_accumulate4_scalar(h, m, r)
}

struct Poly1305State {
    h: [u32; 5],
    r: [u64; 5],
    s: [u64; 4],
}

impl Poly1305State {
    fn new(key: &[u8; 32]) -> Self {
        // Parse Poly1305 key: first 16 bytes → r (clamped), next 16 bytes → s
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        let r0 = (t0 & 0x3ffffff) as u64;
        let r1 = (((t0 >> 26) | (t1 << 6)) & 0x3ffff03) as u64;
        let r2 = (((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff) as u64;
        let r3 = (((t2 >> 14) | (t3 << 18)) & 0x3f03fff) as u64;
        let r4 = ((t3 >> 8) & 0x00fffff) as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        Self {
            h: [0u32; 5],
            r: [r0, r1, r2, r3, r4],
            s: [s1, s2, s3, s4],
        }
    }

    /// Absorb a byte slice, zero-padding it to a 16-byte boundary
    /// (RFC 8439 pad16: append 0x00 bytes to reach a multiple of 16).
    fn absorb_padded(&mut self, data: &[u8]) {
        let mut i = 0;
        let n = data.len();

        // Four blocks at a time via the batched polynomial, so the SIMD kernels
        // get independent multiplications to run in parallel lanes.  The powers
        // of `r` are derived once for the whole run.
        let bulk = n - (n % (4 * POLY1305_BLOCK_SIZE));
        if bulk > 0 {
            // `[u32; 5]` copy of the clamped `r`.  `self.r` is wiped in
            // `finalize`, but that does not wipe *this* stack copy, and `r` is
            // the Poly1305 MAC key.  `Poly1305Powers` wipes its own derived
            // powers on drop; this covers the input they were derived from.
            let mut r = [
                self.r[0] as u32,
                self.r[1] as u32,
                self.r[2] as u32,
                self.r[3] as u32,
                self.r[4] as u32,
            ];
            let powers = Poly1305Powers::new(&r);
            poly1305_absorb_bulk(&mut self.h, &data[..bulk], &powers);
            // `powers` borrows nothing, so it is dead here; wipe `r` after it is
            // last used.  The drop of `powers` (and its wipe) happens at the end
            // of this block, which is fine — order between the two is irrelevant.
            zeroize_array(&mut r);
            i = bulk;
        }

        // Process full 16-byte blocks
        while i + POLY1305_BLOCK_SIZE <= n {
            let block: [u8; POLY1305_BLOCK_SIZE] =
                data[i..i + POLY1305_BLOCK_SIZE].try_into().unwrap();
            self.process_block(&block, true); // hibit=1 for data blocks
            i += POLY1305_BLOCK_SIZE;
        }

        // Process remaining bytes as a partial block, padded with zeros
        let rem = n - i;
        if rem > 0 {
            let mut block = [0u8; POLY1305_BLOCK_SIZE];
            block[..rem].copy_from_slice(&data[i..n]);
            // Pad remainder with zeros (0x00) — pad16 per RFC 8439
            // block[rem..16] is already zero
            self.process_block(&block, true); // hibit=1 for data blocks
        }
    }

    /// Process a single 16-byte block.
    ///
    /// `hibit` controls whether bit 24 of the 5th number is set (the `2^128`
    /// term of RFC 8439 §2.8.1 block decomposition).
    ///
    /// Every call site in this crate passes `true`, **including the length
    /// block**: this construction's MAC input is `aad || pad16(aad) ||
    /// plaintext || pad16(plaintext) || le64(len_aad) || le64(len_pt)`, and
    /// every component is zero-padded to a 16-byte multiple, so the whole input
    /// is a multiple of 16 and every block — length block included — is a full
    /// block receiving `hibit`.  The parameter is kept because
    /// `Poly1305State::process_block` is also the reference the Kani harness
    /// `poly1305_hibit_adds_2_128` compares against.
    ///
    /// Regression guard: passing `false` for the length block was the bug that
    /// made every KAT fail — it changes the tag for every message, so a
    /// self-consistent encrypt/decrypt pair cannot detect it.
    fn process_block(&mut self, block: &[u8; 16], hibit: bool) {
        // RFC 8439 §2.8.1 block decomposition — matches reference implementation exactly.
        // Each 26-bit number straddles byte boundaries; overlapping reads must be
        // constructed bit-by-bit, NOT via u32::from_le_bytes(...) >> N.
        let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff;

        let mut b1: u32 = 0;
        b1 |= (block[3] as u32) >> 2;
        b1 |= (block[4] as u32) << 6;
        b1 |= (block[5] as u32) << 14;
        b1 |= (block[6] as u32) << 22;
        b1 &= 0x3ffffff;

        let mut b2: u32 = 0;
        b2 |= (block[6] as u32) >> 4;
        b2 |= (block[7] as u32) << 4;
        b2 |= (block[8] as u32) << 12;
        b2 |= (block[9] as u32) << 20;
        b2 &= 0x3ffffff;

        let mut b3: u32 = 0;
        b3 |= (block[9] as u32) >> 6;
        b3 |= (block[10] as u32) << 2;
        b3 |= (block[11] as u32) << 10;
        b3 |= (block[12] as u32) << 18;
        b3 &= 0x3ffffff;

        let mut b4: u32 = 0;
        b4 |= (block[12] as u32) >> 8;
        b4 |= block[13] as u32;
        b4 |= (block[14] as u32) << 8;
        b4 |= (block[15] as u32) << 16;
        if hibit {
            b4 |= 1 << 24;
        }

        self.h[0] = self.h[0].wrapping_add(b0);
        self.h[1] = self.h[1].wrapping_add(b1);
        self.h[2] = self.h[2].wrapping_add(b2);
        self.h[3] = self.h[3].wrapping_add(b3);
        self.h[4] = self.h[4].wrapping_add(b4);

        let d0 = (self.h[0] as u64) * self.r[0]
            + (self.h[1] as u64) * self.s[3]
            + (self.h[2] as u64) * self.s[2]
            + (self.h[3] as u64) * self.s[1]
            + (self.h[4] as u64) * self.s[0];
        let d1 = (self.h[0] as u64) * self.r[1]
            + (self.h[1] as u64) * self.r[0]
            + (self.h[2] as u64) * self.s[3]
            + (self.h[3] as u64) * self.s[2]
            + (self.h[4] as u64) * self.s[1];
        let d2 = (self.h[0] as u64) * self.r[2]
            + (self.h[1] as u64) * self.r[1]
            + (self.h[2] as u64) * self.r[0]
            + (self.h[3] as u64) * self.s[3]
            + (self.h[4] as u64) * self.s[2];
        let d3 = (self.h[0] as u64) * self.r[3]
            + (self.h[1] as u64) * self.r[2]
            + (self.h[2] as u64) * self.r[1]
            + (self.h[3] as u64) * self.r[0]
            + (self.h[4] as u64) * self.s[3];
        let d4 = (self.h[0] as u64) * self.r[4]
            + (self.h[1] as u64) * self.r[3]
            + (self.h[2] as u64) * self.r[2]
            + (self.h[3] as u64) * self.r[1]
            + (self.h[4] as u64) * self.r[0];

        let mut c: u64 = d0 >> 26;
        self.h[0] = (d0 as u32) & 0x3ffffff;
        let d1 = d1.wrapping_add(c);
        c = d1 >> 26;
        self.h[1] = (d1 as u32) & 0x3ffffff;
        let d2 = d2.wrapping_add(c);
        c = d2 >> 26;
        self.h[2] = (d2 as u32) & 0x3ffffff;
        let d3 = d3.wrapping_add(c);
        c = d3 >> 26;
        self.h[3] = (d3 as u32) & 0x3ffffff;
        let d4 = d4.wrapping_add(c);
        c = d4 >> 26;
        self.h[4] = (d4 as u32) & 0x3ffffff;
        self.h[0] = self.h[0].wrapping_add((c as u32) * 5);
        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ffffff;
        self.h[1] = self.h[1].wrapping_add(c as u32);
    }

    /// Finalize: reduction modulo 2^130-5, then add Poly1305 pad.
    fn finalize(mut self, key: &[u8; 32]) -> [u8; 16] {
        // Reduction modulo 2^130-5
        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        let mut c = g[0] >> 26;
        g[0] &= 0x3ffffff;
        g[1] = self.h[1].wrapping_add(c);
        c = g[1] >> 26;
        g[1] &= 0x3ffffff;
        g[2] = self.h[2].wrapping_add(c);
        c = g[2] >> 26;
        g[2] &= 0x3ffffff;
        g[3] = self.h[3].wrapping_add(c);
        c = g[3] >> 26;
        g[3] &= 0x3ffffff;
        g[4] = self.h[4].wrapping_add(c).wrapping_sub(1u32 << 26);
        let mask = (g[4] >> 31).wrapping_sub(1);
        g[0] &= mask;
        g[1] &= mask;
        g[2] &= mask;
        g[3] &= mask;
        g[4] &= mask;
        let nmask = !mask;
        self.h[0] = (self.h[0] & nmask) | g[0];
        self.h[1] = (self.h[1] & nmask) | g[1];
        self.h[2] = (self.h[2] & nmask) | g[2];
        self.h[3] = (self.h[3] & nmask) | g[3];
        self.h[4] = (self.h[4] & nmask) | g[4];

        // Convert to 128-bit value and add Poly1305 pad (key[16..32])
        //
        // Must be an *addition*, not a bitwise OR of shifted limbs: limb 1 is
        // only guaranteed < 2^26 + 21 (see `process_block`), so `h[1] << 26`
        // can overlap the bit range of `h[2] << 52`.  OR would silently drop
        // that carry and produce a tag differing from the reference
        // implementation by 2^52 for roughly 1 in 3.3e7 blocks.
        //
        // Both are `mut` so they can be wiped in place below.  A shadowing
        // rebind (`let mut x = x; zeroize_array(&mut x)`) would wipe a *copy*
        // and leave the original on the stack — the exact defect documented in
        // `chacha20_block`.
        let mut h_val: u128 = (self.h[0] as u128)
            .wrapping_add((self.h[1] as u128) << 26)
            .wrapping_add((self.h[2] as u128) << 52)
            .wrapping_add((self.h[3] as u128) << 78)
            .wrapping_add((self.h[4] as u128) << 104);

        let mut s_val = u128::from_le_bytes(key[16..32].try_into().unwrap());

        // Compute the tag first, then wipe every value it was derived from.
        let tag = h_val.wrapping_add(s_val).to_le_bytes();

        // 【侧信道防护】就地清零全部密钥派生中间值。
        //
        // `self.h` is the reduced accumulator, `self.r` the clamped MAC key,
        // `self.s` its 5x multiples, and `g` the conditional-subtraction scratch
        // (a copy of `h`).  `s_val` is the Poly1305 pad — raw key material — and
        // `h_val` the recombined accumulator.
        //
        // Note the earlier form of this code (`let mut h = self.h;
        // zeroize_array(&mut h); self.h = h;`) wiped `h` only by round-tripping
        // it through a copy, and left the locals `h_val`, `s_val` and `g`
        // unwiped entirely.  Wiping the fields in place is both simpler and
        // correct; the locals are wiped above.
        zeroize_array(&mut self.h);
        zeroize_array(&mut self.r);
        zeroize_array(&mut self.s);
        zeroize_array(&mut g);
        zeroize_array(&mut h_val);
        zeroize_array(&mut s_val);

        tag[..16].try_into().unwrap()
    }
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

    // ── KAT Test Vectors (c2sp.org ChaCha20-Poly1305-SIV, 16-byte nonce) ──

    #[test]
    fn test_vector_1_empty() {
        // Test Vector 1: empty plaintext, empty AAD
        let key = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2");
        let nonce = hex("530ee5e3dae7693017d28e5d7c6936ce");
        let aad: Vec<u8> = vec![];
        let plaintext: Vec<u8> = vec![];
        let expected_ct: Vec<u8> = vec![];
        let expected_tag = hex("85ebd6b3a2dbad07d4811283aaf9777acff58bdab40939a13237be73d3ddd73a");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_vector_2() {
        // Test Vector 2: Ladue and Gentlemen passage
        let key = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2");
        let nonce = hex("530ee5e3dae7693017d28e5d7c6936ce");
        let aad: Vec<u8> = vec![];
        let plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let expected_ct = hex("935fc3675f8b409d4441409418d92f7d7f52af0a00adc07176c998dbdfaa4d06524ea0769635e044a6aaf00327096437613bec8c76eea651dcaccc2fc66087bda224f38ab220208a9471a3e9eec612c2553d8179f1bd1bf7e884fa25336e5f19ef46bb3581245603969b1b11293ad5611608");
        let expected_tag = hex("cb0ff82acbd025c9db100311c6628f41ad9ba81a960b8ccd7fdb19c51252e902");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_vector_3() {
        // Test Vector 3: different nonce
        let key = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2");
        let nonce = hex("85975d0ee263b966a551adab8325ebe3");
        let aad: Vec<u8> = vec![];
        let plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let expected_ct = hex("00abda8eb9d81e4bbfec468c33175102ca865a9e10bd1af861a205a996c9818993bd0f5957a0a163a1585bf469ca154802b300c78dd873c9a67111d7eeb3b9d3ee7e7ad37db8375ba30031afaaab163057418225f403b4cbdd0cd3dc4024b984462802ec7fb87bd91ff548a13db805695fa9");
        let expected_tag = hex("4417acff4230861c1ee555cc839fe8b9ccb122fda85b3970d677dc71e8515276");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_vector_4() {
        // Test Vector 4: different key
        let key = hex("3ef4832df6f83cd761539792c7c34b90fde64ca02d31151fdf924bf2206e37cb");
        let nonce = hex("530ee5e3dae7693017d28e5d7c6936ce");
        let aad: Vec<u8> = vec![];
        let plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let expected_ct = hex("b00fea62ad4a7d06b99ce816e2800bb51ac0a7ad39a216a1131eb23efd2771f824df9ea5773d68d26a83e04a00e81587cf68353157e5b1abd2a99d9d8c50557ae3c6dfcbad6ad1ccee167c24cb049cf11221ffe1f63231efedf89c3e31c549df66281722670ad82a5014b7fa3869f91a9ccc");
        let expected_tag = hex("1d54d3476529356000f20919ac9de59d8ed4f39a62225bc689822916b748cab0");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_vector_5_with_aad() {
        // Test Vector 5: with AAD
        let key = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2");
        let nonce = hex("530ee5e3dae7693017d28e5d7c6936ce");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let expected_ct = hex("65047ab0ada975747e1a1737abd6cb0aeb126b8e8f974c6dc0a45e091a4992ad1190080ab2acc2a5a62c9fff72466f7e054d2b4e9474f01d5b200cc6788e0e30351842fc058faee14fe97fe7cee8d0c84e64fa1b55c19e658468d6035376616182d6d09e3066e9318134e4e2bfadfd381256");
        let expected_tag = hex("e85b5e838e89c84d2f544f40cd65bcccfe6f4438ed6325a06d301881ec2e90d2");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_vector_6_short() {
        // Test Vector 6: short plaintext
        let key = hex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2");
        let nonce = hex("530ee5e3dae7693017d28e5d7c6936ce");
        let aad = hex("2891ec111a27c55b3a6757ff173ef9cfc02bb682bcee4aaa317715b0b7895a58");
        let plaintext = hex("aeadc48d4a2ea7ee06f9f41a6fbcd651ac5df158860e14af1fb0ebbe0a04bab2");
        let expected_ct = hex("10287f0d994ca8b920dcede7ce86a29a055ac8e1c0ca14fe651bb363a2af7e03");
        let expected_tag = hex("9283515c1a67bf9234494025356684abae8325ad5a2f7ce275ac7fa49d88d735");

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

        let (ct, tag) = encrypt16(&key_arr, &nonce_arr, &aad, &plaintext).unwrap();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        assert_eq!(ct, expected_ct);

        let pt = decrypt16(&key_arr, &nonce_arr, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── XChaCha20 KAT (draft-irtf-cfrg-xchacha-03, 24-byte nonce) ──
    // These pin the HChaCha20 nonce-suffix layout: the 4 NUL bytes come FIRST,
    // then nonce[16..24].  Without these, a wrong-but-self-consistent layout
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
    fn test_xchacha20_poly1305_key_kat() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1 — Poly1305 key of the AEAD vector.
        // This is exactly ChaCha20(HChaCha20(key, iv[0..16]), 0, 0^4||iv[16..24])[0..32],
        // i.e. our subkey derivation, so it pins the nonce-suffix byte order.
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

    // ── XChaCha20-Poly1305-SIV KAT (24-byte nonce public API) ──
    //
    // These lock the *fusion* construction: XChaCha20-style subkey derivation
    // (HChaCha20 + SUBKEY_DOMAIN || nonce[16..24]) feeding the c2sp.org CCP-SIV
    // core, plus the CTX context-commitment XOR over
    // BLAKE3.derive_key(COMMITMENT_CONTEXT, aad).
    //
    // The vectors were regenerated with the independent reference implementation
    // in `tools/ref_impl.py`, written from the RFC 8439 /
    // draft-irtf-cfrg-xchacha-03 pseudocode and the c2sp.org specification, after
    // the tag change.  That reference is checked
    // against the published RFC 8439 §2.3.2 / §2.5.2, HChaCha20 draft, and
    // c2sp.org Test Vectors 1/6 before it emits anything, so it is not merely a
    // restatement of
    // this code.

    #[test]
    fn test_xchacha20_poly1305_siv_kat_draft_key() {
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
            "dfa76facb54a5a3cc8f8a057e3f36a5f58959d61839d89e8a0d19b9a5a04a94473ed6695de07f533eabd19f30802394cfdb2b530b15d14d0a84371729bc49c05646711d2b9195c74e98fedc117a0c9f8a180625405f4723e533816421ada64e21f1853cacfb6046ec6a9314ca2aab38d29ee",
        );
        let expected_tag = hex("ad52200aa3c45f46df1feff1476d7ca86441ae714a65587522db132b8aaef846");

        let (ct, tag) = encrypt(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());

        let back = decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn test_xchacha20_poly1305_siv_kat_c2sp_key() {
        // c2sp.org key with a 24-byte nonce; exercises the empty-AAD path
        // (where the commitment term is BLAKE3("") rather than zero).
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
            "f77735b432f46c7a47a96ac8c656548e188a08f56e466155e041dab0cdda4a44c68a62a81f0b9aa797e1102f1805b0226edc234a9f966015b26bd415e01fecdbe7ac2eb349d07ba4e64668be4beac7be0656c25411f3d8eda63e516fb62dded19a93c1ac6c9a7fbe640628a37343a46d13d5",
        );
        let expected_tag = hex("b59ebd0b456b3ab9a8d920e0bf2a1544232bef202b29ad049e5a96c5138be941");

        let (ct, tag) = encrypt(&key, &nonce, &[], &pt).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());

        let back = decrypt(&key, &nonce, &[], &ct, &tag).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn test_xchacha20_poly1305_siv_kat_empty() {
        // Empty plaintext + empty AAD: the tag alone authenticates.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let expected_tag = hex("e4bbc5a4bad30698dd4e36745b54e23374ba2241eb07f154e263580d89ed9494");

        let (ct, tag) = encrypt(&key, &nonce, &[], &[]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
    }

    /// Context commitment (CMT-3): with `(key, nonce, plaintext)` held fixed,
    /// changing *only* the associated data must change the tag **and** the
    /// ciphertext.  The ciphertext matters too: the encryption key and the
    /// encryption nonce both come from the tag, so if only the tag moved a
    /// decrypting oracle would still see one ciphertext under two contexts.
    ///
    /// Note the direction that is *not* claimed: because encryption consumes
    /// only `tag[0..28]`, two tags can share a ciphertext (see `derive_tag`).
    /// The commitment is carried by the tag, which is transmitted and compared
    /// in full.
    ///
    /// This is the property the c2sp.org base construction does not have (its
    /// own specification says so), and the reason the CTX XOR over
    /// `BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)` is applied.
    #[test]
    fn test_context_commitment_aad_changes_tag_and_ciphertext() {
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; 24];
        let pt = b"context commitment matters";

        let (ct_a, tag_a) = encrypt(&key, &nonce, b"aad-A", pt).unwrap();
        let (ct_b, tag_b) = encrypt(&key, &nonce, b"aad-B", pt).unwrap();

        assert_ne!(tag_a, tag_b, "AAD must change the tag (CMT-3)");
        assert_ne!(ct_a, ct_b, "AAD must change the ciphertext");

        // Both must still round-trip under their own AAD...
        assert_eq!(decrypt(&key, &nonce, b"aad-A", &ct_a, &tag_a).unwrap(), pt);
        assert_eq!(decrypt(&key, &nonce, b"aad-B", &ct_b, &tag_b).unwrap(), pt);
        // ...and neither may verify under the other's AAD.
        assert!(decrypt(&key, &nonce, b"aad-B", &ct_a, &tag_a).is_err());
        assert!(decrypt(&key, &nonce, b"aad-A", &ct_b, &tag_b).is_err());
    }

    /// The commitment must cover the *whole* AAD, including its length and any
    /// trailing bytes: a truncation or an appended byte has to change the tag.
    #[test]
    fn test_context_commitment_covers_whole_aad() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let pt = b"msg";

        let (_, t_base) = encrypt(&key, &nonce, b"abcd", pt).unwrap();

        // Truncated.
        let (_, t_short) = encrypt(&key, &nonce, b"abc", pt).unwrap();
        assert_ne!(t_base, t_short);

        // Appended.
        let (_, t_long) = encrypt(&key, &nonce, b"abcde", pt).unwrap();
        assert_ne!(t_base, t_long);

        // Different content, same length.
        let (_, t_diff) = encrypt(&key, &nonce, b"abce", pt).unwrap();
        assert_ne!(t_base, t_diff);

        // Same bytes split differently across a longer AAD must not collide
        // either (length encoding lives inside BLAKE3's padding).
        let (_, t_pad) = encrypt(&key, &nonce, b"abcd\0", pt).unwrap();
        assert_ne!(t_base, t_pad);
    }

    /// Domain separation: for the same (key, nonce), this scheme's one-time
    /// Poly1305 key MUST differ from XChaCha20-Poly1305's, otherwise reusing a
    /// nonce across the two schemes would reuse the Poly1305 one-time key and
    /// break authentication.
    #[test]
    fn test_subkey_domain_separation_vs_xchacha20_poly1305() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1 key/IV.
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let iv: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();

        let subkey = hchacha20(&key, &iv[0..16].try_into().unwrap());

        // XChaCha20-Poly1305 layout: 0^4 || nonce[16..24].
        let mut x_nonce = [0u8; 12];
        x_nonce[4..12].copy_from_slice(&iv[16..24]);
        let mut x_block = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &x_nonce, &mut x_block);

        // This scheme's layout: SUBKEY_DOMAIN || nonce[16..24].
        let mut s_nonce = [0u8; 12];
        s_nonce[0..4].copy_from_slice(&SUBKEY_DOMAIN);
        s_nonce[4..12].copy_from_slice(&iv[16..24]);
        let mut s_block = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &s_nonce, &mut s_block);

        // The published XChaCha20-Poly1305 Poly1305 key for this input.
        assert_eq!(
            &x_block[0..32],
            hex("7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5").as_slice(),
            "XChaCha20-Poly1305 derivation anchor"
        );
        assert_ne!(
            &s_block[0..32],
            &x_block[0..32],
            "Poly1305 one-time key must not collide with XChaCha20-Poly1305"
        );
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

    /// The batched four-block Poly1305 path (SIMD or scalar) must produce the
    /// exact same tag as the strictly serial single-block reference, for every
    /// message length that crosses a 64-byte boundary.
    #[test]
    fn test_poly1305_batch_matches_serial() {
        let key = [0x9Au8; 32];

        // Lengths around the 4-block boundary plus longer runs.
        let mut sizes: Vec<usize> = (0..=200).collect();
        sizes.extend_from_slice(&[255, 256, 257, 511, 512, 513, 1023, 1024, 4096]);

        for &size in &sizes {
            let msg: Vec<u8> = (0..size).map(|i| ((i * 7 + 13) % 256) as u8).collect();

            // Batched path (used by the AEAD).
            let mut batched = Poly1305State::new(&key);
            batched.absorb_padded(&msg);
            let got = batched.finalize(&key);

            // Serial reference: one block at a time, never entering the batch.
            let mut serial = Poly1305State::new(&key);
            let mut i = 0;
            while i + POLY1305_BLOCK_SIZE <= size {
                let block: [u8; POLY1305_BLOCK_SIZE] =
                    msg[i..i + POLY1305_BLOCK_SIZE].try_into().unwrap();
                serial.process_block(&block, true);
                i += POLY1305_BLOCK_SIZE;
            }
            if i < size {
                let mut block = [0u8; POLY1305_BLOCK_SIZE];
                block[..size - i].copy_from_slice(&msg[i..]);
                serial.process_block(&block, true);
            }
            let want = serial.finalize(&key);

            assert_eq!(got, want, "Poly1305 batch mismatch at size {size}");
        }
    }

    /// Explicitly compare the four-block kernels against the scalar batch, so a
    /// broken SIMD backend cannot hide behind the dispatcher's fallback.
    #[test]
    fn test_poly1305_accumulate4_kernels_match_scalar() {
        for seed in 0..16u8 {
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = seed.wrapping_mul(37).wrapping_add(i as u8);
            }
            let state = Poly1305State::new(&key);
            let r = [
                state.r[0] as u32,
                state.r[1] as u32,
                state.r[2] as u32,
                state.r[3] as u32,
                state.r[4] as u32,
            ];
            let powers = Poly1305Powers::new(&r);

            let mut m = [[0u8; 16]; 4];
            for (k, block) in m.iter_mut().enumerate() {
                for (i, b) in block.iter_mut().enumerate() {
                    *b = seed.wrapping_add((k * 16 + i) as u8).wrapping_mul(3);
                }
            }

            let h = [
                0x0123_4567u32 & 0x3fff_ffff,
                0x00ab_cdef,
                0x1357,
                0x2468,
                0x1,
            ];
            let scalar = poly1305_accumulate4_scalar(&h, &m, &powers.r);
            let dispatched = poly1305_accumulate4(&h, &m, &powers.r, &powers.s);
            assert_eq!(scalar, dispatched, "kernel mismatch at seed {seed}");

            // And the full reduction must agree too.
            let mut hb = h;
            let mut hs = h;
            poly1305_reduce_wide(&mut hs, &scalar);
            poly1305_batch4(&mut hb, &m, &powers);
            assert_eq!(hs, hb, "reduced mismatch at seed {seed}");
        }
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

    /// The final limb→`u128` recombination must be an addition, not a bitwise
    /// OR of shifted limbs.
    ///
    /// Regression guard: limb 1 is only bounded by `< 2^26 + 21` (the tail of
    /// `process_block` is `h[1] += c`), so `h[1] << 26` can overlap `h[2] << 52`.
    /// With OR the carry was silently dropped and the tag came out 2^52 too
    /// small — a reachable divergence roughly every 3.3e7 blocks, and one that
    /// self-consistent encrypt/decrypt could never detect.
    #[test]
    fn test_finalize_recombination_is_exact() {
        // The concrete diverging state found by fuzzing: h[1] = 2^26 + 8.
        let st = Poly1305State {
            h: [937497, 67108872, 7261385, 43907646, 43426469],
            r: [0; 5],
            s: [0; 4],
        };
        assert!(st.h[1] >= (1 << 26), "precondition: limb 1 exceeds 2^26");

        let h_val: u128 = (st.h[0] as u128)
            .wrapping_add((st.h[1] as u128) << 26)
            .wrapping_add((st.h[2] as u128) << 52)
            .wrapping_add((st.h[3] as u128) << 78)
            .wrapping_add((st.h[4] as u128) << 104);

        // Ground truth: the limb sum reduced mod 2^128 (the tag takes the low
        // 16 bytes, so anything at or above 2^128 is discarded).
        let expect: u128 = (st.h[0] as u128)
            .wrapping_add((st.h[1] as u128).wrapping_mul(1u128 << 26))
            .wrapping_add((st.h[2] as u128).wrapping_mul(1u128 << 52))
            .wrapping_add((st.h[3] as u128).wrapping_mul(1u128 << 78))
            .wrapping_add((st.h[4] as u128).wrapping_mul(1u128 << 104));
        assert_eq!(h_val, expect);

        // And the OR form really does differ on this input.
        let or_val: u128 = (st.h[0] as u128)
            | ((st.h[1] as u128) << 26)
            | ((st.h[2] as u128) << 52)
            | ((st.h[3] as u128) << 78)
            | ((st.h[4] as u128) << 104);
        assert_ne!(or_val, expect, "this state must exercise the carry");
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

    #[test]
    fn test_nonce_misuse_resistance() {
        // SIV mode: same (key, aad, plaintext) with different nonces
        // should produce DIFFERENT tags (nonce-misuse resistant)
        let key = [0u8; 32];
        let nonce1 = [0u8; 24];
        let nonce2 = [1u8; 24];
        let plaintext = b"Same message";
        let aad = b"same aad";

        let (tag1, _) = encrypt(&key, &nonce1, aad, plaintext).unwrap();
        let (tag2, _) = encrypt(&key, &nonce2, aad, plaintext).unwrap();

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_key_commitment() {
        // Key-committing: different keys with same nonce/aad/pt should produce different tags
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"Key commitment test";
        let aad = b"";

        let (_, tag1) = encrypt(&key1, &nonce, aad, plaintext).unwrap();
        let (_, tag2) = encrypt(&key2, &nonce, aad, plaintext).unwrap();

        assert_ne!(tag1, tag2);
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
        assert_eq!(TAG_LEN, 32); // 256-bit tag
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
    fn test_decrypt16_does_not_leak_plaintext_on_failure() {
        // Same guarantee as the 24-byte path: a failed authentication MUST
        // return Err, never the (unverified) plaintext.
        let key = [0x42u8; 32];
        let nonce = [0u8; 16];
        let plaintext = b"Secret message";
        let wrong_key = [0x43u8; 32];

        let (ct, tag) = encrypt16(&key, &nonce, b"", plaintext).unwrap();
        assert!(decrypt16(&wrong_key, &nonce, b"", &ct, &tag).is_err());

        // Tampered ciphertext must also fail.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xFF;
        assert!(decrypt16(&key, &nonce, b"", &bad_ct, &tag).is_err());
    }

    #[test]
    fn test_api_constants() {
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(KEY_LEN, 32);
        assert_eq!(TAG_LEN, 32);
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
        // Exercise multi-block ChaCha20 + Poly1305 padding boundaries.
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
    // a hand-written ChaCha20/Poly1305 is most likely to have: a round function,
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

    /// The tag must depend on **every** byte of the AAD, including bytes past
    /// the first Poly1305 block and past the SIMD batch boundary.
    ///
    /// `test_context_commitment_covers_whole_aad` does this for a 4-byte AAD;
    /// this sweeps every position of a longer one, so a `&aad[..16]`
    /// truncation would be caught.
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

    // ── CTX commitment: mode and layout pins ──

    /// The commitment term must be `BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`
    /// and **not** a bare `BLAKE3(aad)`, and the context string must not change
    /// silently.
    ///
    /// Both are 32-byte collision-resistant hashes, so swapping one for the
    /// other keeps every roundtrip test passing while changing every tag ever
    /// produced — a wire-format break that only an anchored vector can catch.
    /// The expected value here was produced by `tools/ref_impl.py`.
    #[test]
    fn test_commitment_is_domain_separated_blake3() {
        let aad = b"aad-A";
        let got = context_commitment(aad);

        let expected: [u8; 32] =
            hex("c5718123028533d1b0221c94479cbed4b6fffb8a969e4a5c55d0744ff5c0c851")
                .try_into()
                .unwrap();
        assert_eq!(got, expected, "commitment term changed");

        // The bare hash of the same AAD must differ: if it did not, the
        // derive_key domain separation is not in effect.
        let bare = *blake3::hash(aad).as_bytes();
        assert_ne!(got, bare, "commitment must not equal a bare BLAKE3(aad)");

        // BLAKE3's published empty-input hash, to pin the bare-hash path too.
        assert_eq!(
            *blake3::hash(b"").as_bytes(),
            <[u8; 32]>::try_from(
                hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262").as_slice()
            )
            .unwrap(),
            "blake3::hash anchor changed"
        );
    }

    /// Pins the layout fact that makes the CMT-3 argument run through the tag
    /// rather than the ciphertext: encryption consumes `tag[0..16]` (as
    /// `enc_key` material) and `tag[16..28]` (as the encryption nonce), so
    /// `tag[28..32]` does not influence the ciphertext.
    ///
    /// This is *not* a vulnerability — the tag is transmitted and compared in
    /// full, so a forged tag is rejected — but it is the kind of thing a future
    /// refactor could turn into one by, say, truncating the stored tag to 28
    /// bytes or comparing only a prefix.  If someone changes the construction so
    /// that the whole tag reaches the ciphertext, this test fails and the
    /// documentation in `derive_tag` must be updated with it.
    #[test]
    fn test_tag_tail_does_not_reach_the_ciphertext() {
        let tag_key = [0x33u8; 32];

        let mut t1 = [0u8; TAG_LEN];
        let mut t2 = [0u8; TAG_LEN];
        t1[28..32].copy_from_slice(&[1, 2, 3, 4]);
        t2[28..32].copy_from_slice(&[9, 9, 9, 9]);

        // `enc_key` and the encryption nonce are functions of the tag prefix only.
        assert_eq!(
            derive_enc_key(&tag_key, &t1),
            derive_enc_key(&tag_key, &t2),
            "enc_key must depend only on tag[0..16]"
        );
        let n1: [u8; 12] = t1[16..28].try_into().unwrap();
        let n2: [u8; 12] = t2[16..28].try_into().unwrap();
        assert_eq!(n1, n2, "encryption nonce must depend only on tag[16..28]");

        // End to end: two tags differing only in the tail decrypt the SAME
        // ciphertext to the same plaintext when the tag check is bypassed — i.e.
        // the ciphertext genuinely does not commit to the tail.  (Both fail
        // authentication, because the tag is compared in full.)
        let key = [0x44u8; 32];
        let nonce = [0x55u8; 24];
        let aad = b"tail";
        let pt = b"tail test message";
        let (ct, tag) = encrypt(&key, &nonce, aad, pt).unwrap();

        let mut tail_flipped = tag;
        tail_flipped[28] ^= 0xFF;
        assert_ne!(tail_flipped, tag);
        assert!(
            decrypt(&key, &nonce, aad, &ct, &tail_flipped).is_err(),
            "a tag with a flipped tail must be rejected"
        );

        // The in-place decryptor must also wipe on that rejection.
        let mut buf = ct.clone();
        assert!(decrypt_in_place_detached(&key, &nonce, aad, &mut buf, &tail_flipped).is_err());
        assert!(
            buf.iter().all(|&b| b == 0),
            "buffer must be zeroized when the tag tail is wrong"
        );

        // And the genuine tag still round-trips.
        assert_eq!(decrypt(&key, &nonce, aad, &ct, &tag).unwrap(), pt);
    }

    /// The `COMMITMENT_CONTEXT` string is part of the wire format: changing it
    /// changes every tag.  Pin its exact value and its length so an edit cannot
    /// pass unnoticed.
    #[test]
    fn test_commitment_context_is_pinned() {
        assert_eq!(
            COMMITMENT_CONTEXT,
            "XChaCha20-Poly1305-SIV context commitment v1"
        );
        // BLAKE3's derive_key contexts must be hardcoded and application
        // specific; the crate's value is deliberately self-describing.
        assert_eq!(COMMITMENT_CONTEXT.len(), 44);
    }

    /// Domain separation of the *subkey derivation*: the constant goes in the
    /// first 4 bytes of the ChaCha20 **nonce** (counter 0), not in the counter.
    ///
    /// The two readings produce different Poly1305 keys, so this pins the
    /// layout the module documentation describes and the KATs encode.
    #[test]
    fn test_subkey_domain_occupies_nonce_not_counter() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];

        let (poly_key, _) = derive_subkeys(&key, &nonce);
        let subkey = hchacha20(&key, &nonce[0..16].try_into().unwrap());

        // The layout the code uses: domain in the nonce, counter 0.
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&SUBKEY_DOMAIN);
        n[4..12].copy_from_slice(&nonce[16..24]);
        let mut buf = [0u8; 64];
        chacha20_keystream_raw(&subkey, 0, &n, &mut buf);
        assert_eq!(poly_key.as_slice(), &buf[0..32]);

        // The documented-but-wrong reading (domain in the counter) must differ.
        let mut n2 = [0u8; 12];
        n2[4..12].copy_from_slice(&nonce[16..24]);
        let mut buf2 = [0u8; 64];
        chacha20_keystream_raw(&subkey, u32::from_le_bytes(SUBKEY_DOMAIN), &n2, &mut buf2);
        assert_ne!(
            poly_key.as_slice(),
            &buf2[0..32],
            "domain must live in the nonce, not the counter"
        );
    }

    /// `poly1305_reduce_wide` guarantees the *residue*, not a canonical limb
    /// vector: congruent accumulators may reduce to different limbs.  Pinning
    /// that here stops someone from "simplifying" on the false assumption that
    /// the representation is canonical.
    #[test]
    fn test_reduce_wide_is_residue_not_representation() {
        // 0 and u64::MAX are both representable accumulators that the function
        // accepts; they must not be assumed to produce identical limbs.
        let mut a = [0u32; 5];
        let mut b = [0u32; 5];
        poly1305_reduce_wide(&mut a, &[0u64; 5]);
        poly1305_reduce_wide(&mut b, &[u64::MAX, 0, 0, 0, 0]);
        assert_ne!(
            a, b,
            "reduce_wide is not a canonicaliser; do not rely on it being one"
        );

        // What it *does* guarantee: the reduced limbs are small (each < 2^26+1).
        for v in [a, b] {
            assert!(v.iter().all(|&x| x <= (1 << 26) + 1), "{v:?}");
        }
    }

    /// The scalar four-block batch is the *only* Poly1305 batch path on
    /// non-x86/non-aarch64 targets, and it produces accumulators near 2^58 —
    /// far above the `< 2^28` an earlier comment claimed.  That matters because
    /// `poly1305_reduce_wide`'s second fold pass must therefore be load-bearing.
    #[test]
    fn test_scalar_batch_accumulators_are_wide() {
        let key = [0x9Au8; 32];
        let st = Poly1305State::new(&key);
        let r = [
            st.r[0] as u32,
            st.r[1] as u32,
            st.r[2] as u32,
            st.r[3] as u32,
            st.r[4] as u32,
        ];
        let m = [[0xFFu8; 16]; 4];
        let acc = poly1305_accumulate4_scalar(&[0u32; 5], &m, &[r, r, r, r]);
        let max = *acc.iter().max().unwrap();
        assert!(
            max > (1u64 << 28),
            "accumulator {max} unexpectedly small; the doc's 2^28 claim would hold"
        );
        assert!(
            max < (1u64 << 62),
            "accumulator {max} exceeds the documented < 2^62 bound"
        );
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
            key,
            crate::random::generate_key().unwrap(),
            "two consecutive keys were identical -- entropy source broken"
        );

        // A zero-length request must succeed rather than error.
        crate::random::fill(&mut []).expect("empty fill must succeed");
        crate::random::fill(&mut nonce.clone()).expect("plain fill must succeed");
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

    /// `poly1305_absorb_bulk` must reject a `data` length that is not a whole
    /// number of four-block groups, in **every** build profile.
    ///
    /// Regression guard: this used to be a `debug_assert!`, so a release build
    /// would silently skip the trailing bytes and compute a MAC over a shorter
    /// input than the caller supplied.  That yields a self-consistent but wrong
    /// tag, which no roundtrip test can detect.  The assertion is now hard, and
    /// this test pins that.
    #[test]
    #[should_panic(expected = "poly1305_absorb_bulk requires")]
    fn test_absorb_bulk_rejects_partial_group() {
        let key = [0x11u8; 32];
        let st = Poly1305State::new(&key);
        let r = [
            st.r[0] as u32,
            st.r[1] as u32,
            st.r[2] as u32,
            st.r[3] as u32,
            st.r[4] as u32,
        ];
        let powers = Poly1305Powers::new(&r);
        let mut h = [0u32; 5];

        // 130 is not a multiple of 64 (4 blocks x 16 bytes).
        let data = vec![0u8; 130];
        poly1305_absorb_bulk(&mut h, &data, &powers);
    }

    /// The companion case: a whole number of groups must be accepted, so the
    /// assertion above cannot be passing merely because the function always
    /// panics.
    #[test]
    fn test_absorb_bulk_accepts_whole_groups() {
        let key = [0x22u8; 32];
        let st = Poly1305State::new(&key);
        let r = [
            st.r[0] as u32,
            st.r[1] as u32,
            st.r[2] as u32,
            st.r[3] as u32,
            st.r[4] as u32,
        ];
        let powers = Poly1305Powers::new(&r);
        let mut h = [0u32; 5];

        for len in [0usize, 64, 128, 192] {
            let data = vec![0xABu8; len];
            poly1305_absorb_bulk(&mut h, &data, &powers);
        }
    }
}
