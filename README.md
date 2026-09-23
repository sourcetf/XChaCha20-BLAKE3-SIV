# XChaCha20-Poly1305-SIV

Misuse-resistant, key- and context-committing AEAD with a 24-byte (192-bit)
nonce.

```rust
use xchacha20_poly1305_siv::{encrypt, decrypt};

let key   = [0x42u8; 32];
let nonce = [0x55u8; 24];          // 192-bit nonce
let aad   = b"associated data";

let (ciphertext, tag) = encrypt(&key, &nonce, aad, b"secret message")?;
let plaintext = decrypt(&key, &nonce, aad, &ciphertext, &tag)?;
assert_eq!(plaintext, b"secret message");
# Ok::<(), xchacha20_poly1305_siv::Error>(())
```

A detached, in-place API is also available
(`encrypt_in_place_detached` / `decrypt_in_place_detached`) for protocols that
store the tag separately or want to avoid a second allocation.

## Not a standard

**There is no published specification for this construction, and it is not
byte-compatible with anything else.** It is a deliberate fusion of two
standards:

| Component | Source |
| --- | --- |
| Subkey derivation (HChaCha20 nonce extension) | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) |
| SIV core (tag → tag-key-derived encryption key) | [c2sp.org/chacha20-poly1305-siv](https://c2sp.org/chacha20-poly1305-siv) |
| Context commitment (CTX transform) | Chan & Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022 |

Two deviations from the c2sp.org base construction are load-bearing:

1. **Domain separation of the subkey-derivation block.** XChaCha20-Poly1305
   leaves the first 4 bytes of that block's ChaCha20 nonce as NUL padding; this
   crate puts `"XSIV"` there. Without it, the same `(key, nonce)` would derive
   the *same one-time Poly1305 key* in both schemes, so a protocol that mixed
   the two would reuse that key and lose authentication outright.

2. **The CTX context-commitment term.** The tag is
   `c2sp_tag XOR BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`. The c2sp.org
   construction is key-committing but explicitly *not* context-committing (its
   own specification says so), because a CMT-3 adversary chooses the key and
   therefore knows Poly1305's `r`, making the Poly1305 tag solvable rather than
   collision resistant. XORing in a domain-separated hash of the AAD closes
   that gap at the cost of one hash of the AAD — independent of the message
   length — without lengthening the tag.

   `derive_key` rather than a bare `BLAKE3(aad)` so the commitment has a domain
   of its own; `COMMITMENT_CONTEXT` is part of the wire format.

The unmodified c2sp.org construction remains available internally as
`encrypt16`/`decrypt16`, which is what the c2sp.org known-answer vectors are
checked against.

### Wire format is not frozen

Because the construction is bespoke, treat the byte format as unstable until
this crate reaches 1.0: the tag construction and `COMMITMENT_CONTEXT` have
already changed once (from a bare `BLAKE3(aad)` to
`derive_key(COMMITMENT_CONTEXT, aad)`), which invalidates every previously
produced ciphertext and tag.

## Properties

- **SIV mode** — the tag is computed before encryption, so nonce reuse degrades
  gracefully instead of catastrophically.
- **Key- and context-committing** — a 256-bit tag, giving 128-bit committing
  security.
- **Constant-time** — the tag is compared with `subtle::ConstantTimeEq`;
  `Plaintext` compares in constant time too. Decryption is decrypt-then-verify
  (SIV requires the plaintext to recompute the tag), and the unverified
  plaintext is wiped, never returned.
- **Zeroization** — intermediate secrets are wiped with volatile stores, and
  the returned `Plaintext` wipes itself on drop.
- **`no_std`** — with `alloc`.
- **SIMD** — SSE2 / AVX2 on x86-64, NEON on aarch64, with a scalar reference
  fallback on every other target. All backends are held byte-identical to the
  scalar path by differential tests.
- **No hidden entropy** — `encrypt` is a deterministic function of
  `(key, nonce, aad, plaintext)`; nothing is drawn from a random source
  internally. That is what makes the known-answer vectors and the formal
  harnesses meaningful.

## Security level

**The 256-bit tag does not mean 256-bit security.** Read the numbers, not the
tag size:

| Property | Strength | Determined by |
| --- | --- | --- |
| Confidentiality (plaintext recovery) | 256-bit | the ChaCha20 key |
| **Forgery resistance** | **≈103-bit**, degrading with message length | Poly1305's `r` (106 bits of entropy) |
| **Key commitment** (CMT-1/CMTk) | **2^128** | birthday bound on the 256-bit tag |
| **Context commitment** (CMT-3, added here) | **2^128** | birthday bound, resting on BLAKE3 |

Both "weak" figures are the construction's documented design parameters, not
implementation shortcomings. The c2sp.org specification this builds on states
them itself: *"256-bit security against plaintext recovery and 103-bit security
against forgery"*, and *"the 256-bit tag should provide 128-bit key-committing
security (CMT-1/CMTk) due to the birthday bound"*.

- **Forgery.** Poly1305's `r` has only 106 bits of entropy after clamping, so a
  single forgery succeeds with probability ≲ `ℓ/2^106` where `ℓ` is the number of
  16-byte blocks — about 2^-100 for a 1 KiB message, but only **2^-72 at the
  2^38-byte maximum**. A longer tag would not help: the cap is the MAC, not the
  tag. Extending the tag raises commitment, never forgery resistance.
- **Commitment.** Commitment is a *collision* property, so an `n`-bit tag caps
  it at `2^(n/2)`: 256 bits gives 2^128, and going beyond that would require a
  longer tag, not a different construction. The CTX transform XORs a hash of the
  context into the tag; an XOR does not add the two sides' strengths, it takes
  the weaker, so the binding power here equals BLAKE3's differential collision
  resistance.

Three further consequences of the design, worth stating plainly:

- **The commitment term is unkeyed and covers the AAD only.** It is
  `BLAKE3.derive_key(COMMITMENT_CONTEXT, aad)`, a public function, and since the
  tag is public anyone can strip the mask (`inner = tag XOR H(aad)`). Hashing
  only the AAD is inherited from CTX; the key and nonce are bound indirectly
  through the tag key. If you need commitment over the whole context — protocol
  identifier, header, ciphertext — commit to it in the AAD explicitly.
- **`tag[28..32]` does not influence the ciphertext.** Encryption consumes
  `tag[0..16]` (encryption key) and `tag[16..28]` (encryption nonce) only. The
  commitment therefore lives on the *tag*, which is transmitted and compared in
  full. Treat "transmit the whole tag and compare all 32 bytes in constant time"
  as an invariant: truncating it, or comparing a prefix, breaks the commitment.
  `test_tag_tail_does_not_reach_the_ciphertext` pins the underlying fact.
- **Nonce reuse reuses the one-time Poly1305 key** (`poly_key` depends only on
  `(key, nonce)`), which is not how Poly1305 is meant to be used. No exploit
  follows — the Poly1305 output is never exposed, only masked by a PRF under the
  same tag key — but this is why misuse resistance must not be relied on as
  margin. Use a counter (see below).

**In short:** this is suitable for what it claims (≈103-bit forgery, 128-bit
commitment). It is not suitable where you need more than 128-bit commitment or
more than 103-bit forgery resistance.

## Nonces, and where randomness comes from

The construction needs **no** internal randomness. The nonce is the caller's
responsibility, and it is the easiest thing to get wrong, so:

> A nonce MAY be public and predictable. It **MUST be unique for every
> encryption under the same key.**

Misuse resistance is a fail-safe for an occasional slip, not a licence to
reuse: security degrades with every repetition, and reusing a nonce with the
same key, AAD and plaintext reveals that the same triple was encrypted.

Two acceptable strategies:

- **A counter** — incremented after every encryption, never allowed to wrap.
  Deterministic, testable, and free of any collision bound. Prefer this when
  the application has somewhere to store the counter.
- **Random nonces** — the c2sp.org specification this construction extends
  RECOMMENDS "randomly generate[d] nonces with a CSPRNG" and gives the budget
  as 2^48 messages under one key at a collision probability of 2^-32, aligning
  with NIST guidance. (The bare birthday bound for a 192-bit nonce is far more
  generous; the specification's figure is the conservative one.)

Do **not** form a nonce by XORing a counter with a random value: the c2sp.org
specification calls that out explicitly as unsuitable for commitment.

With the opt-in `rng` feature the crate will draw from the OS CSPRNG for you:

```toml
xchacha20-poly1305-siv = { version = "0.1", features = ["rng"] }
```

```rust
use xchacha20_poly1305_siv::{encrypt, random};

let key = random::generate_key()?;      // 256-bit
let nonce = random::generate_nonce()?;  // 192-bit
let (ct, tag) = encrypt(&key, &nonce, b"aad", b"message")?;
# Ok::<(), random::Error>(())
```

The feature is off by default so `no_std` users and users who already have an
entropy source pay nothing — not even the dependency. `random::fill` returns a
`Result` rather than panicking, and there is deliberately **no userspace
fallback PRNG**: a silent fallback would turn "the OS had no entropy" into
"your messages are forgeable" without anyone noticing.

## Verification

Two entry points, both runnable from a fresh checkout:

```sh
./check.sh                  # provision deps, build every target, then verify
./check.sh --all            # ...including qemu execution and Kani

./verify.sh                 # the verification stages on their own
./verify.sh --aarch64-exec  # ...plus executing the aarch64 suite under qemu
./verify.sh --kani          # ...plus Kani bounded model checking (slow)
./verify.sh --all           # everything
```

`check.sh` is the "just make it work" wrapper: it installs the optional
dependencies (cross targets, an aarch64 emulator), builds host and cross
targets, and then delegates the verification stages to `verify.sh` — the stage
logic lives in exactly one place so the two cannot drift apart. Use `verify.sh`
directly for the narrow "re-prove after a small edit" case
(`./verify.sh --kani-only`), which is much cheaper.

Neither script needs root. Package downloads use `apt-get download`, which
works unprivileged, and the emulator is extracted into `~/.local/bin`.

- **Published vectors** — RFC 8439 (ChaCha20 block, Poly1305),
  draft-irtf-cfrg-xchacha-03 (HChaCha20, XChaCha20 keystream, Poly1305 key), and
  c2sp.org ChaCha20-Poly1305-SIV Test Vectors 1–6.
- **Differential testing** — `tools/ref_impl.py` is an independent
  implementation written from the pseudocode, self-checked against the published
  vectors above before it emits anything. It generates
  `tests/vectors_differential.txt`, replayed by
  `tests/differential_reference.rs` across every internal length boundary.
- **Cross-architecture execution** — the aarch64 code path (the NEON backend and
  its scalar transpose) is *executed*, not merely type-checked, by running the
  musl-target test binaries under `qemu-aarch64`. On x86 the NEON backend is
  compiled out entirely, so without this step nothing would ever run it. The
  build needs no cross C toolchain: `.cargo/config.toml` selects `rust-lld` and
  musl supplies its own `libc.a`. Setup on Debian/Ubuntu needs no root:

  ```sh
  rustup target add aarch64-unknown-linux-musl
  apt-get download qemu-user && dpkg-deb -x qemu-user_*.deb /tmp/qemu
  cp /tmp/qemu/usr/bin/qemu-aarch64 ~/.local/bin/
  ```

  What this does **not** cover: throughput. qemu does not model real aarch64
  performance, so the SIMD speedups are measured on x86 only.
- **Kani** — bounded model checking of the construction properties: limb
  arithmetic, carry propagation, both independent 26-bit block decodings, the
  `finalize` reduction in *both* its regimes, counter sequencing, buffer wiping,
  length limits, and the shape of the CTX transform. `-Z stubbing` is required
  (see `src/proofs.rs` for the cost model and for which stubs are honest
  abstractions).

Kani proves properties of the *implementation*, not cryptographic hardness.
"An adversary cannot forge a tag" is a claim about computational infeasibility,
which a SAT solver has no model of; that half rests on the underlying primitives
and on using them as specified.

## Layout

```
src/lib.rs           the construction, the SIMD backends, and the test suite
src/proofs.rs        Kani harnesses (`cfg(kani)` only)
tests/               differential vectors and their replay
tools/ref_impl.py    independent Python reference implementation
tools/gen_test_vectors.py   fixture generator for the differential vectors
standard.txt         the two specification documents this is built from
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. This matches the `license = "MIT OR Apache-2.0"` field in
`Cargo.toml`.
