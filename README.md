# XChaCha20-BLAKE3-SIV

Misuse-resistant, key- and context-committing AEAD with a 24-byte (192-bit)
nonce.

```rust
use xchacha20_blake3_siv::{encrypt, decrypt};

let key   = [0x42u8; 32];
let nonce = [0x55u8; 24];          // 192-bit nonce
let aad   = b"associated data";

let (ciphertext, tag) = encrypt(&key, &nonce, aad, b"secret message")?;
let plaintext = decrypt(&key, &nonce, aad, &ciphertext, &tag)?;
assert_eq!(plaintext, b"secret message");
# Ok::<(), xchacha20_blake3_siv::Error>(())
```

A detached, in-place API is also available
(`encrypt_in_place_detached` / `decrypt_in_place_detached`) for protocols that
store the tag separately or want to avoid a second allocation.

## Not a standard

**There is no published specification for this construction, and it is not
byte-compatible with anything else.** It combines two published primitives under
a construction of this project's own design:

| Component | Source |
| --- | --- |
| Subkey derivation (HChaCha20 nonce extension) | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) |
| Session key derivation | ChaCha20 keystream ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)) |
| Authenticated encryption (the MAC) | [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) in keyed mode |

The construction in full:

```
K (256-bit)   N (192-bit)   A (associated data)   M (message)

1. subkey   = HChaCha20(K, N[0..16])
   material = ChaCha20_keystream(subkey, counter 0, "XSIV" || N[16..24])   64 B
   mac_key  = material[0..32]      enc_seed = material[32..64]

2. tag = BLAKE3_keyed(mac_key,
            "XSIV-TAG" || K || N || le64(|A|) || le64(|M|) || A || M)     65 B

3. km      = BLAKE3_keyed(enc_seed, "XSIV-ENC" || tag)                    44 B
   enc_key = km[0..32]             enc_nonce = km[32..44]

4. C = ChaCha20(enc_key, counter 0, enc_nonce, M)
```

Decryption runs step 3 and 4 first (SIV requires the plaintext to recompute the
tag), then recomputes the tag and compares all 65 bytes in constant time.

Three details are load-bearing rather than incidental:

1. **Domain separation of the subkey-derivation block.** XChaCha20-Poly1305
   leaves those 4 bytes as NUL padding; this crate puts `"XSIV"` there, so the
   same `(key, nonce)` derives different material in the two schemes and a
   protocol that mixed them would not be reusing keys across schemes.

2. **The key goes into the tag input directly**, not only through the derived
   `mac_key`. Binding it only via `mac_key` would let an adversary search for
   two keys colliding on that 256-bit value — a 2^128 effort — and bypass the
   520-bit tag entirely (`test_tag_binds_the_key_directly`).

3. **Both lengths are encoded, and every field is fixed width.** BLAKE3 is not
   vulnerable to length extension (its finalisation is flagged, unlike
   Merkle–Damgård constructions), but `A || M` alone would be ambiguous:
   `("ab", "c")` and `("a", "bc")` would hash identically. The two `u64` length
   fields remove that (`test_aad_message_split_is_unambiguous`).

This is **not** the c2sp.org ChaCha20-Poly1305-SIV construction: it does not use
Poly1305, its tag is 65 bytes rather than 32, and it is not interoperable with
anything.

### Wire format is not frozen

Because the construction is bespoke, treat the byte format as unstable until
this crate reaches 1.0. It has already changed once: v0.1 used Poly1305 with a
CTX-transformed 32-byte tag, and v0.2 replaces that with a keyed-BLAKE3 65-byte
tag.

## Properties

- **SIV mode** — the tag is computed before encryption, so nonce reuse degrades
  gracefully instead of catastrophically.
- **Key- and context-committing** — a 520-bit tag, giving **2^260** committing
  security (see below).
- **Constant-time** — the tag is compared with `subtle::ConstantTimeEq`;
  `Plaintext` compares in constant time too. Decryption is decrypt-then-verify
  (SIV requires the plaintext to recompute the tag), and the unverified
  plaintext is wiped, never returned.
- **Zeroization** — intermediate secrets are wiped with volatile stores; the
  returned `Plaintext` wipes itself on drop; and BLAKE3's internal state (which
  holds the MAC key) is explicitly zeroized, since it is unreachable from here
  and is not cleared on drop.
- **`no_std`** — with `alloc`.
- **SIMD** — SSE2 / AVX2 on x86-64, NEON on aarch64, with a scalar reference
  fallback on every other target. All backends are held byte-identical to the
  scalar path by differential tests.
- **No hidden entropy** — `encrypt` is a deterministic function of
  `(key, nonce, aad, plaintext)`; nothing is drawn from a random source
  internally. That is what makes the known-answer vectors and the formal
  harnesses meaningful.

## Security level

| Property | Strength | Determined by |
| --- | --- | --- |
| Confidentiality (plaintext recovery) | 256-bit | the ChaCha20 key |
| Forgery resistance | **256-bit** | BLAKE3 keyed mode as a PRF over a 256-bit key |
| Key commitment (CMT-1/CMTk) | **2^260** | birthday bound on the 520-bit tag |
| Context commitment (CMT-3) | **2^260** | birthday bound, resting on BLAKE3 |

**On forgery: 256 bits is the ceiling, not a choice.** Forgery resistance is
bounded by the key's entropy, so with a 256-bit key it cannot exceed 256 bits.
A longer tag does not raise it; it raises commitment. (Exceeding 256-bit forgery
would require a larger key, which would be a different construction.)

**On commitment: the tag is 65 bytes because commitment must exceed 2^256.**
Commitment is a *collision* property, so an `n`-bit tag caps it at `2^(n/2)`.
A 64-byte (512-bit) tag would give exactly `2^256` — not *more* than 256 bits —
so 65 bytes (520 bits) is the smallest byte-aligned size that strictly exceeds
it, giving `2^260`.

**What is assumed, and what is not proven.** The figures above rest on BLAKE3
being a secure PRF and collision-resistant, and on ChaCha20 being a secure
stream cipher. Those are standard, heavily analysed assumptions — but they are
assumptions, not theorems, and this particular *composition* has no public
specification and has not been independently analysed. The formal harnesses in
`src/proofs.rs` prove properties of the implementation (that the fields reach
the hash, that every output byte is used, that the tag reaches the ciphertext),
not cryptographic hardness.

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
xchacha20-blake3-siv = { version = "0.1", features = ["rng"] }
```

```rust
use xchacha20_blake3_siv::{encrypt, random};

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
./verify.sh --cross-exec    # ...plus executing the aarch64/i686 suites under qemu
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

- **Published vectors** — RFC 8439 §2.3.2 (ChaCha20 block),
  draft-irtf-cfrg-xchacha-03 §2.2.1 (HChaCha20), and **BLAKE3's official
  `test_vectors.json` keyed vectors**. The last of these is the anchor for the
  new MAC: without an external check, the tag vectors would only be validated
  against this crate's own reference implementation, which proves nothing.
- **Differential testing** — `tools/ref_impl.py` is an independent
  implementation written from the RFC and BLAKE3 specifications, self-checked
  against the published vectors above before it emits anything. It generates
  `tests/vectors_differential.txt` (49 vectors, 65-byte tags), replayed by
  `tests/differential_reference.rs` across every internal length boundary. The
  Python and Rust keyed-BLAKE3 paths were verified byte-identical before relying
  on them.
- **Cross-architecture execution** — two configurations are *executed* under
  qemu, not merely type-checked. On x86 the aarch64 (NEON) backend is compiled
  out entirely, so `qemu-aarch64` is the only thing that ever runs it; and
  `qemu-i386` is the only place the 32-bit code paths run, where `usize` is 32
  bits and every length calculation takes a different route. `--aarch64-exec` is
  still accepted as an alias of `--cross-exec`.
- **Kani** — bounded model checking of the construction shape: that the domain,
  key, nonce and both lengths reach the hash in the specified layout; that every
  output byte comes from the hash; that every AAD and message byte reaches the
  tag; and that `derive_enc` consumes all 65 tag bytes (so the ciphertext
  commits to all 520 bits). Plus the ChaCha20 counter sequencing, zeroization
  and length-limit harnesses. `-Z stubbing` is required, and the MAC is stubbed
  through a single seam so no call site can escape the model.
- **Constant-time, mechanically** — `tools/ctgrind.sh` marks secrets as undefined
  in valgrind's shadow memory and requires memcheck to report no branch depending
  on them, apart from the two documented SIV accept/reject decisions. The script
  first proves its own negative control is detected, so a clean run cannot come
  from poisoning that never took effect.
- **Fuzzing** — `fuzz/fuzz_targets/roundtrip.rs` under `cargo-fuzz` + libFuzzer +
  AddressSanitizer, asserting round-trip correctness, rejection of every
  single-bit corruption, and the wipe-on-failure contract.
- **Dependency hygiene** — `cargo deny check` (advisories, licences, bans,
  sources) and `cargo-audit`.
- **Measured performance** (see below).

Kani proves properties of the *implementation*, not cryptographic hardness.
"An adversary cannot forge a tag" is a claim about computational infeasibility,
which a SAT solver has no model of; that half rests on the underlying primitives
and on using them as specified.

## Performance

Measured on the development machine (WSL2, x86-64), release profile with
`lto`/`codegen-units=1`, `blake3` with its `pure` Rust backends as this crate
ships it. Figures are best-of-N with per-iteration A/B interleaving, because this
host's throughput drifts by up to 2x between runs; ratios are the stable signal.

End-to-end, versus the previous Poly1305-based version of this crate:

| Message | encrypt | decrypt |
| --- | --- | --- |
| 64 B | 1.06–1.16x | 0.95–1.13x |
| 1 KiB | 0.85–0.88x | 0.84–1.05x |
| 16 KiB | 0.71–0.97x | 0.97–1.10x |
| 64 KiB | 0.99–1.33x | 1.21–1.25x |
| 1 MiB | 1.01–1.09x | 1.15–1.33x |

(ratio > 1 means faster.) Isolated MAC throughput, two independent runs:

| Message | Poly1305 | BLAKE3-XOF | ratio |
| --- | --- | --- | --- |
| 64 B | ~104 MB/s | ~103 MB/s | 0.98–1.01x |
| 1 KiB | ~462 MB/s | ~237 MB/s | 0.50–0.53x |
| 16 KiB | ~516 MB/s | ~910 MB/s | 1.63–1.91x |
| 1 MiB | ~499 MB/s | ~875 MB/s | 1.60–1.95x |

In short: no large regression. The new construction is faster for bulk messages
(BLAKE3 beats Poly1305 by 1.6–2x there) and roughly 10–15% slower around 1 KiB,
where Poly1305's four-block batching still helps and BLAKE3's wide parallelism
has not yet engaged.

Not covered: qemu cannot model real aarch64 performance, so the NEON figures
would need measurement on real hardware. The `pure` feature also caps BLAKE3's
throughput relative to its assembly kernels; switching would require a C
toolchain and so would complicate cross-compilation.

## Layout

```
src/lib.rs                  the construction, the SIMD backends, the test suite
src/proofs.rs               Kani harnesses (`cfg(kani)` only)
tests/                      differential vectors and their replay
tools/ref_impl.py           independent Python reference implementation
tools/gen_test_vectors.py   fixture generator for the differential vectors
tools/kani_shards.py        derives the CI proof shards from src/proofs.rs
standard.txt                the c2sp.org / XChaCha specification text this
                            crate's older v0.1 construction was built from.
                            Retained for the RFC 8439 and HChaCha20 test
                            vectors it quotes; it does NOT describe the
                            current construction.
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. This matches the `license = "MIT OR Apache-2.0"` field in
`Cargo.toml`.
