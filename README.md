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
  scalar path by differential tests, and to *each other* by
  `test_all_accelerated_paths_agree_on_a_boundary_corpus`, whose expected digest
  was produced identically by AVX2, SSE2-only, NEON, scalar, and a big-endian
  target. CI runs that test under qemu on aarch64 and i686, so one backend
  drifting from the others fails there.
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

**What no tool here detects: variable-latency operations on secrets.** ctgrind
reports branches and memory indices that depend on poisoned data; a division, a
remainder or a float operation has neither, and its latency varies inside the ALU with
the operand. Measured, not assumed: with a division by a secret-derived byte planted
inside `decrypt`, ctgrind passes and the release timing screen reports t = 0.22 / 0.48
— the effect on this CPU is a few cycles against a floor of about seventeen. The
control is therefore a list rather than a tool: `tests/variable_latency.rs` inventories
every `/` and `%` in the crate's non-test source and fails if one appears that is not
in the table with a reason. It makes them visible; it cannot tell whether one is safe,
and the table's one entry today divides by the compile-time alignment of `usize`.

**What is not defended against.** Fault injection — a voltage, clock or laser
glitch that makes the *hardware* execute something other than what the code says —
is outside this crate's threat model, and outside every tool used to verify it:
Miri, Kani, ctgrind, ThreadSanitizer and libFuzzer all model *correct* execution,
and none of them can observe a glitch. Concretely, the accept/reject decision is a
single branch on a single comparison in both `decrypt` and
`decrypt_in_place_detached`, so one skipped instruction is the difference between a
forgery being rejected and being accepted. That is also the shape RustCrypto's
`chacha20poly1305` has, and neither crate documents fault countermeasures.

What the construction gives for free is asymmetric: a fault on the *encryption*
side degrades to rejection rather than to forgery, because the tag is computed over
the plaintext (see the SIV property above), so a corrupted keystream, a corrupted
key derivation or a corrupted tag can only produce a message the receiver refuses.
The data path is held to that empirically — every single-bit corruption of
ciphertext, tag and AAD is rejected by the tests, and 115 million fuzz executions
found no acceptance — but those are *non-physical* analogues: they show the
acceptance predicate is exact, not that the decision survives a glitch.

### The opt-in `hardened` feature

For deployments where the cheap end of that threat model is real, the crate has an
opt-in `hardened` feature that hardens exactly one thing: **the accept/reject
decision**, which is the single-fault point where a forgery is accepted. It makes
the decision two independently *recomputed* checks, each with its own branch, so
one skipped instruction reaches the other gate instead of accepting. Both
combinations use `&` and never `&&`, so both comparisons always run and the time
taken does not reveal which gate failed; `bool::from` is the conversion `subtle`
documents for the end of a verification, so no new content-dependent branch is
introduced. `tools/ctgrind.sh --features hardened` checks that mechanically, and
`tools/fi_check.sh` writes the fault down as a source change and requires the
default build to *fail* the decision test with it while the hardened build passes.

| Single fault on the decision (a skipped branch, or a corrupted gate *value*) | **defended** — `tools/fi_check.sh` runs this as a campaign row on the hardened build |
| A fault that replaces the computed tag with the received one | **not defended, and pinned**: the campaign asserts that both builds accept it, so a change in either direction is noticed. Both gates compare the same two values, so both are satisfied; a source-level fault model has nothing closer to the memory fault this represents |
| Two independent faults | not defended — this is where the attacker's cost moves to a synchronized two-glitch bench |
| A targeted fault inside the tag computation, making it produce the attacker's tag | not defended — precision injection, laboratory grade |
| Key recovery by differential fault analysis of ChaCha20 | not defended — laboratory grade, and harder against ARX than against AES |
| Extracting unverified plaintext by skipping the failure-path wipe | not defended — needs a read primitive as well as the fault |
| Availability (any single glitch causes a rejection or a crash) | not defended, by anything |

A bounded mutation run over the decision (`cargo mutants -f src/lib.rs -F
'decrypt|passed_gates' --features hardened -- --test decision`, in CI) tests the other
half of that: every mutant of the decision must be caught by `tests/decision.rs`. Four
of them are excluded as **equivalent under fault-free testing** — `&` to `|` or `^` in
the two-comparison expression — and that exclusion is itself informative: the two
comparisons inside a gate always agree, because they compare the same two arrays, so
they differ *only* when a fault makes them disagree. That case cannot be reached by
any fault-free test, which is why it is a row of the fault campaign instead.

The same question at the level of the *compiled* code: `tools/fi_instruction.sh`
replaces every byte of the decision's machine code with `NOP`, one at a time, and
re-runs the decision test. Both builds answer **zero** — 3081 single-byte faults in the
default build and 3987 in the hardened one, none of which turns a rejected forgery into
an accepted one; most of the rest merely crash. Two caveats are in that script's header
and matter here: `NOP` is the *neutralise an instruction* fault, which biases towards
rejection, so it says nothing about a bit flip that turns a comparison into an
acceptance — that symmetric case is what the second gate is for, and what the
campaign's `gate0-value-forced` row covers. And the map is of machine code, so a
different host and toolchain will produce a different one.
One more thing the campaign turned up, which is worth knowing before trusting a
green suite here: the failure-path wipe of the *allocating* `decrypt` is not
observable from a test at all — the plaintext is wiped and then freed, so a skipped
wipe there leaves data in freed memory and nothing outside the crate can see it. The
campaign therefore mutates the *in-place* wipe, which the caller's buffer does expose,
and the allocating one rests on reading the code (the first version of that row
mutated the unobservable one and the campaign reported "expected fail, got pass",
which is what a mutation nothing can catch looks like).

Measured cost, in-place round trip on the host above: **+10.8% at 64 bytes, +8.9% at 256, +3.6% at 1 KiB, +4.1% at 4 KiB, +2.5% at 16 KiB, +1.0% at 64 KiB, +0.4% at 1 MiB** — the added work
is four 65-byte constant-time comparisons, so it does not scale with the message. The hardened build is byte-for-byte identical on the wire (the KATs and
both differential fixtures replay unchanged), which is what keeps every other piece
of evidence in this file valid for it.

**None of that is a claim of fault-injection resistance**, and nothing here has been
validated on a real fault-injection bench. If your adversary can glitch silicon, a
software AEAD is the wrong component: use a secure element or an HSM, whose
protection is a hardware property, and whose per-operation latency is orders of
magnitude worse than what the table above describes.

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
- **Random differential testing** — `tools/broad_differential.py` drives
  thousands of vectors with arbitrary keys, nonces, AADs and messages, sized to
  straddle every dispatch boundary and with ~5% large enough to take the tag's
  contiguous hash path, and compares each one with that same independent
  reference. It runs the crate through `examples/xsiv_stdin.rs` rather than
  committing a generated fixture — which is the point, because the committed
  fixture reconstructs its inputs from their lengths, and so can never test an
  arbitrary key or an arbitrary byte. The same script with and without
  `--features pure` compares BLAKE3's two backends over identical vectors, and
  both match the reference.
- **Concurrency** — `tests/threads.rs` starts 32 threads that all make their
  first call from cold, so they race the cached AVX2 detection, and requires them
  to agree on every ciphertext and tag; the detached API runs in the same loop.
  `tools/tsan.sh` runs it under ThreadSanitizer, after proving the sanitizer can
  see a race at all: a deliberately racy `#[ignore]`d test must be reported before
  the clean run is allowed to mean anything. The suite also runs under
  AddressSanitizer.
- **Cross-architecture execution** — three configurations are *executed* under
  qemu, not merely type-checked. On x86 the aarch64 (NEON) backend is compiled
  out entirely, so `qemu-aarch64` is the only thing that ever runs it; `qemu-i386`
  is the only place the 32-bit code paths run, where `usize` is 32 bits and every
  length calculation takes a different route; and `qemu-ppc64` is the only place
  the code runs on a **big-endian** machine, where the `from_le_bytes`/
  `to_le_bytes` conversions are no longer identity functions. `--aarch64-exec` is
  still accepted as an alias of `--cross-exec`.
- **Every accelerated path under Miri** — the SSE2 and scalar paths in a default
  build, the AVX2 kernel with `-C target-feature=+avx2` (Miri refuses a
  `#[target_feature]` call whose feature is not enabled, which is why it is a
  separate run), the NEON kernel by cross-interpreting the aarch64 target, and
  big-endian execution by cross-interpreting s390x.
- **Kani** — bounded model checking of the construction shape: that the domain,
  key, nonce and both lengths reach the hash in the specified layout; that every
  output byte comes from the hash; that every AAD and message byte reaches the
  tag; and that `derive_enc` consumes all 65 tag bytes (so the ciphertext
  commits to all 520 bits). Plus the ChaCha20 counter sequencing, zeroization
  and length-limit harnesses. `-Z stubbing` is required, and the MAC is stubbed
  through a single seam so no call site can escape the model. The suite runs with
  CBMC's extra pointer checks, in parallel shards — those checks were
  unaffordable on a hosted runner until the tag harness's input shapes became
  separate call sites, which was a harness bug rather than a runner limit.
- **Constant-time, mechanically** — `tools/ctgrind.sh` marks secrets as undefined
  in valgrind's shadow memory and requires memcheck to report no branch depending
  on them, apart from the one documented SIV accept/reject decision. That decision
  lives in `accept_or_reject`, a function of its own, because a valgrind entry
  permits every branch in the function it names — one naming `decrypt` would permit
  anything later added to `decrypt`. The script refuses to run unless the entry
  names nothing else, and plants a secret-dependent branch inside `decrypt` in a
  throwaway copy and requires that run to *fail* before it reports a clean one.
  Reports are classified by whether they touch this crate, so the check does not
  depend on libtest/std/glibc frames; the control verifies itself with valgrind's
  `GET_VBITS` and `COUNT_ERRORS`.
- **Checks that are not vacuous** — `tools/mutation_check.sh` plants known bugs
  (a `ct_eq` → `==` regression, a changed domain constant) in a throwaway copy and
  requires the relevant check to fail. This exists because one of them was
  silently vacuous once: the ctgrind control was compiled to a branchless `setcc`
  that memcheck does not report, and the guard meant to catch that was satisfied
  by unrelated startup noise.
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

Measured head-to-head against RustCrypto's `chacha20poly1305` — the natural
reference point, since `XChaCha20Poly1305` has the same 24-byte nonce and the same
ChaCha20 core. Reproduce with `cargo bench --bench compare`, which drives both
sides through `aead`'s in-place interface so neither pays for an API shape the
other does not have. Every figure below comes from one run of that harness; the
12-byte-nonce `ChaCha20Poly1305` is measured too and tracks `XChaCha20Poly1305`
within about 4%, so it is not tabulated. Release profile as shipped (`lto`,
`codegen-units = 1`), AMD Ryzen 9 7945HX under WSL2, 3 bytes of AAD, and both
sides on their native SIMD backends (BLAKE3's C/assembly kernels, Poly1305's AVX2
four-block path).

Throughput, ratio against `XChaCha20Poly1305` (> 1 means this crate is faster):

| Message | encrypt | decrypt | round trip |
| --- | --- | --- | --- |
| 64 B | **1.54x** | **1.41x** | **1.56x** |
| 256 B | **1.21x** | **1.28x** | **1.35x** |
| 1 KiB | 0.99x | 0.85x | 0.88x |
| 4 KiB | **1.16x** | **1.06x** | **1.16x** |
| 16 KiB | **1.38x** | **1.25x** | **1.11x** |
| 64 KiB | **1.27x** | **1.15x** | **1.19x** |
| 1 MiB | **1.36x** | **1.43x** | **1.38x** |

Per-message latency, microseconds, median of criterion's samples; the ratio is
again against `XChaCha20Poly1305`, and below 1 means this crate answers sooner:

| Message | encrypt | decrypt | round trip |
| --- | --- | --- | --- |
| 64 B | 0.87 vs 1.27 (**0.68x**) | 0.90 vs 1.35 (**0.67x**) | 1.80 vs 2.70 (**0.67x**) |
| 256 B | 1.10 vs 1.30 (**0.85x**) | 1.10 vs 1.40 (**0.78x**) | 2.07 vs 2.86 (**0.72x**) |
| 1 KiB | 1.89 vs 1.86 (1.02x) | 2.00 vs 1.70 (1.18x) | 3.85 vs 3.37 (1.14x) |
| 4 KiB | 2.97 vs 3.59 (**0.83x**) | 3.37 vs 3.56 (**0.95x**) | 5.98 vs 6.48 (**0.92x**) |
| 16 KiB | 7.46 vs 10.43 (**0.72x**) | 7.93 vs 9.73 (**0.81x**) | 16.53 vs 18.65 (**0.89x**) |
| 64 KiB | 30.5 vs 37.0 (**0.82x**) | 28.5 vs 34.6 (**0.83x**) | 55.9 vs 67.4 (**0.83x**) |
| 1 MiB | 393 vs 554 (**0.71x**) | 408 vs 567 (**0.72x**) | 826 vs 1134 (**0.73x**) |

Read both tables as: this crate pays more *per message* (two key derivations, a
65-byte tag, and wiping all of it) and less *per byte* (BLAKE3 beats Poly1305 once
there is enough data to batch). Latency is not throughput divided by size, because
the fixed per-message cost dominates at the small end — at 64 bytes this crate is
0.4 us cheaper *per call*, and it has the lower latency at every size except
around 1 KiB, where `Poly1305`'s four-block AVX2 path is at its best and BLAKE3
has little to batch (decrypt 1.18x, round trip 1.14x).

Two structural properties bound what a caller can do with that latency, and both
follow from the construction rather than from this implementation:

* **Encryption cannot produce its first ciphertext byte until the whole message has
  been hashed.** The tag covers the plaintext, the encryption key is derived from
  the tag, and only then does the ChaCha20 pass start: two serialized passes, no
  early output, and a single message's latency does not shrink with more cores.
  It is still faster end to end — 393 us against 554 us at 1 MiB — because BLAKE3
  hashes faster than ChaCha20 streams, but a caller cannot overlap the work with
  its own processing the way a one-pass AEAD allows.
* **Decryption starts immediately but decides late.** The encryption key depends
  only on the tag, which the caller supplies, so the ChaCha20 pass runs at once;
  authentication then hashes the recovered plaintext in full. The plaintext
  therefore exists in the buffer before it is verified, which is why the API wipes
  it and never returns it on failure, and why an application must not act on it
  until `decrypt` returns.

The percentiles in the latency table are per *sample*, each averaging hundreds of
calls, so they do not show per-call jitter: this host's clock costs ~35 ns per
`Instant::now()`, which is exactly why each sample averages hundreds of calls -- and
a genuine tail-latency measurement still needs bare metal, where the clock and the
scheduler are far quieter than in this container.

The allocating `encrypt`/`decrypt` API costs more than the in-place one on a round
trip, and by how much depends on the allocator: 5-13% in the criterion harness but
up to 2.2x at 1 MiB in a standalone probe (`examples/profile_probe.rs`). The extra
work is real either way -- two 1 MiB allocations, the copies into them, and the
wipe of the `Plaintext` that `decrypt` returns -- and the in-place path touches
none of it. For large messages, use the in-place API.

**Where the remaining headroom is, and where it is not.** Measured, so that nobody
has to rediscover it:

* The ChaCha20 *tail* and the 64-byte key-material block stay scalar, even though a
  four-lane kernel cuts their instruction count by roughly two thirds. Tried:
  callgrind put the scalar rounds at 28% of the instructions in a 64-byte round
  trip, so routing them through `blocks4` looked like free money -- and it measured
  22% *slower* at 64 bytes and 10% slower at 100, because the four-lane kernel
  writes a 256-byte keystream into a scratch that must then be zeroized (64 bytes
  for the scalar block) and transposes lanes the scalar path does not need. A small
  message is latency- and memory-bound, not issue-bound. The comment in
  `chacha20_apply` carries these numbers.
* Wiping BLAKE3's internal state costs 15% of the instructions in a 64-byte round
  trip -- it wipes the whole CV stack, most of which a one-chunk input never
  touched. It stays: that no copy of the MAC key survives the call is the
  guarantee, and only the dependency can say which of its state that covers.
* Above a few megabytes, intra-message parallelism is real, but it is a policy
  decision rather than an oversight. Hashing 16 MiB with a reused four-thread pool
  measured 3.7x against one thread (8 threads: 4.8x); at 1 MiB the same measurement
  gives 1.02-1.08x, because a single core already runs at ~8.9 GiB/s there and the
  coordination costs what the parallelism buys. The crate does not do it: it would
  need `std`, a thread pool, and cores the caller may already be using. BLAKE3
  ships threaded hashing (`update_rayon`) as an opt-in feature for the same reason,
  and RustCrypto's ciphers are single-threaded. Parallelise across messages
  instead, and check a workload with `examples/profile_probe.rs` before assuming
  anything here.

Two implementation choices dominate the throughput numbers, both verified to leave
the wire format byte-identical (the KATs, the differential fixture and
`test_all_accelerated_paths_agree_on_a_boundary_corpus` pin every byte, and they
run against both):

* **BLAKE3's native backends, not `pure`.** The `pure` feature selects BLAKE3's
  Rust-intrinsics backends; leaving it off lets BLAKE3 use its C/assembly SIMD
  kernels, which is worth 24–32% from 4 KiB up. See the note in `Cargo.toml` for
  the portability story (it falls back to the Rust backends when the target has
  no compiler) and for the two cases that still pass `--features pure`.
* **One contiguous buffer for the tag, for mid-sized messages.** BLAKE3's
  incremental API only takes its batched path when a call starts on a chunk
  boundary, so feeding it `head`, then `aad`, then `msg` dropped the whole message
  onto the one-block-at-a-time path — 2.1–2.3x slower at 4–16 KiB. Messages from
  2 KiB to 64 KiB are now hashed through one exact-sized, wiped buffer, which
  removed the 4 KiB deficit entirely (it was 1.66x behind XChaCha20-Poly1305
  there; it is now level). Above 64 KiB the copy costs more than the batching
  saves, so the three-part call stays.

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
