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

> **Bound your input before you decrypt.** `decrypt` allocates a buffer as large as
> the ciphertext it is handed, so the call holds ciphertext **and** plaintext — twice
> the message in memory — and the format's ceiling (`MAX_MSG_SIZE`, 256 GiB) is not a
> safe one: it is the largest message the *construction* supports, not the largest a
> service should accept. A caller whose message length comes off the wire must cap it
> itself: `decrypt_bounded(key, nonce, aad, ciphertext, tag, max_len)` enforces the
> caller's limit *before* the allocation, and `MAX_MSG_SIZE` is public so a length can
> be rejected before the body is even read. Both allocating entry points allocate
> *fallibly* — a refusal is `Error::AllocationFailed`, not a process `abort` — but a
> request the kernel accepts can still be killed when the buffer is written to, and no
> in-process library can catch that. This is the misuse this crate cannot catch on the
> caller's behalf.

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

### Wire format: frozen by revision, and the crate is 0.x

Two version numbers, deliberately kept apart (see `CHANGELOG.md`, which is written
in the same terms):

* **construction revision** — `v0.2` today. The bytes: domain strings, key
  derivation, tag size. This is what a consumer has to match.
* **crate version** — `0.1.0` in `Cargo.toml`. The Rust API: names, signatures,
  features.

**The byte format is frozen at revision v0.2.** It will not change without a
revision bump, a `CHANGELOG` entry and the known-answer vectors updated in the same
commit — and that is mechanical rather than a promise: `kat_regression_lock`
re-asserts the published bytes from a fixture no in-crate change can edit, and both
differential fixtures replay against the independent reference implementation.

Frozen does not mean finished, or standard: the format is this project's own, it is
**not interoperable with anything**, and until this crate reaches 1.0 it is `0.x`,
so a consumer should pin an exact version rather than a range. A format change
before 1.0 would be a revision bump, not a silent one.

## Properties

- **SIV mode** — the tag is computed before encryption, so nonce reuse degrades
  gracefully instead of catastrophically.
- **Key- and context-committing** — the tag binds the key, the nonce, the AAD and the
  message, so a ciphertext cannot be re-opened under another key or context: a second key
  would have to reproduce the published tag, which is a `2^-520` event per candidate key
  (`≈ 2^-264` over the entire key space). That is what the 65-byte width is for. This file
  claimed `2^260` for a while and that was wrong — see "Security level" below, which also
  separates this *target* bound from the tag's `2^128` *collision* bound.
- **Constant-time** — the tag is compared with `subtle::ConstantTimeEq`;
  `Plaintext` compares in constant time too. Decryption is decrypt-then-verify
  (SIV requires the plaintext to recompute the tag), and the unverified
  plaintext is wiped, never returned.
- **Zeroization** — intermediate secrets are wiped with volatile stores; the
  returned `Plaintext` wipes itself on drop, and so does the `Key` that
  `random::generate_key` returns; and BLAKE3's internal state (which holds the MAC
  key) is explicitly zeroized, since it is unreachable from here and is not cleared
  on drop. It is a *volatile-store* wipe, which is a bound worth stating: it does
  not cover a page that was already swapped out, a core dump, or a cold boot — see
  "What this crate cannot fix for you" below.
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
| Forgery resistance | **256-bit** | BLAKE3 keyed mode as a PRF over a 256-bit key; a *target* problem, so no birthday search applies |
| Context commitment (CMT-3) | `2^520` per attempt against a given ciphertext | a target hit in the 520-bit output: the width is what sets it |
| Key commitment (CMT-1/CMTk) | `2^520` per attempt against a given ciphertext | the same, plus the key being bound into the tag's *input* as well as its derivation |
| Tag collision resistance (the DAE bound's collision term) | **2^128** | the *chaining value*, not the tag: keyed BLAKE3's output is a function of its 256-bit state, so a state collision gives byte-identical tags of any length |

**On forgery: 256 bits is the ceiling, not a choice.** Forgery resistance is
bounded by the key's entropy, so with a 256-bit key it cannot exceed 256 bits.
A longer tag does not raise it.

**On commitment: this table said `2^260`, and that was wrong twice.** The reasoning was
"commitment is a collision property, so an `n`-bit tag caps it at `2^(n/2)`, and 65 bytes
gives `2^260`". First, commitment is not a birthday problem at all: an attacker has to make a
*given* ciphertext open under a second key, which means hitting the tag it published — a
target, `2^-520` per candidate key, and *that* is what the width buys (see the bullets below).
Second, the collision resistance the old rationale was reaching for is not `2^260` either:
keyed BLAKE3's XOF output is
`compress(cv, tail, |tail|, counter, flags | ROOT)`, a function of the **256-bit chaining
value** (plus the final block and the flags), so two inputs that agree on that state produce
*byte-identical tags of any length*. Colliding that state is `2^128` by birthday, and no tag
width can raise it. `SECURITY-ANALYSIS.md` §4.5 carries the argument.

Two consequences, stated here because the old claim invited the opposite reading:

* the width **is** load-bearing, but for the *target* and not the birthday: a candidate key that
  is not the real one opens a given ciphertext with probability `2^-520`, so enumerating the whole
  `2^256` key space succeeds with probability `≈ 2^-264`. A 32-byte tag would make that
  `2^256 · 2^-256 ≈ 1` — one second key within reach of a key-space enumeration — which is the
  non-committing failure mode of the 16-byte-tag SIV family (`AES-GCM-SIV`). So the width stays,
  and a future revision cannot drop it without giving up CMT-1/CMTk;
* what the width does **not** buy is collision resistance (`2^128` either way, state-bound) or
  forgery resistance (`2^256` either way, key-search-bound). `2^128` is still far out of reach of
  a practical attack, but it is **below** the construction's 256-bit key strength — so "the tag
  commits more strongly than the key" was never true, and the table now says so.

**`2^128` bounds *collisions*, not *targets*.** The state shortcut above helps only when
both sides of the collision are the adversary's to search. A tag that has to be hit as
given — a forged tag, or a tag that must also validate under a *second* key — is a target
in the 520-bit output, still `2^520` per attempt. So forgery and key commitment against a
fixed ciphertext are untouched by the correction, and what `2^128` bounds is the
`q²/2^257` collision term in the DAE bound and the two-time-pad event described under
"Deterministic encryption" below.

**What is assumed, and what is not proven.** The figures above rest on BLAKE3
being a secure PRF and collision-resistant, and on ChaCha20 being a secure
stream cipher. Those are standard, heavily analysed assumptions — but they are
assumptions, not theorems, and this particular *composition* has no public
specification and has not been independently analysed. One of them is this crate's
own to declare rather than inherit: binding the key into the tag's *input* as well
as into its key derivation puts a derived key and the value it is derived from in
one hash call, which the black-box PRF assumption does not cover. It is stated as
`L3.6` in [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md) §2.1, with the separation
showing no reduction reaches it and the reason it is still believed. The formal
harnesses in `src/proofs.rs` prove properties of the implementation (that the fields
reach the hash, that every output byte is used, that the tag reaches the ciphertext),
not cryptographic hardness.

**The reduction, written out.** [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md) is the
mathematical treatment: the construction as a tuple of functions, each assumption as an
explicit game, the SIV/DAE theorem with its five-hop reduction and concrete bound
(`q²/2^257 + q·2^-520` plus the PRF advantages, one of which is `L3.6` and not the
ordinary keyed-hash one), every pair of uses of one
primitive enumerated with what separates it, and a falsification table — what would refute
each claim, which refutations have been attempted, and which are out of reach of any test.
Two properties it needs are pinned by tests added with it:
`nonce_reuse_does_not_reuse_the_keystream` (the mechanical content of misuse resistance,
which a keystream derived from `(key, nonce)` alone would fail while every other test in
the suite still passed) and `the_key_material_block_is_not_the_message_keystream`.

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
and none of them can observe a glitch. The decision a forgery turns on is a branch
on a secret-derived comparison, and no software measure removes that branch; what
*can* be removed is the failure mode where a fault skips the check entirely. The
decision therefore writes its outcome through a parameter the caller initialises to
a rejection, so a fault that never makes the call accepts nothing — that shape is
not decoration: `tools/fi_instruction.sh` measured six single-byte faults in
`decrypt` that skipped the call and accepted a forgery while the outcome was
returned by value. That is also the shape RustCrypto's `chacha20poly1305` has, and
neither crate documents fault countermeasures.

What the construction gives for free is asymmetric: a fault on the *encryption*
side degrades to rejection rather than to forgery, because the tag is computed over
the plaintext (see the SIV property above), so a corrupted keystream, a corrupted
key derivation or a corrupted tag can only produce a message the receiver refuses.
The data path is held to that empirically — every single-bit corruption of
ciphertext, tag and AAD is rejected by the tests, and every fuzz run recorded in
CI has found no acceptance — but those are *non-physical* analogues: they show the
acceptance predicate is exact, not that the decision survives a glitch.  (This
claimed a specific "115 million fuzz executions".  No artefact in the repository
records that many: the configured budget is 120 s locally and 300 s in CI, at
roughly 1100 exec/s.  The claim is removed rather than re-derived, because a number
nobody can reproduce is worth less than no number.)

### The `hardened` decision — on by default

The crate hardens exactly one thing: **the accept/reject decision**, which is the
single-fault point where a forgery is accepted. It is the default configuration, not
an opt-in: the property it protects is the one a forgery turns on, it costs nothing
on large messages, and an opt-in that most callers never enable would mean most
callers are unprotected while this file claims hardening. `default-features = false`
gives the single-gate build back for a caller who has measured the cost. It makes
the decision two independently *recomputed* checks, each with its own branch, so
one skipped instruction reaches the other gate instead of accepting. "Recomputed"
is load-bearing and is enforced rather than hoped for: the second gate re-reads
both operands with a volatile read, because the two gate expressions are otherwise
identical and an optimizer is entitled to merge them into one comparison — which
would leave one fault carrying both gates. Both combinations use `&` and never
`&&`, so both comparisons always run and the time taken does not reveal which gate
failed; `bool::from` is the conversion `subtle` documents for the end of a
verification, so no new content-dependent branch is introduced.
`tools/ctgrind.sh` checks that mechanically in both configurations, and
`tools/fi_check.sh` writes the faults down as source changes: the opt-out build must
*fail* the decision test when the single gate is skipped or its value corrupted, the
default (hardened) build must pass, and — the row that makes the other two mean
something — it must *fail* when the second gate is replaced by a copy of the first.

| A fault that skips the decision call altogether | **defended** — the caller writes *two* rejections before the call, so skipping it accepts nothing (`tools/fi_instruction.sh` measured six such faults before that shape was adopted, and none after) |
| A fault that corrupts one decision *value* | **defended** — the two gates write two independent slots and the caller rejects if either says so; one corrupted slot leaves the other. `tools/fi_check.sh`'s `one-check-neutralised` row is this attack, and it is rejected |
| Single fault on the decision (a skipped branch, or a corrupted gate *value*) | **defended** — `tools/fi_check.sh` runs this as a campaign row on the hardened build |
| A single corrupted byte or bit **inside the decision function** | **defended, and measured**: `tools/fi_instruction.sh` sweeps every byte of the compiled `accept_or_reject` — both fault models, three configurations — and attributes each accepting fault to the symbol it sits in. Accepting faults inside the decision: **0 in the `hardened` build and 0 in `ultra`, in both models**. The opt-out build has **3** in the bit-flip model, which is the control that the sweep reaches the decision at all: its single `test`/`je` pair is one flipped bit away from falling through into the accept store, and that is precisely the defect the second gate removes |
| A single corrupted byte or bit **anywhere in the swept code** (the two entry points and the decision) | **measured, and not zero — the mechanism is not the gate**: last full local sweep, `(total, inside the decision)` — opt-out `2, 0` (nop) and `117, 3` (bits); `hardened` `0, 0` and `1, 0`; `ultra` `0, 0` and `4, 0`. The accepting sites outside the decision are in the shared KDF/MAC/SIMD code, and several are the middle byte of a multi-byte instruction, where corruption desynchronises the decoder and the following bytes execute as different instructions — no source structure prevents that. **The raw totals are not comparable across configurations**, and an earlier revision of this table compared them as if they were: `ultra`'s entry points contain more code than `hardened`'s (the witness call, an extra gate operand, a ciphertext copy), so a longer region naturally collects more accepting bytes even when every one of them is outside the decision. What is comparable is the decision-scoped count, which is why that is what the tool gates on. For scale, the same technique over RustCrypto's `XChaCha20Poly1305` measures 13 of 1081 (nop) and 106 of 8648 (bits) — on a *different region*, its whole tag-verification function rather than a decision helper of 18–25 bytes, so the two are not like-for-like either |
| A fault inside the constant-time comparison itself (a shortened loop, a corrupted bound) | **not defended by `hardened`, closed by `ultra`**: with only `hardened`, both gates — and both of `dual-mac`'s recomputations, when it is on — go through the same `subtle` loop, so one fault shortening it disarms every gate at once and a forgery costs `2^(8 * compared bytes)` instead of `2^520`.  **Hand-modelled, not by a committed tool**: no script in `tools/` shortens that loop — the campaign's faults are source-level changes of other kinds (`tools/mutation_check.sh` plants a `==` where `ct_eq` was, which is not a shortened loop) and `tools/fi_instruction.sh` sweeps the compiled bytes uniformly rather than aiming at a loop bound — so both counts in this row came from cutting the comparison down by hand in a throwaway copy.  Hand-measured against that fault: an accept after **2,573 attempts** with the comparison cut to two bytes.  Under `dual-mac`/`ultra` the second gate also `AND`s in `ct_eq_independent`, a differently *written* comparison, and the same hand-made fault then yields **no forgery in 2,000,000 attempts**.  Two faults still defeat both, which is the boundary this row states rather than hides |
| A fault that replaces the computed tag with a constant, or with the received tag | **not defended by `hardened`, closed by `ultra`/`dual-mac`**: with only `hardened` this is the strongest fault model in the table and it defeats the two gates *together* — either gate is `computed_tag ? tag`, so forcing `computed_tag` to equal `tag` satisfies both at once, and two gates over one value are one gate for this attack, not two witnesses. That half is pinned rather than hidden: `tools/fi_check.sh`'s `computed-tag-replaced` row applies exactly this fault to the hardened build and requires it to be accepted, so a change in either direction is noticed. `dual-mac`, part of `ultra`, closes it by doing the thing an earlier revision of this row said was not done here: computing the tag *twice, independently* — a second MAC pass, and the tag pass is a large part of a short message — and requiring the recomputation to agree with the stored value **and** with the received tag (`recomputed_tag.ct_eq(&computed_tag) & recomputed_tag.ct_eq(tag)`, in both decrypt entry points). A rewritten stored tag then disagrees with the recomputation, and `tools/fi_check.sh`'s `dual-mac-blocks-tag-substitution` row runs that same source fault on the `ultra` build and is rejected there. The residual is the rest of this row's boundary: two faults, one in each derivation, or one aimed at the arithmetic both derivations share (`derive_tag` and the keyed BLAKE3 under it), still defeat it — that is a synchronized two-glitch bench or precision injection, and the answer for a deployment that faces it is a hardware countermeasure — dual-rail logic, an HSM — rather than software |
| Two independent faults | not defended — this is where the attacker's cost moves to a synchronized two-glitch bench |
| A targeted fault inside the tag computation, making it produce the attacker's tag | not defended — precision injection, laboratory grade |
| Key recovery by differential fault analysis of ChaCha20 | not defended — laboratory grade, and harder against ARX than against AES |
| Extracting unverified plaintext by skipping the failure-path wipe | not defended — needs a read primitive as well as the fault |
| Availability (any single glitch causes a rejection or a crash) | not defended, by anything |

A bounded mutation run over the decision (`cargo mutants -f src/lib.rs -F
'decrypt|accept_or_reject' --features ultra -- --test decision --test security`, in CI)
tests the other half of that: every mutant of the decision and of its caller-visible
limits must be caught, by the decision detector and by the security suite. The `&` → `|`
mutants in the two-comparison expression are excluded as **equivalent under fault-free
testing**, and that exclusion is itself informative: the two comparisons inside a gate
always agree, because they compare the same two arrays, so `x | x == x & x`. The
exclusion is deliberately *only* `|`: an earlier version also excluded `&` → `^`, and
since `x ^ x == 0` that mutant makes the gate reject everything, which the decision test
kills — so the exclusion discarded killable mutants and the reason given for it was wrong
for half of them. The case where a gate's two comparisons *disagree* cannot be reached by
any fault-free test, which is why it is a row of the fault campaign instead.

The feature set is `ultra`, because that is what compiles the *most* of the decision:
`cargo mutants` does not evaluate `cfg`, so a mutant of a cfg'd-out line is built,
tested, passes, and reported as uncaught. Two rounds of that measurement shaped the code
rather than the run. First, with `hardened` alone, four `&` → `^` mutants on the
`dual-mac` line came back MISSED — hence `hardened,dual-mac`. Then, with the witness
added, **eight more** did: `ultra`'s agreement and gate operand sat on `#[cfg]`-selected
lines of their own, and no single run compiles both an arm and its alternatives. The fix
was to make the configuration a *value* instead of an arm: `witness_ok` is the witness
agreement under `ultra` and a constant `true` otherwise, bound in both cases and folded
into the one `gate_pair` line every configuration compiles. There is now exactly one
`second` expression per gate, and no operator left on a line that only one configuration
compiles.

The same question at the level of the *compiled* code: `tools/fi_instruction.sh` damages
one byte — or one bit — of the decision's machine code at a time and re-runs the decision
test, over three configurations, and reports each accepting fault with the symbol it sits
in. The decisive number is the decision-scoped one, `accept_or_reject` itself: **zero
accepting faults there in the `hardened` and `ultra` builds, in both models**, against
three in the opt-out build's bit-flip model — which is both the defect the second gate
removes and this sweep's proof that it reaches the decision at all. The totals over the
whole swept region are not zero and are not comparable between configurations (see the
table above); they live in the shared KDF/MAC/SIMD code and in decoder desynchronisation,
and the tool prints all six counts rather than asserting a number, because the map is of
machine code and a different host and toolchain produce a different one.

Three configurations, and the reason each is there: the opt-out build is the control
(its single gate is one bit from accepting), `hardened` is the default and the property
the second gate exists for, and `ultra` is the build whose *totals* are largest and whose
decision-scoped count is still zero — the witness adds code to both entry points without
adding an accepting byte to the decision. The sweep is sharded across cores
(`--jobs`, default the core count capped at 16), which is what makes the full
three-configuration sweep a two-minute check instead of a quarter-hour one.

One more thing the campaign turned up, which is worth knowing before trusting a
green suite here: the failure-path wipe of the *allocating* `decrypt` is not
observable from a test at all — the plaintext is wiped and then freed, so a skipped
wipe there leaves data in freed memory and nothing outside the crate can see it. The
campaign therefore mutates the *in-place* wipe, which the caller's buffer does expose,
and the allocating one rests on reading the code (the first version of that row
mutated the unobservable one and the campaign reported "expected fail, got pass",
which is what a mutation nothing can catch looks like).

Measured cost, in-place round trip on the host above: **+10.8% at 64 bytes, +8.9% at 256, +3.6% at 1 KiB, +4.1% at 4 KiB, +2.5% at 16 KiB, +1.0% at 64 KiB, +0.4% at 1 MiB** — the added work
is four 65-byte constant-time comparisons, so it does not scale with the message. That is the cost of the *default* build over `--no-default-features`; the default build is byte-for-byte identical on the wire (the KATs and
both differential fixtures replay unchanged), which is what keeps every other piece
of evidence in this file valid for it.

**None of that is a claim of fault-injection resistance**, and nothing here has been
validated on a real fault-injection bench. If your adversary can glitch silicon, a
software AEAD is the wrong component: use a secure element or an HSM, whose
protection is a hardware property, and whose per-operation latency is orders of
magnitude worse than what the table above describes.

### `ultra`: every defence at once

`ultra` enables every opt-in layer there is. It exists because "turn on all the security
features" should be one word rather than a checklist someone gets half-right.

```toml
xchacha20-blake3-siv = { version = "0.1", features = ["ultra"] }
```

| Layer | What it defends | Cost (measured, this host) |
| --- | --- | --- |
| `hardened` (already default) | a single corrupted decision value or instruction | +10.8% at 64 B, +3.6% at 1 KiB, +0.4% at 1 MiB |
| `dual-mac` | the tag being pinned to a constant or to the received tag — the one model the two gates fail *together* on | +30% at 64 B, +40% at 1 KiB, +24% at 1 MiB on decryption; +8–25% on a round trip |
| `dual-mac` | a fault inside the shared constant-time comparison (a shortened loop): the second gate uses a differently *written* comparison, so one fault reaches only one of them | one extra 65-byte comparison, ~+2.7% at 64 B |
| `dual-mac` | the `blake3` dependency's XOF output surviving in its own stack frames: `scrub_stack()` overwrites the 16 KiB below the entry point after the last derivation | ~16 KiB of volatile stores, ~0.5–1 µs per operation, **and ~16 KiB of stack per call**. Measured on a thread with a 32 KiB stack: the default build still runs after 16 KiB of the stack is already consumed, this one does not survive 8 KiB. A caller that spawns threads with small stacks must size them for it — the scrub is a 16 KiB frame, so it can fault the thread it is protecting |
| `witness` (in `ultra` only) | a fault aimed at the **derivation arithmetic both tag computations share** — `derive_tag`, the keyed BLAKE3 under it, and the SIMD kernels: the one model `dual-mac` alone cannot close, and where every accepting fault the sweep finds in the `hardened` build sits | decryption **1.4x at 64 B, 2.1x at 1 KiB, 6.3x at 64 KiB, 9.2x at 1 MiB** (§). It is a *scalar* implementation, so its cost is per byte; the encrypt-side cross-check is ~+20% of the encrypt path's instructions. It does not make the *totals* in the fault table zero — it removes accepting faults from the decision and from the shared derivation, and the `ultra` build has a handful elsewhere (§§) |
| `locked` | key pages readable out of **swap** or a **core dump** | ~7 µs once per key (`mlock`+`munlock`), not per message. The key is heap-allocated so its address is stable: `mlock` is address-based, and a key returned by value moves after being locked, which left this layer protecting a dead stack slot |
| `rng` | nothing about the cipher; it is how a caller gets a key at all | — |

(§§) Last full sweep, bit-flip model, as `(total, inside the decision)`: the `hardened`
build is `1, 0` and `ultra` is `4, 0`. The 4 are in `ultra`'s own entry points — which
hold more code than `hardened`'s, because the witness call, the extra gate operand and the
ciphertext copy all live there — and they are the same class as the `hardened` build's 1:
decoder desynchronisation, where corrupting one byte makes the following bytes execute as
different instructions. Nothing at the source level prevents that; what the witness does
prevent is an accepting fault in the *decision* or in the *shared derivation*, which is
where every accepting fault in the `hardened` build sits.

(§) Measured with `examples/bench_aead.rs`, release, on this host, comparing
`hardened,dual-mac,locked,rng` — which is `ultra` minus the witness — against `ultra`:
decryption 30.1 → 20.8 MB/s at 64 B, 259 → 121 at 1 KiB, 1462 → 232 at 64 KiB, 1767 → 192
at 1 MiB, and encryption 46.8 → 32.0, 444 → 247, 2089 → 588, 2406 → 610 on the same
sizes. The deterministic half of that measurement (cachegrind instruction counts on
`examples/xsiv_stdin.rs`, per message) agrees: the decrypt path's added work is 17 k
instructions at 64 B and 64 M at 1 MiB, i.e. it grows with the message while every other
layer here is fixed-cost. `ultra` is the mode for callers who have decided that a second
implementation on the path is worth more than throughput; a caller who wants the other
layers without it can spell them out (`features = ["hardened", "dual-mac", "locked",
"rng"]`) or take `--no-default-features --features dual-mac` and keep the default build's
speed where it matters.

`pure` is deliberately **not** in `ultra`: it forces BLAKE3's portable backends, costs
24–32%, and buys no security — the C/assembly kernels are constant-time by construction and
covered by the same differential tests. `ultra` is about defences, not about giving up speed
for nothing.

**What the witness is, and what "independent" means here.** `src/witness.rs` is a second
implementation of the whole construction — ChaCha20, HChaCha20 and keyed BLAKE3 with the
reference CV-stack tree logic, written from the specification rather than by adapting the
crate's code — and `ultra` compares its answer to the crate's bit for bit on every decrypt
(`witness_tag == computed_tag` **and** `witness_plaintext == plaintext`) and on every
encrypt (its tag against the one about to be returned). It shares no code with the crate's
crypto: not the `blake3` dependency, not the SIMD kernels, not `derive_tag`, not the
buffering. That is exactly what makes the model above reachable — a single fault in the
shared derivation changes one answer and not the other, and the gate that `AND`s the
agreement in rejects. It is not two physically independent machines: same CPU, same
compiler, same source file tree, so a *systematic* fault (a compiler bug, a wrong constant
in both implementations, a fault that hits both code paths in one glitch) is still outside
what this can see. What it does not share, and what makes it worth 4x on a large message,
is the *machine code that computes the tag*.

Two things follow, and both are asserted rather than promised: the agreement is a `Choice`
folded into the second gate (so a disagreement is a rejection on the same branch as
everything else, and no new secret-dependent branch exists — `tools/ctgrind.sh --features
ultra`), and the witness is inventoried like the rest of the crate (`tests/variable_latency.rs`
counts its control flow in its own table; `tools/cache_profile.sh` under `XSIV_FEATURES=ultra`
compares its cache and branch profile for two different keys, in both the encrypt-only and
round-trip phases).

The encrypt-side cross-check goes through `accept_or_reject` too, and that was a finding
rather than an implementation choice: written as a comparison followed by an `if` at its own
call site, it is a branch on the tag — both operands secret-derived — and `tools/ctgrind.sh
--features ultra`, added with this layer, reported exactly that inside `encrypt`. It is not a
forgery defence (a fault there would emit a ciphertext the peer refuses: availability, not
authenticity), but the branch was on the secret path where no suppression entry may reach,
so it is the one decision function's business like everything else.

**What `ultra` still cannot defend against**, because a mode that claims total immunity and
writes down no limits is worse than one that states its boundaries:

- **A fault inside the tag computation itself** that makes it produce the attacker's tag.
  `dual-mac` recomputes the tag a second time and requires the two to agree with each other
  *and* with the received tag, so a corrupted stored value is caught; `ultra` additionally
  requires a second *implementation* to produce the same answer, so a corruption in the
  arithmetic both derivations share is caught too. What is left is a fault that corrupts
  both answers — two independent faults, or one aimed at the code both implementations use,
  which is now only the gate, the caller and the primitives both call (`subtle`,
  `core::ptr::read_volatile`) rather than the cipher. That is a laboratory bench with
  synchronization, and the answer is a secure element, not software.
- **A debugger, `ptrace`, or `/proc/<pid>/mem`** from a process with the same uid, and a
  hypervisor reading guest memory. `locked` asks the kernel to keep pages out of swap and
  core dumps; it cannot stop a process that is allowed to read this one's memory.
- **Cold-boot remanence.** DRAM keeps its contents briefly without power, and nothing in
  userspace changes that.
- **Deterministic encryption and length disclosure.** Both are the construction, not a
  defect: the same `(key, nonce, aad, message)` gives the same ciphertext forever, and the
  ciphertext is exactly as long as the message.
- **Availability.** Every glitch, every refusal and every refusal-to-allocate is a
  rejection or an error; no mode makes the system keep working.

Where each layer is *verified* rather than asserted: `tests/ultra.rs` (the wiring of each
layer, and that the kernel's own `VmLck` accounting shows a `LockedKey` is really locked),
`tools/ctgrind.sh --features ultra` (no secret-dependent branch, with the witness's own code
in the run), `XSIV_FEATURES=ultra tools/cache_profile.sh` (the witness's cache and branch
profile does not depend on the key, with its planted-leak control re-run in the same
configuration), `tools/fi_check.sh` and `tools/fi_instruction.sh` (single-fault behaviour,
both models — the campaign's three configurations are opt-out, `hardened` and `ultra`),
`tests/decision.rs` (forgeries), `tests/decision_scope.rs` (the shape of the decision and
where the witness is folded into it), `tests/security.rs` (lengths, allocation, nonce
reuse).

### What this crate cannot fix for you

Properties of the construction or of the machine. They are listed because each one
is a real exposure a user might take for a defect, and because the answer for every
one of them is "somewhere else": the construction, the caller's protocol, or the
deployment.

- **Deterministic encryption.** `encrypt` is a pure function of
  `(key, nonce, aad, plaintext)`: the same four inputs give the same ciphertext and
  tag, forever, with no per-message randomness anywhere. That is what the mode *is*
  (see "No hidden entropy"), and it is why nonce reuse is survivable rather than
  catastrophic — but it also means anyone who can guess a message can confirm it by
  comparing ciphertexts, and equality of two ciphertexts under one `(key, nonce)`
  says their plaintexts are equal. A protocol that needs ciphertext
  unpredictability has to supply it: a fresh nonce per message (see "Nonces, and
  where randomness comes from"), or its own padding to a fixed length. One caveat
  belongs with the word "survivable": equal tags mean *equal keystreams*, so if two
  distinct messages under one nonce ever collided in the tag — a `2^128` birthday
  search over the tag's 256-bit chain value, `SECURITY-ANALYSIS.md` §4.5 — their
  ciphertexts would satisfy `C₁ ⊕ C₂ = M₁ ⊕ M₂`, which is a two-time pad and not
  merely an equality leak. That event is out of reach (`q²/2^257` in queries, i.e.
  `2^-129` at `q = 2^64`), but "nonce reuse degrades to equality" is only true while
  the tags differ, and the difference is worth stating rather than glossing.
- **Length is revealed.** The ciphertext is exactly as long as the plaintext and the
  tag is fixed-size, so the message length is public to anyone who sees the
  ciphertext. Every length-preserving AEAD has this; hiding a length means padding
  or chunking at the application layer, before the bytes reach this crate.
- **A stack scan finds the `blake3` dependency's own frame residue, and this crate
  cannot reach it.** Measured with `tools/stack_residue.sh`: after a full round trip,
  the master key never appears in the call-chain stack region, but the *XOF output* of
  the keyed hash does — a full 44-byte `enc_key ‖ enc_nonce` — because `blake3` keeps
  its output block in frames of its own. The key itself is not left (measured: longest
  run 4 bytes); the derived material is. `blake3`'s `zeroize` feature is already on and
  the crate already calls `reader.zeroize(); hasher.zeroize();`, which is the entire
  reach a caller has. What this means in practice: an attacker who can read this
  process's stack gets per-message encryption keys, not the master key — and such an
  attacker can usually read the caller's own key copy anyway. It is written down here
  because the crate's own claim ("no copy of the MAC key survives the call") is about
  the MAC key, and a reader should not extend it to the encryption key. Two source
  changes in this crate reduce the residue that *is* reachable — `derive_enc` writes
  through caller slices instead of returning a 44-byte aggregate, and
  `chacha20_rounds` mutates in place instead of taking the key state by value — and
  both were found by exactly this scan.
- **Zeroization is a volatile-store wipe.** It clears the bytes this crate owns, when
  it drops them. It does not reach a page that had already been swapped out, a core
  dump or a hibernation image the OS writes, a debugger attached to the process, or
  DRAM remanence after a cold boot. Those are deployment controls — `mlock` and
  `MADV_DONTDUMP` for the process's own buffers, `RLIMIT_CORE`, suspend and swap
  policy, disk encryption for the image, memory encryption or tamper-resistant
  hardware for the physical end. A library that allocates through `alloc` and runs
  on an OS it does not own is not where they belong, and this one does not pretend
  otherwise.
- **Bounding the input is the caller's job.** `decrypt` allocates a buffer as large
  as its ciphertext argument, so the peak for the call is twice the message — the
  ciphertext the caller already holds, plus the plaintext — and the format's own
  ceiling is `MAX_MSG_SIZE` (256 GiB, public, so a caller can check before it trusts a
  length off the wire; `decrypt_bounded` enforces a policy limit before the
  allocation). Both allocating entry points are fallible, so an allocator refusal
  arrives as `Error::AllocationFailed` rather than as an `abort` the application
  cannot catch — but a request the kernel *accepts* can still be OOM-killed while the
  buffer is written to, and no in-process library can prevent that. A service that
  reads unbounded input has to cap it. **Under `ultra` the peak is three times the
  message**, not two: the witness decrypts into a second buffer of its own (`decrypt`)
  or keeps a copy of the ciphertext plus an output buffer (`decrypt_in_place_detached`).
  All of them are allocated up front, before any key material exists, and fallibly —
  `tests/security.rs::every_allocation_happens_before_any_derivation` pins both halves
  of that, because the `?` on an allocation taken after a derivation returns through
  live keys without wiping them (a defect this crate has now had twice).
- **A failed in-place decryption destroys the caller's buffer.** By design: the
  unverified plaintext must not be readable out of it, so it is wiped to zeros
  before the error is returned. Retry logic needs the ciphertext again; `decrypt`
  is the entry point for a caller that would rather keep its buffer.
- **Length errors and authentication failures are distinguishable.**
  `MessageTooLong`/`AadTooLong` versus `AuthenticationFailed`. Lengths are public
  information, so the distinction reveals nothing that was not already known, and a
  protocol needs it to report a usable failure instead of "something went wrong"; a
  caller that must not distinguish them can collapse the variants itself.
- **`MAX_MSG_SIZE` is exactly the block counter's capacity, and that is enforced.**
  2^38 bytes is 2^32 ChaCha20 blocks — the number of values a `u32` counter has, with
  no margin — so a maximum-length message ends on counter `u32::MAX` and one block more
  would wrap to 0 and reuse keystream *inside one message*. A `const` assertion binds
  the constant to the counter arithmetic, so raising it is a **build** failure rather
  than a silent wrap, and `tests/counter_range.rs` checks the arithmetic at run time
  and that every call site either starts at zero or forwards its own counter.
- **The wire format is frozen, and it is not a standard** ("Wire format: frozen by
  revision, and the crate is 0.x" above): the bytes will not move without a revision
  bump, while the *crate* is `0.x`, so the Rust API is the unstable part — and none of
  it is interoperable with any standard, so a consumer on the other end must be this
  crate, or a reimplementation of the same three domain strings and the same tag
  construction.  (This bullet said "not frozen"; that was true before the format was
  frozen at revision `v0.2`, and the sentence was left behind when the section above was
  rewritten.)

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

./verify.sh                 # stages 1-4: the reference self-checks, fmt/clippy, the
                            # test suite, and the cross-target type-checks
./verify.sh --cross-exec    # ...plus executing the aarch64/i686/ppc64 suites under qemu
./verify.sh --kani          # ...plus Kani bounded model checking (slow)
./verify.sh --tools         # ...plus the tool-level gates CI runs on every push: the
                            # 13-row fault campaign, both instruction sweeps, the
                            # cache-profile differential and its planted-leak control,
                            # the planted-bug checks, the Kani cfg check, and the
                            # 4000-vector differential against the Python reference
./verify.sh --deep          # every switch above; `--all` is the same set
```

`--deep` and `--all` are synonyms, and that is a correction: `--all` used to set *fewer*
switches than `--deep` (no ctgrind, no cargo-deny, no fuzzing, no TSAN) while this file
called it "everything", and neither ran the tool-level gates at all — they lived in CI
alone. Both names now mean the full set, and a run under either refuses to finish while
any stage was skipped.

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
  `GET_VBITS` and `COUNT_ERRORS`. Three configurations run it — default, the
  opt-out build, and `ultra`, whose hand-written second implementation is new code
  on the secret path and would be reported if it branched on a key. The same
  question at the level of the compiled code's cache and branch profile is asked by
  `tools/cache_profile.sh`, which now runs both an encrypt-only and a round-trip
  phase (the decrypt path, including the witness under `XSIV_FEATURES=ultra`) and
  re-runs its planted-leak control in whichever configuration it was pointed at.
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

**These tables are re-measured as a whole, never one cell at a time**, and the run
below is the second one: the first predated `hardened` becoming the default, and
its **decrypt** column no longer described the shipped build. Measured now, at 64
bytes, this crate's decryption is **1.02x** the reference's rather than the 1.41x
the first run reported, and the round trip at 64 bytes is 1.31x rather than 1.56x;
every other cell is within run-to-run noise. Two things moved, and both are worth
naming: `hardened` is on by default now and its second gate is a fixed per-message
cost on *decrypt* (two full 65-byte constant-time comparisons, the volatile
re-reads, the fail-closed plumbing and the wipes), which is why the change shows up
at the small end and not at 1 MiB; and RustCrypto's own decryption got faster in
this dependency set (`chacha20poly1305` 0.10.1, `poly1305` 0.8.0, `blake3` 1.8.7,
from `Cargo.lock`). What did **not** move: encryption, which is 1.53x at 64 bytes
and 1.34x at 1 MiB here against 1.54x and 1.36x there.

Throughput, ratio against `XChaCha20Poly1305` (> 1 means this crate is faster):

| Message | encrypt | decrypt | round trip |
| --- | --- | --- | --- |
| 64 B | **1.53x** | 1.02x | **1.31x** |
| 256 B | **1.31x** | 1.01x | **1.14x** |
| 1 KiB | 0.95x | 0.83x | 0.81x |
| 4 KiB | **1.06x** | 0.96x | 1.01x |
| 16 KiB | **1.26x** | **1.24x** | **1.14x** |
| 64 KiB | **1.30x** | **1.19x** | **1.23x** |
| 1 MiB | **1.34x** | **1.40x** | **1.37x** |

Per-message latency, microseconds, median of criterion's samples; the ratio is
again against `XChaCha20Poly1305`, and below 1 means this crate answers sooner:

| Message | encrypt | decrypt | round trip |
| --- | --- | --- | --- |
| 64 B | 0.80 vs 1.22 (**0.65x**) | 1.16 vs 1.18 (0.98x) | 1.80 vs 2.37 (**0.76x**) |
| 256 B | 0.95 vs 1.25 (**0.76x**) | 1.26 vs 1.26 (0.99x) | 2.18 vs 2.49 (**0.87x**) |
| 1 KiB | 1.83 vs 1.74 (1.05x) | 1.96 vs 1.62 (1.21x) | 3.98 vs 3.23 (1.23x) |
| 4 KiB | 2.90 vs 3.08 (**0.94x**) | 3.35 vs 3.20 (1.05x) | 6.51 vs 6.56 (0.99x) |
| 16 KiB | 7.10 vs 8.96 (**0.79x**) | 7.53 vs 9.32 (**0.81x**) | 15.67 vs 17.93 (**0.87x**) |
| 64 KiB | 27.5 vs 35.7 (**0.77x**) | 28.1 vs 33.5 (**0.84x**) | 54.4 vs 67.2 (**0.81x**) |
| 1 MiB | 414 vs 556 (**0.74x**) | 396 vs 553 (**0.72x**) | 796 vs 1090 (**0.73x**) |

Read both tables as: this crate pays more *per message* (two key derivations, a
65-byte tag, and wiping all of it) and less *per byte* (BLAKE3 beats Poly1305 once
there is enough data to batch). Latency is not throughput divided by size, because
the fixed per-message cost dominates at the small end — at 64 bytes this crate is
0.42 us cheaper *per call* on encryption and answers sooner on the round trip, and
it is the slower of the two only around 1 KiB, where `Poly1305`'s four-block AVX2
path is at its best and BLAKE3 has little to batch (decrypt 1.21x, round trip
1.23x). **Decryption at 64–256 bytes is a tie** (0.98x, 0.99x), and that is the
number the `hardened` decision costs: two 65-byte constant-time comparisons, the
volatile re-reads and the fail-closed plumbing are all fixed per-message work on
the decrypt path, so they are invisible at 1 MiB (0.72x) and dominate here.

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

**Every number above is the default build.** `ultra` is a different trade and is
measured separately in its own section: its independent second implementation costs
1.4x at 64 bytes and 9.2x at 1 MiB on decryption, because it is scalar and re-runs
both passes. Nothing above changes if you turn `ultra` on and then off again — the
default build's machine code is untouched by the feature.

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
src/witness.rs              the `ultra` build's independent second implementation
tests/                      differential vectors and their replay
tools/ref_impl.py           independent Python reference implementation
tools/gen_test_vectors.py   fixture generator for the differential vectors
tools/kani_shards.py        derives the CI proof shards from src/proofs.rs
standard.txt                the c2sp.org / XChaCha specification text the
                            construction's earlier revision (a crate-version-independent
                            "construction revision v0.1") was built from.
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
