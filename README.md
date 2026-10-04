# XChaCha20-BLAKE3-SIV

Misuse-resistant AEAD with a 24-byte (192-bit) nonce, committing to the key and the
context: a *given* ciphertext cannot be re-opened under another key or context (the
target form of commitment — see "Security level" for why the attacker-chosen games the
literature names are a different question).

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

1. subkey = HChaCha20(K, N[0..16])
   b0     = ChaCha20_keystream(subkey, counter 0, "XSIV" || N[16..24])   64 B
   b1     = ChaCha20_keystream(subkey, counter 1, "XSIV" || N[16..24])   64 B
   k_in   = b0[0..32]   k_out = b0[32..64]   enc_seed = b1[0..32]

2. X   = BLAKE3_keyed(k_in,  "XSIV-PRE" || N || le64(|A|) || le64(|M|) || A || M)  32 B
   tag = BLAKE3_keyed(k_out, "XSIV-TAG" || X)                                     65 B

3. km      = BLAKE3_keyed(enc_seed, "XSIV-ENC" || tag)                   44 B
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

2. **The tag is two keyed BLAKE3 calls, and no hash message contains the key.**
   The inner hash absorbs the public context (nonce, lengths, AAD, message) under
   `k_in`; the outer turns that 32-byte digest into the tag under the independent
   key `k_out`. This is the NMAC shape. A *single* level keyed by the derived
   `mac_key` would need `K` in its input to stay committing, but that puts the
   hash's key and a 32-byte substring of its message in the same call as two
   correlated functions of one secret — a key-dependent-input step that no
   reduction from "keyed BLAKE3 is a PRF" reaches (`SECURITY-ANALYSIS.md` §2.1,
   node L3.6, with a separation showing the gap is real). Two levels remove the
   correlation outright. They do **not** widen the equal-material route, though an
   earlier revision of this file said they did: all three derived values are
   functions of the single 256-bit `subkey`, so two keys agreeing on the triple need
   a `subkey` collision — a `2^128` birthday, the same order as the tag's own
   collision bound, not a 768-bit one. In `v0.2` the `K`-in-input step made such a
   collision harmless; here it is not, so a subkey collision yields one ciphertext
   that opens under both keys. That is the *attacker-chosen* commitment game, and
   `SECURITY-ANALYSIS.md` §4.5 prices two of its three routes at `2^128` — this
   subkey-collision key route and a chosen-context route, both with the two openings
   decrypting to the *same* plaintext — leaving only the different-message salamander
   underived. The *target* bound — a given ciphertext, `2^-520` per candidate key — is
   unchanged (`test_tag_binds_both_derived_keys`).

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

* **construction revision** — `v0.3` today. The bytes: domain strings, key
  derivation, tag size. This is what a consumer has to match.
* **crate version** — `0.1.0` in `Cargo.toml`. The Rust API: names, signatures,
  features.

**The byte format is frozen at revision v0.3.** It will not change without a
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
  message, so a ciphertext cannot be re-opened under another key or context **in the target
  setting, where the attacker is given the ciphertext**: a second key
  would have to reproduce the published tag, which is a `2^-520` event per candidate key
  (`≈ 2^-264` over the entire key space). That is what the 65-byte width is for. The
  literature's *attacker-chosen* commitment games (CMT-1/CMT-3) are a different game whose
  bound is written down in `SECURITY-ANALYSIS.md` §4.5 rather than here, because it is not
  derived. This file claimed `2^260` for a while and that was wrong — see "Security level"
  below, which also separates this *target* bound from the tag's `2^128` *collision* bound.
- **Constant-time** — the tag is compared with `subtle::ConstantTimeEq`;
  `Plaintext` compares in constant time too. Decryption is decrypt-then-verify
  (SIV requires the plaintext to recompute the tag), and the unverified
  plaintext is wiped, never returned.
- **Zeroization** — intermediate secrets are wiped with volatile stores; the
  returned `Plaintext` wipes itself on drop, and so does the `Key` that
  `random::generate_key` returns; and BLAKE3's internal state (which holds the
  keyed-BLAKE3 key material) is explicitly zeroized, since it is unreachable from here and is not cleared
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
| Context commitment (nonce/AAD) | **key-holder target: `≈ 2^256`; attacker-chosen: `2^128`, completion immediate** | the context enters the tag's *hash input* (`X`), not the tag's *key*, so the 65-byte width does **not** set this bound: a second context that reproduces a given `X` is a preimage of BLAKE3's 256-bit chaining value (`≈ 2^256`), and two *chosen* contexts whose `X` values collide are a `2^128` birthday — after which the tag, and therefore the derived keystream, are equal, so both openings share one plaintext and no fixed point is needed. The byte components of the AAD are what this exposes; a length re-split has too few candidates to reach a 256-bit preimage at all. An earlier revision of this row wrote `2^-520` per candidate key and "the width is what sets it", which is the *key*-search game, not this one — see below |
| Key commitment **against a given ciphertext** (the target game) | `2^-520` per candidate key (other than the real one) | a target hit in the 520-bit output: the width is what sets it. The key enters the tag through `k_in` (the inner digest) and `k_out` (the tag's own derivation); `enc_seed` does **not** enter the tag at all — it keys the KDF *whose input is the tag*, which is how the tag binds the keystream material too. The literature's CMT-3 is *attacker-chosen*, not this — see below |
| Commitment in the **attacker-chosen** games (invisible salamanders, CMT-1/CMT-3) | **two priced routes at `2^128`, both with identical plaintexts (key half and context half); the different-message salamander is not derived here** | the adversary outputs both keys (or contexts), both messages and `(C,T)`, so `2^520` does not describe it. A `subkey` collision at `2^128` gives two keys whose derived material, tag and keystream all coincide — one `(C,T)` valid under both, decrypting to the **same** plaintext (the key half). A collision of the inner digest `X` between two *chosen contexts* under one key does the same for the context half: equal tag, equal KDF output, equal keystream, one plaintext, completion immediate. The salamander — two *different* messages — is what is left: it needs `KS₁ ≠ KS₂`, hence two keys, so its object is the fixed point `T = tag(K₂, N, A, C ⊕ KS₂(T))` and it is not analysed. `SECURITY-ANALYSIS.md` §4.5, Thm 2 and §8.1 |
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
  and a future revision cannot drop it without giving up that target bound;
* what the width does **not** buy is collision resistance (`2^128` either way, state-bound) or
  forgery resistance (`2^256` either way, key-search-bound). `2^128` is still far out of reach of
  a practical attack, but it is **below** the construction's 256-bit key strength — so "the tag
  commits more strongly than the key" was never true, and the table now says so.

**Two games are both called "commitment", and `2^520` answers only one of them.** This is a
distinction the table above now draws explicitly, because an earlier revision of this file put the
literature's names next to the number and let the reader assume it covered them:

* **The target game** — the adversary is *given* a ciphertext/tag, say a published one, and must
  find a second key under which that same `(C, T)` validates. It has to hit the published tag, so
  it is a target: `2^-520` per candidate key (`≈ 2^-264` over the whole key space). **This is what
  `2^520` means, here and in `SECURITY-ANALYSIS.md` §4.5**, and it is what the 65-byte width buys.
* **The attacker-chosen games** — these are the ones the commitment literature formalises as
  `CMT-1`/`CMT-3` (and the "invisible salamanders" attack): the adversary *outputs the entire
  tuple* — two keys (or two contexts), two messages, and the `(C, T)` — and wins if one `(C, T)`
  validates under both. There is no fixed value to hit, so a target bound is the wrong shape for
  it, and **this file does not have the number that fits the whole of it.** Two of its three
  routes are priced, and both complete immediately *because* their plaintexts coincide:
  * the **key** route: a `subkey` collision at `2^128` gives two keys whose derived material, tag
    and keystream all coincide — **key commitment, broken at `2^128`** — and the two keys decrypt
    the one `(C, T)` to the *same* plaintext;
  * the **context** route: two *chosen* contexts under one key (a second AAD or nonce) whose
    inner digests collide at `2^128` give the same tag, and the KDF's input is the tag rather
    than the context, so the keystream is the same too — one `(C, T)`, two contexts, one
    plaintext, no fixed point to solve. (This is CMT-3's context half; earlier revisions here
    and in §4.5 priced only the key route and called *all* of the remainder a fixed point, which
    is true of the different-message case alone.)
  * the **salamander** route — two *different* messages — is the one not derived: it needs
    `KS₁ ≠ KS₂`, hence two keys with different material, and the object to find becomes the fixed
    point `T = tag(K₂, N, A, C ⊕ KS₂(T))` over the 520-bit tag space (`≈ 2^520` on the obvious
    route; `SECURITY-ANALYSIS.md` §4.5 does not claim that is optimal).
  On top of that, the colliding-*tag* search is `q²/2^257` with birthday point `2^128` (the state
  collision above). So the construction's commitment in those games rests on two computed routes
  at `2^128` — Thm 2's `k_in`/`k_out` cascade for the key route, the 256-bit inner digest for the
  context route; both same-plaintext — plus the design argument, and `SECURITY-ANALYSIS.md`
  records the different-message case as an open obligation rather than a bound.

**`2^128` bounds *collisions*, not *targets*.** The state shortcut above helps only when
both sides of the collision are the adversary's to search. A tag that has to be hit as
given — a forged tag, or a tag that must also validate under a *second* key — is a target
in the 520-bit output: guessing the tag is a `2^520` search, while a second key has only
`2^256` candidates to try, each succeeding with probability `2^-520`, so a full key-space
enumeration succeeds with probability `≈ 2^-264`. So forgery and commitment *against a
given* ciphertext are untouched by the correction. (The context row above is the one place the
object to hit is neither 520-bit nor the key: moving a given `(C, T)` to a second *context* means
reproducing the 256-bit inner digest `X`, so that target is `≈ 2^256` and no tag width reaches it.)
What `2^128` bounds is the
`q²/2^257` collision term in the DAE bound and the two-time-pad event described under
"Deterministic encryption" below. What `2^128` does *also* bound, in the attacker-chosen
game, is the search that *starts* the attack — a lower bound on that search, not a bound on
the attack.

**What is assumed, and what is not proven.** The figures above rest on BLAKE3
being a secure PRF and collision-resistant, and on ChaCha20 being a secure
stream cipher. Those are standard, heavily analysed assumptions — but they are
assumptions, not theorems, and this particular *composition* has no public
specification and has not been independently analysed. The one assumption an
earlier revision of this crate added on top of those — binding the key into the
tag's *input* as well as into its key derivation, which put a derived key and the
value it is derived from in one hash call — is **gone** as of revision `v0.3`: the
tag is now two levels and no hash message contains the master key, so the assumption
list is the primitives' own: three irreducible conjectures — ChaCha20, HChaCha20 and keyed
BLAKE3 are PRFs — with the two BLAKE3 *mode* statements (the tree preserves PRF-ness, the XOF
keeps it past the first block) reduced to the keyed-BLAKE3 conjecture in §2.1 rather than counted
as assumptions of their own. `SECURITY-ANALYSIS.md` §2.1 keeps the node `L3.6` and
its separation as the record of *why* the single-level form was replaced; §2.2 there
is a ledger mapping an auditor's own lettered list of assumptions onto the document,
so "which of these do you actually assume, and which are proved or falsified?" has a
one-table answer. The formal
harnesses in `src/proofs.rs` prove properties of the implementation (that the fields
reach the hash, that every output byte is used, that the tag reaches the ciphertext),
not cryptographic hardness.

**The reduction, written out.** [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md) is the
mathematical treatment: the construction as a tuple of functions, each assumption as an
explicit game, the SIV/DAE theorem with its five-hop reduction and concrete bound
(`q²/2^257 + q·2^-520` plus the PRF advantages — `3·Adv^{A3}` for the two-level tag and the
key derivation, with **no** `L3.6` term since `v0.3` removed it), every pair of uses of one
primitive enumerated with what separates it, and a falsification table — what would refute
each claim, which refutations have been attempted, and which are out of reach of any test.
Two properties it needs are pinned by tests added with it:
`nonce_reuse_does_not_reuse_the_keystream` (the mechanical content of misuse resistance,
which a keystream derived from `(key, nonce)` alone would fail while every other test in
the suite still passed) and `the_key_material_block_is_not_the_message_keystream`.

**What no tool here detects: variable-latency operations on secrets.** ctgrind
reports branches that depend on poisoned data (memcheck does not report an *address*
derived from a poisoned byte, see `tests/ctgrind.rs`); a division, a
remainder or a float operation has neither a branch nor a secret-dependent index, and its latency varies inside the ALU with
the operand. Measured, not assumed: with a division by a secret-derived byte planted
inside `decrypt`, ctgrind passes and the release timing screen reports t = 0.22 / 0.48
— the effect on this CPU is a few cycles against a floor of about seventeen. The
control is therefore a list rather than a tool: `tests/variable_latency.rs` inventories
every literal `/` and `%` in `src/lib.rs`'s non-test source (not in `src/witness.rs`, and
only the literal operators, not divisions hidden behind a helper) and fails if one appears that is not
in the table with a reason. It makes them visible; it cannot tell whether one is safe,
and the table's one entry today divides by the compile-time alignment of `usize`.

**What is not defended against.** Fault injection — a voltage, clock or laser
glitch that makes the *hardware* execute something other than what the code says —
is outside this crate's threat model, and outside every tool used to verify it:
Miri, Kani, ctgrind, ThreadSanitizer and libFuzzer all model *correct* execution,
and none of them can observe a glitch. (`SECURITY-ANALYSIS.md` §8 is the systematic
version of this section: every attack class and how each configuration stands
against it, with what it costs to mount one.) The decision a forgery turns on is a branch
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
records that many: the configured budget is 120 s locally and 300 s in CI.  The claim is
removed rather than re-derived, because a number
nobody can reproduce is worth less than no number.)

### The `hardened` decision — on by default

The crate hardens exactly one thing: **the accept/reject decision**, which is the
single-fault point where a forgery is accepted. It is the default configuration, not
an opt-in: the property it protects is the one a forgery turns on, it costs nothing
on large messages, and an opt-in that most callers never enable would mean most
callers are unprotected while this file claims hardening. `default-features = false`
gives the single-gate build back for a caller who has measured the cost. It makes
the decision two comparisons over the same values, the second independently *shaped*,
each with its own branch, so
one skipped instruction reaches the other gate instead of accepting. The second
comparison is load-bearing and is enforced rather than hoped for: the second gate re-reads
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
| A single corrupted byte or bit **anywhere in the swept code** (the two *decrypt* entry points — `decrypt` and `decrypt_in_place_detached` — and the decision) | **measured, and not zero — the mechanism is not the gate**: last full local sweep, `(total, inside the decision)` — opt-out `17, 0` (nop) and `163, 4` (bits); `hardened` `1, 0` and `5, 0`; `ultra` `0, 0` and `5, 0`. (Those numbers are from the run after the driver's aggregation was fixed: it used to `cat` the shards' accepted-offset files, whose last lines had no trailing newline, so the printed total was `true count − (files with entries − 1)` — 4 printed as 3, 15 as 7. The counts also move with the code, which is why they are dated "last full local sweep" rather than quoted as constants.) The accepting sites outside the decision are in the shared KDF/MAC/SIMD code, and several are the middle byte of a multi-byte instruction, where corruption desynchronises the decoder and the following bytes execute as different instructions — no source structure prevents that. **The raw totals are not comparable across configurations**, and an earlier revision of this table compared them as if they were: `ultra`'s entry points contain more code than `hardened`'s (the witness call, an extra gate operand, a ciphertext copy), so a longer region naturally collects more accepting bytes even when every one of them is outside the decision. What is comparable is the decision-scoped count, which is why that is what the tool gates on. For scale, the same technique over RustCrypto's `XChaCha20Poly1305` measures 13 of 1081 (nop) and 106 of 8648 (bits) — on a *different region*, its whole tag-verification function rather than a decision helper of 18–25 bytes, so the two are not like-for-like either |
| A fault inside the constant-time comparison itself (a shortened loop, a corrupted bound) | **closed in every configuration that builds the gates — `hardened` (the default) and above — but not in the opt-out build**: every gate compares the two tags through *two differently written* constant-time comparisons — `subtle`'s per-byte loop and an 8-byte fold into a `u64` — so a fault that shortens one shape leaves the other saying "different", and a forgery needs two faults aimed at two shapes.  The `--no-default-features` build compiles neither the fold nor a second gate, so it keeps its single shape and the accepting sites its own row above reports; that is what "opt-out" means, and the layer table says so — quantified by an audit that NOP-ed the accumulator instruction *inside* that 65-byte comparison loop: **100% of forgeries accepted on the opt-out build** (random tags, mutated tags, ciphertext-bit flips and no-op probes alike) with legitimate inputs still accepted, while the `hardened` and `ultra` builds fail closed on the same patch.  **Hand-modelled, not by a committed tool**: no script in `tools/` shortens those loops — the campaign's faults are source-level changes of other kinds (`tools/mutation_check.sh` plants a `==` where `ct_eq` was, which is not a shortened loop) and `tools/fi_instruction.sh` sweeps the compiled bytes uniformly rather than aiming at a loop bound — so the counts in this row came from cutting the comparison down by hand in a throwaway copy.  Hand-measured against that fault: an accept after **2,573 attempts** when both comparisons were the same shape (which was the `hardened` build until the fold was made unconditional within the gate-building builds), and **no forgery in 2,000,000 attempts** with both shapes present.  The fold costs **1.4 ns**, measured.  Two faults still defeat both, which is the boundary this row states rather than hides — and an audit's full fault matrix put numbers on it: a shortened second comparison **plus** an inverted first gate accepts 0.37–0.43% of forgeries on `hardened` and 0 of 2,000,000 on `ultra`, while two site pairs (`c2+ini1`, `ci0+ci1`) that are **invisible one at a time** jointly accept every probe — including the honest ciphertext — in all three configurations |
| A fault that replaces the computed tag with a constant, or with the received tag | **not defended by `hardened`, closed by `ultra`/`dual-mac`**: with only `hardened` this is the strongest fault model in the table and it defeats the two gates *together* — either gate is `computed_tag ? tag`, so forcing `computed_tag` to equal `tag` satisfies both at once, and two gates over one value are one gate for this attack, not two witnesses. That half is pinned rather than hidden: `tools/fi_check.sh`'s `computed-tag-replaced` row applies exactly this fault to the hardened build and requires it to be accepted, so a change in either direction is noticed. `dual-mac`, part of `ultra`, closes it by doing the thing an earlier revision of this row said was not done here: computing the tag a second time through the shared `derive_tag` path (catching a post-derivation rewrite of the stored value, not a fault inside the derivation) — a second MAC pass, and the tag pass is a large part of a short message — and requiring the recomputation to agree with the stored value **and** with the received tag (`recomputed_tag.ct_eq(&computed_tag) & recomputed_tag.ct_eq(tag)`, in both decrypt entry points). A rewritten stored tag then disagrees with the recomputation, and `tools/fi_check.sh`'s `dual-mac-blocks-tag-substitution` row runs that same source fault on the `ultra` build and is rejected there. A byte-level probe of the same fault is **profile-dependent**, and worth recording as such: zeroing `derive_tag`'s stores makes a zero tag acceptable on an LTO-off `hardened` build, while under this crate's shipping profile (LTO on) that patch no longer produces a constant tag and all three configurations stay fail-closed — the mechanism claim above is pinned by the *source-level* `computed-tag-replaced` row, not by that probe. The residual is the rest of this row's boundary: two faults, one in each derivation, or one aimed at the arithmetic both derivations share (`derive_tag` and the keyed BLAKE3 under it), still defeat it — that is a synchronized two-glitch bench or precision injection, and the answer for a deployment that faces it is a hardware countermeasure — dual-rail logic, an HSM — rather than software |
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

Measured cost, on the host `performance.md` describes and re-measured for `v0.3`: the added
work is the **second gate** — two more 65-byte constant-time comparisons plus an independently
written eight-byte fold (so four 65-byte comparison passes in total on the default build,
against the opt-out build's two) — a fixed per-message cost that does not scale — **+25% at 64 B, +24% at 256 B, +23% at 1 KiB, +11% at 4 KiB, and
within the noise floor from 16 KiB up** (default over `--no-default-features`; `performance.md`'s
latency and ratio tables are the source). Encryption pays nothing for it (flat to the noise
floor at every size), so the in-place *round trip* shows a smaller, noisier fraction of the same
cost. The default build is byte-for-byte identical on the wire (the KATs and
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

`ultra` includes `rng`, which pulls in `getrandom` and therefore needs an OS entropy
source. It **does not build on bare-metal `no_std` targets** (e.g. `--features ultra
--target thumbv7em-none-eabihf` fails with `getrandom`'s "target is not supported");
a `no_std` caller that wants the same defences without OS randomness should spell them
out as `features = ["hardened", "dual-mac", "locked"]`.

| Layer | What it defends | Cost (measured, this host) |
| --- | --- | --- |
| `hardened` (already default) | a single corrupted decision value or instruction | +25% at 64 B, +24% at 256 B, +23% at 1 KiB, +11% at 4 KiB, and within the noise floor from 16 KiB up (`performance.md`'s latency and ratio tables are the source) |
| `hardened` (moved here from `dual-mac`) | a fault inside the shared constant-time comparison (a shortened loop, a corrupted bound): the second gate `AND`s a differently *written* comparison (an 8-byte fold into a `u64`, rather than `subtle`'s per-byte loop), so one fault reaches only one of the two shapes and a forgery needs two faults | **+1.4 ns** per decryption, measured (0.1% at 64 B). It was `dual-mac`-only until the two numbers were put side by side: this cost against a hand-modelled change from "forgery accepted after 2,573 attempts" to "no forgery in 2,000,000" |
| `dual-mac` | the tag being pinned to a constant or to the received tag — the one model the two gates fail *together* on | +30% at 64 B, +40% at 1 KiB, +24% at 1 MiB on decryption (a +21–40% range); +6–25% on a round trip (the two ranges `Cargo.toml` and the changelog state). An independent build measured the same layer higher on its own harness (1.69–1.81x at 1 KiB, and +43–44% on the *encrypt* side at 64 B, where the fixed `scrub_stack` cost dominates); `performance.md` says how far these ratios move between builds |
| `dual-mac` | key residue surviving in stack frames this crate cannot name — the `blake3` dependency's XOF output (`enc_key ‖ enc_nonce`) and, under `pure`, the outer key `k_out`: `scrub_stack()` overwrites the 16 KiB below the entry point after the last derivation | ~16 KiB of volatile stores, ~0.5–1 µs per operation, **and ~16 KiB of stack per call**. Measured on a thread with a 32 KiB stack: the default build still runs after 16 KiB of the stack is already consumed, this one does not survive 8 KiB. A caller that spawns threads with small stacks must size them for it — the scrub is a 16 KiB frame, so it can fault the thread it is protecting. The number is public as `stack_requirement_bytes()` (zero outside `dual-mac`), and `the_reported_stack_requirement_is_sufficient` measures that a thread given that budget survives a round trip |
| `witness` (in `ultra` only) | a fault aimed at the **derivation arithmetic both tag computations share** — `derive_tag`, the keyed BLAKE3 under it, and the SIMD kernels: the one model `dual-mac` alone cannot close, and where every accepting fault the sweep finds in the `hardened` build sits | decryption costs **2.7x at 64 B, 4.0x at 1 KiB, 11.0x at 64 KiB, 12.4x at 1 MiB** against the default configuration, and the round trip 2.2x/2.8x/6.1x/6.5x in place or 2.5x/3.3x/6.6x/7.1x allocating (re-measured after the witness's residue-wipe pass) (measured; the four tables are in [`performance.md`](performance.md), and that file's "what the `ultra` layer costs" table is the one to read for this row). It is a *scalar* implementation, so its cost is per byte, and on the encrypt side it is present **only on the allocating `encrypt`** — see "What the witness is" for why the in-place path does not carry it. It does not make the *totals* in the fault table zero — it removes accepting faults from the decision and from the shared derivation, and the `ultra` build has a handful elsewhere (§§) |
| `locked` | key pages readable out of **swap** or a **core dump** | ~7 µs once per key (`mlock`+`munlock`), not per message. The key is heap-allocated so its address is stable: `mlock` is address-based, and a key returned by value moves after being locked, which left this layer protecting a dead stack slot |
| `locked` | a **hardware fault or bit flip in the key page** turning into a silent wrong key | `+42 ns` per use, measured: an 8-byte BLAKE3 tag of the key is stored beside it and checked (constant time) on every `as_bytes()`, so a corrupted page panics at the first use instead of decrypting with a key that is not the caller's. It does not detect a fault that rewrites the tag too, nor one outside the key-and-tag region (the rest of the page is never read) |
| `locked` | a **debugger** attaching to the process, or another process reading its memory | one `prctl` call, opt-in: `locked::deny_debugging()` makes the process non-dumpable, after which the kernel refuses `PTRACE_MODE_ATTACH` (and `/proc/<pid>/mem`) even to the same user without `CAP_SYS_PTRACE`. Not automatic, not even under `ultra`, because it is *process* policy — it also disables core dumps and breaks crash reporters, which is the application's call rather than a library's |
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
decryption 30.1 → 20.8 MiB/s at 64 B, 259 → 121 at 1 KiB, 1462 → 232 at 64 KiB, 1767 → 192
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
crate's code — and `ultra` compares its answer to the crate's bit for bit on **every decrypt
path** (`witness_tag == computed_tag` **and** `witness_plaintext == plaintext`) and on **the
allocating `encrypt`** (its tag against the one about to be returned). It shares no code with
the crate's crypto: not the `blake3` dependency, not the SIMD kernels, not `derive_tag`, not the
buffering. That is exactly what makes the model above reachable — a single fault in the
shared derivation changes one answer and not the other, and the gate that `AND`s the
agreement in rejects. It is not two physically independent machines: same CPU, same
compiler, same source file tree, so a *systematic* fault (a compiler bug, a wrong constant
in both implementations, a fault that hits both code paths in one glitch) is still outside
what this can see. What it does not share, and what makes it worth its price on a large
message — 6.3x at 64 KiB and 9.2x at 1 MiB on decryption, measured against `ultra` minus the
witness above — is the *machine code that computes the tag*.

**`encrypt_in_place_detached` has no encrypt-side cross-check, and that asymmetry is now stated
rather than implied.** The earlier revision of this paragraph said "on every encrypt", which was
false for the in-place path — found by *measuring*, when the three-configuration benchmark showed
`ultra`'s in-place encryption costing the same as the default at 1 MiB while its decryption cost
10.1x (12.4x after the witness's residue-wipe pass). Two reasons not to close the gap in code: what an encrypt-side witness can see is a fault
that produces a ciphertext the *peer* will reject, which is availability rather than authenticity
(the tag is over the plaintext the caller supplied, and the peer recomputes it over what it
decrypts), and the check is a full re-hash with the scalar witness — per byte, measured at about
+1.2 ms per MiB — which is the wrong trade on the API a caller picks for speed. The allocating
`encrypt` keeps it because that is the convenient-by-default path. `tests/ultra.rs` pins both
halves by source shape (`the_witness_is_called_from_exactly_these_entry_points`), so the
documentation cannot drift from the code again.

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
  says their plaintexts are equal. That is a *chosen-plaintext* distinguisher, not
  just a curiosity, whenever the protocol encrypts plaintext the attacker can
  influence under a nonce that repeats: the attacker learns, bit for bit, which
  guesses are right. A protocol that needs ciphertext
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
- **Replay, and freshness.** Decryption is a deterministic function of
  `(key, nonce, aad, ciphertext, tag)`: the same bytes authenticate again, every
  time, forever. A legitimate retransmission and an attacker's replay are
  byte-identical, and no symmetric AEAD can distinguish them — so "this
  authenticated" means "someone holding the key produced it at some point", never
  "this is new". An application that equates the two has a replay hole, and the
  fix is protocol state this crate does not have: a sequence number inside the
  AAD, a challenge the sender must echo, or a timestamp window. (`SECURITY.md`
  lists this under what is explicitly out of scope, so it is not reported as a
  vulnerability.)
- **On a 32-bit target the length guard cannot fire.** `check_lengths` compares
  against `MAX_MSG_SIZE`, which is 2^38 — larger than `u32::MAX`, so on a 32-bit
  target every length a caller can express is accepted and the *caller* is the
  limit. The check is unreachable there rather than untested
  (`test_length_guard_cannot_fire_on_32_bit` records it), the internal arithmetic is
  written to be safe anyway (`checked_add` on every length sum, no wrapping), and
  the practical ceiling is the address space; but a 32-bit deployment that wants a
  bound must impose it itself, e.g. through `decrypt_bounded` and its own check.
- **A stack scan finds the `blake3` dependency's own frame residue, and this crate
  cannot reach it.** Measured with `tools/stack_residue.sh`: after a full round trip,
  the master key never appears in the call-chain stack region, but the *XOF output* of
  the keyed hash does — a full 44-byte `enc_key ‖ enc_nonce` — because `blake3` keeps
  its output block in frames of its own. Under the `pure` (Rust-backend) build the
  outer key `k_out` also survives `derive_tag` as a ~16-byte stack run, so the residue
  is not only the XOF buffer; `ultra`'s `scrub_stack` is what overwrites the derivation
  region and clears both, which is why the `ultra` scan reports clean. The key itself
  is not left (measured: longest
  run 4 bytes); the derived material is. `blake3`'s `zeroize` feature is already on and
  the crate already calls `reader.zeroize(); hasher.zeroize();`, which is the entire
  reach a caller has apart from `scrub_stack`. What this means in practice: an attacker who can read this
  process's stack gets per-message encryption keys, not the master key — and such an
  attacker can usually read the caller's own key copy anyway. It is written down here
  because the crate's own claim ("no copy of the keyed-BLAKE3 key material survives the call") is about
  that material, and a reader should not extend it to the encryption key. The same scan
  covers `locked`'s integrity tag — a hash of the master key — and reaches the same
  conclusion: the crate's own copies are wiped, the residue is the frames described
  above (the dependency's XOF buffer, plus `k_out` under `pure`), and the tool attributes it with a blake3-only control. Three source changes
  in this crate reduce the residue that *is* reachable — `derive_enc`, `derive_material`
  and `integrity_tag` all write through caller slices instead of returning an aggregate
  (the last one's return value was a copy of `BLAKE3(key)` in a frame no wipe could
  reach), and `chacha20_rounds` mutates in place instead of taking the key state by
  value — and each was found by exactly this scan.
- **Zeroization is a volatile-store wipe.** It clears the bytes this crate owns, when
  it drops them. It does not reach a page that had already been swapped out, a core
  dump or a hibernation image the OS writes, a debugger attached to the process, or
  DRAM remanence after a cold boot. Those are deployment controls — `mlock` and
  `MADV_DONTDUMP` for the process's own buffers, `locked::deny_debugging()` for
  non-root `ptrace`, `RLIMIT_CORE`, suspend and swap
  policy, disk encryption for the image, memory encryption or tamper-resistant
  hardware for the physical end. A library that allocates through `alloc` and runs
  on an OS it does not own is not where they belong, and this one does not pretend
  otherwise.
- **`fork` copies the key and drops the lock.** `mlock` is per-process: a forked child
  inherits the parent's pages (it can read the key bytes, and the integrity tag) but its
  own `VmLck` is zero, so its copy is *not* locked and can reach swap — after a
  copy-on-write split, or once the parent drops its key. What the child does inherit is
  `MADV_DONTDUMP` and the dumpable flag, so `locked::deny_debugging()` still applies, but
  a dump exclusion is not a lock. A service that forks should load keys after the fork
  (or in each child) or re-`mlock` there; `execve` also resets the dumpable flag, so an
  exec'd child is dumpable again until it calls `deny_debugging()` itself. (Measured, not
  assumed: parent locked, child reads the plaintext, child `VmLck` = 0, the child's pages
  swap after one COW write.) An earlier revision of this list named debuggers, hypervisors,
  cold boot and hibernation but not `fork`, which is the one a server actually hits.
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
  and that every *message*-keystream call site either starts at zero or forwards its
  own counter (the derivation's two single-block calls at counters 0 and 1 are the one
  scoped exception, and they share no key with the message keystream).
- **The wire format is frozen, and it is not a standard** ("Wire format: frozen by
  revision, and the crate is 0.x" above): the bytes will not move without a revision
  bump, while the *crate* is `0.x`, so the Rust API is the unstable part — and none of
  it is interoperable with any standard, so a consumer on the other end must be this
  crate, or a reimplementation of the same three domain strings and the same tag
  construction.  (This bullet said "not frozen"; that was true before the format was
  frozen, and the sentence was left behind when the section above was
  rewritten.)

## Nonces, and where randomness comes from

The construction needs **no** internal randomness. The nonce is the caller's
responsibility, and it is the easiest thing to get wrong, so:

> A nonce MAY be public and predictable. It **MUST be unique for every
> encryption under the same key.**

Misuse resistance is a fail-safe for an occasional slip, not a licence to
reuse: security degrades with every repetition, and reusing a nonce with the
same key, AAD and plaintext reveals that the same triple was encrypted. That
last sentence is the *equality* leak, and it is not the whole of what a
repeated nonce can cost: if two *distinct* `(A, M)` pairs under one nonce ever
land on the same tag — a `2^128` birthday search over the tag's 256-bit chain
value, `SECURITY-ANALYSIS.md` §4.5 — then both are encrypted with the *same*
derived keystream, and every observer of both ciphertexts gets `C₁ ⊕ C₂ =
M₁ ⊕ M₂`, a two-time pad. The event is out of reach (`q²/2^257`, i.e. `2^-129`
at `q = 2^64` queries), and it is the honest version of "degrades to equality",
which is only true while the tags differ.

**How much of the nonce you vary is how much nonce entropy you have.** The
24 bytes are not interchangeable halves: `N[0..16]` goes through HChaCha20 into
the subkey and `N[16..24]` into the message cipher's nonce, and *all* 192 bits
are live inputs (differential tests cover the tail bytes). But if an
application varies only part of the nonce — the common shape is a 64-bit
counter in the last 8 bytes with the rest fixed — then its effective nonce
space is that part: collisions, i.e. repetitions of the *whole* nonce, appear
after about `2^32` messages rather than `2^96`. For a SIV construction that is
the survivable case and not a break — that is the point of the mode — but the
cost of the repetition is the one described just above: the equality leak, and
only if two distinct `(A, M)` pairs under that nonce also collide in the tag
(the `2^128` event), the two-time pad. An application that
believes it has 192 bits of separation when it has 64 should know; if the
full separation is wanted, vary all 24 bytes (or derive them from a counter and
a per-key label).

Two acceptable strategies:

- **A counter** — incremented after every encryption, never allowed to wrap.
  Deterministic, testable, and free of any collision bound. Prefer this when
  the application has somewhere to store the counter.
- **Random nonces** — the c2sp.org **ChaCha20-Poly1305-SIV** specification (vendored as
  `standard.txt`; this crate is a different construction from it, but shares its
  misuse-resistant, key-committing design) RECOMMENDS "randomly generate[d] nonces with a
  CSPRNG" and gives the budget as 2^48 messages under one key at a collision probability of
  2^-32, aligning with NIST guidance. (The bare birthday bound for a 192-bit nonce is far more
  generous; the specification's figure is the conservative one.)

Do **not** form a nonce by XORing a counter with a random value: the same specification
calls that out explicitly as unsuitable for commitment.

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
./verify.sh --tools         # ...plus the tool-level gates: the fourteen-row fault
                            # campaign, both instruction sweeps (quick mode), the
                            # cache-profile differential and its planted-leak control,
                            # the planted-bug checks, the cargo-mutants campaign with
                            # its committed-evidence gate, the Kani cfg check, the
                            # 4000-vector differential against the Python reference
                            # (the rotation CI defers to its scheduled `wide` job
                            # rather than running on every push), and the advisory
                            # stack-residue scan.
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
  big-endian execution by cross-interpreting s390x (both `verify.sh --miri` and
  the Deep Miri job run all four; the s390x pass executes the boundary corpus,
  which is the byte-order sensitive one).
- **Kani** — bounded model checking of the construction shape: that the domain,
  key and both lengths reach the hash in the layout the spec fixes for the
  three-part inner shape; that a key change moves *some* output byte (the
  key-change harness is one-sided, so no harness checks all 65); that every AAD
  and message byte reaches the tag; and that `derive_enc` consumes all 65 tag
  bytes (so the ciphertext commits to all 520 bits). Two boundaries: the
  **nonce** is not varied or read back by any harness, so its binding rests on
  `test_tag_matches_blake3_over_the_documented_input`, not on Kani; and the
  contiguous one-part hash shape (2 KiB–64 KiB) is reached by no harness (its
  stub assertions are documentation, and the shape equivalence is pinned by
  `test_both_tag_call_shapes_hash_the_same_bytes`). Plus the ChaCha20 counter sequencing, zeroization
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
- **Measured performance** — throughput and latency against RustCrypto's
  `chacha20poly1305` in all three configurations, with the noise floor measured
  rather than assumed ([`performance.md`](performance.md)).

Kani proves properties of the *implementation*, not cryptographic hardness.
"An adversary cannot forge a tag" is a claim about computational infeasibility,
which a SAT solver has no model of; that half rests on the underlying primitives
and on using them as specified.

## Performance

Benchmarks — throughput and latency against RustCrypto's `chacha20poly1305` for all three
configurations, the measured noise floor, and the cost of each defence — are in
[`performance.md`](performance.md), split out so this file stays about the construction and
the security argument. The short version, so a reader need not open it: this crate pays
**more per message** (three derived keys, a 65-byte tag, and wiping all of it) and **less
per byte** (BLAKE3 beats Poly1305 once there is data to batch), so in the default
configuration it is ahead of `XChaCha20Poly1305` on encryption from 256 B up (level at
1–4 KiB, where the noise floor is a tie) and ahead on decryption from 16 KiB up, the small
sizes within the noise floor and 1 KiB behind (the fixed per-message cost dominates there).
The two costs it prices are a fixed per-message cost on
`hardened` decryption (the second gate's two 65-byte constant-time comparisons plus the
independently written fold, over the opt-out build; a fixed cost, so its share is inside the
measured noise floor from 16 KiB up) and a per-byte
cost on `ultra` decryption, whose scalar witness is **2.7x at 64 B and 12.4x at 1 MiB**.

Two structural properties constrain a caller, and both follow from the construction rather
than from this implementation:

* **Encryption cannot emit its first ciphertext byte until the whole message is hashed** —
  the tag covers the plaintext and the encryption key is derived from the tag, so the two
  passes are serialized and a single message's latency does not shrink with more cores.
* **Decryption starts immediately but decides late** — the encryption key depends only on
  the caller-supplied tag, so the ChaCha20 pass runs at once, and the plaintext therefore
  exists in the buffer before it is verified. That is why the API wipes it on failure and
  never returns it, and why an application must not act on it before `decrypt` returns.

`performance.md` states both with their measurements, and records where the remaining
headroom is (and where it is not) so nobody has to rediscover it.

## Layout

```
src/lib.rs                  the construction, the SIMD backends, the test suite
src/proofs.rs               Kani harnesses (`cfg(kani)` only)
src/witness.rs              the `ultra` build's independent second implementation
tests/                      differential vectors and their replay
tools/ref_impl.py           independent Python reference implementation
tools/gen_test_vectors.py   fixture generator for the differential vectors
tools/kani_shards.py        derives the CI proof shards from src/proofs.rs
AUDIT-RESPONSE.md           the disposition of the four third-party audit reports:
                            what was fixed (with commits) and what was not, and why
SECURITY-ANALYSIS.md        the security argument: assumptions, reductions, bounds,
                            attack classes, and what would falsify each claim
performance.md              benchmarks against RustCrypto's chacha20poly1305, the
                            measured noise floor, and the cost of each defence
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
