# Security analysis: what is proven, what is assumed, and what would refute it

This document is the mathematical treatment of the construction. It has one purpose: to
separate the three kinds of statement this repository makes about itself, so that none of
them is read as another.

1. **Proven here, from explicit assumptions** — the reduction. Given the primitives are
   the PRFs they are believed to be, the composed scheme has the properties claimed, with
   the exact place where each assumption is used and the concrete loss at each hop.
2. **Assumed** — the PRF security of ChaCha20, HChaCha20 and keyed BLAKE3. Nobody can
   prove these; there is no proof of any ARX primitive of this size, and a document that
   blurred that line would be lying by structure rather than by sentence.
3. **Neither** — the implementation, the side channels, the fault models. Those are
   covered elsewhere (`README.md`, `SECURITY.md`, `tests/README.md`, and the tools under
   `tools/`), and nothing here should be read as evidence about them.

**What kind of document this is.** It is a specification, a reduction and a test
programme, written alongside the implementation rather than by an independent party. That
limits it in a way no amount of care removes: the reduction can be checked line by line
(which is the point of writing the assumptions as games and naming where each one
enters), and the preconditions can be — and are — enforced by tests, but "the author
checked their own composition" is not an audit. §7 lists what is mechanically pinned, so
a reader can see how much of the argument is enforced by something other than prose.

The falsification programme is §5: every claim has a stated refutation, and the ones that
can be tested are tested. §4 is the part that answers "does composing these pieces create
new problems" — each hazard is enumerated, and each is either proved away, shown to be a
probability statement about secret values, or recorded as a residual with a number.

---

## 1. The construction

Let `{0,1}^*` mean finite byte strings, `‖` concatenation, `⟨n⟩₆₄` the 8-byte little-endian
encoding of `n`, and `X[a:b]` a byte-range.

**Domains.** `SUBKEY_DOMAIN = "XSIV"` (4 bytes), `DOM_TAG = "XSIV-TAG"`, `DOM_ENC =
"XSIV-ENC"` (8 bytes each). All three are distinct fixed-width byte strings; §4.4 is about
why that matters and §7 about how it is enforced.

**Parameters.** Key `K ∈ {0,1}^256`, nonce `N ∈ {0,1}^192`, associated data `A ∈ {0,1}^*`,
message `M ∈ {0,1}^*` with `|A|, |M| ≤ 2^38`. Tag `T ∈ {0,1}^520`. Ciphertext `C = |M|` bytes.

**Primitives**, named for the analysis:

| Symbol | Primitive | Domain → Range |
| --- | --- | --- |
| `HC` | HChaCha20 (draft-irtf-cfrg-xchacha §2.2) | `{0,1}^256 × {0,1}^128 → {0,1}^256` |
| `CC` | ChaCha20 block function (RFC 8439 §2.3.2) | `{0,1}^256 × {0,1}^96 × {0,1}^32 → {0,1}^512` |
| `B3` | keyed BLAKE3, XOF mode | `{0,1}^256 × {0,1}^* → ({0,1}^8)^ℓ` for any `ℓ` |
| `KS` | ChaCha20 keystream from counter 0 | `{0,1}^256 × {0,1}^96 × ℕ → ({0,1}^8)^*` |

`KS(k, n, ·)` is the concatenation `CC(k, n, 0) ‖ CC(k, n, 1) ‖ CC(k, n, 2) ‖ …`.

**Derivation** (`derive_material`). With `N = N₁ ‖ N₂`, `|N₁| = 128`, `|N₂| = 64`:

```
subkey   = HC(K, N₁)
sn       = SUBKEY_DOMAIN ‖ N₂                     -- 96 bits, public
mat      = CC(subkey, sn, 0)                      -- 512 bits
mac_key  = mat[0:256]      enc_seed = mat[256:512]
```

**Tag** (`derive_tag`), a 520-bit value:

```
T = B3(mac_key, DOM_TAG ‖ K ‖ N ‖ ⟨|A|⟩₆₄ ‖ ⟨|M|⟩₆₄ ‖ A ‖ M)[0:520]
```

**Per-message key and nonce** (`derive_enc`), from the *whole* tag:

```
(enc_key, enc_nonce) = B3(enc_seed, DOM_ENC ‖ T)    split 256 / 96
```

**Encryption** (`encrypt`): `C = M ⊕ KS(enc_key, enc_nonce)` truncated to `|M|`.

**Decryption** (`decrypt`): `M' = C ⊕ KS(enc_key(T), enc_nonce(T))`, then accept iff
`T = T(K, N, A, M')` — that is, the tag is recomputed over the *recovered* plaintext and
compared in constant time over all 65 bytes.

Two structural remarks that the rest of the document depends on:

* the tag is computed over the plaintext, and the message is encrypted *with a key derived
  from the tag*: this is the SIV construction (Rogaway–Shrimpton 2006), and the ciphertext
  is not a function of the message alone but of the whole quadruple;
* the tag's input contains `K` and `N` themselves, which is not required by SIV and is what
  turns the tag into a commitment to the key and the nonce (§4.3).

---

## 2. Assumptions

Each is stated as a game, because an assumption that cannot be written as one is not an
assumption, it is a hope.

**A1 (ChaCha20 is a PRF / secure stream cipher).** For a uniformly random key `k`, the
function `(n, c) ↦ CC(k, n, c)` is indistinguishable from a uniformly random function
`{0,1}^96 × {0,1}^32 → {0,1}^512` by any adversary making a polynomial number of queries.
Equivalently, and in the form used below: for distinct `(k, n)` pairs the keystreams `KS(k,
n, ·)` are jointly pseudorandom.

*Status*: assumed. Best published cryptanalysis of ChaCha20 reaches a small number of
rounds; the 20-round function is a NIST/IRTF standard and the assumption is the standard
one. It is also assumed by every deployment of ChaCha20-Poly1305 and XChaCha20.

**A2 (HChaCha20 is a PRF).** For a uniformly random key `K`, the function `N₁ ↦ HC(K, N₁)`
is indistinguishable from a uniformly random function `{0,1}^128 → {0,1}^256`.

*Status*: assumed; same standing as A1, and it is precisely the assumption XChaCha20 rests
on when it uses HChaCha20 to extend the nonce.

**A3 (keyed BLAKE3 is a PRF with long output).** For a uniformly random key `k`, the
function `x ↦ B3(k, x)` — *including every prefix of the XOF stream*, so the 65-byte tag
and the 44-byte key/nonce are both PRF outputs — is indistinguishable from a uniformly
random function into the same output space.

*Status*: assumed, and the weakest of the three to state in the abstract: BLAKE3's PRF
claim is a design argument (the compression function keyed through its key words, with the
tree's chunk counters and the `CHUNK_END`/`ROOT` flags providing the domain separation
between internal nodes and the root), not a theorem, and tree hashing does not inherit the
Merkle–Damgård PRF proofs. There is no attack; there is also no proof, and this is the
place where the whole construction is most exposed to future cryptanalysis.

**A4 (the encodings are injective).** The map `(K, N, A, M) ↦ DOM_TAG ‖ K ‖ N ‖ ⟨|A|⟩₆₄ ‖
⟨|M|⟩₆₄ ‖ A ‖ M` is injective.

*Status*: **provable, and proven by inspection** — see §4.4. This is the one assumption
that is not about a primitive, and it is the one that is fully discharged here. (It is also
checked from the other side by Kani, see §7.)

**A5 (standard model).** No related-key, nonce-respecting-only, or quantum-model claims are
made here except where §6 states them explicitly.

---

## 3. What follows

Each theorem names the assumptions it uses. Nothing below is circular, and no step uses a
property of a composed object that was not first established for its parts.

### Theorem 1 (key material is a PRF of the nonce)

`N ↦ (mac_key, enc_seed)` is a PRF with 512 bits of output: for any `q` distinct nonces
`N⁽¹⁾, …, N⁽ᑫ⁾`, the `q` pairs are jointly indistinguishable from independent uniform
512-bit strings.

*Proof.* Hybrid. (i) Replace `N₁ ↦ HC(K, N₁)` with a uniformly random function `F₁*` (cost
`Adv^{A2}`). (ii) Now each distinct nonce's subkey is an independent uniform 256-bit value,
so replace each of the `q` evaluations `CC(subkeyᵢ, ·, ·)` with an independent uniformly
random function (cost `q · Adv^{A1}`); this is legal because the evaluation points are
distinct — different `N₁` gives a different subkey, and equal `N₁` with different `N₂`
gives a different `sn`. The outputs are then `q` independent uniform 512-bit strings.
∎

Consequences used below: (a) the two halves are jointly pseudorandom, so nothing is lost by
splitting one 512-bit block into `mac_key` and `enc_seed` instead of deriving them
separately — the two keys are as good as independent; (b) *distinct nonces never share key
material*, even if the caller repeats a message or an AAD.

### Theorem 2 (the tag is a PRF over `(N, A, M)`, and a commitment)

For a uniformly random `K`, `(N, A, M) ↦ T` is a PRF with 520-bit output.

*Proof.* For each fixed `N`, `mac_key` is pseudorandom (Thm 1), so by one hybrid step we
may treat it as an independent uniform key `k_N` per *distinct* nonce. `B3(k_N, ·)` is then
a PRF (A3). Distinct nonces carry independent `k_N` (Thm 1), so the joint statement over
all queries follows. ∎

Consequences:

* **Collision resistance.** Finding two distinct inputs with the same tag requires either
  breaking the PRF or a birthday event over 520 bits: `q² / 2^521` for `q` queries.
* **Commitment to the key.** Because `K` (and `N`) are *inputs* to the hash rather than
  only the key that keys it, a tag that is valid under `K₁` is valid under `K₂ ≠ K₁` only
  if `B3(k_{N,K₁}, X ‖ K₁ ‖ …) = B3(k_{N,K₂}, X ‖ K₂ ‖ …)` — a collision between two PRF
  values under independent keys, cost 2^520 per attempt. This is the "invisible
  salamanders" attack (a ciphertext that opens under two keys) made infeasible by the tag
  width *and* the key binding; it is a stronger property than plain SIV provides, and it is
  deliberate.
* **Commitment to the nonce and the lengths.** Same argument, byte for byte, since both
  are inputs to the same hash: a tag cannot be moved to another nonce or reinterpreted
  under a different length split (that is the same statement as §4.4).

### Theorem 3 (per-tag key separation, and keystream binding)

For distinct tags, the derived `(enc_key, enc_nonce)` pairs are jointly pseudorandom; and a
change anywhere in `(K, N, A, M)` changes the tag with probability `1 − 2^-520`, hence
changes the keystream entirely.

*Proof.* Immediate from A3 (multi-query PRF security at distinct points `DOM_ENC ‖ T`) and
Thm 2. ∎

This is the theorem that makes nonce reuse survivable (see the Corollary below) and that
makes the ciphertext
depend on the AAD, the key, the nonce and the message *contents* rather than only on their
lengths.

### Theorem 4 (SIV / deterministic-AE security)

Define the usual MRAE game: the adversary has an encryption oracle `(N, A, M) ↦ (C, T)` and
a decryption oracle, and must distinguish the real scheme from an ideal one whose
encryption is a uniformly random function of `(N, A, M)` (so repeated queries repeat their
answer) with the same length profile. Then

```
Adv^{priv} ≤ Adv^{A1} + Adv^{A2} + 2·Adv^{A3} + q²/2^521 + q²/2^353
Adv^{auth} ≤ Adv^{A1} + Adv^{A2} +     Adv^{A3} + q·2^-520 + q²/2^353
```

where `q` bounds the adversary's oracle queries and `Adv^{A1}`, `Adv^{A2}`, `Adv^{A3}` are
the *multi-query* PRF advantages (each is already defined for a polynomial query bound;
the tag and the key derivation together account for the `2·` on the third). MRAE security
is the pair.

*Proof (reduction chain, five hops).*

1. Replace the key derivation with two independent random keys per nonce (Thm 1). Nothing
   observable changes except with the stated advantage.
2. Replace the tag function with a uniformly random function (Thm 2). From here, tags are
   uniform and independent for distinct `(N, A, M)`; two queries collide in the tag with
   probability `q²/2^521`.
3. Replace `(enc_key, enc_nonce)` with a uniformly random function of the tag (A3). Tags
   that differ now give independent `(key, nonce)` pairs; a collision in that 352-bit value
   has probability `q²/2^353`, and even that collision is not a break by itself (it makes
   two queries share a keystream, which is exactly the event this term bounds).
4. Each query's ciphertext is now `M ⊕ KS(k, n)` under a key pair that is *used once*
   across all queries except with the two collision probabilities above. Replace each such
   keystream with an independent uniform string (A1, one query per key): the ciphertexts
   are uniform and independent, with the deterministic exception that a repeated `(N, A,
   M)` query produces a repeated answer — which is exactly what the ideal MRAE scheme does.
5. The two worlds are therefore identical up to the listed terms. For **authenticity**: a
   forgery consists of `(N, A, C, T)` with `T ≠ T(K, N, A, M')` for the recovered `M'` —
   i.e. the adversary must output the value of a PRF at a point it does not get to choose
   directly, since `M'` depends on `T` itself through the KDF. Each decryption query
   succeeds with probability at most `2^-520` (fresh `T`, a PRF output) or by colliding
   with a tag the oracle already produced (≤ `q · 2^-520` in total). The self-referential
   dependence `M'(T)` does not help: inverting it is as hard as inverting the KDF, and the
   key is secret. ∎

*Where each assumption enters:* A1 in the keystream (hop 4) and in the key material (hop 1);
A2 in the subkey (hop 1); A3 twice — the tag (hop 2) and the per-message key derivation
(hop 3). A4 is needed for the *statement* of the game (that the encoded input defines the
query) and is discharged in §4.4.

### Corollary (nonce misuse degrades exactly as SIV does)

If the adversary repeats a nonce, hops 1–3 are unchanged: the per-query tags still determine
independent keystreams (Thm 3), so two *different* `(A, M)` pairs under one nonce are still
encrypted with independent keys. What the adversary learns is exactly:

* whether two `(A, M)` pairs are equal (identical tags ⇒ identical ciphertexts), and
* the message length.

This is the strongest misuse behaviour a deterministic scheme can have, and it is the whole
reason the per-message key is derived from the tag rather than from `(K, N)` alone — a
scheme in which it were derived from `(K, N)` would hand over `M₁ ⊕ M₂` on nonce reuse, and
`src/lib.rs`'s `nonce_reuse_does_not_reuse_the_keystream` test exists to make that failure
mode impossible to introduce quietly.

---

## 4. Composition hazards, and what happens to each

The question "does chaining the assumptions create new problems" has a general answer:
composition is safe when the pieces are used in *disjoint domains*, and unsafe when two
uses of one primitive can collide. Every pair of uses in this construction is enumerated
below. Nothing here is left implicit in the theorems above.

### 4.1 Two ChaCha20 uses at counter 0 — *the one residual, and its number*

`derive_material` burns counter 0 of `(subkey, sn)` for the key-material block; the message
keystream is counter 0 of `(enc_key, enc_nonce)`. Both are counter 0, separated by *key* and
by *nonce*, not by counter.

* Is it exploitable? No. For the two keystreams to be equal, `enc_key = subkey` and
  `enc_nonce = sn` must both hold; `(enc_key, enc_nonce)` is a 352-bit KDF output under a
  secret key and `subkey` is an HChaCha20 output under the master key, so the event has
  probability ≈ `2^-352`, and — the part that matters — **it is not computable without `K`**:
  both sides are secret-derived, so an adversary can neither detect it nor cause it. It is a
  statement about two values only the key holder can compute.
* The reason it is worth writing down at all is that it is the only place in the
  construction where a separation rests on a probability rather than on a structural
  disjointness. `src/lib.rs`'s `the_key_material_block_is_not_the_message_keystream` computes
  both keystreams for a spread of inputs and requires them to differ, so the collapse (make
  `derive_enc` ignore the tag, or give the two call sites the same nonce) is a test failure.
* The structural remedy — reserve counter 0 for the derivation and start the message at
  counter 1 — is **not available**: it changes every ciphertext, and the wire format is
  frozen (see `CHANGELOG.md`). It is recorded here as the one thing a future revision could
  do to convert this paragraph into a disjointness proof. It would also shrink the maximum
  message by one block unless the counter arithmetic is re-derived.

### 4.2 The same primitive for two purposes (BLAKE3 twice)

The tag and the per-message key derivation both use keyed BLAKE3, with **different keys**
(`mac_key` vs `enc_seed`, independent by Thm 1) *and* different domain strings *and*
different input layouts. Even in the impossible case `mac_key = enc_seed`, the tag is
`B3(k, DOM_TAG ‖ …)` and the key derivation is `B3(k, DOM_ENC ‖ T)`, so the two families
remain separated by A4. This is defence in depth: the separation does not depend on the key
derivation being right.

### 4.3 Cross-protocol key reuse (XChaCha20 / XChaCha20-Poly1305)

Standard XChaCha20 leaves the first four bytes of the 12-byte ChaCha20 nonce as zeros when
it extends a 24-byte nonce. If this crate did the same, then for the same `(K, N)` it would
derive identical per-message key material to XChaCha20-Poly1305 and the two schemes would
share keystream in a mixed deployment. `SUBKEY_DOMAIN = "XSIV"` occupies those bytes
instead. The placement matters as much as the value: putting the label in the *counter*
would not separate this scheme from XChaCha20-Poly1305, which leaves the counter at 0.
Pinned by `test_subkey_domain_occupies_nonce_not_counter` and
`test_domain_separators_are_pinned`.

This does not make the scheme interoperable with anything — it is *not* a standard, and
`README.md` says so — it makes the two schemes not collide.

### 4.4 Encoding ambiguity

`A ‖ M` alone is ambiguous: `("ab","c")` and `("a","bc")` concatenate identically. The two
`⟨len⟩₆₄` fields remove it, and because every field in the head is fixed width
(`8 + 32 + 24 + 8 + 8`), the whole encoding is injective — this is A4, and it is discharged
here rather than assumed:

* the head is a fixed 80-byte layout, so its boundaries do not depend on the data;
* `K`, `N` are fixed width; `|A|`, `|M|` are fixed width;
* given the encoding, `|A|` and `|M|` are read off at fixed offsets, so `A` and `M` split
  uniquely;
* hence two different quadruples cannot produce the same byte string. ∎

Trailing zeros are covered by the same argument (`"c"` and `"c\0"` have different `|M|`),
and `test_aad_message_split_is_unambiguous` checks both. BLAKE3 is not length-extendable to
begin with (its finalisation is flagged), but the explicit lengths mean the construction
does not rely on that: even a Merkle–Damgård MAC under this encoding would be unambiguous
*as a function of the encoded input*.

### 4.5 Tag width, and the three "birthday" numbers

The tag is 520 bits for a stated reason: commitment is a *collision* property, so an
`n`-bit tag gives at most `2^{n/2}`, and 64 bytes would give exactly `2^256` — not more
than the key. The numbers that follow from the construction, all with 128-bit margin:

| Event | Bound |
| --- | --- |
| Tag collision (same key, `q` queries) | `q² / 2^521` (≈ 2^260 at the birthday point) |
| Derived `(key, nonce)` collision | `q² / 2^353` |
| Forgery (one decryption query) | `2^-520`, plus tag-collision terms |
| Exhaustive key search | `2^256` |
| Quantum (Grover) on the key / on collisions | `2^128` / `2^260` |

### 4.6 Counter discipline

`MAX_MSG_SIZE = 2^38` is exactly `2^32` blocks — the number of values a `u32` counter has,
with no margin. One block more would wrap the counter *inside a single message* and reuse
keystream from the start of that same message: silent, and catastrophic. The binding is a
`const` assertion in `src/lib.rs` (raising the limit does not compile), a run-time check on
every target including the 32-bit ones where `usize` cannot express the limit, a source
scan of every keystream call site (`tests/counter_range.rs`), and a Kani harness.

### 4.7 Tag truncation

An earlier revision consumed only the first 28 tag bytes in the key derivation, so the last
four bytes of the tag could not affect the ciphertext — the commitment was nominally 520
bits and actually 224. `derive_enc` now takes the whole tag, `test_every_tag_byte_reaches_the_ciphertext`
checks all 65 positions, and a Kani harness proves every byte is consumed. The same class of
bug in the *tag* input is caught by `test_tag_covers_every_aad_and_message_byte` and by the
Kani layout harnesses.

### 4.8 Lengths, widths and the 32-bit edge

`aad.len() + msg.len()` can exceed `usize` on a 32-bit target (where `check_lengths` cannot
fire, because the limit is larger than any `usize`), so the concatenating fast path uses
`checked_add` and falls back rather than wrapping. A wrapping sum would have picked a
branch by accident; an `overflow-checks` build would have panicked on caller input. This is
an *implementation* hazard that the composition created (the fast path exists only because
two hash call shapes were measured against each other), and it is written down here because
that is exactly how such things get lost.

### 4.9 What the composition does **not** introduce

No step above needed an assumption beyond A1–A3 plus the injectivity of the encoding. In
particular, none of the following is assumed: that `mac_key` and `enc_seed` are *separately*
derived (splitting one PRF block is fine, Thm 1); that a nonce is used once (that is the
misuse case, §3 Corollary); that the encryption is randomized (it is deterministic by
design); that the tag is secret (it is public, and Thm 3 does not need it to be).

---

## 5. Falsification programme

A security claim that cannot say what would refute it is not a claim. Each row states the
refutation, and the status of the attempt.

| # | Claim | What would refute it | Status |
| --- | --- | --- | --- |
| 1 | A1, A2, A3 (PRF security of the primitives) | A distinguisher for ChaCha20 / HChaCha20 / keyed BLAKE3 | **Not attempted, and not attemptable by test**: these are open problems in cryptanalysis. The evidence is the primitives' standing, their published test vectors (replayed here), and the fact that the construction's use of them is standard |
| 2 | Tag is a PRF over `(N,A,M)` | Two distinct `(N,A,M)` with equal tags under one key | Out of reach (`q²/2^521`); *structural* variants tested: length ambiguity, A/M swap, trailing zeros, single-byte changes in A and M, key and nonce reaching the tag |
| 3 | Key commitment | A `(C,T)` that opens under two keys | Out of reach (2^520); *mechanism* tested: the tag binds `K` directly (`test_tag_binds_the_key_directly`) and Kani proves `K` reaches the hash in the specified layout |
| 4 | Keystream is tag-dependent | `ct₁ ⊕ ct₂ = M₁ ⊕ M₂` under one nonce, or `ct` invariant under an AAD change | **Tested**: `nonce_reuse_does_not_reuse_the_keystream` (message change, AAD change, first-block check, attached and in-place paths) |
| 5 | The two ChaCha20 uses are separate | The key-material block equals the message keystream | **Tested**: `the_key_material_block_is_not_the_message_keystream` (16 trials, key, nonce and keystream compared); the residual is §4.1 |
| 6 | The KDF consumes the whole tag | A tag byte that does not move the derived key | **Proved + tested**: Kani (all 65 bytes consumed), `test_every_tag_byte_reaches_the_ciphertext` |
| 7 | The encoding is unambiguous | Two quadruples with the same encoding | **Proved by inspection** (§4.4) + `test_aad_message_split_is_unambiguous` |
| 8 | The counter cannot wrap inside a message | A message length above the bound that still encrypts | `const` assertion (build failure), `tests/counter_range.rs`, Kani |
| 9 | Nonce reuse leaks only equality | Two distinct `(A,M)` under one nonce with the same tag or keystream | Tested at the keystream level (#4); a tag collision is out of reach |
| 10 | Cross-scheme separation | Keystream agreement with XChaCha20-Poly1305 for one `(K,N)` | Tested at the derivation level: the label is in the nonce, not the counter (`test_subkey_domain_occupies_nonce_not_counter`) |
| 11 | The implementation matches the design | A divergence between `src/lib.rs` and the specification above | Differential testing against an independent Python reference, published KATs (RFC 8439, the XChaCha draft, BLAKE3's official keyed vectors), the independent implementation in `src/witness.rs` under `ultra`, and the Kani layout harnesses |
| 12 | An adversary cannot get unverified plaintext | A decryption failure that returns bytes, or that returns them for a moment the caller can observe | `tests/security.rs`, the wipe contracts, and `tools/fi_check.sh`'s `wipe-skipped` row |

Rows 1–3 are the honest boundary: **no test in this repository, and none that could be
written, falsifies or establishes them.** They are the standing bet that every symmetric
scheme makes.

---

## 6. Residual risk, in one place

* **Cryptanalytic risk.** The construction is exactly as strong as ChaCha20, HChaCha20 and
  BLAKE3. A break in any of them breaks this; a break in BLAKE3's *keyed* mode is the most
  exposed of the three, because that mode's PRF claim is a design argument rather than an
  inherited proof.
* **The counter-0 coincidence** (§4.1): probability `≈ 2^-352`, not computable without the
  key, not exploitable. A future revision could remove it structurally at the cost of the
  wire format.
* **Determinism and length** (§3 Corollary): equal `(K,N,A,M)` ⇒ equal ciphertext forever,
  and the ciphertext length equals the message length. Both are properties of the mode, not
  defects, and both are documented in `README.md`.
* **Beyond the model.** Side channels, fault injection, a debugger, cold boot, a hostile
  hypervisor: out of scope here and covered where they belong.
* **Not claimed:** that this is a standard, that it has been cryptanalysed by anyone else,
  or that the tag width makes forgery harder than 2^256 — it does not, because forgery is
  bounded by the key, not by the tag (the tag width buys *commitment*, and that is the
  property that would otherwise cap at 2^256 and does not).

---

## 7. Where each claim is enforced, so it cannot quietly change

| Claim | Enforcement |
| --- | --- |
| The tag's exact input layout, and that every field reaches the hash | Kani (`tag_is_keyed_hash_of_the_whole_context`, `every_aad_and_message_byte_reaches_the_tag`, `tag_changes_when_the_key_changes`), `test_tag_matches_blake3_over_the_documented_input` |
| Every one of the 65 tag bytes is consumed | Kani (`derive_enc_reads_every_tag_byte`), `test_every_tag_byte_reaches_the_ciphertext` |
| The counter never wraps | `const` assertion, `tests/counter_range.rs`, Kani (`chacha20_counter_sequencing_is_exact`, `max_msg_size_fits_in_the_block_counter`, `max_msg_size_boundary_matches_counter_capacity`) |
| Domains are distinct, fixed width, and correctly placed | `test_domain_separators_are_pinned`, `test_subkey_domain_occupies_nonce_not_counter` |
| The AAD and the message are separately bound | `test_aad_message_split_is_unambiguous`, `test_tag_covers_every_aad_and_message_byte` |
| Nonce reuse cannot reuse a keystream | `nonce_reuse_does_not_reuse_the_keystream` |
| The two ChaCha20 uses are separate | `the_key_material_block_is_not_the_message_keystream` |
| The design on the wire is the design in the paper | The differential fixtures, the published KATs, and `src/witness.rs` under `ultra` |
| The properties here are not silently weakened by a code change | The source-shape tests in `tests/decision_scope.rs`, `tests/variable_latency.rs`, `tests/counter_range.rs` |

The pattern is deliberate: where a property cannot be proven, it is tested; where it cannot
be tested, it is measured; and where it can be neither, it is written down with its number,
here and in `README.md`.

---

## References

* P. Rogaway, T. Shrimpton, *A Provable-Security Treatment of the MAC-then-Encrypt
  Approach*, EUROCRYPT 2006 — the SIV construction and its theorem.
* C. Namprempre, P. Rogaway, T. Shrimpton, *Reconsidering Generic Composition*,
  EUROCRYPT 2014 — the MRAE formulation used in §3.
* S. Gueron, Y. Lindell, *GCM-SIV: Full Nonce Misuse-Resistant Authenticated Encryption
  at Under One Cycle per Byte*, CCS 2015, and RFC 8452 (*AES-GCM-SIV*) — the same
  "tag first, derive the per-message key from the tag" two-pass structure, with a proof,
  which this construction mirrors with BLAKE3 and ChaCha20 in place of Polyval and AES.
* RFC 8439 (ChaCha20 and Poly1305), draft-irtf-cfrg-xchacha-03 (XChaCha20 and HChaCha20),
  and the BLAKE3 specification — the primitives and the vectors this repository replays.
