# Security analysis: what is proven, what is assumed, and what would refute it

This document is the mathematical treatment of the construction. It has one purpose: to
separate the three kinds of statement this repository makes about itself, so that none of
them is read as another.

1. **Proven here, from explicit assumptions** — the reduction. Given the primitives are
   the PRFs they are believed to be, the composed scheme has the properties claimed, with
   the exact place where each assumption is used and the concrete loss at each hop.
2. **Assumed** — the PRF security of ChaCha20, HChaCha20 and keyed BLAKE3. Nobody can prove
   these; there is no proof of any ARX primitive of this size, and a document that blurred that
   line would be lying by structure rather than by sentence. (Through revision `v0.2` there was a
   seventh item here — L3.6, a statement the tag's layout added on top of those three; `v0.3`'s
   two-level tag removed it, so the assumed list is exactly the primitives' own.)
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
What has changed since the first revision is that independent readers *have* gone through
this document and the code, and what they found is in `CHANGELOG.md` (the collision bound
of §4.5, the two-time-pad consequence in §3, the L3.6 gap and its removal in `v0.3`, and a
`MADV_DODUMP` that was never called): that is evidence about the *document*, not independent
cryptanalysis of the design, and the distinction is the one this paragraph exists to keep.

The falsification programme is §5: every claim has a stated refutation, and the ones that
can be tested are tested. §4 is the part that answers "does composing these pieces create
new problems" — each hazard is enumerated, and each is either proved away, shown to be a
probability statement about secret values, or recorded as a residual with a number.

---

## 1. The construction

Let `{0,1}^*` mean finite byte strings, `‖` concatenation, `⟨n⟩₆₄` the 8-byte little-endian
encoding of `n`, and `X[a:b]` a range in the unit the surrounding expression uses — bits in
this section, bytes in §4.

**Domains.** `SUBKEY_DOMAIN = "XSIV"` (4 bytes), `DOM_PRE = "XSIV-PRE"`, `DOM_TAG = "XSIV-TAG"`,
`DOM_ENC = "XSIV-ENC"` (8 bytes each). All four are distinct fixed-width byte strings; §4.4 is
about why that matters and §7 about how it is enforced.

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
b0       = CC(subkey, sn, 0)                      -- 512 bits
b1       = CC(subkey, sn, 1)                      -- 512 bits (first 256 used)
k_in     = b0[0:256]    k_out = b0[256:512]    enc_seed = b1[0:256]
```

**Tag** (`derive_tag`), a 520-bit value, computed in **two levels**:

```
X = B3(k_in,  DOM_PRE ‖ N ‖ ⟨|A|⟩₆₄ ‖ ⟨|M|⟩₆₄ ‖ A ‖ M)[0:256]
T = B3(k_out, DOM_TAG ‖ X)[0:520]
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
* the tag is computed in **two levels** (the NMAC shape), and **no hash message contains `K`**:
  the inner hash absorbs the public context under `k_in`, the outer turns that digest into the
  tag under `k_out`. SIV does not require this, and it is what makes the tag's PRF/collision
  claim an ordinary keyed-BLAKE3 cascade (§3, Thm 2) rather than a key-dependent-input step. An earlier
  revision (`v0.2`) used a *single* level with `K` in its input, which bound the key more directly
but needed an assumption — L3.6 — that no reduction covered; §2.1 records the change. The
equal-material route the old layout closed is **not** closed here: all three separate derived
values (`k_in`, `k_out`, `enc_seed`) are, for a fixed nonce, functions of the single 256-bit
`subkey` (the 96-bit `sn` is fixed too), so it is a `2^128` subkey birthday in the
attacker-chosen game (§4.5/§4.10), not a structural win.

---

## 2. Assumptions

Each is stated as a game, because an assumption that cannot be written as one is not an
assumption, it is a hope.

> **Revision note (`v0.3`).** A sixth conjecture, **L3.6**, was part of this list through
> revision `v0.2`. It declared the correlation the single-level tag introduced: the master key
> both keyed the tag hash and appeared in that hash's input. Revision `v0.3` replaced the tag with
> a two-level (NMAC-shaped) construction in which **no hash message contains the master key**,
> which removes the correlation and with it L3.6. The node is kept in §2.1 and §2.2 below, marked
> as removed, because its separation is the record of *why* the change was made and because §2.3's
> non-redundancy argument was written against the six-conjecture set. The construction now rests
> on A1–A4 plus the key-direction assumption A2′ and L3.1–L3.5 alone — of which
> L3.1–L3.3 are irreducible primitive conjectures and L3.4/L3.5 reduce to L3.3 (§2.1) —
> which is exactly what the primitives' own assumptions provide, with nothing added by the
> encoding.

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

**A2′ (HChaCha20's key direction).** For every fixed `N₁`, the map `K ↦ HC(K, N₁)` is
indistinguishable from a uniformly random function `{0,1}^256 → {0,1}^256`. In particular,
distinct keys collide with probability at most `q(q-1)/2^257`, and a given 256-bit `subkey` is
hit by a candidate key with probability `≈2^-256`. This is the key-direction counterpart of A2,
and A2 does
**not** imply it: PRF security in the nonce direction is compatible with a keyed family that
identifies many keys (a PRF may have key collisions without being distinguishable from a
random function for a uniformly random key). The target key-commitment bound and the
attacker-chosen key route both use A2′; the tag/encryption PRF steps do not, but Thm 4's
key-guess forgery term does.

*Status*: assumed, with the same standing as A2 (the key is the only secret input in this
direction); it is stated separately because the composition uses it in a direction A2 does not
cover.

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

**A4 (the encodings are injective).** The map `(N, A, M) ↦ DOM_PRE ‖ N ‖ ⟨|A|⟩₆₄ ‖ ⟨|M|⟩₆₄ ‖ A ‖ M`
(the tag's inner-hash input) is injective, and the outer hash is applied to a fixed-width 32-byte
digest, so the composed tag input is injective too.

*Status*: **provable, and proven by inspection** — see §4.4. This is the one assumption
that is not about a primitive, and it is the one that is fully discharged here. (It is also
checked from the other side by Kani, see §7.)

**A5 (standard model).** No related-key, nonce-respecting-only, or quantum-model claims are made
here except where §6 or §8.1 states them explicitly. An earlier revision of this construction also
declared one *correlation* — the master key both keyed the tag derivation and appeared in the
tag's input — as L3.6. Revision `v0.3` removed it: the tag is now two levels (NMAC-shaped) and no
hash message contains the master key, so the tag/encryption assumptions are A1–A4; the target
key-commitment statements additionally use A2′. §2.1 keeps L3.6 and its separation as the record
of *why* that revision was made.

### 2.1 The assumption tree, layer by layer

Numbering the assumptions A1–A4 plus A2′ (with A5 a standard-model scope statement rather than a
conjecture) is not enough to audit a composition: each of those has to be
pushed down until it rests on something that cannot be pushed further — a theorem with a
proof and a citation, or a conjecture about a primitive that nobody has proven. This is that
tree. Every node names its own falsifier, and no node is left as "it's standard".

```
L0  the claim:  MRAE/DAE security of the AEAD                    (§3 Thm 4)
     |
L1  proven composition theorems (no assumption at this level)
     |-- L1.1  SIV/DAE: PRF tag + IND-CPA IV-based encryption => secure
     |         (Rogaway-Shrimpton, EUROCRYPT 2006; MRAE form: Namprempre-Rogaway-Shrimpton,
     |          EUROCRYPT 2014)
     |-- L1.2  ...and its "per-message key derived from the tag" variant, which is what this
     |         construction does (Gueron-Lindell, CCS 2015 / RFC 8452, §4)
     |-- L1.3  the standard reductions used at the joints:
     |         * PRF => collision resistance (q^2/2^s, where `s` is the size of the *state*
     |           the output is a function of -- for an XOF that is the chaining value, not
     |           the output width, see §4.5)
     |         * PRF output splitting: the halves of one PRF output are jointly pseudorandom
     |         * cascade: a PRF keyed by a PRF output is a PRF
     |         * counter-mode encryption from a PRF (a stream cipher is IND-CPA if its block
     |           function is a PRF at distinct counter values)
     |         * one-time-pad with pseudorandom keys
     |
L2  lemmas proved in §3 from L3 (this document's own contribution)
     |-- Thm 1  the key material (k_in, k_out, enc_seed) is a PRF of the nonce up to
     |            the 256-bit subkey-collision event (128-bit collision level)
     |-- Thm 2  the tag is a PRF of (N,A,M) up to the 256-bit inner-digest collision
     |            event, hence 128-bit collision security in the worst case; key-committing
     |            (target) under A2′
     |-- Thm 3  distinct tags => independent (enc_key, enc_nonce)
     |-- A4      the encoding is injective                        (proved by inspection, §4.4)
     |-- the counter lemma: no counter value repeats in one message (§4.6)
     |-- the acyclicity lemma: the dependency graph is a DAG  (§3, after Thm 4)
     |-- the two structural separation lemmas                   (§4.10)
     |
L3  primitive-level conjectures -- each one a statement about an object, not a mode
     |-- L3.1  CC(k, n, c) = P(k,n,c) + (k,n,c) is a PRF in (n, c) for random k
     |         [ChaCha20 = counter-mode + Even-Mansour-style feed-forward over the
     |         20-round ARX permutation P]
     |-- L3.2  HChaCha20 = trunc(P(x)) is a PRF in the nonce for random k
     |         [the *same* permutation, no feed-forward, 8 of 16 words]
     |-- L3.3  the BLAKE3 compression function, keyed through its key words with the
     |         KEYED_HASH flag, is a PRF in the message block
     |-- L3.4  the BLAKE3 tree preserves PRF-ness: the root node's output is a PRF
     |         [reduced to L3.3 + Lemma T in §2.1; a proof sketch, this document's own]
     |-- L3.5  the BLAKE3 XOF keeps that property past the first output block
     |         [reduced to L3.3 in §2.1: successive output blocks are distinct points]
     |-- L3.6  [REMOVED in revision v0.3] for a uniform `K`, the map
     |         `(N, A, M) ↦ B3(D(K, N), P ‖ K ‖ S)` was a PRF, where `D(K, N)` was the
     |         derived hash key (`mac_key`) and the *scheme* inserted the secret `K` between
     |         a fixed prefix `P` (`DOM_TAG`) and the caller-chosen suffix `S`
     |         (`N ‖ ⟨|A|⟩ ‖ ⟨|M|⟩ ‖ A ‖ M`): the input was a function of the key, a shape
     |         the black-box PRF game does not model and no reduction from L3.3 reaches.
     |         The single-level tag needed it because `K` was in the tag's input; the
     |         two-level tag v0.3 uses has no hash message containing `K`, so the node is
     |         gone. Kept here, with its separation below, as the record of the change
     |
L4  implementation properties (constant-time, no reachable panic, wipes, counter range)
     -- out of scope here; README and tests/README cover them
```

**Why L3.1 and L3.2 are two conjectures and not one.** They are statements about the same
permutation, and it is tempting to think the first implies the second. It does not, and the
literature is the reason: the feed-forward construction `P(x) + x` is a PRF up to the birthday
bound (that is the Even–Mansour story, and it is *false* beyond it), while a truncated
permutation output is not a PRF at all in general — it can be distinguished by collision
counting once more than `2^(output/2)` outputs are available. The two modes have different
proofs, different bounds and different failure modes, so a construction that uses both needs
both. (XChaCha20 needs both, which is why the pair is standard practice rather than a
corollary of anything.)

**Why L3.4 is not inherited from Merkle–Damgård results.** There are real theorems that an
iterated hash built from a PRF compression function is a PRF — Bellare–Canetti–Krawczyk for
HMAC/NMAC is the canonical one — but they are about *sequential* iteration. A tree is not
covered. What supports L3.4 here is structural: every node of a BLAKE3 tree is a keyed
compression with a distinct, injectively-encoded input (chunk counter, block index, length,
and the CHUNK_START/CHUNK_END/PARENT/ROOT flags), so two distinct messages cannot produce the
same node input except by colliding inside the compression function itself. That is an
argument rather than a citation, and BCK cannot be pointed at it; so, because it is the one
place in this tree where the document leans on a structural fact rather than a theorem, the
argument is written out as an actual reduction below.

**The reduction: L3.4 follows from L3.3 plus the tree's injectivity.** Two ingredients, one
structural and one primitive-level.

* **Lemma T (node-input injectivity).** In one keyed BLAKE3 tree over an input `M`, every
  compression call sits at a *distinct point* of the compression function's domain — a distinct
  `(block, counter, block_len, flags)` — unless two chaining values in that tree collide.
  *Proof, by cases; inspection-level, the same kind of statement as A4.* (i) Within a chunk the
  blocks chain sequentially, and only the first and last carry CHUNK_START/CHUNK_END, so two
  blocks of one chunk share a compression input only if a chaining value repeated — a CV
  collision. (ii) Different chunks carry a different `counter`. (iii) A parent carries `PARENT`,
  which no chunk block has, and `ROOT` marks the root, so parent and chunk calls never coincide.
  (iv) Two parents share an input only if their `(left_cv, right_cv)` pairs are equal — again a
  CV collision. ∎

* **Theorem (L3.4, from L3.3 + Lemma T).** For a uniformly random key `k`, `M ↦ root_output(k, M)`
  is a PRF, with loss `depth · Adv^{L3.3} + q²/2^257`, where `depth` is the tree height (≤ 28 for
  `MAX_MSG_SIZE`, since 2^38 bytes is 2^28 chunks).
  *Proof sketch (hybrid, bottom-up).* (1) By Lemma T the chunk-level compression calls are at
  pairwise distinct points, so — L3.3 being a **multi-query** PRF, held for each flag setting, and
  the flags are public domain separation so that is the natural reading — replace every completed
  chunk's chaining value with an independent uniform string, at one multi-query advantage. (2)
  Suppose every node at level `j` now outputs an independent uniform CV. A level-`j+1` parent's
  input `left_cv ‖ right_cv` is then a fresh uniform point, *unless* two parents share one, which
  Lemma T reduces to a CV collision — charged at `q²/2^257` (256-bit CVs). Replace each parent's
  output by uniform: one more L3.3 advantage per level. (3) After the root the output is uniform,
  so the real and ideal trees are indistinguishable up to the accumulated terms. ∎

So L3.4 is **not a separate primitive conjecture**: it is L3.3 applied to a tree, with Lemma T as
the only construction-specific input. The non-redundancy table in §2.3 is consistent with this and
not contradicted by it — it shows L3.3 *alone* does not imply L3.4, because a *different* root
assembly (one that ignores half a child) still satisfies L3.3 while defeating injectivity; Lemma T
is exactly the hypothesis BLAKE3's own assembly supplies. **L3.5 reduces the same way**: the
successive XOF output blocks are the root compression at `counter = 0, 1, 2, …`, distinct points
by construction, so the whole multi-block stream is one multi-query L3.3 application.

**Two honest caveats, so the reduction is not read as more than it is.** First, this is *this
document's* argument, not a cited or peer-reviewed theorem — BCK covers sequential iteration and
says nothing about a tree, so what is offered is a proof sketch with its kernel named (Lemma T);
the nodes stay on the conjecture list until an independent party checks the sketch. Second, the
loss is `depth · Adv^{L3.3}` rather than a single advantage, because the hybrid runs level by
level; at `depth ≤ 28` that is at most a factor of 28 on an already-negligible term. The
irreducible primitive conjectures are therefore **L3.1, L3.2 and L3.3**; L3.4 and L3.5 are
reductions, and A4 is proved outright.

**Would more rounds help? No, for two independent reasons.** An auditor's natural reading of
A3 ("BLAKE3 uses 7 rounds where BLAKE2s uses 10") is that the primitive is under-margined and one
could simply add rounds. It does not work here. (i) **The bounds this construction is limited by
are not the round count.** Forgery is `2^256` because the key is 256 bits, and collisions are
`2^128` because the output is a function of a 256-bit chaining value (§4.5); neither number moves
when the compression function gets slower or longer-round, because neither is set by the rounds.
More rounds cannot, e.g., turn a 128-bit collision bound into a 160-bit one — the CV is still 32
bytes. (ii) **There is no such primitive to switch to.** "BLAKE3 with more rounds" is not BLAKE3;
it is an unanalyzed bespoke variant, and A3 is defensible *precisely because* it is a standard
primitive that outside cryptanalysts have attacked. A 10-round re-parameterisation would trade the
one body of evidence that supports L3.3 for a construction with none, which is a strict loss of
assurance. What *would* matter is a full-round distinguisher for BLAKE3 as specified — that is the
stated falsifier of L3.1–L3.3 (§5.2, item 1), and it is a break of the primitive, not something a
caller can pre-empt by adding rounds. A deployment that genuinely wants a different margin wants a
*different, independently analyzed* primitive (SHA-3/KMAC, or SHA-512), not a tweaked BLAKE3 — and
that is a wire-format change with its own performance and analysis story, which is a revision
decision rather than a hardening one.

**Why L3.6 was an assumption of its own, and what removed it.** This subsection is kept because
it is the record of a design change: revision `v0.3` replaced the single-level tag with a
two-level one precisely to delete this node, and the separation below is the reason that was a
fix rather than a preference.

First, the statement, because the obvious phrasing of it is not well posed. "The tag is a PRF in
`K`" cannot mean a PRF whose inputs the adversary chooses, since the input contains `K` and the
adversary does not know it. What the single-level tag's reduction needed — and what L3.6
asserted — was the game the theorems used: `K` is drawn uniformly, the adversary chooses
`(N, A, M)`, *the scheme* builds the byte string `DOM_TAG ‖ K ‖ N ‖ ⟨|A|⟩ ‖ ⟨|M|⟩ ‖ A ‖ M` with
the secret inside it, and the output `T = B3(D(K), ·)` must be indistinguishable from a uniformly
random function of `(N, A, M)`. The distinguishing feature of this game, and the reason it is not
L3.3, is that the *key* of the hash and a 32-byte *substring of its input* were two correlated
functions of one secret — the key-dependent-input setting, the cousin of KDM.

It looks like it should follow from L3.3, and it does not. L3.3 is the statement that
`x ↦ B3(k, x)` is a PRF for a key `k` drawn uniformly **and independently of the input**; there
the key was derived from the very value the input contained. The reduction that would close the
gap cannot be written down: it would have to hold `D(K)` as the challenge key of the PRF game
while *placing `K` in the query string*, and the input would have to contain the preimage of a
value the reduction is not given. (Concretely: the reduction's oracle is `B3(k*, ·)` with `k*`
uniform and unknown; to answer a query it must build `D(K) ‖ … ‖ K ‖ …`, which needs `K`, and
`D` is not invertible without `K`.)

What a separation can show here is narrower than an earlier revision of this paragraph claimed.
Take any keyed hash `B3'` that is L3.3-secure but *notices* its input: `B3'(k, x) = 0` if `k`
occurs in `x`, and `B3(k, x)` otherwise. For a fixed query string that function is still a PRF —
the bad event is that the key occurs anywhere in `x`, at most `|x|` starting positions, so it
costs at most `|x|·2^-256` per query (`≈ 2^-218` at the `2^38`-byte message limit) — and yet the
composed map `K ↦ B3'(K, P ‖ K ‖ S)`, where the *same* secret keys the hash **and** appears in
its message, is the constant zero function: distinguishable from random by a single query. That
separates the **key-dependent-input shape** from L3.3, and no black-box reduction reaches that
shape.

It does **not** separate the `v0.2` tag's composed map, which is the shape L3.6 concerned.
`v0.2` keyed the hash with `mac_key = D(K, N)` while the message held the **master** `K`, so
`D(K, N)` occurring in the message is itself a negligible event, and `K ↦ B3'(D(K), P ‖ K ‖ S)`
is *not* the constant zero function — with this `B3'` it is the actual `v0.2` map up to that
negligible event, so the example exhibits no distinguisher for it. The gap L3.6 names therefore
rests on the reduction-impossibility argument two paragraphs above — the reduction would have to
hold `D(K, N)` as the challenge key while placing `K`, whose image it is, in the query — rather
than on this separation. That argument is heuristic (a reduction cannot be *written*, not a proof
that no distinguisher exists), and `v0.3` removed the construction instead of resolving it.

**How the two-level tag removes it.** The `v0.3` tag is

```text
X   = B3(k_in,  DOM_PRE ‖ N ‖ ⟨|A|⟩ ‖ ⟨|M|⟩ ‖ A ‖ M)          (the inner hash)
tag = B3(k_out, DOM_TAG ‖ X)                                   (the outer hash)
```

In **both** calls the message is a value a reduction can construct: the inner message is public,
and the outer message is the inner digest, which a reduction that has idealised `k_in` (a standard
PRF step at a distinct point, not key-dependent) can compute. Neither call has a secret in its
message, so the key-dependent-input shape is gone, Thm 2's hybrid (i) is the ordinary PRF step,
and the node is deleted. The price the single level paid for its input-side binding — this
assumption — is not paid here, but neither is the route that binding closed: the three separate
derived values are jointly pseudorandom yet, for a fixed nonce, all functions of the single
256-bit `subkey`, so the equal-material route is a `2^128` subkey birthday rather than a structural separation
(§4.5/§4.10, and the §2.3 non-redundancy row).

**What supports the replacement is structural, and it is a stronger statement than the design
argument the single level rested on.** BLAKE3's keyed mode still puts the key words in the initial
state and admits message words only through the round function, but the two-level construction no
longer needs that property to be more than L3.3: it is exactly the NMAC shape, whose PRF security
from a PRF compression function is the standard cascade argument (L1.3), and — unlike HMAC on a
tree hash — it never relies on a theorem about iteration (the outer call is a single short
message; L3.4 covers the inner one).

**What each use of a primitive consumes.**

| Use | Consumes | Because |
| --- | --- | --- |
| `subkey = HC(K, N₁)` | L3.2 | truncated permutation output, keyed by `K` |
| `(k_in, k_out) = CC(subkey, sn, 0)[0..64]` | L3.1 | feed-forward block function, counter 0 |
| `enc_seed = CC(subkey, sn, 1)[0..32]` | L3.1 | the same block function at counter 1 (a distinct point) |
| `X = B3(k_in, DOM_PRE ‖ …)` | L3.3 (and L3.4, = L3.3 + Lemma T) | keyed compression and tree over the public context |
| `T = B3(k_out, DOM_TAG ‖ X)` | L3.3, L3.5 | keyed compression, single short message, 65-byte XOF output |
| `(enc_key, enc_nonce) = B3(enc_seed, …)` | L3.3, L3.5 | keyed compression, 44-byte XOF output |
| `C = M xor KS(enc_key, enc_nonce)` | L3.1 (via L1.3's counter-mode reduction) | distinct counters per block, §4.6 |

No row consumes L3.6, because the construction no longer contains a hash whose key and whose
message share the master key.

**Falsifiers, per node.** L3.1: a distinguisher for ChaCha20's block function (published
cryptanalysis reaches 7–8 of 20 rounds; a full-round distinguisher would falsify it). L3.2: a
distinguisher for HChaCha20 (no published attack beyond the same reduced-round results). L3.3:
a PRF distinguisher for keyed BLAKE3 — the BLAKE2/BLAKE3 literature has boomerang and
rotational attacks on *reduced* rounds only. L3.4: a collision or a PRF distinguisher that
exploits the tree (this would be a structural attack on BLAKE3, and none is known). L3.5: an
XOF distinguisher past the first output block (the output counter is part of the root
compression's input, so this reduces to L3.3/L3.4). **L3.6 (removed)**: its falsifier was any
distinguisher for the composed map `K ↦ B3(D(K), … ‖ K ‖ …)` that was *not* a distinguisher for
`x ↦ B3(k, x)` at a fixed input — a concrete exploit of the key also appearing in the message.
The separation above showed such distinguishers exist for the key-dependent-input shape (the same
secret keying the hash and occurring in its message); the `v0.2` map itself (keyed by `D(K, N)`,
containing `K`) rests on the reduction argument above, not on that example. That is why the node
was treated as a real assumption and why `v0.3` removed it rather than keeping it; no such
structure is known in BLAKE3. A4 (the encoding) is not a conjecture: it is proven in §4.4.

**The honest bottom line.** Every tag/encryption claim in this document rests on **L3.1, L3.2
and L3.3**; the target key-commitment statements additionally rest on **A2′**, the key-direction
assumption in §2. There is no proof of any of them, and no test in this repository — or any
other — can establish them, because they are statements about the infeasibility of computation.
What the remainder of the document does is make sure that *nothing else* is assumed. Three
irreducible PRF conjectures — one per primitive — plus A2′, the key-direction face of
HChaCha20 that the target key-commitment statements use, are the primitive assumptions; A2′ is
not an encoding-introduced assumption, but it is a fourth primitive assumption and is listed
rather than hidden. Unlike revision `v0.2`, which added a sixth (`L3.6`) from a choice of
encoding, revision `v0.3` adds none of its own beyond making A2′ explicit: L3.4 and L3.5 are reduced to L3.3 in §2.1 above (with the
tree's encoding injectivity, Lemma T, as the only construction-specific input), A4 is proved by
inspection, and the two-level tag's only further requirement is that the inner digest be a PRF
output, which is L3.3 itself. The distinction §4.10 draws (no *joint* assumption between ChaCha20
and BLAKE3) still holds, and there is now no encoding-introduced assumption on top of it either.

### 2.2 An auditor's lettered list, mapped onto this document

Audits of this construction arrive with their own numbering, and one such list — with the items
ChaCha20-is-a-PRF, keyed-BLAKE3-is-a-PRF, HChaCha20-is-a-PRF, the two-level cascade-is-a-PRF,
"the 520-bit XOF output gives more than `2^256` collision resistance", the SIV composition theorem,
and the `K`-in-the-head key-dependent-input step — maps onto this document as follows. **The
letters below are the auditor's, not §2's**; this section's own A1–A5 are a different list, and the
numbers in `Adv^{A1}`–`Adv^{A3}` in the theorems refer to *this* document's, so the mapping is
worth having in one place:

| Auditor's item | Where it lives here | Status |
| --- | --- | --- |
| ChaCha20 is a secure PRF | L3.1 | assumed (L3.1's standing paragraph; no full-round attack, huge deployment) |
| Keyed BLAKE3 is a secure PRF | L3.3 (with L3.4/L3.5 reduced to it in §2.1) | assumed (design argument, not a theorem; the most exposed of the three) |
| HChaCha20 is a secure PRF | L3.2 | assumed, and a *separate* conjecture from L3.1 though it is the same permutation |
| The two-level derivation cascade is a PRF | **Thm 1** | **proved** here from L3.1 + L3.2, not assumed — the same construction XChaCha20 rests on, but with the argument written out |
| "The 520-bit XOF output gives more than `2^256` collision resistance" | §4.5 | **falsified**: the whole output is a function of a 256-bit chain value, so collisions are `2^128`-class and the width cannot raise them. (The claim was never needed for commitment — that is a *target*, §3 Thm 2 — which is why falsifying it does not weaken the scheme's commitment) |
| The SIV composition theorem applies | L1.1 (RS06), L1.2 (the key-derived-from-tag variant: Gueron–Lindell / RFC 8452), L1.3 | literature, cited; the MRAE form used in §3 is NRS14's |
| The `K`-in-the-head step is sound (KDI/KDM-flavoured) | **L3.6 (removed in `v0.3`)** | **This row was the single-level tag's one added assumption**, and it was *not* implied by L3.3 — there was a separation showing no black-box reduction existed. It was immediate only under a random-oracle model of keyed BLAKE3 (strictly stronger than the PRF assumption). Revision `v0.3` **removed the row's cause**: the two-level tag puts no `K` in any hash message, so the step is no longer taken and the construction assumes nothing beyond the primitives. The row is kept so an auditor holding the old list can see where it went |

Nothing in the table is silently assumed: each row either points at a proof in this document, at
a citation, or at a named conjecture with its own falsifier in §5. In revision `v0.3` **there is no
`K`-in-the-head step to push on** — it was removed rather than argued — and §5's row 15 records
the removal.

### 2.3 Is the conjecture set consistent, and is any conjecture redundant?

An assumption list needs two things beyond each entry: the entries must be *simultaneously
satisfiable* (no contradiction hides in the set) and *non-redundant* (none is a consequence of
another, or it is doing no work and should be deleted). Both are discharged here, which is the
part of an assumption audit that usually goes missing.

**Consistency: the conjectures hold together, in one model.** Take `CC` and `HC` to be independent
random functions of their inputs (each is then a PRF, so L3.1 and L3.2 hold), and take keyed
BLAKE3 to be a random oracle `R(k, x)` whose output stream is uniform and independent for every
distinct `(k, x)`. Then:

* L3.3 holds: at a fixed `x`, `k ↦ R(k, x)` is a random function;
* L3.4 holds: whatever the tree does with chaining values, the root's output is a fresh uniform
  string per distinct root input — there is no structure left to exploit (and §2.1 reduces it to
  L3.3 + Lemma T, so a model of L3.3 that also satisfies Lemma T models it);
* L3.5 holds: later output blocks are part of the same uniform stream.

So no two assumptions contradict each other, and the idealised world the reductions compare
against is itself a model of the assumptions. (In `v0.2` a fourth bullet was needed here, for
L3.6 — that the map `(N, A, M) ↦ R(D(K, N), P ‖ K ‖ S)` was uniform per query and the correlation
between the derived key and the `K` inside the input was invisible to a random function. `v0.3`
removed both the correlation and the bullet.)

**Non-redundancy: no conjecture follows from another.** Each row is a *separating construction* —
an object in which the left-hand assumption holds and the right-hand one fails — so the
implication cannot exist in general. They are sketches, not full definitions, which is what a
separation needs to be when the two statements are about different objects:

| If … held | … would it give …? | No: the separating object |
| --- | --- | --- |
| L3.1 (CC is a PRF) | L3.2 (HC is a PRF) | the object is the *same* permutation `P`; `P(x)+x` is a PRF up to the birthday bound and false beyond it, while `trunc(P(y))` is not a PRF at all (a truncated permutation is distinguished by collision counting). §2.1's "why L3.1 and L3.2 are two conjectures" |
| L3.2 | L3.1 | the same pair, read the other way: dropping the feed-forward is not a strengthening |
| L3.3 (keyed compression is a PRF) | L3.4 (the tree preserves it) | keep BLAKE3's compression, change only the *root's input assembly* so that half of the left chaining value is ignored: the compression is still a PRF, but two messages differing in the ignored half have identical roots *deterministically*, and no PRF does that. So L3.3 **alone** does not give L3.4 — but L3.3 + Lemma T does (§2.1): the separated object is precisely one where Lemma T fails, and BLAKE3's own assembly is one where it holds |
| L3.3 | L3.5 (the XOF keeps it past block 1) | keep the compression and the tree, define output block `i ≥ 1` as a constant: the first block is still a PRF and the tree is untouched, while the multi-block output carries no input-dependence at all. Again L3.3 alone does not give it, but with the output counter in the compression input (BLAKE3's own assembly) the blocks are distinct points and §2.1 reduces it |
| L3.3 | L3.6 (the composed tag map is a PRF) — **the row that motivated `v0.3`** | the grep-the-key hash of §2.1: `B3'(k, x) = 0` if `k` occurs in `x`, else `B3(k, x)`. L3.3 holds up to `|x|·2^-256` per query, and for the **key-dependent-input shape** (`K ↦ B3'(K, P ‖ K ‖ S)`) the composed map is the constant zero function. It does *not* reach the `v0.2` map (`B3'(D(K,N), P ‖ K ‖ S)`), where the value keying the hash does not occur in the message; that gap rests on §2.1's reduction-impossibility argument. This is why the two-level tag exists: it removes the key-dependent-input shape rather than assuming the composed map is a PRF |
| any of L3.1–L3.3 | any other | different objects: they are statements about three different primitives, so nothing follows in either direction, and the document cites each only for the layer that uses it |

The converse directions are not claimed and not needed: the document never derives a lower layer
from a higher one. What the table buys is the statement §4.10 makes — the composition adds nothing
of its own — with each of the five shown to be pulling its own weight rather than restating its
neighbour. (Through `v0.2` the sentence read "the composition adds L3.6 and *only* L3.6"; `v0.3`
removed L3.6, and the rows above are kept, marked, because they are the argument for the change.)

---

## 3. What follows

Each theorem names the assumptions it uses. Nothing below is circular, and no step uses a
property of a composed object that was not first established for its parts.

### Theorem 1 (key material is a PRF of the nonce, with a 256-bit subkey bottleneck)

`N ↦ (k_in, k_out, enc_seed)` produces 768 bits, but it is not a 768-bit PRF in the strict
sense: all three values are functions of the single 256-bit `subkey = HC(K, N₁)` and the
96-bit `sn = "XSIV" || N₂`; the 256-bit subkey is the bottleneck. The accurate statement is
that, for any `q` distinct nonces, the `q` triples are jointly
indistinguishable from `q` independent triples of uniform 256-bit strings up to the
subkey-collision term:

```
Adv^{Thm1}(q) ≤ Adv^{A2} + Adv^{A1} + q(q-1)/2^257,
```

The last term is not optional in the strict PRF game: if two nonces have the same `N₂` and
their `N₁` values collide under `HC(K, ·)`, the triples are identical. The collision level of
the triple is therefore `2^128` (a 256-bit subkey birthday), not a 768-bit one; the extra
width is output, not entropy.

*Proof.* Hybrid. (i) Replace `N₁ ↦ HC(K, N₁)` with a uniformly random function `F₁*` (cost
`Adv^{A2}`). For distinct `N₁`, `F₁*` outputs are independent uniform 256-bit values, but they
are not necessarily distinct: for each pair, equality has probability `2^-256`. Let `E` be
the event that some two nonces have equal `N₂` and equal `F₁*` outputs; the union bound is
`q(q-1)/2^257`. Condition on `¬E`. Then the pairs `(subkey, sn)` are distinct: if `N₂` is equal, `¬E` rules out a subkey
collision for distinct `N₁`; if `N₁` is equal, `sn` differs; and the two blocks per nonce use
counters 0 and 1. Apply A1 to the `2q` block queries; they are at
distinct `(subkey, sn, counter)` points, so their outputs are jointly pseudorandom (cost
`Adv^{A1}`, the multi-query advantage for those `2q` block evaluations). The `2q`
blocks give `q` independent uniform 512-bit counter-0/1 pairs, from which
`(k_in, k_out, enc_seed)` are three disjoint 256-bit ranges. On `E`, the bound has already
paid the collision term. ∎

Consequences used below: (a) the values are jointly pseudorandom for a *fixed* key, so nothing is
lost by splitting the counter-0 block into `k_in` and `k_out` instead of deriving them
separately, nor by taking `enc_seed` from the counter-1 block — for an adversary who does not
know the subkey, the three keys are as good as independent; (b) *distinct nonces share the
`subkey` when `N₁` repeats*, and can produce the same triple when `N₁` differs but `N₂`
repeats and the subkey collides; the collision probability over `q` nonces is at most
`q(q-1)/2^257`, and a collision in the two CC blocks is at most `2^-768` per pair, so the
subkey event dominates; (c) **768 bits of output is not 768 bits of entropy, and the
distinction matters here**: the triple is a deterministic function of `(subkey, sn)`, with the
256-bit subkey as the bottleneck, so an adversary who searches *keys* finds two that agree on the whole triple
at a `2^128` subkey birthday over a `2^256` key space — the same order as the tag's own `2^128`
collision bound, **not** a `2^384` event. (An earlier revision of this document claimed
`2^384`; the triple has no more entropy than the subkey, and the codomain width is irrelevant
when the domain is 256 bits.) This is the route into the *attacker-chosen* commitment game
discussed in §4.5, and it is the reason the two-level tag is not, by itself, a commitment
improvement over `v0.2` — see Thm 2's commitment bullet.

### Theorem 2 (the tag has 520-bit output; collision security is 2^128 in the worst case)

For a uniformly random `K`, `(N, A, M) ↦ T` produces 520 bits, but it is not a 520-bit PRF: the
adversary can repeat a nonce, which fixes `k_out` and makes the tag a function of the 256-bit
`X`, so a collision search costs a 256-bit birthday (`2^128`). Across *distinct* nonces the
per-pair tag collision is at most the `k_out`-collision + `X`-collision route (`2^-512`) or the
direct outer collision (`2^-520`), so the repeated-nonce case is the worst one. In the
PRF/collision accounting,

```
Adv^{tag}(q) ≤ Adv^{A2} + Adv^{A1} + 2·Adv^{A3} + q(q-1)/2^257,
```

where `q(q-1)/2^257` is that worst-case (repeated-nonce) upper bound; it is the same
inner-digest collision that appears in Thm 4. The outer 520-bit collision term `q²/2^521` is
dominated by it.

*Proof.* Three hybrids. (i) Replace `N ↦ (k_in, k_out)` with independent uniformly random
functions, so that per distinct nonce the two tag keys are uniform and independent of everything
else. This is the ordinary PRF step — A1/A2 at distinct points, with `k_in` and `k_out` the two
halves of one block, which L1.3's output-splitting covers — and it carries **no key-dependent
input**: the master key is not in either hash message. If `N₁` repeats with different `N₂`, the
subkey is shared and this step is the multi-query A1 statement at distinct `sn` points, not
statistical independence. (ii) With `k_in` uniform and independent of the message,
`X = B3(k_in, DOM_PRE ‖ …)` is a PRF of the public context (A3, with L3.4 for the tree and A4
for the encoding), so `X` may be replaced by a uniformly random function of `(N, A, M)`. This
function is 256-bit. (iii) With `k_out` uniform and `X` a random function of the query,
`T = B3(k_out, DOM_TAG ‖ X)`. Group the queries by nonce: within one nonce `k_out` is fixed, so
an `X` collision gives identical tags (the `q²/2^257` term); across distinct nonces `k_out`
differs, and a tag collision needs either the direct 520-bit outer collision (`2^-520` per
pair) or a `k_out` collision plus an `X` collision (`2^-512` per pair), both dominated by the
repeated-nonce term. The joint statement over repeated `N₁` follows from the same multi-query
A1 step, not from independent keys. ∎ Through `v0.2` step (i) needed L3.6, because the
single-level tag's key and its input were two functions of the one master key; `v0.3`'s
two-level tag removes that, and what remains is the ordinary cascade above plus the
inner-digest collision term.

Consequences. Two different "collision" quantities live here and the numbers differ by 2^264, so
they are stated separately:

* **Collision resistance between two *given* inputs.** For a fixed pair of distinct inputs
  **under the same nonce** (the worst case; different nonces change `k_out`, so the pair is
  bounded by `2^-512 + 2^-520` instead), the two tags agree if the inner 256-bit digest collides
  (`≈2^-256`) or, conditional on distinct digests, if the 520-bit outer outputs collide
  (`2^-520`); the inner-digest event dominates, so the probability is `≈2^-256`, not `2^-520`.
  This is the statement Thm 3 uses. (It is a *target*, not a birthday: the adversary does not get
  to search.)
* **Collision resistance over `q` *chosen* inputs.** Here the tag is not a random 520-bit
  string: with the nonce fixed (the worst case; distinct nonces make `k_out` differ and improve
  the bound), all 65 bytes are functions of BLAKE3's root state — the **256-bit chaining
  value**, the final block, its length, the counter and the flags — so an adversary who holds
  the tail fixed and varies the prefix buys a tag collision for the price of a
  *chaining-value* collision: `q² / 2^257`, i.e. `2^128` at the birthday point, not `2^260`.
  §4.5 carries the argument and §5 its falsifier. This is the number in Thm 4's bound.
* **Commitment to the key.** A tag that is valid under `K₁` is valid under `K₂ ≠ K₁` if the
  second key reproduces the 256-bit `subkey = HC(K₂, N₁)`: that one value fixes `k_in`, `k_out`
  and `enc_seed`, and with them the tag, the derived key pair and the recovered message. So this
  is a *target* problem, not a birthday — and the object to hit is the **subkey, not the 520-bit
  tag**: the attempt succeeds with probability `≈ 2^-256` per candidate key, and enumerating the
  whole `2^256` key space expects `≈ 1` second key — *existence* `P(≥ 1) = 1 − e^-1 ≈ 0.63` — i.e.
  key-search level; a game that requires the adversary to output one key different from `K₁`
  without being given `K₁` wins with `E[N/(1+N)] = e^-1 ≈ 0.368` (an earlier revision quoted `0.63`
  for both). (The
  *pure tag-collision* route — a candidate whose `subkey` misses and whose computation still
  lands on the published `T₁` — is `2^-520` per candidate and is dominated by it. An earlier
  revision of this bullet quoted that one alone, as
  `2^-520` per candidate and `≈ 2^-264` over the key space; §4.5 carries the correction.)
  Neither route is moved by the chaining-value
  correction below, which helps only
  when both sides of a collision are the adversary's to search. (The `T`-coupling makes that
  concrete here: `T` determines the message through the KDF, so a collision found between two
  arbitrary tags is not a ciphertext that opens under two keys — it would have to be a fixed point
  of that coupling as well.) This is the *invisible-salamander* class of attack — one ciphertext
  that opens under two keys — made infeasible **in the target setting, where the adversary attacks
  a ciphertext it is *given***. The literature's commitment games (**CMT-1/CMT-3**) are
  *attacker-chosen*: there the adversary outputs the whole tuple, so there is no fixed tag to hit
  and `2^520` does not describe that game. **Its bound is not derived here** — §4.5, "The two
  commitment games", keeps the two apart and prices the salamander's cheapest known construction
  at the key-search level (`≈ 2^256`): a construction, not a bound. What keeps a *chosen*-key
  search from being cheaper **is not** the width of the derived material, and an earlier revision
  of this document said it was. The route is a search over keys the adversary chooses for two that agree
  on the **whole** derived material (`k_in`, `k_out`, `enc_seed`), which gives equal tags and equal
  keystreams — one ciphertext opening under both, to the *same* plaintext (the bullet below is
  about exactly that qualification). Through `v0.2` the single-level tag defeated that
  route by binding `K` into the hash input: two keys with equal derived material still produced
  *different tags*, at the price of L3.6. The two-level tag does not bind `K`, and deriving three
  values instead of one does **not** compensate, because all three are functions of the single
  256-bit `subkey` (Thm 1, consequence (c)): the route is a `subkey` collision at a `2^128`
  birthday, the same order as the tag's own collision bound — **not** the `2^384` an earlier
  revision claimed.
* **What that route does and does not give, stated precisely**, because an earlier revision of
  this bullet called it "a complete salamander at `2^128`" and that overstates it. Equal derived
  material means equal keystreams, so the two keys decrypt the one ciphertext to the *same*
  plaintext. What falls at `2^128` is therefore **key commitment** — one `(C, T)` valid under two
  distinct keys, complete and immediate — and it is **not** a *salamander* in the literature's
  sense, which requires the two openings to be *different* messages `M₁ ≠ M₂`. That form needs
  `KS₁(T) ≠ KS₂(T)`, hence *different* derived material, which is exactly what this route rules
  out: it forces `KS₁ = KS₂` and therefore `M₁ = M₂`. The different-message form is the completion
  §4.5 already records as circular — `T = tag(K₂, N, A, C ⊕ KS₂(T))` — and its price is the
  **key-search level, `≈ 2^256`, not `2^520`**: the cheapest construction this document can find
  never searches the tag space. Fix `k_out₁ = k_out₂` first (a birthday over ≈`2^128.5` sampled
  keys), then choose the message: for a candidate `M₁`, the first opening
  is satisfied *by construction* — `T = tag(K₁, N, A, M₁)` and `C = M₁ ⊕ KS₁(T)` — and the second
  equation becomes `X(k_in₂, C ⊕ KS₂(T)) = X(k_in₁, M₁)`. Equal tag keys make the second tag
  `G(k_out, X(k_in₂, M₂))`, so equal tags reduce to equal **256-bit inner digests**; each
  candidate hits that with probability `2^-256`, ≈`2^256` candidates find one, and `KS₁ ≠ KS₂`
  generically gives `M₁ ≠ M₂`. An earlier revision of this bullet *searched* the 520-bit tag
  space for the fixed point, `≈ 2^520` — an overestimate by `2^264`, because choosing the message
  chooses the tag: only the digest is searched. It is not a proof that `2^256` is optimal, and
  this document does not claim one; what it establishes is that the salamander's object is the
  same 256-bit digest as every other route here, so the route sits at the key-search level. So
  `v0.2`'s `K`-in-input had closed the
  key-commitment break, `v0.3` reopens it at `2^128`, and the salamander half is not reached at
  `2^128` at all. `2^128` is infeasible today, and the attacker-chosen games are priced by route,
  not by a bound (§4.5), so the *target* commitment — the property this crate actually claims, `≈ 2^-256`
  per candidate key, key-search level — is a different game and is untouched by that break; its
  *object* did move with the same revision (from the 520-bit tag to the `subkey`, as the correction
  at the head of this bullet records), so the trade for removing L3.6 is real and is recorded here
  rather than described as a free structural win. A revision that wanted both would have to break
  the 256-bit `subkey` bottleneck, e.g. by deriving the tag keys from `K` directly rather than
  through `HChaCha20(K, N₁)`.
* **Commitment to the nonce, the AAD and the lengths — not "byte for byte".** An earlier
  revision of this bullet said "Same argument, byte for byte", and that is not true of the
  context components, because the context enters the tag's *hash input* (`X`), not the tag's
  *key*. The two games price it separately:
  * *Target, key-holder — AAD only (key and nonce fixed).* A second AAD `A′` that reproduces
    a given inner digest `X = B3(k_in, DOM_PRE ‖ …)` is a preimage of BLAKE3's 256-bit
    chaining value: `≈ 2^256` per success — **not** `2^-520` per candidate, because the object
    that must be reproduced is `X`, not the 520-bit `T`, and no tag width raises a 256-bit
    preimage. The nonce is **not** covered by this `X`-preimage argument: changing it also
    re-derives `k_in`/`k_out` and changes the bytes hashed into `X`, so a second nonce must
    match the tag itself (see §8.1's nonce note). A length re-split has at most ~`2^128`
    candidates, so it cannot reach a 256-bit preimage at all (`2^-256` per candidate and
    ~`2^128` candidates, so a total of ~`2^-128` — no attack); the length-split *binding*
    itself is §4.4's statement and is unaffected.
  * *Attacker-chosen — CMT-3's AAD half (nonce fixed).* Two AADs the adversary chooses,
    colliding in `X` (`q²/2^257`, a `2^128` birthday), give the **same tag** — and the KDF's
    input is the tag, not the context, so the **same keystream**. One `(C, T)` therefore
    validates under both contexts and decrypts to the **same plaintext**: the completion is
    *immediate*, with no fixed point and no second key. The nonce has to be held fixed here:
    a nonce change moves `k_in`/`k_out` and is itself hashed into `X`, so an `X` collision
    under two nonces does not give equal tags. A subkey collision alone does not complete
    either — the nonce bytes in `X` still differ — which is why §5 row 17(b) says the
    cross-nonce completion fails. So the AAD half of the attacker-chosen game is broken at
    `2^128` exactly as the key half is, with the same identical-plaintext qualification; the
    half that needs two *different* messages is priced by construction at the key-search level
    in §4.5, with no *bound* derived.

### Theorem 3 (per-tag key separation, and keystream binding)

For distinct tags, the derived `(enc_key, enc_nonce)` pairs are jointly pseudorandom; and a
change anywhere in `(K, N, A, M)` changes the tag with probability `1 − O(2^-256)`, hence
changes the keystream entirely.

*Proof.* First replace `(k_in, k_out, enc_seed)` with independent uniform 256-bit values via
Thm 1, including its subkey-collision term; this is needed because A3 is stated for a
uniformly random key and `enc_seed` is only pseudorandom under Thm 1. Then apply A3's
multi-query PRF property at the distinct points `DOM_ENC ‖ T`; Thm 2 supplies the tag
distribution. The fixed-pair statement is `≈2^-256 + 2^-520` **under one nonce** (the worst
case; different nonces make `k_out` differ and give `2^-512`-class instead): the two inputs'
inner digests collide with probability `2^-256`, which dominates the outer 520-bit PRF
collision; the older
`2^-520` figure counted only the latter. It is still not the birthday-level number — an
adversary free to search over many changes gets a collision at `2^128` (§4.5), which is why
that bound, and not this one, appears in Thm 4. ∎

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
Adv^{priv} ≤ 2·Adv^{A1} + Adv^{A2} + 3·Adv^{A3} + q²/2^257
Adv^{auth} ≤ 2·Adv^{A1} + Adv^{A2} + 3·Adv^{A3} + q·2^-256 + q·2^-520 + q²/2^257
```

where `q` bounds the adversary's oracle queries and each `Adv` is the *multi-query* PRF
advantage of the corresponding assumption (each is already defined for a polynomial query
bound). `Adv^{A1}` is the ChaCha20 term, charged **twice** — the key-material block function
(Thm 1, hop 1) and the message keystream (hop 4) — and `Adv^{A2}` is the HChaCha20 term of the
key derivation (Thm 1); the `Adv^{A3}` term is the three A3 applications the scheme makes — the tag's two
keyed-BLAKE3 calls (the inner and outer hashes of Thm 2) and the per-message key derivation —
charged as `3·Adv^{A3}`. There is no L3.6 term: revision `v0.3`'s
two-level tag puts no master key in any hash message, so the tag is an ordinary A3 cascade.
MRAE security is the pair.

The two forgery routes differ, and the larger is the *key guess*: a decryption
query can be computed **offline under a guessed key** `K′`, and it is accepted whenever `K′`'s
256-bit `subkey` is the real one — `≈ 2^-256` per query, the same event as Thm 2's commitment
bullet (§3, §4.5; the `subkey` reproduction is the key-direction assumption A2′) — while the
alternative is a **fresh-tag guess** at `2^-520` (a PRF output hit directly, at a point
determined by the guessed `T` itself). The displayed bound keeps both routes, `q·2^-256` and
`q·2^-520`; the fresh-tag term is dominated and may be omitted. An earlier revision printed
only `q·2^-520` and called it the per-query bound; the key-guess route dominates it. The
**strength**
headline is unaffected: it is the minimum of the two, `min(2^256 key search, 2^520 tag guess) =
2^256`, and the key-guess route is a key search.

An earlier revision of this document wrote `Adv^{A3} + Adv^{L3.6}` in place of `3·Adv^{A3}` and
`q²/2^521` in place of `q²/2^257`. The `q²/2^521` treated the 65-byte tag as 65 independent
random bits, which §4.5 shows it is not; the `Adv^{L3.6}` was the *v0.2* tag's extra assumption,
now removed rather than priced. Both corrections lower nothing that was not already lower: the
`q²/2^257` term is `2^-129` at `q = 2^64`.

*Proof (reduction chain, five hops).*

1. Replace the key derivation with **three** independent random values per nonce — `k_in`,
   `k_out` and `enc_seed` (Thm 1) — not two: hop 3 keys the KDF with `enc_seed`, and A3 needs
   that key uniform, not merely pseudorandom. Nothing observable changes except with the
   stated advantage.
2. Replace the two-level tag function with a uniformly random function (A3, twice: the inner
   hash and the outer, as in Thm 2's cascade). From here, tags are uniform and independent for
   distinct *chaining values* (the tag is a function of the 256-bit state, §4.5); two queries
   collide in the tag with probability `q²/2^257`, the birthday bound of that state, not
   `q²/2^521`.
3. Replace `(enc_key, enc_nonce)` with a uniformly random function of the tag (A3; hop 1
   made `enc_seed` uniform). Tags
   that differ now give independent `(key, nonce)` pairs. A collision in that value is partly
   covered by hop 2 — equal tags give equal pairs by construction — and between *distinct*
   tags it needs a collision in the 328-bit state the KDF's root compression sees (`2^164`,
   §4.5), which is rarer than the tag collision itself, so the bound keeps the one `q²/2^257`
   term. It is *not* the generic `q²/2^353` of a 352-bit output, and it is not a break by
   itself either (it makes two queries share a keystream, which is exactly the event the term
   bounds).
4. Each query's ciphertext is now `M ⊕ KS(k, n)` under a key pair that is *used once*
   across all queries except with the two collision probabilities above. Replace each such
   keystream with an independent uniform string (A1, one query per key): the ciphertexts
   are uniform and independent, with the deterministic exception that a repeated `(N, A,
   M)` query produces a repeated answer — which is exactly what the ideal MRAE scheme does.
5. The two worlds are therefore identical up to the listed terms. For **authenticity**: a
   forgery consists of `(N, A, C, T)` with `T ≠ T(K, N, A, M')` for the recovered `M'` —
   i.e. the adversary must output the value of a PRF at a point it does not get to choose
   directly, since `M'` depends on `T` itself through the KDF. Each decryption query
   succeeds by one of two routes, and the larger is the *key guess*: a query computed
   **offline under a guessed key** `K′` — encrypt a chosen `(N, A, M)` under `K′`, submit the
   tuple — is accepted whenever `K′`'s 256-bit `subkey` is the real one, probability
   `≈ 2^-256` (Thm 2's commitment bullet, §4.5; a tag collision under a wrong key is its
   `2^-520` tail). The pure alternative — no key guess at all — is a **fresh-tag guess**,
   `2^-520`, a PRF output hit directly. So the
   per-query acceptance is at most `2^-256 + 2^-520`, i.e. `q · 2^-256 + q · 2^-520` over `q`
   queries, and the key-guess term dominates. (An earlier revision quoted the `2^-520` route
   alone and called it the per-query bound.) Hitting a tag the oracle already produced is a
   *target* as well, and the chaining-value shortcut of §4.5 does not apply: it makes pairs of
   *searchable* tags collide cheaply, and here the value to hit is fixed by someone else. The
   self-referential dependence `M'(T)` does not help: inverting it is as hard as inverting the
   KDF, and the key is secret; nor does it impede the key guess, which inverts nothing. The
   **strength** is unchanged — `min(2^256 key search, 2^520 tag guess) = 2^256`, and the
   key guess *is* a key search. ∎

*Where each assumption enters:* A1 in the keystream (hop 4) and in the key material (hop 1);
A2 in the subkey (hop 1); A3 in the tag (hop 2, twice — the two-level cascade) and in the
per-message key derivation (hop 3). **A2′** is the key-direction preimage assumption behind the
`q·2^-256` key-guess/commitment term; it is not used by the tag PRF itself. There is no L3.6
hop: the tag's two hashes have no secret in their messages, so hop 2 is the ordinary cascade.
A4 is needed for the *statement* of the game (that the encoded input defines the
query) and is discharged in §4.4.

### Corollary (nonce misuse degrades exactly as SIV does, with one collision-shaped caveat)

If the adversary repeats a nonce, hops 1–3 are unchanged: the per-query tags still determine
independent keystreams (Thm 3), so two *different* `(A, M)` pairs under one nonce are still
encrypted with independent keys. What the adversary learns is:

* whether two `(A, M)` pairs are equal (equal pairs give identical tags, hence identical
  ciphertexts), and
* the message length.

This is the strongest misuse behaviour a deterministic scheme can have, and it is the whole
reason the per-message key is derived from the tag rather than from `(K, N)` alone — a
scheme in which it were derived from `(K, N)` would hand over `M₁ ⊕ M₂` on nonce reuse *by
construction*, and `src/lib.rs`'s `nonce_reuse_does_not_reuse_the_keystream` test exists to
make that failure mode impossible to introduce quietly.

**The caveat, stated rather than implied: `M₁ ⊕ M₂` is still what a tag collision hands over.**
"Degrades to equality" is the statement about what happens *when the tags differ*; it is not a
claim that two-time-pad leakage is impossible. If two distinct `(A, M)` pairs under one nonce
land on the same tag — the `q²/2^257` event of §4.5, and the same one Thm 3 rules out for a
*fixed* pair at `≈2^-256` (the inner-digest collision dominates the outer `2^-520` term) — then the two messages are encrypted under the *same* derived
keystream, and every ciphertext pair satisfies `C₁ ⊕ C₂ = M₁ ⊕ M₂`. An adversary does not even
need to cause the collision: whoever observes both ciphertexts gets the two-time pad, and can
then strip any known plaintext from one message off the other. So the honest statement of
misuse resistance here is: *nonce reuse leaks equality plus, with probability `q²/2^257`, a
two-time pad* — which is negligible for any feasible `q` (`2^-129` at `q = 2^64`), but is a
stronger leak than "equality" alone, and it is why §4.5's collision number matters to the
misuse story and not only to the proof's bookkeeping. A scheme that derived the keystream from
`(K, N)` would hand over the two-time pad *always* under misuse; this one hands it over only
inside an event an attacker cannot reach.

### Lemma (each hybrid preserves determinism — the obligation an MRAE reduction must discharge)

Every hop of Thm 4's chain replaces one object by another, and there is an obligation hiding in
"another" that is easy to miss: the ideal MRAE scheme is *deterministic in `(N, A, M)`* (a
repeated query repeats its answer, which is why equality is the only misuse leak), and the
adversary may repeat a query — including a *nonce*. If any hop replaced its object with
per-query freshness, the hybrid would answer a repeated query differently from the real scheme,
and the comparison would be vacuous for exactly the adversary the misuse claim is about.

The lemma is that no hop does that: after every hop the encryption oracle is still a **function**
of `(N, A, M)`.

* Hop 1 replaces `N₁ ↦ HC(K, N₁)` by a single fixed random function `F*`. A function, not a
  fresh draw: equal `N₁` gives equal subkeys, distinct `N₁` gives independent ones (§3 Thm 1's
  argument uses both halves).
* Hop 2 replaces the tag by `B3(k_N, ·)`, where `k_N` is derived from that fixed `F*`. Equal `N`
  gives equal `k_N`, so the tag remains a function of `(N, A, M)`.
* Hop 3 replaces `(enc_key, enc_nonce)` by a function of the tag, which is itself a function of
  the query.
* Hop 4 replaces each keystream by a uniform string **keyed by the derived pair**, not by the
  query: two queries that reach the same derived pair get the same string, and distinct pairs get
  independent ones. (Keying the replacement by the query instead would be the vacuity the lemma
  exists to rule out, and it would also erase the collision event the bound is counting.)

Determinism is therefore preserved hop by hop, and the *only* behavioural difference the ideal
world has — two distinct queries receiving the same answer — is precisely the collision event
whose probability is the `q²/2^257` term. That is the formal content of the Corollary above, and
it is the reason the bound may be read as "misuse degrades to equality plus a collision term"
rather than as a statement about nonce-respecting adversaries only. ∎

### The acyclicity lemma (encryption is a DAG — while *verification* is deliberately a fixed point)

SIV has an unusual dependency shape, and it is worth isolating because a different shape would
be unbuildable rather than merely weaker:

```
X = B3(k_in,  DOM_PRE || N || |A| || |M| || A || M)             X depends on M
T = B3(k_out, DOM_TAG || X)                                     T depends on X
(enc_key, enc_nonce) = B3(enc_seed, DOM_ENC || T)               the key depends on T
C = M xor KS(enc_key, enc_nonce)                                C depends on M and T
```

*Proof of acyclicity (the encryption direction).* Read the edges: `T -> key -> C`, and
`M -> T`, `M -> C`. There is no edge from `C` or from the derived key back into `T`, so the
graph is a DAG and each value is defined before it is used. ∎

**The *verification* direction is not a DAG, and the difference is load-bearing.** An earlier
revision of this lemma was titled "the construction is a DAG, not a fixed point", which
overclaims in the one direction that matters to the security argument — an auditor reading the
title against Thm 2's commitment bullet (which says a tag collision alone is not a salamander
because it "would have to be a fixed point of that coupling as well") finds the two statements
contradicting each other. They do not, once the directions are separated. A verifier holds
`(C, T *)` and accepts iff

```
T* = F_C(T*),   where  F_C(T) = B3(k_out, DOM_TAG ‖ B3(k_in, … ‖ A ‖ M′(T)))   and
                        M′(T) = C xor KS(B3(enc_seed, DOM_ENC ‖ T))
```

— a fixed-point test, exactly as the commitment argument says. What makes it *usable* rather
than a puzzle is that the fixed point is trivially computable and unique in the only sense the
scheme needs: `F_C(T)` depends on `T` only through the derived key, so a verifier evaluates it
once, in one pass, with no search (`T*` is an input, not an unknown). The DAG property above is
what guarantees *encryption* terminates without equation-solving; the fixed-point shape is what
makes *decryption* single-pass too — and it is also why the decryption entry points decrypt
before they can verify, which is the next bullet.

Two further consequences, both load-bearing:

* **Encryption needs the whole message before it can produce a byte**, because `T` is a
  function of `M` and the keystream is a function of `T`. That is why `encrypt` is two serial
  passes and why its latency does not shrink with more cores (`performance.md`).
* **Decryption must decrypt before it can verify, and cannot be reordered.** The verifier needs
  `T`, `T` needs `M`, and `M` needs the keystream that `T` selects — so the plaintext necessarily
  exists in the buffer before any tag comparison happens. That is a property of the *mode*, not
  of this implementation, and it is the reason the crate wipes the buffer on failure and never
  returns it, and the reason `tests/ctgrind.supp` exists at all: the accept/reject branch is
  unavoidable, so instead of removing it the crate isolates it in one function.

A construction that instead verified a tag *before* decrypting would have to commit to the
ciphertext rather than the plaintext, which is a different mode (and loses the misuse-resistance
argument above, since the tag would no longer bind the message content).

### Multi-key deployments, quantified

Every theorem above is a single-key statement, and the document used to leave the multi-key case
to the reader. It does not need its own analysis — the standard hybrid does it — but the numbers
are worth writing down, because the collision bounds of §4.5 are the ones that move.

Consider `Q` independent keys (one per device is the usual shape), each used for `q` queries, and
an adversary that wins if it breaks *any* of them. A hybrid over the keys — replacing the `i`-th
key's scheme by its ideal counterpart, one key at a time — gives

```
Adv^{priv}_{multi}(Q, q) ≤ Q · Adv^{priv}_{single}(q),      Adv^{auth}_{multi}(Q, q) ≤ Q · Adv^{auth}_{single}(q)
```

so Thm 4's bound gains the factor `Q` on every term, and in particular the collision term becomes
`Q · q²/2^257`. At `Q = 2^32` devices and `q = 2^32` messages each — 2^64 messages in total, well
past any real deployment — that is `2^(32+64-257) = 2^-161`, and the forgery term is dominated
by the key-guess route, `Q·q·2^-256 = 2^-192` (an earlier revision quoted the fresh-tag-guess
route alone, `Q·q·2^-520 = 2^-456`, which is not the leading term): the multi-user loss is not
what a deployment size costs.

Two things do *not* follow that factor, and one that does is worth naming separately:

* **The commitment properties (CMT-1/CMT-3) are per key.** A second key that opens a ciphertext
  is a statement about *that* pair of keys; a break for one key says nothing about another, so `Q`
  does not enter the `≈ 2^-256` target bound at all (it enters as "there are `Q` keys to *try* to
  attack", which is the next point). The `Q` factor below is the per-key union bound the theorems
  carry; the *attacker-chosen* commitment game of §4.5 is a separate obligation named there — its
  salamander route is priced by construction there, and what is not derived is a bound on it.
* **the collision events do not cross keys.** Two tags that collide under *different* keys derive
  *different* keystreams (the KDF is keyed by that key's `enc_seed`), so the two-time-pad event of
  §3's Corollary is per key, and the `Q` factor above is a union bound over independent events,
  not a cross-key collision;
* **multi-target key search does divide the cost.** An adversary who is satisfied with breaking
  *any one* of the `Q` keys — and who has a per-key test, which forgery and the determinism
  property both give — pays `2^256 / Q` instead of `2^256`. That is the standard multi-target
  caveat, it applies to any 256-bit-keyed scheme, and it is the reason the README's table is a
  *per-key* statement: a device fleet of `2^32` should read its key strength as `2^224`, not
  `2^256`.

---

## 4. Composition hazards, and what happens to each

The question "does chaining the assumptions create new problems" has a general answer:
composition is safe when the pieces are used in *disjoint domains*, and unsafe when two
uses of one primitive can collide. Every pair of uses in this construction is enumerated
below. Nothing here is left implicit in the theorems above.

### 4.1 Two ChaCha20 uses at counter 0 — *the one residual, and its number*

`derive_material` burns counter 0 of `(subkey, sn)` for the two tag keys and counter 1 for the
encryption seed; the message keystream is counter 0 of `(enc_key, enc_nonce)`. So the derivation's
counter-0 block and the message keystream are both counter 0, separated by *key* and by *nonce*,
not by counter.

* Is it exploitable? No. For the two keystreams to be equal, `enc_key = subkey` and
  `enc_nonce = sn` must both hold; `(enc_key, enc_nonce)` is a 352-bit KDF output under a
  secret key and `subkey` is an HChaCha20 output under the master key, so the event has
  probability ≈ `2^-352`, and — the part that matters — **it is not computable without `K`**:
  both sides are secret-derived, so an adversary can neither detect it nor cause it. It is a
  statement about two values only the key holder can compute.
* The reason it is worth writing down at all is that it is the only place in the
  construction where a separation rests on a probability rather than on a structural
  disjointness. `src/lib.rs`'s `the_key_material_block_is_not_the_message_keystream` computes
  both keystreams for a spread of inputs and requires them to differ, so the collapse (point the
  message keystream at `subkey` with the derivation's nonce, or otherwise give the two call sites
  the same key and nonce) is a test failure.
* The structural remedy — start the message at a counter the derivation does not use (now
  counter 2, since `v0.3`'s derivation burns 0 and 1) — is **not available**: it changes every
  ciphertext, and the wire format is frozen (see `CHANGELOG.md`). It is recorded here as the one
  thing a future revision could do to convert this paragraph into a disjointness proof. It would
  also shrink the maximum message by two blocks unless the counter arithmetic is re-derived.

### 4.2 The same primitive for two purposes (BLAKE3 twice)

The tag and the per-message key derivation both use keyed BLAKE3, with **different keys**
(the tag's `k_in`/`k_out` vs `enc_seed`, independent by Thm 1) *and* different domain strings
*and* different input layouts. Even in the impossible case two of those keys coincide, the tag
is `B3(k, DOM_PRE ‖ …)` / `B3(k, DOM_TAG ‖ …)` and the key derivation is `B3(k, DOM_ENC ‖ T)`,
so the families remain separated by S1 (their distinct 8-byte prefixes). This is defence in depth: the separation does not depend
on the key derivation being right.

### 4.3 Cross-protocol key reuse (XChaCha20 / XChaCha20-Poly1305)

Standard XChaCha20 leaves the first four bytes of the 12-byte ChaCha20 nonce as zeros when
it extends a 24-byte nonce. If this crate did the same, then for the same `(K, N)` its
subkey would equal XChaCha20's, its two derivation blocks would equal XChaCha20's first two
keystream blocks, and `k_in`/`k_out`/`enc_seed` would coincide with values an XChaCha20
implementation exposes as keystream. The message keystream is *not* automatically shared —
this crate derives `enc_key`/`enc_nonce` from the tag, rather than encrypting under
`subkey` — but the tag keys and derivation blocks would overlap, which is a cross-protocol
hazard even before a tag collision. `SUBKEY_DOMAIN = "XSIV"` occupies those bytes
instead, so the two schedules diverge at the first block. The placement matters as much as
the value: putting the label in the *counter* would not separate this scheme from
XChaCha20-Poly1305, which leaves the counter at 0.
Pinned by `test_subkey_domain_occupies_nonce_not_counter` and
`test_domain_separators_are_pinned`.

This does not make the scheme interoperable with anything — it is *not* a standard, and
`README.md` says so — it makes the two schemes not collide.

### 4.4 Encoding ambiguity

`A ‖ M` alone is ambiguous: `("ab","c")` and `("a","bc")` concatenate identically. The two
`⟨len⟩₆₄` fields remove it, and because every field in the head is fixed width
(`8 + 24 + 8 + 8` — the domain, the nonce, and the two lengths; the key is not in
the encoding), the whole encoding is injective — this is A4, and it is discharged
here rather than assumed:

* the head is a fixed 48-byte layout, so its boundaries do not depend on the data;
* `N` is fixed width; `|A|`, `|M|` are fixed width;
* given the encoding, `|A|` and `|M|` are read off at fixed offsets, so `A` and `M` split
  uniquely;
* hence two different quadruples cannot produce the same byte string. ∎

Trailing zeros are covered by the same argument (`"c"` and `"c\0"` have different `|M|`),
and `test_aad_message_split_is_unambiguous` checks both. BLAKE3 is not length-extendable to
begin with (its finalisation is flagged), but the explicit lengths mean the construction
does not rely on that: even a Merkle–Damgård MAC under this encoding would be unambiguous
*as a function of the encoded input*.

### 4.5 Tag width, and the numbers it does and does not buy

**What was claimed, and why it was wrong.** The rationale used to read: *commitment is a
collision property, so an `n`-bit tag caps it at `2^(n/2)`; 64 bytes gives exactly `2^256`, so
65 bytes gives `2^260`.* Two things are wrong with that. It treats commitment as a birthday
problem, where a commitment attack must hit the tag *it published* and is therefore a target
(see the commitment bullet of Thm 2) — the argument names the wrong property even though its
conclusion, "the tag must be wider than 32 bytes", is right for a different reason, given
below. And it treats the tag's 520 bits as independent, which they are not: the number it
produces, `2^260`, is not the birthday level of anything. That level is where collision
resistance lives, and it is `2^128`. Keyed BLAKE3's XOF output is

```
compress_xof(cv, tail, |tail|, counter, flags | ROOT)
```

— a function of the **256-bit chaining value**, the final block, its length, the counter and the
flags. Two inputs that agree on that state produce *byte-identical* tags, at every output length,
because every output block of the root is a function of the same state. Colliding that state is
`2^128` in the number of hashes computed, and no tag width can raise it: the tag is not 520
independent bits, it is a 256-bit state observed through a 520-bit window.

**This is not a property of this crate's encoding** — it is a property of BLAKE3's XOF, and the
general claim "a 520-bit XOF output gives more than `2^256` collision resistance" is false for
any input shape an adversary can search: two inputs that agree on the final block collide in the
output as soon as their chaining values do, whatever the caller's layout is. The same statement
holds for the derived `(key, nonce)` pair and for any other multi-block output of the same hash.
What the layout controls is only whether the adversary can hold that tail fixed, and here (as in
most encodings) it can.

**The collision is reachable by construction, which is why this matters.** The adversary does not
have to collide the whole input — only the state that enters a block it holds fixed. Take two
messages of equal length that agree on their final block `S`, and vary the bytes before it: the
chaining value entering `S` is a 256-bit value, so a collision in it costs a birthday search over
that state (`2^128` candidates), and the two colliding inputs then have identical
`(cv, tail, |tail|, counter, flags)` — hence identical tags, and therefore identical derived keys
and keystreams: two equal-length messages under that `(key, nonce)` are a two-time pad
(`C₁ ⊕ C₂ = M₁ ⊕ M₂`), since `derive_enc` is a function of the tag alone. The same argument
applies to a multi-chunk input by fixing the subtree that holds the tail and colliding the
prefix subtree's chaining value. This is a *collision* search, not a
preimage: the adversary needs the two tags to agree *with each other*. A tag that must be hit *as
given* — a forged tag, or a ciphertext that must open under a second key — is still a target, but
the object it hangs from is 256-bit: a second key succeeds by reproducing the 256-bit `subkey`,
with probability `≈ 2^-256` per candidate, so a full enumeration of the `2^256`-key space expects
`≈ 1` second key (existence `≈ 0.63`; a one-output game `≈ 0.368`, Thm 2) — key-search level. The *pure tag-collision* route — a
candidate whose `subkey` misses yet whose tag computation still lands on the given tag — is
`2^-520` per candidate and is dominated by it (a tag
*guess* is the `2^520` search; a key search cannot run more trials than there are keys).

**Consequently, the numbers are these, and the pair (target, birthday) is now written out
wherever the distinction matters. All of the classical bounds still carry at least 128 bits of
margin** (the model-dependent BHT row below is the one exception, at ≈`2^85`).

| Event | Bound |
| --- | --- |
| Tag collision, same key and nonce, `q` queries (the worst case) | `q² / 2^257` (≈ `2^128` at the birthday point); distinct nonces improve it to `q²/2^513`-class |
| Derived `(key, nonce)` collision over `q` queries | `q² / 2^257` — see below: the tag term dominates it, and the KDF's own birthday is over a 328-bit state (256-bit chain value plus the 72-bit tail block), not the 352-bit output |
| A tag agreeing with a *given* tag (forgery, second open, commitment **against a given ciphertext**) | the object to hit is 256-bit in every case: forgery is `min(2^256 key search, 2^520 tag guess)`, and a second key reproduces the 256-bit `subkey` at `≈ 2^-256` per candidate — `≈ 1` second key over the key space. The pure tag collision is `2^-520` per candidate and dominated |
| Forgery (one decryption query) | `≈ 2^-256` — a query computed offline under a guessed key, the same 256-bit `subkey` event as the commitment row above — plus the fresh-*tag*-guess route `2^-520`, which it dominates, and the tag-collision terms. **Forgery *strength* is `min(2^256 key search, 2^520 tag guess) = 2^256`** — this row is the per-query acceptance probability, not the strength; §8.1 writes the minimum out |
| **Attacker-chosen commitment game** (CMT-1/CMT-3 as the literature writes them — the adversary *outputs* both keys, both messages and `(C,T)`) | **two of its three routes are priced at `2^128`, both with identical plaintexts**: the *key* route (a `subkey` collision gives equal `k_in`/`k_out`/`enc_seed`) and the *AAD-context* route (an inner-digest collision under a fixed key and nonce gives equal `T`, and the KDF takes `T` rather than the context, so equal keystreams too). Both completions are immediate. A nonce change is **not** this route: it re-derives the keys and is hashed into `X`, so a second nonce must match the tag, and a subkey collision alone does not complete. The **different-message** route — the salamander — is **priced by construction at the key-search level, `≈ 2^256`, with no bound derived**: it needs `KS₁ ≠ KS₂`, so two keys, but the cheapest construction this document can find never searches the tag space — equal `k_out` first (a birthday over ≈`2^128.5` sampled keys), then a chosen-message search for the 256-bit inner-digest equality `X(k_in₂, C ⊕ KS₂(T)) = X(k_in₁, M₁)`, which ≈`2^256` candidates hit. See "The two commitment games" below |
| Exhaustive key search | `2^256` |
| Quantum: Grover on the key | `2^128` |
| Quantum: BHT collision finding on the 256-bit state | ≈`2^85` — model-dependent (it needs large quantum memory), and a property of *any* 256-bit state, SHA-256's collisions included; see the note below |

**The two commitment games, kept apart — and the one priced by construction rather than by a
bound.** Two different games are both called "commitment", and they do not share a number. An
earlier revision of this document put the literature's names (`CMT-1`/`CMT-3`, invisible
salamanders) next to a `2^520` and left the reader to assume the number belonged to the named
game. It does not — and, as the first bullet below now records, `2^520` is not the *target*
game's number either.

* **The *target* game.** The adversary is *given* a ciphertext/tag
  `(C, T)` (a published one, say) and must produce a second key under which that same `(C, T)`
  validates. It has to hit a *fixed* value, so it is a target — but the value is the **256-bit
  `subkey`**, not the 520-bit tag: a second key whose subkey matches reproduces the derived
  material and everything downstream of it, so the event is `≈ 2^-256` per candidate key and the
  whole key space expects `≈ 1` second key (existence `≈ 0.63`; a one-output game `≈ 0.368`) — key-search level. This is the
  number in Thm 2's commitment bullet, in the table above, and in the README's security table.
  What the wide tag prices in this game is only the *pure tag-collision* route (`2^-520` per
  candidate), which the `subkey` route dominates above 256 bits; below 256 bits the tag itself
  becomes the binding object, which is why the width is not free to shrink (§4.10, and Thm 2's
  commitment bullet on the derivation route).
* **The *attacker-chosen* game — this is what the literature's CMT-1/CMT-3 are.** Those games are
  **not** "given a ciphertext": the adversary *outputs the entire tuple* — two keys (or two
  contexts), two messages, and the `(C, T)` — and wins if the one `(C, T)` validates under both.
  There is no fixed value to hit, so a target bound does not describe it, and this document does
  **not** have the single number that covers it. All three of its routes are priced just below:
  two at `2^128` with identical plaintexts, and the third by construction at the key-search
  level; what is missing is a *bound*, not a price.

**Why the two cannot be swapped, in one sentence each.** In the attacker-chosen game the adversary
is free to collect tags for `q` inputs *it chooses* and look for a **collision** among them, which
is `q²/2^257` with birthday point **`2^128`** — the chaining-value birthday of the table's first
row, not a 520-bit target. So the collision route that the target bound does not price is exactly
the route the attacker-chosen game offers, at `2^128`. **What is not derived is a bound on the
completions; each route is priced, and "the rest" is narrower than an earlier revision of this
section said.** The completion depends on which route is being completed, and there are three:

* **Two keys whose derived material agrees** (a `subkey` collision). Tags and keystreams agree,
  so the completion is *immediate*: one `(C, T)` opens under both keys to the *same* plaintext.
* **Two contexts under one key whose inner digests agree.** The tag is the same, and the KDF takes
  the tag rather than the context, so the keystream is the same; the completion is *immediate*
  again — one plaintext under two contexts.
* **Two *different* messages.** This is the only circular-looking case: it needs two keys with
  different keystreams, and then an adversary who knows both keys would set
  `M₂ = M₁ ⊕ KS₁ ⊕ KS₂`, but `KS₂` is derived from `T₂ = T₁` — the shared tag — so the message it
  must exhibit to finish is the message it was trying to choose, making the completion look like a
  fixed point of the tag/keystream coupling. (This is the same `T* = F_C(T*)` shape the acyclicity
  lemma in §3 isolates for the *verifier*, where it is benign because `T*` is an input; here `T*`
  is what the attacker is trying to fix.) The construction below prices it without searching the
  tag space: fix `k_out₁ = k_out₂` first, then *choose* `M₁` — the tag is then
  `T = tag(K₁, N, A, M₁)` by construction, not a value to search — and the coupling collapses to
  a 256-bit inner-digest equality, `X(k_in₂, C ⊕ KS₂(T)) = X(k_in₁, M₁)`, which ≈`2^256`
  candidates satisfy.

Whether that last case blocks the completion, and at what cost, is **answered for the route this
document can construct — it does not block at the key-search level.** Fix `k_out₁ = k_out₂` (a
birthday over ≈`2^128.5` sampled keys), then *choose* the message: `M₁` fixes
`T = tag(K₁, N, A, M₁)` and `C = M₁ ⊕ KS₁(T)`, and the second opening needs
`X(k_in₂, C ⊕ KS₂(T)) = X(k_in₁, M₁)` — a `2^-256` event per candidate, ≈`2^256` candidates for a
hit, and `KS₁ ≠ KS₂` generically gives `M₁ ≠ M₂`. So the
honest statement is: *the target bound is `≈ 2^-256` per candidate key — the `subkey` preimage,
not a tag hit — and is proved under A2′; the attacker-chosen game's key and AAD-context routes
are broken at `2^128`, both with identical plaintexts; its different-message
route is **priced by construction at the key-search level (`≈ 2^256`)**, with no bound derived.*
The `2^128` birthday that starts the construction is the price of one step, not a bound on the
attack, and no claim that `2^256` is optimal is made here. §5 row 17 records the missing bound,
which is where a reader looking for "what would settle it" should go.

**Five consequences, stated plainly.**

* **The width is *not* what sets the target commitment bound — the 256-bit `subkey` is, and an
  earlier revision of this section said otherwise.** A candidate key that is not the real one opens
  a given ciphertext by reproducing the 256-bit `subkey = HC(K′, N₁)` (under A2′; that one value fixes `k_in`,
  `k_out` and `enc_seed`, and with them the derived key pair, the recovered message, the inner
  digest and the tag. So the attempt succeeds with probability `≈ 2^-256`, and enumerating the whole
  `2^256` key space expects **`≈ 1` second key** (existence `≈ 0.63`; a one-output game `≈ 0.368`) — key-search level, the same
  tier as the context route above. The *pure tag-collision* route — a candidate whose `subkey`
  misses and whose tag nonetheless lands on the published one — is `2^-520` per candidate, and
  the `subkey` route dominates it. A 32-byte tag
  would raise the expectation from `≈ 1` to `≈ 2` and change nothing else; it is *not* the
  `2^256 · 2^-256 ≈ 1` non-committing failure the SIV literature is about. So the earlier rationale
  reached the right *decision* — a tag must not be short enough for its own guess route to become
  the binding object, which happens below 256 bits — through a *property* this construction does
  not have: the number to quote is the `subkey` preimage, `≈ 2^-256` per candidate key, not
  `2^-520` per candidate and `≈ 2^-264` over the key space, and not the `2^260` birthday the width
  was once claimed to set.
* **What the width does *not* buy is collision resistance**, which is `2^128` either way, forgery,
  which is `2^256` either way (bounded by key search, which no tag length raises), or the target
  commitment bound above, which is `subkey`-bound. The width is kept because the format is frozen
  at revision `v0.3` *and* because it keeps the pure tag-collision route from ever being the weakest
  link: at 32 bytes that route would sit exactly at the 256-bit level, and at 16 bytes — the
  short-tag SIV family's setting — it would be `2^-128` per candidate and therefore the binding
  object. It would not by
  itself settle the *attacker-chosen* games of the literature, whose bound this document does not
  derive (see "The two commitment games" above) — the width does not govern the game this document
  can price; it prices the route that game would otherwise have to lean on.
* **The KDF's own collision is `2^164`, and it is dominated.** Two *distinct* tags `T₁ ≠ T₂` that
  yield the same derived pair must collide the state the KDF's root sees: the 256-bit chain value
  *and* the 72-bit final block (`T[56:65]` plus padding), so the birthday is over 328 bits —
  `2^164`, not the `2^176` a 352-bit output would suggest and not `2^128` either. It matters
  little, because a *tag* collision implies this one (equal tags ⇒ equal derived pairs) and is
  strictly cheaper at `2^128`, so the bound carries one collision term and the tag's number is
  the right one. What would be wrong is quoting `q²/2^353`: that is the birthday of the output
  size, and the state that produces the output is what constrains it.
* **Confidentiality and forgery are not moved by the correction — `2^256` classically, `2^128`
  under Grover** (the number the 256-bit key design targets). The target key commitment is a
  256-bit `subkey` preimage as well, so Grover also gives `≈2^128` there; claw-finding adds no
  known advantage, but the target is **not** "unaffected". What is *not* 128-bit quantum is
  the collision property: a 256-bit state has a ~`2^85` quantum collision search (BHT), which
  is inherent to the state size — SHA-256's collisions have the same quantum bound — and is one
  more reason not to claim that the tag width buys post-quantum margin. The correction changes
  *bounds*, not a security level anyone could have relied on: `2^128` classical collisions were
  never reachable, and `2^-129` at `q = 2^64` queries was never the obstacle.
* **The one property the correction leaves exactly where it was is the escape from a birthday
  shortcut**: forgery and commitment are target problems, and the chaining-value shortcut of the
  first bullet above applies only when the adversary can search *both* sides. What it bounds is
  the adversary's ability to find *two* colliding tags, which is exactly the `q²/2^257` term in
  Thm 4's bounds and the two-time-pad event of §3's Corollary.

### 4.6 Counter discipline

`MAX_MSG_SIZE = 2^38` is exactly `2^32` blocks — the number of values a `u32` counter has,
with no margin. One block more would wrap the counter *inside a single message* and reuse
keystream from the start of that same message: silent, and catastrophic. The binding is a
`const` assertion in `src/lib.rs` (raising the limit does not compile), a run-time check on
every target including the 32-bit ones where `usize` cannot express the limit, a source
scan of every keystream call site (`tests/counter_range.rs`), and a Kani harness.

### 4.7 Tag truncation

An earlier revision consumed only the first 28 tag bytes in the key derivation, so the last
four bytes of the tag could not affect the ciphertext — the commitment was nominally 256
bits and actually 224 (that revision's tag was 32 bytes; the 65-byte tag arrived with `v0.2`,
and the truncated derivation went with it). `derive_enc` now takes the whole tag, `test_every_tag_byte_reaches_the_ciphertext`
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

The tag and encryption reduction uses A1–A4. The target key-commitment, the attacker-chosen
key route, and Thm 4's key-guess forgery term additionally use **A2′**, the
key-direction collision/preimage assumption of §2; that is a real extra assumption, not a
consequence of A2, and it is listed rather than absorbed into "A1–A4". (Through `v0.2` there was
also L3.6 in §2.1 — a property of the tag layout rather than a step of the composition;
`v0.3`'s two-level tag removed it. A4 is the injectivity of the encoding, discharged in §4.4.)
In
particular, none of the following is assumed: that `k_in` and `k_out` are *separately*
derived (splitting one PRF block is fine, Thm 1); that a nonce is used once (that is the
misuse case, §3 Corollary); that the encryption is randomized (it is deterministic by
design); that the tag is secret (it is public, and Thm 3 does not need it to be).

---

### 4.10 The interaction inventory: why the combination adds no joint assumption of its own

This is the answer to the question "does putting ChaCha20, HChaCha20 and BLAKE3 together in
*this* way create a problem that none of them has alone?". The answer is a proof obligation,
not an opinion, and it has three parts: enumerate every use, enumerate every value that crosses
between uses, and show that each crossing is either a composition the L1 theorems already cover,
a *structural* disjointness, or a bounded-probability event. The enumeration has to be complete,
so the completeness argument is stated last and it is the part that is mechanised (a test).

**The seven uses.** Every cryptographic call **in the construction** is one of these, and the
inventory test (`tests/construction_inventory.rs`) fails if the set changes. There is one further
cryptographic call in the non-test source that is *not* part of the construction — the unkeyed
BLAKE3 hash behind `locked`'s key-integrity tag — and it is inventoried by the same test and
argued separately below; the sentence here is scoped to the construction because that is what
§4.10's case analysis is about.

| # | Call | Key | Input | Output | Consumed next by |
| --- | --- | --- | --- | --- | --- |
| U1 | `hchacha20` | `K` | `N₁` (16 B) | `subkey` (32 B) | U2 |
| U2 | `chacha20_keystream_raw`, counter 0 | `subkey` | `"XSIV" ‖ N₂` | `k_in ‖ k_out` (64 B) | U3a, U3b |
| U2′ | `chacha20_keystream_raw`, counter 1 | `subkey` | `"XSIV" ‖ N₂` | `enc_seed` (32 B) | U4 |
| U3a | `blake3_keyed_multi` (inner tag hash) | `k_in = U2[0:32]` | `"XSIV-PRE" ‖ N ‖ len ‖ A ‖ M` | `X` (32 B) | U3b |
| U3b | `blake3_keyed_multi` (outer tag hash) | `k_out = U2[32:64]` | `"XSIV-TAG" ‖ X` | `T` (65 B) | U4, and the wire |
| U4 | `blake3_keyed_xof` | `enc_seed = U2′[0:32]` | `"XSIV-ENC" ‖ T` | `enc_key`, `enc_nonce` | U5 |
| U5 | `chacha20_keystream` | `enc_key` | `enc_nonce`, counters 0… | keystream | XOR with `M` |

A *use* is not a call site, and the inventory test counts the latter because that is the
stronger signal: U3a appears as three call sites (the contiguous shape, the three-part shape
and the fallback taken when the allocator refuses the contiguous buffer), all hashing the same
bytes — the shapes are pinned to each other by `test_both_tag_call_shapes_hash_the_same_bytes`
— while U3b and `blake3_keyed_xof`'s single site are one each. The count in
`tests/construction_inventory.rs` therefore moves when a *site* moves, and §4.10's argument
below is about the uses.

**The values that cross.** `subkey` (U1→U2/U2′), `k_in ‖ k_out` (U2→{U3a,U3b}) and `enc_seed`
(U2′→U4), `X` (U3a→U3b), `T` (U3b→U4, and U3b→the wire), and the pair `enc_key`, `enc_nonce`
(U4→U5). Nothing else is passed between the calls, and that is a statement about the code which
the inventory test pins. So the case analysis below is over a finite, known set: no crossing can
be missed by construction.

**The one call outside the construction.** `locked::integrity_tag` calls unkeyed BLAKE3
(`blake3::Hasher::new`, not `blake3::hash` — the explicit hasher is used so its state can be
zeroized)
on the 32-byte key, to store an 8-byte tag beside it in the locked page (`src/lib.rs`, and §8.2's
Rowhammer row). It is inventoried by the same test (so a change to it fails there too), and it is
*not* in the table above because it is not part of the construction's composition: it is unkeyed
(no master key is involved), its input is the key itself rather than anything an adversary
controls, its output is compared and discarded (nothing is derived from it), and it relates no
two primitives. It is not "a second use of BLAKE3" in the sense §4.2 is about, so it adds no
assumption to the tree and no row to the pairwise table.

**Pairwise separation.** For each pair of uses that could in principle share a key, an input
point, or an output, the table says what keeps them apart and what kind of argument that is.

| Pair | Could they collide? | Separation | Kind |
| --- | --- | --- | --- |
| U1, U2/U2′ | no | `subkey` is U1's output and U2/U2′'s key: this is XChaCha20's own structure | composition, L3.2 then L3.1 |
| U2, U2′ | no | same key, same nonce, **different counter** (0 vs 1): distinct points of the block function, so distinct blocks under A1 | structural (counter) + L3.1 |
| U2/U2′ vs U5 | yes, probability `2^-352` | U2 (counter 0 under `subkey`) and U5 (counter 0 under `enc_key`) are both ChaCha20 at counter 0; separated by key *and* nonce, not by counter (§4.1). The event needs `enc_key = subkey` **and** `enc_nonce = "XSIV"‖N₂`, both secret-derived, so no one without `K` can compute or detect it | **bounded event, requires K** |
| U3a, U3b | no | different keys (`k_in` vs `k_out`, jointly pseudorandom by Thm 1) **and** input strings that differ in their first 8 bytes (`DOM_PRE` vs `DOM_TAG`) | structural (prefix) + Thm 1 |
| U3a, U4 | no | different keys and disjoint input spaces (`DOM_PRE` vs `DOM_ENC`) | structural (prefix) + Thm 1 |
| U3b, U4 | no | different keys (`k_out` vs `enc_seed`) and disjoint input spaces (`DOM_TAG` vs `DOM_ENC`) | structural (prefix) + Thm 1 |
| U4, U5 | not a collision but a *composition* | U4's output **is** U5's key; nothing is reused | by construction |
| U3b, U5 | no | `T` is public and U5's key is not derived from it in any invertible way: U5's key is `B3(enc_seed, DOM_ENC‖T)`, a PRF value under an unknown key | L3.3 |
| U1, U3a/U3b/U4/U5 | no | `subkey` never leaves U2/U2′ | structural |
| U3b, U3b (across two messages, same nonce) | yes, `q²/2^257` | tag collisions (§4.5) — the SIV term, not a composition term; the birthday is over the 256-bit chain value, not over the 520-bit output, and a collision here is also the two-time-pad event of §3's Corollary | L1.1 term |
| U4, U4 (two distinct tags, same nonce) | yes, `q²/2^257` | dominated by the tag collision above: two *distinct* tags collide in the derived pair only through the KDF's own 328-bit state (`2^164`), and a tag collision implies this event, so the tag's `2^128` is the binding number — not the generic `q²/2^353` of the 352-bit output | L1.2/L1.3 term |

**Two structural lemmas worth stating on their own**, because both are proved by inspection and
neither depends on a primitive being strong:

*Lemma S1 (the three BLAKE3 input spaces are disjoint).* U3a's input begins with
`DOM_PRE = "XSIV-PRE"`, U3b's with `DOM_TAG = "XSIV-TAG"` and U4's with `DOM_ENC = "XSIV-ENC"`;
all are 8 bytes and pairwise distinct, so no byte string is the input to two of them. Even in the
impossible case two of the keys coincide — `k_in`, `k_out` and `enc_seed` come from two ChaCha20
blocks, so a `2^-256`-class event — the BLAKE3 families remain separated by *input space* rather
than by key. ∎

*Lemma S2 (no cross-scheme keystream reuse with XChaCha20-Poly1305).* For the same `(K, N)`,
HChaCha20 gives both schemes the *same* subkey (both use `HC(K, N₁)` with the same `N₁`), so the
separation has to come from the second half of the nonce. XChaCha20-Poly1305's first data block
is `CC(subkey, 0⁴ ‖ N₂, 0)`; this crate's counter-0 key-material block is `CC(subkey, "XSIV" ‖ N₂, 0)`.
The two nonces differ in four fixed bytes, so these are evaluations of ChaCha20 at **different
points of its domain** — a structural separation, not a probabilistic one. This is why the label
sits in the *nonce* rather than the counter, and why it is a fixpoint of the format (§4.3). ∎ (The
counter-1 block `CC(subkey, "XSIV" ‖ N₂, 1)` is a third point, distinct from both by the counter.)

**Completeness.** The case analysis is exhaustive because (i) the seven uses are all the
cryptographic calls in the construction — mechanically checked — and (ii) the set of values that
flow between them is exactly the ones listed, so any interaction is a pair in the table above.
There is no interaction that the table does not cover, and the table's rows are each discharged
by one of: an L1 theorem, a lemma proved in §3, an inspection-level structural fact, or a
probability bound.

**Therefore the combination introduces no joint assumption of its own.** (A2′ is a direction of
one primitive, not a joint assumption about two.) Every joint use is covered by
the L1 reductions, which need the primitives only with *independent keys*; the keys are derived
and their independence is a theorem (Thm 1) rather than a hope; and the one place where two uses
share a point of a primitive's domain (the counter-0 uses U2/U5) needs the master key even to
detect. Nothing in this construction requires a joint assumption about ChaCha20 and BLAKE3 — no
"these two are unrelated" conjecture, no "this key is safe to use in both" conjecture.

**The one assumption the *encoding* added, and its removal in `v0.3`.** Through revision `v0.2`
the tag's input contained `K` as well as being keyed by `K`'s derivation. That was a property of
the chosen layout, not of BLAKE3, and so it was one further thing to assume on top of L3.1–L3.5 —
the sixth conjecture, L3.6, stated in §2.1 with its separation and its falsifier. It was
deliberately *not* counted as a composition hazard, because it was a statement inside a single
primitive (no ChaCha20 object and no BLAKE3 object were related by it), which is why the sentence
above read "no assumption that relates the two primitives" rather than "no assumption at all".
Revision `v0.3` removes the conjunct: the two-level tag puts no `K` in any hash message, so there
is no longer an encoding-introduced assumption, and the sentence above is now the stronger "no
assumption of its own" in the plain sense. That removal is **not free**, and an earlier revision
of this paragraph described it as one. The route the old layout closed — a chosen-key search for
two keys with equal derived material, which gives one ciphertext opening under both — is closed by
`v0.2`'s `K`-in-input step and is *not* closed by the two-level tag: for a fixed nonce, all three
derived values are functions of the single 256-bit `subkey`, so the route costs a `2^128` subkey birthday, not the
`2^384` an earlier revision claimed (Thm 1 consequence (c), Thm 2's commitment bullet). The
derivation does stay a standard cascade rather than a key-dependent-input step, which is the
L3.6 removal; the commitment trade is the price, recorded rather than glossed.

**What this does *not* prove, stated plainly.** It does not prove that ChaCha20 and BLAKE3 are
secure, and it cannot rule out a future cryptanalytic relation between them: if someone found a
relation that made this cascade break, that would be a break of L3.3 (the keyed BLAKE3 PRF
assumption) or of L3.1/L3.2, not a flaw in the composition — but the distinction would matter to
a user, so it is written here rather than left to be inferred. "No unknown problem" is not a
theorem anyone can prove about any construction; what is proven here is the weaker and precise
statement that *the composition adds no conjunct of its own*. In `v0.3` that is a literal
statement — there is no seventh assumption and no sixth — where through `v0.2` it came with the
L3.6 caveat this paragraph used to carry.

## 5. Falsification programme

A security claim that cannot say what would refute it is not a claim. Each row states the
refutation, and the status of the attempt.

| # | Claim | What would refute it | Status |
| --- | --- | --- | --- |
| 1 | A1, A2, A3 (PRF security of the primitives) | A distinguisher for ChaCha20 / HChaCha20 / keyed BLAKE3 | **Not attempted, and not attemptable by test**: these are open problems in cryptanalysis. The evidence is the primitives' standing, their published test vectors (replayed here), and the fact that the construction's use of them is standard. Which primitive holds which property, and what each break would cost, is written out for readers in `README.md`'s "Security level" ("On the primitives") — including that the two are ARX relatives rather than independent bets |
| 2 | Tag is a PRF over `(N,A,M)` | Two distinct `(N,A,M)` with equal tags under one key | A *fixed* pair is out of reach (`2^-256`, the inner chain-value target); *searching* for a pair is the chain-value birthday, `q²/2^257` (§4.5), also out of reach. *Structural* variants tested: length ambiguity, A/M swap, trailing zeros, single-byte changes in A and M, key and nonce reaching the tag. Not testable: both numbers are bounds on computation |
| 3 | Key commitment **against a given ciphertext** (the target game) | A `(C,T)` that opens under two keys | Against a given `(C,T)` this is a target and stays out of reach — but the object to hit is the 256-bit `subkey`, not the tag: `≈ 2^-256` per candidate key, `≈ 1` second key over the whole key space, key-search level, and not a bound the width sets (§4.5). The *birthday* level for a colliding pair is `2^128` (§4.5), which an invisible-salamander attack against a fixed ciphertext cannot use. *Mechanism* tested: both derived tag keys reach the tag (`test_tag_binds_both_derived_keys`) and Kani proves the inner head's domain/length fields and the outer input are what the spec says (the symbolic harnesses do not vary the nonce; the concrete the `tag_matches_the_model_with_*` harnesses rebuilds the head with it and compares all 65 bytes). **The literature's CMT-1/CMT-3 games are attacker-chosen, not this target; their bound is not derived here** — see the row below and §4.5, "The two commitment games" |
| 4 | Keystream is tag-dependent | `ct₁ ⊕ ct₂ = M₁ ⊕ M₂` under one nonce, or `ct` invariant under an AAD change | **Tested**: `nonce_reuse_does_not_reuse_the_keystream` (message change, AAD change, first-block check, attached and in-place paths) |
| 5 | The two ChaCha20 uses are separate | The key-material block equals the message keystream | **Tested**: `the_key_material_block_is_not_the_message_keystream` (16 trials, key, nonce and keystream compared); the residual is §4.1 |
| 6 | The KDF consumes the whole tag | A tag byte that does not move the derived key | **Proved + tested**: Kani (all 65 bytes consumed), `test_every_tag_byte_reaches_the_ciphertext` |
| 7 | The encoding is unambiguous | Two quadruples with the same encoding | **Proved by inspection** (§4.4) + `test_aad_message_split_is_unambiguous` |
| 8 | The counter cannot wrap inside a message | A message length above the bound that still encrypts | `const` assertion (build failure), `tests/counter_range.rs`, Kani |
| 9 | Nonce reuse leaks only equality | Two distinct `(A,M)` under one nonce with the same tag or keystream | Tested at the keystream level (#4); the tag collision that would *additionally* give `C₁ ⊕ C₂ = M₁ ⊕ M₂` is a `2^128` search (§4.5, §3 Corollary), so that half is a bound rather than a test |
| 10 | Cross-scheme separation | Keystream agreement with XChaCha20-Poly1305 for one `(K,N)` | Tested at the derivation level: the label is in the nonce, not the counter (`test_subkey_domain_occupies_nonce_not_counter`) |
| 11 | The implementation matches the design | A divergence between `src/lib.rs` and the specification above | Differential testing against an independent Python reference, published KATs (RFC 8439, the XChaCha draft, BLAKE3's official keyed vectors), the independent implementation in `src/witness.rs` under `ultra`, and the Kani layout harnesses |
| 12 | An adversary cannot get unverified plaintext | A decryption failure that returns bytes, or that returns them for a moment the caller can observe | `tests/security.rs`, the wipe contracts, and `tools/fi_check.sh`'s `wipe-skipped` row |
| 13 | **The combination needs no joint assumption of its own** (§4.10; A2′ is a key-direction assumption on one primitive, not a joint one) | An unlisted call site of a primitive (the inventory covers the seven construction uses *and* the one standalone unkeyed hash), or two listed uses sharing a key/domain/point in a way the table does not list | **Mechanised**: `tests/construction_inventory.rs` counts the cryptographic call sites in the non-test source and fails if the set changes, and pins the two structural lemmas (S1: the three BLAKE3 input spaces are disjoint by their 8-byte prefixes; S2: this crate's counter-0 key-material block is at a different ChaCha20 point than XChaCha20-Poly1305's first data block, for the same key and nonce) |
| 14 | U2/U5 share counter 0 (§4.1) | The key-material block equals the message keystream for one `(K,N,M)` | **Tested** for a spread of inputs (`the_key_material_block_is_not_the_message_keystream`); a real collision needs the master key to compute, so it is a probability statement (`≈2^-352`) rather than an attack |
| 15 | **L3.6** [REMOVED in `v0.3`]: the tag was a PRF in the master key even though the master key was also in the tag's input (§2.1) | Through `v0.2`: a distinguisher for `K ↦ B3(D(K), … ‖ K ‖ …)` that is not a distinguisher for `x ↦ B3(k, x)` at a fixed input | **No longer a claim.** The two-level tag has no hash message containing `K`, so there is nothing to refute; the row records the removal rather than an attempt. (The `v0.2` evidence was: not attemptable by test — a statement about a primitive's internal structure — supported by BLAKE3's design, a separation showing the black-box reduction cannot exist, and the fact that every `H(k ‖ m)`-shaped MAC rests on the same assumption. `v0.3` removed the assumption instead of arguing it.) |
| 16 | The tag-collision birthday is `2^128`, not `2^260` (§4.5) | An argument that some state other than the 256-bit chain value binds the tag; or a collision search cheaper than `2^128` | **Derived here, not tested**: it is a bound on computation. What the harnesses do pin is the premise — that the tag is exactly the root XOF of the encoded input — through the published keyed-BLAKE3 KATs, the differential reference implementation, and `src/witness.rs` under `ultra` |
| 17 | **Commitment in the attacker-chosen games (CMT-1/CMT-3)** — the adversary outputs both keys (or contexts), both messages and `(C,T)` and wins if one `(C,T)` opens under both (§4.5) | A worked-out attack in that game, or a completed derivation of its probability | **Two of its three routes are priced as same-plaintext breaks at `2^128`; the third is priced by construction at the key-search level, with no bound derived.** (a) *Key route*: a `subkey` collision at `2^128` gives two keys with identical derived material, hence identical tags *and keystreams*; the two decryptions are byte-identical (Thm 2's commitment bullet). Closed in `v0.2` by the `K`-in-input step, **not** closed by the two-level tag — the honest record of that trade. (b) *Context route*: two chosen contexts (a different AAD, with the key, nonce and message held fixed — a nonce change moves `k_in`/`k_out` *and* `enc_seed`, so equal inner digests would not even give equal tags or keystreams: the cross-key search is still a `2^128` birthday, it just does not complete; a subkey collision alone also does not complete, because `N₁` is hashed into `X` and the tag inputs differ even when the derived keys agree) whose inner digests `X` collide at `2^128` give the same tag, and the KDF takes the tag rather than the context, so the same keystream follows; one `(C,T)` validates under both contexts with the same plaintext and no fixed point (Thm 2's context bullet). (c) *Different-message route* — the salamander: needs two keys with `KS₁ ≠ KS₂`. The cheapest construction this document can find never searches the tag space: fix `k_out₁ = k_out₂` (a birthday over ≈`2^128.5` sampled keys), *choose* `M₁` so the first opening is satisfied by construction (`T = tag(K₁, N, A, M₁)`, `C = M₁ ⊕ KS₁(T)`), then search for a second opening whose 256-bit inner digest agrees, `X(k_in₂, C ⊕ KS₂(T)) = X(k_in₁, M₁)` — ≈`2^256` candidates — which generically gives `M₁ ≠ M₂`; the price is the key-search level, `≈ 2^256`, not `2^520`, and it is a construction, not a bound. The target bound (`≈ 2^-256` per candidate key, the `subkey` preimage) does not describe any of the three. A proof (or a break) of (c) would settle what is left: the route is priced, the bound is not; `2^128` is infeasible, and the *target* game is untouched |

Rows 1, 16 and 17 are the honest boundary: **no test in this repository, and none that could be
written, falsifies or establishes them.** Row 1 is the standing bet that every
symmetric scheme makes; row 16 is a bound derived by hand, and the
tests around it check the premises of the derivation rather than the number; row 17 is not a bound
at all — it is the place this document prices the route by construction but *declines* to put a
bound on it, and says so. (Row 15, the
`v0.2` `K`-in-input assumption L3.6, is marked removed above: `v0.3`'s two-level tag no longer
takes that step, so it is no longer part of the boundary. Row 17 now has all three routes priced:
a `subkey` collision at `2^128` breaks the *key* route completely and an
inner-digest collision between two chosen contexts breaks the *context* route equally completely,
both with the two openings sharing a plaintext, while the *different-message* route (the
salamander proper) is priced by construction at the key-search level — fix `k_out₁ = k_out₂`,
choose `M₁`, search ≈`2^256` candidates for the 256-bit inner-digest equality — with no optimality
claim; that distinction is recorded there and
in §4.5, and an earlier revision of this sentence called the whole row "a complete completion",
which it is not.)

### 5.1 The falsification procedures: what an attacker runs, and what it costs

The table above says what would refute each claim; this says *how* someone would go about
refuting it, so that "out of reach" is a number attached to an algorithm rather than a feeling.
Per-attempt costs are in primitive calls (one HChaCha20, the two ChaCha20 blocks of the
derivation — counter 0 for the two tag keys and counter 1 for `enc_seed` — and the two BLAKE3
hashes for the tag), and the numbers are work, not wall-clock.

| Target | Procedure | Per attempt | Where it dies |
| --- | --- | --- | --- |
| **Confidentiality** (fresh nonce, no plaintext oracle) | guess the key: for each `K′ ∈ {0,1}^256`, recompute the tag of one known `(N, A, M)` and compare; on a hit, decrypt everything | ≈ 4 calls (HC, the derivation's counter-0 block, and the two tag hashes) | `2^256` attempts; `2^256/Q` for an attacker satisfied with any of `Q` devices (§3, multi-key) |
| **Forgery** | submit `(N, A, C, T)` guesses to the decryption oracle, or search the key space and then forge *legitimately* | 1 verify (oracle) or ≈ 4 calls (key search) | `≈ 2^-256` acceptance per query — the tuple can be computed *offline under a guessed key* `K′`, and is accepted when `K′`'s 256-bit `subkey` is the real one — with the blind fresh-*tag* guess at `2^-520` (the tag is a PRF of `(N,A,M)`, Thm 2) dominated, or `2^256` key search. Note the per-query route needs the key: a guess is accepted with probability `≈ 2^-256`, and the oracle is what tells the attacker whether the guess was the key |
| **Key commitment** (a second key that opens a *given* ciphertext) | for each candidate `K′`: derive the material from `subkey = HC(K′, N₁)`, decrypt `C` under the tag-derived key pair, recompute the tag over the recovered `M′`, compare with `T` | ≈ 7 calls (HC, both derivation blocks, the KDF, and the two tag hashes), plus the candidate's keystream and re-hash, which are per byte | under A2′, the chance that any one candidate works is `≈ 2^-256`: it has to reproduce the 256-bit `subkey`, which the derivation makes sufficient (the direct `2^-520` tag hit is dominated by it), so the whole `2^256` key space expects `≈ 1` second key — existence `≈ 0.63`, a one-output game `≈ 0.368`, key-search level, not a `2^-264` event. **A 32-byte tag would raise that to `≈ 2`**: the width is not what sets this (§4.5) |
| **Tag collision** (the two-time-pad event of §3's Corollary) | *with the key*: fix `N`, `A`, the lengths and the final block; vary the prefix; hash until two prefixes collide in the 256-bit chaining value. *Without the key*: wait for the birthday event in the traffic | 1 hash per candidate (with the key); zero (without) | `2^128` by birthday. The keyless variant is the one to fear, because at the moment it happens the two-time pad costs the observer *nothing* |
| **The context route to a non-committing ciphertext** (attacker-chosen game, CMT-3's context half) | fix one key, nonce and message; choose two AADs and search for an inner-digest collision `B3(k_in, DOM_PRE ‖ N ‖ le64|A₁| ‖ … ) = B3(k_in, … A₂ …)` (the nonce must be held fixed: a nonce change moves `k_in`/`k_out` *and* `enc_seed`, so equal inner digests would not give equal tags or keystreams and the completion fails — the cross-key digests themselves are still a `2^128` birthday) | 1 inner hash per candidate; the birthday over the 256-bit digest is `2^128` | the tag is `B3(k_out, DOM_TAG ‖ X)`, so equal `X` gives equal `T`; the KDF's input is the tag, not the context, so `(enc_key, enc_nonce)` — and the keystream — are equal too. One `(C,T)` therefore validates under both contexts with the same plaintext: an immediate completion at a `2^128` birthday, no fixed point. It is the *attacker-chosen* game, so the *target* commitment is untouched; the same 256-bit digest is why the *key-holder* target is `≈ 2^256` rather than `2^520` |
| **The derivation route to a non-committing ciphertext** (attacker-chosen game, the key half) | choose `K₁ ≠ K₂` and search for two keys whose derived material agrees — `(k_in, k_out, enc_seed)`, all functions of the 256-bit `subkey = HC(K, N₁)` | 1 HC + 2 CC per candidate key | the triple is a function of the 256-bit `subkey`, so two agreeing keys are a `subkey` **collision at a `2^128` birthday**, and it gives equal tags *and* equal keystreams — one ciphertext opening under both. Through `v0.2` this route was **closed by `K` in the tag input** (equal material still gave different tags); `v0.3`'s two-level tag does **not** close it (Thm 2's commitment bullet, §4.10). It is `2^128` — infeasible — and it is the *attacker-chosen* game, so the *target* commitment (`≈ 2^-256` per candidate key, the `subkey` preimage) is unaffected |
| **Encoding and parsing** (length ambiguity, `A`/`M` re-split, trailing zeros, a tag byte that does not reach the ciphertext) | the differential suite's byte-position scans, the KATs, the Kani layout harnesses | — | §4.4 proves injectivity; §7 names the harnesses; §4.7 records the one member of this class that *was* real (a 28-byte tag truncation) |
| **The implementation** (a divergence from the specification, a secret-dependent branch, a skipped wipe) | `tools/ref_impl.py` differential, `src/witness.rs` under `ultra`, ctgrind, the fault campaign, Kani | — | §7 and `tests/README.md` |

### 5.2 What we cannot run, and in what order the argument would fall

Four programmes are out of reach here, and it is worth naming what each would take down, so the
weight of the claims is visible:

1. **A full-round distinguisher for ChaCha20, HChaCha20 or keyed BLAKE3.** Kills L3.1/L3.2/L3.3 and
   with them every claim in this document. Published cryptanalysis reaches 7–8 of ChaCha20's 20
   rounds and reduced-round BLAKE2/BLAKE3 only; a full-round result would be a major one.
2. **A concrete distinguisher for the *two-level* tag cascade.** Through `v0.2` this item was the
   L3.6 gap: the single-level tag's hash key `D(K, N)` and its message both depended on the master
   `K`, so no black-box reduction from L3.3 was available (this rests on §2.1's
   reduction-impossibility argument; the separation there covers the equal-secret
   key-dependent-input shape, which the `v0.2` map did not literally have). `v0.3` removed that
   construction, so the tag is now an ordinary
   A3 cascade and the only thing that would refute it is a break of A3 (item 1). What remains
   worth naming is narrower: a distinguisher that separates the *cascade* `B3(k_out, DOM ‖ B3(k_in,
   …))` from a random function while leaving `x ↦ B3(k, x)` a PRF — i.e. a failure of the cascade
   lemma for BLAKE3 specifically. That would be a structural property of keyed BLAKE3 the
   assumption list does not name, and none is known.
3. **A collision attack on BLAKE3's 256-bit chaining value cheaper than `2^128`, that can be
   mounted with the final block held fixed.** Kills the collision bound, and with it the
   nonce-reuse story (the two-time pad stops being negligible) — this is the most attractive
   target for a practical attacker, because `2^128` is the smallest *classical* number in
   §4.5's table (the quantum BHT row is smaller but model-dependent).
4. **Anything that makes the target preimages cheap** — structure in BLAKE3's key-versus-message
   separation that a 520-bit tag *target* search could exploit, or the same in HChaCha20 for the
   256-bit `subkey`, which is what actually sets the key-commitment bound (§4.5). This is the
   inversion question rather than the
   unpredictability one: it would say the tag map is *invertible* where the assumption list says
   only that it is *unpredictable*. (Through `v0.2` this item was paired with L3.6, which said the
   composed map was unpredictable; `v0.3` removed the composed map, so the pair is now A3 against
   its inversion, which is the ordinary PRF-versus-preimage distinction — plus **A2′** in the
   key direction, which is the tighter of the two and the one the target commitment row rests
   on.)

Everything else in this document has been attacked with the tools that exist here, and the
record shows the programme is not vacuous: three implementation defects were found and fixed by
exactly this kind of reading (the 28-byte tag truncation, the `madvise` argument count, the
missing `MADV_DODUMP`), one *claim* was falsified and corrected (the `2^260` collision bound,
§4.5), and one assumption was added to the list as a result of an audit rather than being found
missing later (L3.6, §2.1).

---

## 6. Residual risk, in one place

* **Cryptanalytic risk.** The construction is exactly as strong as ChaCha20, HChaCha20 and
  BLAKE3. A break in any of them breaks this; a break in BLAKE3's *keyed* mode is the most
  exposed of the three, because that mode's PRF claim is a design argument rather than an
  inherited proof. **If keyed BLAKE3 fails as a PRF, everything that depends on the tag fails
  together** — forgery resistance, both commitment properties, and the per-tag key separation
  that makes nonce reuse survivable — since all of them are statements about `(N, A, M) ↦ T`.
  What does *not* depend on it is the keystream primitive itself (`C = M ⊕ KS(enc_key, …)` is the
  A1/A3 part), which is why the blow-up is "all tag-derived properties" rather than "the scheme is
  an XOR cipher". There is no partial failure here: the tag is one object. (Through `v0.2` this
  entry named **L3.6** — a *stronger* statement than the PRF assumption alone, introduced by
  putting `K` in the tag's input — as an additional part of the exposure. `v0.3`'s two-level tag
  removed it, so the exposure is now exactly A3, with no encoding-introduced conjunct on top.)
* **Collision properties are 128-bit, not 260-bit, and that is a corrected bound rather than a
  new weakness.** The tag's 65 bytes are a view of a 256-bit chain value (§4.5), so a tag
  collision costs a `2^128` birthday search and the two-time-pad leak of §3's Corollary rides
  on the same event; `q²/2^257` is `2^-129` at `q = 2^64`. Forgery and commitment-against-a-given
  tag are target problems and remain where they were — `≈ 2^-256` per candidate key for
  commitment (the `subkey` preimage), `2^256` for forgery — because commitment was never a
  birthday property; and the width does *not* govern the commitment one (§4.5). An earlier
  revision of this document and of `README.md` advertised `2^260`; that number was wrong, the
  mechanism is written out in §4.5, and the falsifier is row 16 of §5.
* **The counter-0 coincidence** (§4.1): probability `≈ 2^-352`, not computable without the
  key, not exploitable. A future revision could remove it structurally at the cost of the
  wire format.
* **Determinism and length** (§3 Corollary): equal `(K,N,A,M)` ⇒ equal ciphertext forever,
  and the ciphertext length equals the message length. Both are properties of the mode, not
  defects, and both are documented in `README.md`.
* **Stack residue, and the limit of what `scrub_stack` proves.** The crate wipes every
  key-bearing local it can *name*. Before the every-build scrub, four things it cannot
  reach were measured to survive in the call-chain stack: the **whole 32-byte `k_in`** — a derived *key*, left by the
  dependency's by-value temporaries rather than in a frame this crate can name, and the
  largest survivor — the `blake3` dependency's XOF
  output buffer (16 of the 44 bytes of `enc_key ‖ enc_nonce`; a frame this crate does not own),
  `k_out` under the `pure` Rust-backend build (~16 of 32 bytes there, against 4 of 32 on the
  default build), and the
  *return temporaries* of functions
  that return an aggregate by value (which is why `derive_material`/`derive_enc` write through
  caller slices). Every build now calls `scrub_stack` after the last derivation, which
  overwrites the derivation region; that is why the stack scans report clean — but it is a
  **frame-layout heuristic, not a proof**: it is best-effort, compiler-dependent, and covers
  the region the scrubber's own 16 KiB frame happens to reach, not the caller's frames above
  it or values the compiler kept in registers. `README.md`
  ("What this crate cannot fix for you") carries the measurements, and `tools/stack_residue.sh`
  re-runs them from the public construction and now scans the master key, `locked`'s tag,
  and `k_in`/`k_out`/`enc_seed`/`enc_key`/`enc_nonce`; the reference host reports clean.
  A register or a value outside the tool's 1 MiB window remains outside that measurement,
  so the scrub is still a frame-layout heuristic rather than a proof. This is in the
  residual list because it is best-effort and compiler-dependent, not because a known
  derived value survives.
* **Beyond the model.** Side channels, fault injection, a debugger, cold boot, a hostile
  hypervisor: out of scope here and covered where they belong.
* **What "no unknown problem" can and cannot mean.** A break of this construction must be a
  break of L3.1–L3.5 (irreducibly L3.1–L3.3, §2.1) or of an L1 composition theorem; §4.10 proves that the *combination* adds
  no conjunct of its own. Through `v0.2` the encoding added one further conjunct (L3.6, the
  `K`-in-input step); `v0.3`'s two-level tag removed it, so the sentence is now stronger. But a
  proof that no unknown cryptanalytic relation exists between ChaCha20 and BLAKE3 is not something
  any document can supply — such a relation, if found, would present itself as a break of one of
  those primitive conjectures. The distinction is worth stating because the two failures would
  look identical from the outside and have different fixes: a composition flaw is this crate's to
  fix, a primitive break is not.
* **Not claimed:** that this is a standard, that it has been cryptanalysed by anyone else, or that
  the tag width makes forgery harder than `2^256` — it does not, because forgery is bounded by the
  key: key search dominates whatever the tag length is, and a 32-byte tag would be guessed at
  exactly the key-search level. Nor does the width raise the *collision* level: 65 bytes and 32
  bytes both collide at `2^128`, because both are functions of the same 256-bit chaining value
  (§4.5). What the width does *not* buy is the target commitment either: a second key that opens
  a *given* ciphertext costs the same at 65 bytes and at 32 — the `subkey` preimage, key-search
  level — because both attacks bottom out on the same 256-bit intermediates. What the width keeps
  is that its own route never becomes the cheapest one: at 32 bytes the pure tag collision would sit
  exactly at that 256-bit level, and at 16 it would be the binding object. So the width stays
  because the wire format is frozen and because below 256 bits the tag takes over as the thing to
  hit — not because the target bound depends on it.

**The strongest true sentence about this construction.** It is worth writing the whole audit's
conclusion as one paragraph, because it is easy to read the rest as more than it is:

> Given the three irreducible primitive conjectures of §2.1 — L3.1, L3.2 and L3.3, with L3.4/L3.5
> reduced to L3.3 there and A4 proved by inspection — plus **A2′** for the key-direction
> commitment statements, the scheme is a secure MRAE/DAE authenticated encryption: its
> confidentiality and authenticity follow from those conjectures by the reductions in §3, its
> collision-limited properties sit at `2^128`, its target key and AAD commitments at `2^256`
> (nonce-only is stronger: a second nonce requires tag/derived-key agreement, at most `2^-320`, not the AAD `X`-preimage route), and the
> composition adds no assumption beyond A2′ (§2.3, §4.10); the reduction's hybrid chain is valid
> under nonce repetition as well as under nonce uniqueness (§3's lemma).

There is *no* proof of security in the standard model, and there cannot be one: the three
irreducible conjectures are statements about the infeasibility of computation on primitives nobody
has proven anything about, and a document that claimed otherwise would be wrong for a reason no
amount of internal consistency can repair. What the document establishes is the other half — that
the *construction* is not where the risk is: every risk is one of three named conjectures, each with
a falsifier, and all three are about single primitives rather than about this scheme.

---

## 7. Where each claim is enforced, so it cannot quietly change

| Claim | Enforcement |
| --- | --- |
| The tag's exact input layout, and that every field reaches the hash | Kani (`tag_is_keyed_hash_of_the_whole_context`, `every_aad_and_message_byte_reaches_the_tag`, `tag_changes_when_the_key_changes`) for the domain, key and both lengths; the **nonce** is not varied by those symbolic harnesses, but the concrete comparison the `tag_matches_the_model_with_*` harnesses rebuilds the head with it and compares all 65 tag bytes, so it is pinned there too (and by `test_tag_matches_blake3_over_the_documented_input`). The contiguous one-part hash shape (2 KiB–64 KiB) is reached by no harness, so it rests on `test_tag_matches_blake3_over_the_documented_input` (the shape equivalence is pinned by `test_both_tag_call_shapes_hash_the_same_bytes`) |
| Every one of the 65 tag bytes is consumed | Kani (`derive_enc_reads_every_tag_byte`), `test_every_tag_byte_reaches_the_ciphertext` |
| The counter never wraps | the `const` assertion in `src/lib.rs` and the constant-arithmetic Kani harnesses `max_msg_size_fits_in_the_block_counter` / `max_msg_size_boundary_matches_counter_capacity`, plus the run-time arithmetic in `tests/counter_range.rs`. (`chacha20_counter_sequencing_is_exact` pins per-block *sequencing* at a concrete `start = 7`, not the wrap boundary.) |
| Domains are distinct, fixed width, and correctly placed | `test_domain_separators_are_pinned`, `test_subkey_domain_occupies_nonce_not_counter` |
| The AAD and the message are separately bound | `test_aad_message_split_is_unambiguous`, `test_tag_covers_every_aad_and_message_byte` |
| Nonce reuse cannot reuse a keystream | `nonce_reuse_does_not_reuse_the_keystream` |
| The two ChaCha20 uses are separate | `the_key_material_block_is_not_the_message_keystream` |
| The set of primitive uses, and the separations between them | `tests/construction_inventory.rs` |
| The premise of the §4.5 bound — the tag is exactly the root XOF of the encoded input, with no extra step that could add entropy | `test_tag_matches_blake3_over_the_documented_input`, the published keyed-BLAKE3 KATs, `src/witness.rs` under `ultra`, and the Kani layout harnesses (the three-part inner shape; the contiguous shape is not reached) |
| The two-level tag's layout — no hash message contains `K`, and both derived tag keys reach the tag | `derive_tag`'s doc comment in `src/lib.rs`, `test_tag_binds_both_derived_keys`, `test_tag_matches_blake3_over_the_documented_input`, §2.1 (the removal of L3.6), §4.10's closing paragraph |
| The design on the wire is the design in the paper | The differential fixtures, the published KATs, and `src/witness.rs` under `ultra` |
| The properties here are not silently weakened by a code change | The source-shape tests in `tests/decision_scope.rs`, `tests/variable_latency.rs`, `tests/counter_range.rs` |

The pattern is deliberate: where a property cannot be proven, it is tested; where it cannot
be tested, it is measured; and where it can be neither, it is written down with its number,
here and in `README.md`.

---

## 8. Attack classes, resistance per configuration, and what mounting one costs

The three configurations — `opt-out` (`--no-default-features`), `hardened` (the default) and
`ultra` — are one wire format and three fault models. That single sentence settles most of this
section: **against cryptanalysis all three are the same object**, because the same construction
and the same primitives are compiled, with the same bounds; what differs is what happens when the
*machine* misbehaves or when an adversary can observe it. So each row below either says "identical
in the three, bounded in §3/§4.5" or names the layer that differs. Numbers are not repeated here
where they have a home: the fault-model figures are the README's fault table, the collision and
target bounds are §4.5's, and each harness named in the last column is described in
`tests/README.md`.

### 8.1 Cryptanalytic and design-level classes — identical in all three configurations

| Class | What it attacks here | Status |
| --- | --- | --- |
| Differential (incl. truncated, impossible, boomerang, rectangle, higher-order) | ChaCha20's 20 rounds, HChaCha20, BLAKE3's compression and tree | **Out of reach**: published results reach 7–8 of 20 ChaCha rounds and reduced-round BLAKE2/BLAKE3. A full-round distinguisher falsifies L3.1–L3.3 and takes everything with it (§5.2, item 1) |
| Linear (incl. linear hull, zero-correlation, multidimensional) | same | out of reach; same falsifier |
| Rotational / rotational-XOR | the ARX structure itself | out of reach at full rounds — the per-round constants and the tree's counters/flags are what break the symmetry |
| Integral / division-property / cube | ChaCha20, BLAKE3 | out of reach at full rounds |
| Algebraic / SAT / Gröbner | same | no practical result; the systems are far beyond solvable sizes |
| Slide / invariant-subspace | round self-similarity | the same constants and flags make rounds non-identical; no attack |
| Meet-in-the-middle / dissection | key recovery | no published full-round decomposition is known, and there is no key schedule to split: every derived key is a PRF output, so the generic *single-target* cost is `2^256`. A classical time-memory trade-off does not lower that for one target; with `Q` independent targets, an attacker satisfied with any one pays `2^256/Q` total (per-target work stays `2^256`), so `2^128` work appears with `2^128` targets — it does not lower the single-target strength |
| Related-key | key schedule | **not applicable**: the construction is keyed by one uniformly random 256-bit key, and the per-message keys are PRF outputs of distinct nonces (Thm 1). No key class is exposed |
| Length extension | Merkle–Damgård padding | **not applicable**: BLAKE3 finalises with a flag, and the encoding carries explicit `|A|`/`|M|` (§4.4). Its real descendants — re-splitting `A ‖ M`, trailing zeros — are defeated by A4 and pinned by `test_aad_message_split_is_unambiguous` |
| Collision (incl. Joux multicollisions, herding) | the tag | `2^128` by birthday over the 256-bit chain value in the worst case (a repeated nonce), via the fixed-tail procedure of §4.5; distinct nonces improve it (`2^-512`-class per pair). No tag width raises it |
| Commitment **against a given ciphertext** (the target game) | a ciphertext that opens under two keys, with the ciphertext *given* | **`≈ 2^-256` per candidate key under A2′** — the candidate has to reproduce the 256-bit `subkey = HC(K′, N₁)`, which fixes the tag, the derived key pair and the recovered message alike, so enumerating the whole key space expects **`≈ 1` second key** (existence `≈ 0.63`; a one-output game `≈ 0.368`): a target, not a birthday, at key-search level. It is *not* `2^-520` per candidate / `≈ 2^-264` over the space — that is the *pure tag-collision* route, which the `subkey` route dominates — and it is not key recovery either: a `subkey` has no unique preimage — the real key is one, and a sweep of the key space expects **one more** — so in expectation the sweep finds as many second keys as real ones, which is what makes this a second opening rather than a recovery. The wide tag does **not** set this (Thm 2, §4.5) |
| Commitment in the **attacker-chosen** games — the **key-commitment** half (one `(C,T)` valid under two keys) | a ciphertext the *adversary* chooses, opening under two keys it also chooses | **`2^128`** — a `subkey` collision (all three derived values are functions of the 256-bit `subkey`) gives two keys with identical material, tags *and* keystreams, so both keys decrypt to the **same plaintext** and the completion is immediate. This was closed in `v0.2` by `K`-in-input and is **not** closed by the two-level tag: the honest record of that trade. §4.5, "The two commitment games", and §5 row 17 |
| Commitment to the **context**, AAD only (key and nonce fixed) | a ciphertext that opens under a second AAD, with the ciphertext *given* (key-holder) or chosen | **`≈ 2^256` target / `2^128` attacker-chosen**, and the 65-byte width does not set either: the AAD enters the tag's hash input `X`, so a second AAD reproducing a given `X` is a preimage of BLAKE3's 256-bit chaining value, and two *chosen* AADs collide in `X` at a `2^128` birthday — after which the tag, the KDF output and the keystream are all equal, so the completion is immediate and the plaintext is the same. A length re-split has too few candidates to reach a 256-bit preimage. §4.5, Thm 2's context bullet, §5 rows 3 and 17. **Nonce-only is not this row:** a nonce change re-derives the keys and is hashed into `X`. For a given `(C,T)`, a second nonce is bounded by the `k_out`-collision + `X`-collision route, `2^-512` per nonce, hence ≤`2^-320` over the 2^192 nonce space (the direct 520-bit tag match is `2^-328`); if the game additionally requires the same plaintext, the simple `subkey`+`X` route is ≤`2^-384` with `N₂` fixed. A subkey collision alone does not complete because the nonce bytes in `X` differ. The 2^256 figure is the AAD route, not a nonce-only bound |

| Commitment in the **attacker-chosen** games — the **salamander** route (one `(C,T)` opening to two *different* messages) | the same, but the two openings must differ: `M₁ ≠ M₂` | **priced by construction at the key-search level, `≈ 2^256` — no bound derived, and not reached by the `2^128` same-plaintext route**: identical derived material forces `KS₁ = KS₂` and hence `M₁ = M₂`, so two messages need a construction that does not search the tag space — fix `k_out₁ = k_out₂` (a birthday over ≈`2^128.5` sampled keys), choose `M₁` (which fixes `T = tag(K₁, N, A, M₁)` and `C`), and search ≈`2^256` candidates for a second opening that collides in the 256-bit inner digest; `KS₁ ≠ KS₂` generically gives `M₁ ≠ M₂`. §4.5, Thm 2's commitment bullet |
| Forgery (tag guess, second preimage) | the tag | `min(2^256 key search, 2^520 tag guess)` = the key search; the fault-assisted variants are §8.2's subject |
| Two-time pad | a tag collision between two messages | the same `2^128` event; when it happens the observer pays nothing (§3's Corollary) |
| Nonce misuse (related nonce, IV reuse) | SIV's misuse model | **by design**: reuse degrades to equality plus the collision term above; a keystream derived from `(K, N)` alone would leak `M₁ ⊕ M₂` always (`nonce_reuse_does_not_reuse_the_keystream`) |
| Quantum: Grover (key) | key search | `2^128` (§4.5) |
| Quantum: BHT (collisions) | the 256-bit state | ≈`2^85`, model-dependent (§4.5) |
| Quantum: Grover/claw-finding (target commitment) | the 256-bit `subkey` preimage | Grover `≈2^128` (the same bound as key search); claw-finding adds no known advantage. It is not "unaffected", and no BHT-style improvement applies to this target |

### 8.2 Implementation and physical classes — this is where the configurations differ

| Class | `opt-out` | `hardened` | `ultra` | Evidence |
| --- | --- | --- | --- | --- |
| Timing: branch on a secret | defended in the AEAD path — constant-time by construction, with no secret-dependent branch apart from the documented decision there; `locked`'s `check_integrity` fail-stop branches on a key-derived tag but is never taken under no-fault operation and is outside the code ctgrind runs (no `LockedKey` in `tests/ctgrind.rs`) | defended; more constant-time work | defended | ctgrind in three configurations, `tests/variable_latency.rs`, the timing screens (advisory in CI, strict under `verify.sh --deep`) |
| Timing: secret-dependent index or memory access | defended — no tables and no secret-dependent index by construction (ARX, no lookup tables) | same | same | the structural argument (no table in the source) and `tools/cache_profile.sh --trace` (identical address traces for two keys, both phases); memcheck does not report an address derived from a poisoned byte, so this is not ctgrind's evidence |
| Cache-timing (Prime+Probe, Flush+Reload, Evict+Time) | defended — no tables, no secret-dependent indices | same | same | `tools/cache_profile.sh` (instruction counts invariant for two keys, and identical address traces in `--trace` mode, both phases) |
| Microarchitectural / speculative (Spectre family, port contention, execution-unit timing) | not defended | not defended | not defended — **and the crate contributes no gadget** | Two statements, kept apart because they are different claims. (i) *Here*: the constant-time discipline leaves no secret-dependent index or memory access, and the AEAD path's one secret-dependent branch (the decision) has a **public** outcome, so speculating past it reveals what the caller learns anyway — as does `locked`'s integrity fail-stop, which fires only on detected corruption — there is no `if (secret_index < len) { table[secret_index] }` shape to build a gadget from (the ARX structural argument, and `cache_profile.sh`'s trace mode). Software measures for gadgets — index masking (`array_index_nospec`), `lfence`/`csdb` barriers, LLVM's Speculative Load Hardening — exist and are the right answer *for code that has a gadget*; adding a barrier here would serialize a comparison whose result is already public. (ii) *Elsewhere*: no library can bound the CPU's speculation in other code, nor the non-speculative microarchitectural channels (port contention, and the Hertzbleed-class power/frequency channel that constant-time code does not address at all) |
| Power / EM (SPA, DPA, CPA, templates) | not defended | not defended | not defended, **but partly by construction — and the exception is narrower than this row first said** | needs proximity and equipment, and software algorithms for it exist — §8.5 names them (masking, hiding, fresh re-keying, leakage-resilient designs) with the model each is proven in. Fresh re-keying (Medwed–Standaert) is *already the shape of this construction* for the **payload cipher**: `enc_key`/`enc_nonce` are derived from the tag, so they are per message, and traces of the XOR pass cannot be averaged across messages (the same nonce *and* message replays one trace; a different message is a different key). **That argument does not extend to the other BLAKE3 uses, and the exception is nonce reuse.** The derived tag keys `k_in`/`k_out` and `enc_seed` are functions of `(K, N)` alone (Thm 1) — they must be, or the tag would not be deterministic in `(K, N, A, M)` — so `q` messages under one nonce hand the attacker `q` traces of **the tag passes and the enc-KDF under fixed keys with varying, attacker-chosen input**: exactly the setup CPA/DPA averages. The surface grows with the number of messages under a reused nonce, and for the tag pass it grows with the *message length*, since the tag hashes the whole message under `k_in`. Under a nonce-respecting deployment every key but the master key is per message, and the residual is the per-nonce derivation (HChaCha20 plus two ChaCha20 blocks, ~2 blocks, under `K`) — which is what this row claimed for *all* cases, and was wrong. Three consequences: for DPA, nonce reuse is worse than the "leak of equality" the misuse story describes; a nonce collision between two messages does the same thing, so the README's low-entropy-nonce warning covers this class too; and the exposure is **inherent to the frozen format** — a revision could re-key the tag's inner key *from the message* (`T = B3(k_out, DOM_TAG ‖ B3(k_in, A ‖ M))` is still deterministic in the quadruple) and remove it, at the price of changing every tag, which is a revision decision rather than a cleanup. No leakage assessment has been run, so this is a structural argument, not a measurement |
| Single fault, decision *value* | **not defended** — accepting sites exist | defended: two gates, separate branches, fail-closed | defended | README fault table; `tools/fi_check.sh` rows per configuration |
| Single fault, decision *instruction* (skip or corrupt a byte/bit) | **not defended** (4 accepting in the bit model, inside the decision) | 0 | 0 | `tools/fi_instruction.sh`, both models |
| Fault that rewrites the stored tag | not defended | not defended | **defended** (`dual-mac`: a second derivation through the shared `derive_tag` path compared against both values) | `dual-mac-blocks-tag-substitution` row |
| Fault in the *shared derivation* (tag, keyed BLAKE3, SIMD) | not defended | not defended | **detected** by the second implementation — with a stated boundary: both decrypt paths and the allocating `encrypt`; the in-place encrypt carries no cross-check | README "What the witness is"; `tests/ultra.rs`'s source-shape test |
| Two independent faults, synchronized glitch, laser injection | not defended | not defended | not defended | software redundancy (which `ultra` has twice over — the second gate and the `dual-mac` recomputation — but *diversity* only once, in the witness, since both of those recompute through the same `derive_tag`/BLAKE3/SIMD path) cannot cover a fault that hits both computations or the arithmetic beneath them. Software algorithms in this class do exist — infective computation, randomised scheduling, tamper-resilient encodings, key ratcheting with destructive read-out (§8.5) — and each is proven only in a *model* (bounded faults, unknown location); an attacker with precise, repeated faults defeats any of them, and validation needs a fault bench. Not claimed here |
| Fault-assisted key recovery (DFA) | not defended | not defended | not defended, **with a reduced payoff by construction** | same software caveats as above, plus a structural fact worth stating: classic DFA recovers *long-lived* round keys, and nothing in this construction is long-lived beyond the master key. Every intermediate an attacker could recover by faulting the payload path — `enc_key`/`enc_nonce` and the tag — is **per message** (Thm 3, which covers what is derived from the tag), so it decrypts exactly that message and nothing else. (`k_in`/`k_out`/`enc_seed` are **not** in that list: they are functions of `(K, N)` alone — Thm 1, per *nonce* — as the power row above says, so under nonce reuse they are shared across the messages of that nonce. They sit on the per-nonce derivation's surface, not the per-message one.) The honest DFA targets are the per-nonce derivation (`HChaCha20(K, N₁)`, two ChaCha20 blocks) and the tag passes, where the master key is in use. Faulting those is faulting `ultra`'s *witness* territory and is §8.2's row above |
| Combined fault + side channel | not defended | not defended | not defended | the composition of two out-of-scope models |
| Rowhammer-class hardware faults | not defended | not defended | **detected in the stored key**: `LockedKey` keeps an *unkeyed* 8-byte BLAKE3 tag beside the key and verifies it (constant time) on every use, so a flip **in the key or in its 8-byte tag** panics at first use instead of decrypting with a key that is not the caller's (+42 ns per use, measured). The tag is unkeyed on purpose — a check against *malfunction*, not a MAC, and an attacker who can read the page already has the key, so keying it buys nothing. Boundaries, stated because an earlier version of this row said "a flipped key page": it does not stop the flips (ECC or TRR does); it does **not** cover a flip outside the key-and-tag region, which is never read (asserted: `a_corrupted_locked_page_is_detected_on_use` case (c)); and it does not cover a fault that rewrites the tag to match a changed key |
| Swap exposure of a key | not defended | not defended | `locked`: `mlock` on the `LockedKey` page. (Not hibernation: `mlock` pins a page against swap, but neither it nor `MADV_DONTDUMP` keeps the page out of a suspend-to-disk image.) | `tests/locked.rs`, read back from the kernel's `VmLck` |
| **`fork` after a key is loaded** | not defended | not defended | **not defended, and now disclosed**: the child gets a copy-on-write copy which it can read (and the integrity tag with it), its own `VmLck` is 0 so the copy is swappable after a COW split or once the parent drops its key, while `MADV_DONTDUMP` and the dumpable flag *are* inherited (so `deny_debugging` still helps, but a dump exclusion is not a lock). `execve` resets dumpable. A forking service should load keys after the fork or re-`mlock` in the child; an incremental review measured the rows of that table (child reads the plaintext, child `VmLck` = 0, child's page swaps after one COW write) and this row is the disclosure it asked for | `src/lib.rs`'s `LockedKey` docs, README's boundary list |
| Core dumps | not defended | not defended | `locked`: `MADV_DONTDUMP`, and `MADV_DODUMP` restores inclusion on unlock | the `VmFlags` test |
| Cold boot / memory remanence | not defended | not defended | not defended | memory encryption at rest, or a key that never exists in the host's RAM (an HSM). The *userspace software* attempt exists — TRESOR and its descendants keep the key in CPU debug registers so it is never in DRAM — and it does not hold on a general-purpose OS: a debug register is readable by any tracer and the kernel may clobber it at a context switch, so it needs kernel cooperation to be sound. The window can be narrowed (wipe early, lock, refuse debugging) and is not closed |
| Debugger, ptrace, `/proc/<pid>/mem` | not defended | not defended | **opt-in defence**: `locked::deny_debugging()` sets `PR_SET_DUMPABLE = 0`, after which the kernel refuses `PTRACE_MODE_ATTACH` and `/proc/<pid>/mem` even for the same user without `CAP_SYS_PTRACE`. Not automatic — it is process-wide policy that also removes core dumps — and root (or `CAP_SYS_PTRACE`, or a hypervisor) is unaffected | `deny_debugging_is_enforced_by_the_kernel_and_reversible` reads the flag back from the kernel and asserts it; it opens `/proc/self/mem` too, but does **not** assert the refusal (procfs behaviour differs across kernels and container configurations), so only the flag check is evidence |
| Wipe optimised away by the compiler | mitigated (volatile stores) | same | same | `zeroize_slice`, Miri tests |
| UB / miscompilation | mitigated | mitigated | mitigated, **and** a divergence between the two implementations is caught — though a systematic miscompile hits both | Miri under two aliasing models, Kani |
| Dependency supply chain | pinned lockfile, `cargo-deny`, Dependabot | same | same | CI + Deep workflow |

### 8.3 What mounting each one costs

Two scales, because one number cannot describe both a birthday search and a voltage glitch:
**work** is compute or cryptanalytic effort; **access** is what the attacker must physically or
administratively have.

| Class | Work | Access / equipment |
| --- | --- | --- |
| Full-round differential, linear, rotational, integral | research-grade — nobody has done it | none, but it is an open problem |
| Key search (`2^256`, `2^256/Q` multi-target) | large-scale compute | none |
| Collision (`2^128` hashes, fixed-tail procedure) | beyond any existing compute | none |
| Commitment break (`≈ 2^-256` per candidate key — `≈ 1` second key over the whole key space, key-search level) | out of reach | none |
| Tag guess (`2^520` tries) | out of reach | a decryption oracle |
| Nonce reuse | **free** — it is a protocol bug | none |
| Replay / reordering / reflection | **free** | network position |
| Equality oracle (deterministic encryption) | **free** for a guesser | a repeated nonce in the protocol |
| Length-disclosure | **free** | network position (unavoidable for a length-preserving AEAD) |
| Timing / cache side channel | low *if a leak exists* — none is present in the code | co-residency, or a shared machine |
| Power / EM | thousands to millions of traces for ARX | proximity plus ≈ 10 k€ of equipment |
| Single voltage or clock glitch | low | physical access plus a few hundred dollars of hardware |
| Laser or EM fault injection | high | a laboratory |
| Debugger / process memory | trivial with privileges — **unless** the process called `locked::deny_debugging()`, after which `ptrace` and `/proc/<pid>/mem` need root or `CAP_SYS_PTRACE` | root or `ptrace`, or a kernel-level vantage point |
| Cold boot | minutes | physical access and cooling |
| Rowhammer | medium | specific DRAM and co-residency |
| Supply chain (unpinned dependencies or actions) | low | —, and mitigated here (pinned SHAs, lockfile, `cargo-deny`) |

### 8.4 Reading the two tables together

**The configurations are not a cryptanalytic choice.** Every row of §8.1 is identical in all
three; choosing `ultra` does not make a differential attack harder, and choosing `opt-out` does
not make one easier. What the configurations buy is in §8.2, and it is narrow on purpose: the
integrity of the *decision* and of the *shared derivation* against single faults, and the
residency of a caller-managed key against swap and core dumps. Everything else in §8.2 —
power, EM, laser, cold boot, debuggers, speculative execution — is outside what any of the three
attempts, and no configuration setting will change that; those are answered by hardware and
deployment, which is why they are listed in README's "What is not defended against" rather than
in a feature table.

**The cheapest attacks in §8.3 are all in the protocol layer**, and none of them is affected by
any configuration: a repeated nonce (free), a replay (free), an equality oracle for a guesser
(free), a length leak (free). The one that can be catastrophic rather than merely leaky — a tag
collision turning a repeated nonce into a two-time pad — costs `2^128` and is out of reach. So
the deployment decision that matters most is not `opt-out` versus `ultra`; it is whether the
protocol manages nonces, freshness and lengths, which is why those four rows point at
`README.md`'s "What this crate cannot fix for you" and at `SECURITY.md`'s out-of-scope list.

**Which of these could a configuration actually be made to answer?** Asked directly, because the
table's "not defended" is not the same statement as "unanswerable in software". Taking the rows
that no configuration currently covers:

* **Debugger / ptrace** — *done*, above: `PR_SET_DUMPABLE` is the kernel's own enforcement and a
  library can ask for it. It is opt-in because it is process policy.
* **Speculative execution** — *partly structural already*: this crate has no secret-dependent
  index or memory access, so it presents no known Spectre-v1 gadget; the AEAD path's one
  secret-dependent branch (the decision) has a public outcome, and `locked`'s integrity fail-stop
  is never taken under no-fault operation. What remains is not this crate's to fix (the CPU's
  speculation, the OS's mitigations, other code in the process), so a barrier added here would be
  theatre.
* **Power / EM** — *software mitigations exist and are not claimed*: masking with fresh
  randomness is the known answer, at 10–100x cost, with the compiler free to undo it, and with a
  claim whose falsification needs a leakage-assessment lab (§8.5 — the earlier revision of this
  bullet said "unfalsifiable", which was wrong: TVLA and ISO 17825 exist, this repository just
  has no hardware to run them on). The one mitigation that *is* here needs no lab to see: the
  per-tag key derivation is fresh re-keying, so **payload** traces cannot be averaged — with the
  nonce-reuse exception §8.2's row now spells out, where the tag pass and the enc-KDF run under
  fixed per-nonce keys and *are* averageable.
* **Multiple / laser faults, DFA** — *bounded by hardware*: software redundancy (which `ultra`
  already has twice over) cannot cover a fault that hits both computations or the arithmetic
  beneath them. A validated fault bench and hardware countermeasures are the only answers, and
  neither exists in this repository.
* **Cold boot, Rowhammer, a hypervisor, root** — *not software at all*: memory encryption, ECC
  or TRR, and isolation respectively. A crate can shrink the window (wipe early, lock pages,
  refuse to be debugged) and cannot close it.

### 8.5 The software algorithms that do exist for these, and why they are not in this crate

"It cannot be done in software" is the wrong sentence, and this section is the correction. Every
class in §8.2 has *algorithms*, most of them with proofs and a validation methodology; what none
of them has is a proof outside a **model**, and the model is where the attacker who defeats them
lives. The distinction matters because "no algorithm exists" and "the algorithm's guarantee is
conditional, and its validation needs equipment this repository does not have" lead to different
decisions.

| Class | Software algorithms that exist | Model / validation | Why not here |
| --- | --- | --- | --- |
| Power / EM (DPA, CPA) | Boolean and arithmetic **masking** (ISW, threshold implementations, domain-oriented masking); **hiding** (operation shuffling, random delays, dummy rounds); **fresh re-keying** / key ratcheting; leakage-resilient designs | Masking is proven in the **probing model** and evaluated by **TVLA / ISO 17825** on real hardware — so it *is* falsifiable, with a lab | Cost 10–100x; the compiler can undo a software mask (needs asm barriers or a masked-type discipline); validation needs a scope. **One of these is already in the construction, for the payload cipher** (see the table row above): fresh re-keying is what per-tag key derivation *is* — with the nonce-reuse exception spelled out there, where the tag pass and the enc-KDF revert to fixed per-nonce keys and become averageable |
| Faults (single, multi, laser, DFA) | **Infective computation** (Prouff–Giraud: on detection, randomise the output rather than reject); **redundancy with diversity** and randomised scheduling; **tamper-resilient encodings** and **AMD codes**; key ratcheting with destructive read-out; non-malleable codes for continuous tampering | Proven under models: bounded faults, unknown location, no fault in the verifier, encoded secrets. A bench (laser/EM) is what falsifies a claim | `ultra` has *redundancy* twice over (the second gate; the `dual-mac` recomputation) but *diversity* only once — the witness — since both recompute through the same `derive_tag`/BLAKE3/SIMD path. A **stored-secret integrity check** (the `LockedKey` tag, above) is the implemented kernel of the tamper-detection idea, but it is an *unkeyed* hash, so it is not an AMD code as the literature defines one (AMD codes are keyed primitives). Infectivity is deliberately *not* adopted: this crate's detected faults are rejections rather than randomised outputs, because a rejection is what keeps a fault on the encryption side from becoming a ciphertext the caller cannot distinguish from a good one, and because the payoff of a recovered intermediate here is one message (the row above). The rest — encoded secrets, randomised scheduling, non-malleable codes — needs a bench and a redesign of the key path, not a flag |
| Speculative execution | `array_index_nospec`-style index masking, `lfence`/`csdb` barriers, LLVM **Speculative Load Hardening**, retpolines, dual-page mitigations | Falsified by a PoC gadget on the target microarchitecture | This crate has no gadget to harden (no secret index, no secret-dependent access), and the AEAD path's one secret-dependent branch has a public outcome — as does `locked`'s integrity fail-stop, which reveals only whether corruption was detected; a barrier here would serialize a comparison the attacker already knows the result of |
| Cold boot / remanence | **TRESOR** and descendants (key lives in CPU debug registers, never DRAM), Sentry/AESSE-style page encryption, sealed-key suspend | Soundness depends on the OS: debug registers are readable by any tracer and clobbered at context switches, so it needs kernel cooperation | A library cannot hold a key out of RAM on a general-purpose OS; the honest measures are deployment-level (encrypt the image, lock and wipe early) |
| Rowhammer | Guard-page allocators that keep secrets off vulnerable rows, periodic re-touch to force refreshes, **integrity checks** on stored secrets | Falsified by a flip that also lands in the redundancy; ECC/TRR is the only prevention | **The integrity check is implemented**: `LockedKey` stores an unkeyed 8-byte BLAKE3 tag beside the key and verifies it on every use (+42 ns, measured), so a corrupted **key or tag** region fails loudly at first use (a flip in the unused remainder of the page is not read, so it is not reported). Guard pages and refresh loops are not, because they cannot be validated here and would not stop flips |
| Debugger / ptrace | `PR_SET_DUMPABLE = 0`, `PR_SET_PTRACER`, seccomp/Yama; **tracer detection** (`TracerPid` in `/proc/self/status`) with key destruction on attach | Enforced by the kernel up to `CAP_SYS_PTRACE` | The first is **implemented** (`locked::deny_debugging()`); detection-and-destroy is deliberately not: it races the tracer (who reads the key first), it fires on legitimate profilers, and it is the behaviour of malware rather than of a library |
| Supply chain | Reproducible builds, pinned SHAs, `cargo-deny`, signed releases | Falsified by a divergence between source and artefact | Applied — see the workflow headers |

The pattern to take away: for each of these the question is not "*can* software do something" but
"**is the guarantee unconditional, and can it be falsified here**". Masking, tamper-resilient
encodings and TRESOR are real answers with real models, and none of them is verifiable in this
repository — no scope, no fault bench, no kernel cooperation. That is a statement about what this
project can *claim*, not about what cryptography can do, and §9 is the other half of it: for each
of these, the measurement that *would* be run, its pass criterion, and the sentence it would
license.

---

## 9. What would validate the defences this repository cannot validate

§8.5 lists software algorithms whose guarantees need equipment this repository does not have.
"Cannot be validated here" is not the end of the argument, though: for each one there is a
*measurement* that would turn it from an unverifiable claim into a stated result, and this
section writes those measurements down — the method, the pass criterion, and **the exact sentence
the measurement would license**. Until a measurement exists, the sentence is not written
anywhere in this repository; that is the rule this section enforces.

| Defence | Measurement | Method / standard | Pass criterion | The sentence it would license |
| --- | --- | --- | --- | --- |
| **Masking** (first-order DPA/CPA) | Non-specific fixed-vs-random leakage test on the target device, ≥ 100 000 traces per point, at several operating points (voltage, clock, temperature), plus a **second-order** test, because first-order masking is exactly what invites one | TVLA; ISO/IEC 17825 classes; Welch's t-test with the usual multiplicity correction | `|t| < 4.5` at every sample point, both orders, on every configuration of the design under test — and the traces, power model and device published so someone else can re-run it | "First-order (and second-order) leakage is below the detection threshold of 100 000 traces on <device>, at <operating points>. "*Not* "resistant to DPA": a threshold is not a bound, and higher orders are untested |
| **Fault tolerance** (multiple, synchronized, laser) | Timed fault injection across a grid of positions × time offsets × glitch strengths, counting (a) accepting forgeries, (b) observable plaintext on a failed decryption, (c) *undetected* wrong outputs | An FI bench (laser, EM, or voltage/clock) driving the crate through its real entry points; the grid must be published with the result | Zero acceptances and zero observable plaintext over the published grid; for the witness, the undetected rate is reported as a number, not as "zero" | "No accepting fault was found in grid G (positions × timings × strengths) on <device>." The grid's boundary is the claim's boundary |
| **The witness vs `dual-mac` under fault** | Which layer catches which glitch, at what precision, and what the residual undetected rate is | Same bench, both configurations (`hardened,dual-mac` against `ultra`), same grid | A measurable difference in undetected-output rate, which is what the layer's cost is supposed to buy | "The second implementation reduces the undetected-fault rate from X to Y on <device> at <precision>." Today the layer's value is a model, not a measurement |
| **Speculative execution** | A gadget scan of the *compiled crate* in a Spectre harness on the target CPU: does any secret-derived value cross the architected boundary speculatively, and can it be transmitted? | Existing PoC harnesses (Spectre-v1 patterns) applied to the crate's entry points, plus a static scan of the emitted code for the `if (secret < len) { table[secret] }` shape | No gadget found that transmits a secret-derived value; the scan reported with the toolchain and CPU revision | "No speculative gadget was found in this crate's compiled code on <toolchain, CPU>." It says nothing about the rest of the process, which is where the remaining exposure lives |
| **Rowhammer** | Bit-flip rate in the locked key page, with and without the mitigations (guard-page placement, periodic re-touch), and whether the `LockedKey` integrity tag fires | A hammering harness (e.g. the published TRRespass/Drama-style patterns) against the target DRAM, with the crate reading its key on every cycle | Zero flips over N hammer cycles; if a flip occurs **in the key or its 8-byte tag**, the integrity tag must fire — and a flip in the unused remainder of the page must **not** fire, since that region is never read (both halves *are* testable here and are tested, by `a_corrupted_locked_page_is_detected_on_use` cases (a)–(d)) | "No flip was observed in the locked key page over N cycles on <DIMM, machine>; the integrity tag detected the injected faults in the key/tag region and ignored those outside it." |
| **Cold boot** | DRAM remanence window for the deployment's DIMMs: how long after power-off a page is still readable, at which temperatures | The published cold-boot procedure (power off, cold-spray the DIMMs, read them out), with the key page located by a canary | The key page is unrecoverable within the window the deployment's own response time allows — or it is not, and the deployment needs memory encryption or an HSM | "After power-off and <procedure>, the key page was not recoverable within <window> on <machine>." Which is why the honest default remains: memory encryption or no key in host RAM |
| **Power/frequency channels on constant-time code** (Hertzbleed-class) | Whether the same instruction stream has a key-dependent *frequency or thermal* signature a remote observer can measure | A remote-timing harness with frequency monitoring, comparing two keys over many trials, with the workload pinned and the CPU frequency governor reported | No key-dependent difference above the noise floor of the harness, at the tested frequency settings | "No key-dependent frequency signature was detected above X over N trials at <settings>." Constant-time code is not evidence here: the channel does not use branches or indices |

Two defences discussed elsewhere in this document are **not** in the table above, because each has
a committed measurement already: the stack-residue claim is measured by `tools/stack_residue.sh`
(with the residue it cannot reach stated on the row), and the second-comparison-shape defence has
the fold measured at 1.4 ns before the optimizer barrier, and its effect hand-modelled in the README's fault table. (They are not
rows in §8.5 either — §8.5 lists the *unimplemented* algorithms; these two are implemented — which
is why this sentence names them here rather than pointing back at a §8.5 row.) What those two have
in common with the table above is the rule: the claim and the measurement are written next to each
other, and where the measurement is missing the claim is not made.

---

## References

* P. Rogaway, T. Shrimpton, *Deterministic Authenticated-Encryption: A Provable-Security
  Treatment of the Key-Wrap Problem*, EUROCRYPT 2006 (full version: IACR ePrint 2006/221) —
  the DAE/SIV construction and its theorem. (The title was given here as "…of the
  MAC-then-Encrypt Approach" in an earlier revision, which is not a paper: corrected after an
  auditor checked the citation. This document's §3 uses NRS14's MRAE formulation of that
  theorem.)
* C. Namprempre, P. Rogaway, T. Shrimpton, *Reconsidering Generic Composition*,
  EUROCRYPT 2014 — the MRAE formulation used in §3, which revisits and generalises the DAE
  result of RS06.
* S. Gueron, Y. Lindell, *GCM-SIV: Full Nonce Misuse-Resistant Authenticated Encryption
  at Under One Cycle per Byte*, CCS 2015, and RFC 8452 (*AES-GCM-SIV*) — the same
  "tag first, derive the per-message key from the tag" two-pass structure, with a proof,
  which this construction mirrors with BLAKE3 and ChaCha20 in place of Polyval and AES.
* RFC 8439 (ChaCha20 and Poly1305), draft-irtf-cfrg-xchacha-03 (XChaCha20 and HChaCha20),
  and the BLAKE3 specification — the primitives and the vectors this repository replays.
* Y. Dodis, P. Grubbs, T. Ristenpart, J. Woodage, *Fast Message Franking: From Invisible
  Salamanders to Encryptment*, CRYPTO 2018 — the "invisible salamanders" attack (a ciphertext
  that opens under two keys), which §4.5 discusses. The attack is the *attacker-chosen* form of
  the commitment problem; §4.5's *target* form is a different game, and the two are kept apart
  there (the game the term comes from is not the game this document puts a number on).
* S. Menda, J. Len, P. Grubbs, T. Ristenpart, *Context Discovery and Commitment Attacks*,
  EUROCRYPT 2023 — the context-commitment notion and the modern treatment of the commitment
  games this document refers to by the labels the literature gives them (`CMT-1`/`CMT-2`/`CMT-3`;
  the numbering is that line of work's, and this document uses the labels rather than restating
  the definitions). Those games are *attacker-chosen*: the adversary outputs the whole tuple
  rather than attacking a given ciphertext, which is exactly why §4.5 does not attach its
  target bound to them and records the attacker-chosen bound as not derived.
