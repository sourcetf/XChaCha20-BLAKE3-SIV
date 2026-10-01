# Security analysis: what is proven, what is assumed, and what would refute it

This document is the mathematical treatment of the construction. It has one purpose: to
separate the three kinds of statement this repository makes about itself, so that none of
them is read as another.

1. **Proven here, from explicit assumptions** — the reduction. Given the primitives are
   the PRFs they are believed to be, the composed scheme has the properties claimed, with
   the exact place where each assumption is used and the concrete loss at each hop.
2. **Assumed** — the PRF security of ChaCha20, HChaCha20 and keyed BLAKE3, plus the one
   statement the tag's layout adds on top of them (L3.6 in §2.1: the tag is a PRF in the
   master key even though the master key is also bytes of its input). Nobody can prove these;
   there is no proof of any ARX primitive of this size, and a document that blurred that line
   would be lying by structure rather than by sentence.
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
of §4.5, the two-time-pad consequence in §3, the L3.6 gap, and a `MADV_DODUMP` that was
never called): that is evidence about the *document*, not independent cryptanalysis of the
design, and the distinction is the one this paragraph exists to keep.

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
  turns the tag into a commitment to the key and the nonce (§3, Thm 2). It is also the one place
  where the document buys a property with an assumption rather than a theorem: putting `K` in
  the input means the key of the tag's PRF is derived from a value that is also in that PRF's
  input, which is L3.6 in §2.1 — declared there, with its (real) reduction gap and its
  falsifier, rather than counted as free.

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

**A5 (standard model, with one correlation declared).** No related-key, nonce-respecting-only,
or quantum-model claims are made here except where §6 states them explicitly. The construction
does introduce one correlation between a key and the data it is used on — the master key keys
the tag derivation *and* appears in the tag's input — and it is declared rather than hidden: it
is L3.6 in §2.1, an assumption strictly stronger than A3, with its reason and its falsifier
given there.

### 2.1 The assumption tree, layer by layer

Numbering the assumptions A1–A5 is not enough to audit a composition: each of those has to be
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
     |-- Thm 1  the 512-bit key-material block is a PRF of the nonce
     |-- Thm 2  the tag is a PRF of (N,A,M), hence collision-resistant and key-committing
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
     |-- L3.5  the BLAKE3 XOF keeps that property past the first output block
     |-- L3.6  for a uniform `K`, the map `(N, A, M) ↦ B3(D(K), P ‖ K ‖ S)` is a PRF,
     |         where `D(K)` keys the hash and the *scheme* inserts the secret `K` between
     |         the caller-chosen parts `P` and `S`: the input is a function of the key, a
     |         shape the black-box PRF game does not model and no reduction from L3.3
     |         reaches.  Immediate if keyed BLAKE3 is modelled as a random oracle (strictly
     |         stronger than L3.3); assumed, with a separation, in the standard model
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
argument, not a proof, and it is the one place in this tree where "it is standard practice"
is doing more work than a citation.

**Why L3.6 is an assumption of its own.** First, the statement, because the obvious phrasing
of it is not well posed. "The tag is a PRF in `K`" cannot mean a PRF whose inputs the adversary
chooses, since the input contains `K` and the adversary does not know it. What the reduction
actually needs — and what L3.6 asserts — is the game this document's theorems use: `K` is drawn
uniformly, the adversary chooses `(N, A, M)`, *the scheme* builds the byte string
`DOM_TAG ‖ K ‖ N ‖ ⟨|A|⟩ ‖ ⟨|M|⟩ ‖ A ‖ M` with the secret inside it, and the output
`T = B3(D(K), ·)` must be indistinguishable from a uniformly random function of `(N, A, M)`.
The distinguishing feature of this game, and the reason it is not L3.3, is that the *key* of the
hash and a 32-byte *substring of its input* are two correlated functions of one secret — the
key-dependent-input setting, the cousin of KDM.

It looks like it should follow from L3.3, and it does not. L3.3 is the statement that
`x ↦ B3(k, x)` is a PRF for a key `k` drawn uniformly **and independently of the input**; here
the key is derived from the very value the input contains. The reduction that would close the
gap cannot be written down: it would have to hold `D(K)` as the challenge key of the PRF game
while *placing `K` in the query string*, and the input would have to contain the preimage of a
value the reduction is not given. (Concretely: the reduction's oracle is `B3(k*, ·)` with `k*`
uniform and unknown; to answer a query it must build `D(K) ‖ … ‖ K ‖ …`, which needs `K`, and
`D` is not invertible without `K`.)

That this is a genuine gap rather than a missing paragraph is shown by a separation. Take any
keyed hash `B3'` that is L3.3-secure but *notices* its input: `B3'(k, x) = 0` if `k` occurs in
`x`, and `B3(k, x)` otherwise. For a fixed query string that function is still a PRF (the bad
event has probability ≈ `2^-256` per query, so it costs at most `q·2^-256`), yet the composed
map `K ↦ B3'(D(K), P ‖ K ‖ S)` is the constant zero function — distinguishable from random by
a single query. So no black-box reduction can exist: L3.6 is strictly stronger than L3.3, and a
construction that gets it wrong is not caught by the PRF assumption on the hash alone.

**Can it be proved instead of assumed?** Not from L3.1–L3.5 — the separation above is a proof of
*that*. It *is* immediate under a stronger model: if keyed BLAKE3 is modelled as a random oracle
(or as an ideal cipher applied to the state), then `B3(k, x)` is uniform in `k` and `x` alike and
the correlation between the key and the input costs nothing. Preferring that model would trade
one honest assumption for a larger one (a random oracle is strictly stronger than a PRF: it
implies collision resistance, preimage resistance and PRF security at once), so the document
states the assumption instead of moving the goalposts. The third option — removing the
correlation by dropping `K` from the head — is a design change with a price, quantified in §4.10
and in `derive_tag`'s own docs: it re-opens the `2^256`-birthday route through the key
derivation. Taking neither is deliberate.

What supports it here is structural, and weaker than a proof. BLAKE3's compression puts the
key words in the *initial state* (`v[0..8] = k`, with `KEYED_HASH` in the flags) and lets the
message words in only through the round function's `G` mixing; no output byte is a function of
the message alone, the key words are never re-derived from message words, and the keyed mode is
separated from the unkeyed one by a flag rather than by convention. That is the same kind of
design argument as L3.4, and it is the reason the assumption is believed rather than proven.
Two further things are worth stating because they bound the damage if it is false: the
correlation is only present because the encoding chose to bind `K` into the tag (a revision
could drop it, at the cost of the route-closing described at `derive_tag` in `src/lib.rs`), and
the assumption is *not* about ChaCha20 and BLAKE3 interacting — it lives inside a single BLAKE3
call. Every HMAC-style or `H(k ‖ m)`-style construction makes the same assumption, so this is
standard practice; the point of writing it down is that §4.10's claim is "no *joint* assumption
between the two primitives", and L3.6 is not one of those.

**What each use of a primitive consumes.**

| Use | Consumes | Because |
| --- | --- | --- |
| `subkey = HC(K, N₁)` | L3.2 | truncated permutation output, keyed by `K` |
| `mat = CC(subkey, sn, 0)` | L3.1 | feed-forward block function, counter fixed at 0 |
| `T = B3(mac_key, ...)` | L3.3, L3.4, L3.5, **L3.6** | keyed compression, tree, 65-byte XOF output; L3.6 because `K` keys the derivation *and* appears in the input |
| `(enc_key, enc_nonce) = B3(enc_seed, ...)` | L3.3, L3.5 | keyed compression, 44-byte XOF output |
| `C = M xor KS(enc_key, enc_nonce)` | L3.1 (via L1.3's counter-mode reduction) | distinct counters per block, §4.6 |

**Falsifiers, per node.** L3.1: a distinguisher for ChaCha20's block function (published
cryptanalysis reaches 7–8 of 20 rounds; a full-round distinguisher would falsify it). L3.2: a
distinguisher for HChaCha20 (no published attack beyond the same reduced-round results). L3.3:
a PRF distinguisher for keyed BLAKE3 — the BLAKE2/BLAKE3 literature has boomerang and
rotational attacks on *reduced* rounds only. L3.4: a collision or a PRF distinguisher that
exploits the tree (this would be a structural attack on BLAKE3, and none is known). L3.5: an
XOF distinguisher past the first output block (the output counter is part of the root
compression's input, so this reduces to L3.3/L3.4). **L3.6**: any distinguisher for the
composed tag map `K ↦ B3(D(K), … ‖ K ‖ …)` that is *not* a distinguisher for `x ↦ B3(k, x)` at
a fixed input — i.e. a concrete exploit of the key also appearing in the message. The
separation above shows such distinguishers exist in general (a hash that greps its input for
the key), so the falsifier is a *real* one; what is not known is any such structure in BLAKE3,
and the `KEYED_HASH` flag, the key words being the initial state, and the absence of any
feed-forward from the message into the key schedule are the reasons to expect none. A4 (the
encoding) is not a conjecture: it is proven in §4.4.

**The honest bottom line.** Every claim in this document rests on L3.1–L3.6 and nothing else.
There is no proof of any of the six, and no test in this repository — or any other — can
establish them, because they are statements about the infeasibility of computation. What the
remainder of the document does is make sure that *nothing else* is assumed. Six is one more
than an earlier revision of this document claimed and one more than the primitives' own
assumptions provide: L3.6 comes from a *choice of encoding* (binding `K` into the tag as well
as into the key derivation), not from any interaction between ChaCha20 and BLAKE3 — that
distinction is the whole content of §4.10.

### 2.2 An auditor's lettered list, mapped onto this document

Audits of this construction arrive with their own numbering, and one such list — with the items
ChaCha20-is-a-PRF, keyed-BLAKE3-is-a-PRF, HChaCha20-is-a-PRF, the two-level cascade-is-a-PRF,
"the 520-bit XOF output gives more than `2^256` collision resistance", the SIV composition theorem,
and the `K`-in-the-head key-dependent-input step — maps onto this document as follows. **The
letters below are the auditor's, not §2's**; this section's own A1–A5 are a different list, and the
numbers in `Adv^{A1}`–`Adv^{A3}` in the theorems refer to *these* document's, so the mapping is
worth having in one place:

| Auditor's item | Where it lives here | Status |
| --- | --- | --- |
| ChaCha20 is a secure PRF | L3.1 | assumed (L3.1's standing paragraph; no full-round attack, huge deployment) |
| Keyed BLAKE3 is a secure PRF | L3.3, L3.4, L3.5 | assumed (design argument, not a theorem; the most exposed of the three) |
| HChaCha20 is a secure PRF | L3.2 | assumed, and a *separate* conjecture from L3.1 though it is the same permutation |
| The two-level derivation cascade is a PRF | **Thm 1** | **proved** here from L3.1 + L3.2, not assumed — the same construction XChaCha20 rests on, but with the argument written out |
| "The 520-bit XOF output gives more than `2^256` collision resistance" | §4.5 | **falsified**: the whole output is a function of a 256-bit chain value, so collisions are `2^128`-class and the width cannot raise them. (The claim was never needed for commitment — that is a *target*, §3 Thm 2 — which is why falsifying it does not weaken the scheme's commitment) |
| The SIV composition theorem applies | L1.1 (RS06), L1.2 (the key-derived-from-tag variant: Gueron–Lindell / RFC 8452), L1.3 | literature, cited; the MRAE form used in §3 is NRS14's |
| The `K`-in-the-head step is sound (KDI/KDM-flavoured) | **L3.6** | assumed, and *not* implied by L3.3 — there is a separation above showing no black-box reduction exists. Immediate under a random-oracle model of keyed BLAKE3 (strictly stronger than the PRF assumption); the encoding could remove it at the cost of re-opening a `2^256` route (§4.10) |

Nothing in the table is silently assumed: each row either points at a proof in this document, at
a citation, or at a named conjecture with its own falsifier in §5. The one row an auditor should
push on is L3.6, and §5's row 15 says exactly what would refute it.

### 2.3 Is the conjecture set consistent, and is any conjecture redundant?

An assumption list needs two things beyond each entry: the entries must be *simultaneously
satisfiable* (no contradiction hides in the set) and *non-redundant* (none is a consequence of
another, or it is doing no work and should be deleted). Both are discharged here, which is the
part of an assumption audit that usually goes missing.

**Consistency: the six hold together, in one model.** Take `CC` and `HC` to be independent random
functions of their inputs (each is then a PRF, so L3.1 and L3.2 hold), and take keyed BLAKE3 to
be a random oracle `R(k, x)` whose output stream is uniform and independent for every distinct
`(k, x)`. Then:

* L3.3 holds: at a fixed `x`, `k ↦ R(k, x)` is a random function;
* L3.4 holds: whatever the tree does with chaining values, the root's output is a fresh uniform
  string per distinct root input — there is no structure left to exploit;
* L3.5 holds: later output blocks are part of the same uniform stream;
* L3.6 holds: the map `(N, A, M) ↦ R(D(K), P ‖ K ‖ S)` is uniform per query, and distinct queries
  give distinct oracle inputs by A4 (the encoding is injective *given* `K`), so the outputs are
  independent. The correlation between `D(K)` and the `K` inside the input — the whole content of
  L3.6 — is invisible to a random function.

So no two assumptions contradict each other, and the idealised world the reductions compare
against is itself a model of the assumptions. (This is also why L3.6 is believed: the only property
of BLAKE3 it needs is the one a random oracle has by definition, so the assumption is "BLAKE3 is
close enough to an oracle *in this one use*" rather than "BLAKE3 is an oracle".)

**Non-redundancy: no conjecture follows from another.** Each row is a *separating construction* —
an object in which the left-hand assumption holds and the right-hand one fails — so the
implication cannot exist in general. They are sketches, not full definitions, which is what a
separation needs to be when the two statements are about different objects:

| If … held | … would it give …? | No: the separating object |
| --- | --- | --- |
| L3.1 (CC is a PRF) | L3.2 (HC is a PRF) | the object is the *same* permutation `P`; `P(x)+x` is a PRF up to the birthday bound and false beyond it, while `trunc(P(y))` is not a PRF at all (a truncated permutation is distinguished by collision counting). §2.1's "why L3.1 and L3.2 are two conjectures" |
| L3.2 | L3.1 | the same pair, read the other way: dropping the feed-forward is not a strengthening |
| L3.3 (keyed compression is a PRF) | L3.4 (the tree preserves it) | keep BLAKE3's compression, change only the *root's input assembly* so that half of the left chaining value is ignored: the compression is still a PRF, but two messages differing in the ignored half have identical roots *deterministically*, and no PRF does that |
| L3.3 or L3.4 | L3.5 (the XOF keeps it past block 1) | keep the compression and the tree, define output block `i ≥ 1` as a constant: the first block is still a PRF and the tree is untouched, while the multi-block output carries no input-dependence at all |
| L3.3 | L3.6 (the composed tag map is a PRF) | the grep-the-key hash of §2.1: `B3'(k, x) = 0` if `k` occurs in `x`, else `B3(k, x)`. L3.3 holds up to `q·2^-256`; the composed map is the constant zero function |
| any of L3.1–L3.3 | any other | different objects: they are statements about three different primitives, so nothing follows in either direction, and the document cites each only for the layer that uses it |

The converse directions are not claimed and not needed: the document never derives a lower layer
from a higher one. What the table buys is the statement §4.10 makes — the composition adds L3.6
and *only* L3.6 — with each of the six shown to be pulling its own weight rather than restating
its neighbour.

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

*Proof.* Two hybrids. (i) Replace `N ↦ mac_key` with a uniformly random function, so that per
distinct nonce the tag is `B3(k_N, ·)` with `k_N` uniform and independent of everything else.
This is the step that needs L3.6 rather than A3: the key being replaced is *derived from* `K`,
and `K` is still in the input, so key and input are correlated functions of one secret (§2.1
states the gap and shows no black-box reduction from A3 closes it). (ii) With `k_N` uniform
and independent of the input, `x ↦ B3(k_N, x)` is a PRF (A3). Distinct nonces carry independent
`k_N` (Thm 1), so the joint statement over all queries follows. ∎ The rest of this document
uses the idealized form of step (i) — it is the only place where the two statements differ.

Consequences. Two different "collision" quantities live here and the numbers differ by 2^392, so
they are stated separately:

* **Collision resistance between two *given* inputs.** For a fixed pair of distinct inputs the
  two tags agree only if the PRF does, i.e. with probability `2^-520` — this is the statement
  Thm 3 uses. (It is a *target*, not a birthday: the adversary does not get to search.)
* **Collision resistance over `q` *chosen* inputs.** Here the tag is not a random 520-bit
  string: all 65 bytes are functions of BLAKE3's root state — the **256-bit chaining value**,
  the final block, its length, the counter and the flags — so an adversary who holds the tail
  fixed and varies the prefix buys a tag collision for the price of a *chaining-value* collision:
  `q² / 2^257`, i.e. `2^128` at the birthday point, not `2^260`. §4.5 carries the argument and
  §5 its falsifier. This is the number in Thm 4's bound.
* **Commitment to the key.** Because `K` (and `N`) are *inputs* to the hash rather than only the
  key that keys it, a tag that is valid under `K₁` is valid under `K₂ ≠ K₁` only if
  `B3(k_{N,K₁}, X ‖ K₁ ‖ …) = B3(k_{N,K₂}, X ‖ K₂ ‖ …)`. This is a *target* problem, and the
  number is not a birthday at all: the adversary publishes a tag `T` and then needs the second
  key's computation to output *that* value, so the cost is `2^520` per attempt — unchanged by the
  chaining-value correction below, which helps only when both sides of a collision are the
  adversary's to search. (The `T`-coupling makes that concrete here: `T` determines the message
  through the KDF, so a collision found between two arbitrary tags is not a ciphertext that opens
  under two keys — it would have to be a fixed point of that coupling as well.) This is the
  "invisible salamanders" attack made infeasible; it is a stronger property than plain SIV
  provides, and it is deliberate. What the `K`-in-input binding adds is the removal of a cheaper
  route: without it, an adversary searching over keys *it chooses* for two with the same 512-bit
  key-material block (`2^256` by birthday, and the search is over keys, not over hash inputs)
  would get equal `mac_key` *and* equal `enc_seed`, hence equal tags *and* equal keystreams for
  equal messages — one ciphertext opening under both keys at key-search cost, which is exactly
  what "not committing" means. With `K` in the head that route is gone. The price is L3.6.
* **Commitment to the nonce and the lengths.** Same argument, byte for byte, since both
  are inputs to the same hash: a tag cannot be moved to another nonce or reinterpreted
  under a different length split (that is the same statement as §4.4).

### Theorem 3 (per-tag key separation, and keystream binding)

For distinct tags, the derived `(enc_key, enc_nonce)` pairs are jointly pseudorandom; and a
change anywhere in `(K, N, A, M)` changes the tag with probability `1 − 2^-520`, hence
changes the keystream entirely.

*Proof.* Immediate from A3 (multi-query PRF security at distinct points `DOM_ENC ‖ T`) and
Thm 2. The `2^-520` is the *fixed-pair* statement: for one specified change, the two tags agree
only if the PRF does. It is not the birthday-level number — an adversary free to search over
many changes gets a collision at `2^128` (§4.5), which is why that bound, and not this one,
appears in Thm 4. ∎

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
Adv^{priv} ≤ Adv^{A1} + Adv^{A2} + Adv^{A3} + Adv^{L3.6} + q²/2^257
Adv^{auth} ≤ Adv^{A1} + Adv^{A2} + Adv^{A3} + Adv^{L3.6} + q·2^-520 + q²/2^257
```

where `q` bounds the adversary's oracle queries and each `Adv` is the *multi-query* PRF
advantage of the corresponding assumption (each is already defined for a polynomial query
bound). `Adv^{A1}`/`Adv^{A2}` are the ChaCha20/HChaCha20 terms of the key derivation (Thm 1),
`Adv^{A3}` is the per-message key derivation, and `Adv^{L3.6}` is the tag — the composed map,
which needs L3.6 because the master key keys it *and* is in its input. MRAE security is the
pair.

An earlier revision of this document wrote `2·Adv^{A3}` in place of
`Adv^{A3} + Adv^{L3.6}` and `q²/2^521` in place of `q²/2^257`. The first papered over the
L3.6 gap by counting the tag as an ordinary A3 application; the second treated the 65-byte tag
as 65 independent random bits, which §4.5 shows it is not. Both corrections lower nothing that
was not already lower: the `q²/2^257` term is `2^-129` at `q = 2^64`.

*Proof (reduction chain, five hops).*

1. Replace the key derivation with two independent random keys per nonce (Thm 1). Nothing
   observable changes except with the stated advantage.
2. Replace the tag function with a uniformly random function (L3.6, then A3 as in Thm 2).
   From here, tags are uniform and independent for distinct `(N, A, M)`; two queries collide
   in the tag with probability `q²/2^257`, the birthday bound of the 256-bit chaining value
   the tag is a function of (§4.5), not `q²/2^521`.
3. Replace `(enc_key, enc_nonce)` with a uniformly random function of the tag (A3). Tags
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
   succeeds with probability at most `2^-520` (fresh `T`, a PRF output) or by hitting a tag
   the oracle already produced — a *target*, so `≤ q · 2^-520` in total, and the
   chaining-value shortcut of §4.5 does not apply: it makes pairs of *searchable* tags
   collide cheaply, and here the value to hit is fixed by someone else. The self-referential
   dependence `M'(T)` does not help: inverting it is as hard as inverting the KDF, and the
   key is secret. ∎

*Where each assumption enters:* A1 in the keystream (hop 4) and in the key material (hop 1);
A2 in the subkey (hop 1); A3 in the per-message key derivation (hop 3); **L3.6** in the tag
(hop 2) — the one place where a key is derived from a value that is also in the PRF's input.
A4 is needed for the *statement* of the game (that the encoded input defines the
query) and is discharged in §4.4.

### Corollary (nonce misuse degrades exactly as SIV does, with one collision-shaped caveat)

If the adversary repeats a nonce, hops 1–3 are unchanged: the per-query tags still determine
independent keystreams (Thm 3), so two *different* `(A, M)` pairs under one nonce are still
encrypted with independent keys. What the adversary learns is:

* whether two `(A, M)` pairs are equal (identical tags ⇒ identical ciphertexts), and
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
*fixed* pair at `2^-520` — then the two messages are encrypted under the *same* derived
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
T = B3(mac_key, DOM_TAG || K || N || |A| || |M| || A || M)      T depends on M
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
T* = F_C(T*),   where  F_C(T) = B3(mac_key, … ‖ A ‖ M′(T))   and   M′(T) = C xor KS(B3(enc_seed, DOM_ENC ‖ T))
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
  passes and why its latency does not shrink with more cores (README's performance section).
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
past any real deployment — that is `2^(32+64-257) = 2^-161`, and the forgery term `Q·q·2^-520` is
`2^-456`: the multi-user loss is not what a deployment size costs.

Two things do *not* follow that factor, and one that does is worth naming separately:

* **The commitment properties (CMT-1/CMT-3) are per key.** A second key that opens a ciphertext
  is a statement about *that* pair of keys; a break for one key says nothing about another, so `Q`
  does not enter the `2^520` target bound at all (it enters as "there are `Q` keys to *try* to
  attack", which is the next point);
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
and, for equal-length messages, identical ciphertexts, since `derive_enc` is a function of the
tag alone. The same argument applies to a multi-chunk input by fixing the subtree that holds the
tail and colliding the prefix subtree's chaining value. This is a *collision* search, not a
preimage: the adversary needs the two tags to agree *with each other*. A tag that must be hit *as
given* — a forged tag, or a ciphertext that must open under a second key — is still a target in
the 520-bit output and still costs `2^520` per attempt.

**Consequently, the numbers are these, and the pair (target, birthday) is now written out
wherever the distinction matters. All of them still carry at least 128 bits of margin.**

| Event | Bound |
| --- | --- |
| Tag collision, same key, `q` queries | `q² / 2^257` (≈ `2^128` at the birthday point) |
| Derived `(key, nonce)` collision over `q` queries | `q² / 2^257` — see below: the tag term dominates it, and the KDF's own birthday is over a 328-bit state (256-bit chain value plus the 72-bit tail block), not the 352-bit output |
| A tag agreeing with a *given* tag (forgery, second open, commitment) | `2^-520` per attempt; ×`q` for `q` targets |
| Forgery (one decryption query) | `2^-520`, plus the tag-collision terms |
| Exhaustive key search | `2^256` |
| Quantum: Grover on the key | `2^128` |
| Quantum: BHT collision finding on the 256-bit state | ≈`2^85` — model-dependent (it needs large quantum memory), and a property of *any* 256-bit state, SHA-256's collisions included; see the note below |

**Four consequences, stated plainly.**

* **The width is load-bearing for commitment — through the target, not the birthday.** With a
  65-byte tag, a candidate key that is not the real one opens a given ciphertext with probability
  `2^-520`, so enumerating the whole `2^256` key space succeeds with probability `≈ 2^-264`: no
  second key exists in reach. With a 32-byte tag the same enumeration would expect `≈ 1` second
  key, because `2^256 · 2^-256 ≈ 1` — the ciphertext would stop being *committing* and become
  merely as hard to double-open as it is to key-search, which is precisely the failure the SIV
  commitment literature (and the 16-byte tags of AES-SIV / AES-GCM-SIV) is about. So the old
  rationale reached the right *decision* — the tag must be wider than 32 bytes — through the
  wrong *property*: it is the target bound, not a birthday bound, and the number to quote is
  `2^520` per attempt rather than `2^260`.
* **What the width does *not* buy is collision resistance**, which is `2^128` either way, and
  forgery, which is `2^256` either way (bounded by key search, which no tag length raises). The
  width is kept because the format is frozen at revision `v0.2` *and* because it is the
  commitment; a revision that shortened the tag to 32 bytes would have to give up CMT-1/CMTk.
* **The KDF's own collision is `2^164`, and it is dominated.** Two *distinct* tags `T₁ ≠ T₂` that
  yield the same derived pair must collide the state the KDF's root sees: the 256-bit chain value
  *and* the 72-bit final block (`T[56:65]` plus padding), so the birthday is over 328 bits —
  `2^164`, not the `2^176` a 352-bit output would suggest and not `2^128` either. It matters
  little, because a *tag* collision implies this one (equal tags ⇒ equal derived pairs) and is
  strictly cheaper at `2^128`, so the bound carries one collision term and the tag's number is
  the right one. What would be wrong is quoting `q²/2^353`: that is the birthday of the output
  size, and the state that produces the output is what constrains it.
* **Confidentiality and forgery stay at 128 bits, classically and quantumly** (Grover on the key
  is `2^128`, which is the number the 256-bit key design targets). What is *not* 128-bit quantum
  is the collision property: a 256-bit state has a ~`2^85` quantum collision search (BHT), which
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

No step above needed an assumption beyond A1–A3 plus the injectivity of the encoding — with the
single exception of L3.6 (§2.1), which is not a step of the composition but a property of the
tag layout, and is declared rather than assumed silently. In
particular, none of the following is assumed: that `mac_key` and `enc_seed` are *separately*
derived (splitting one PRF block is fine, Thm 1); that a nonce is used once (that is the
misuse case, §3 Corollary); that the encryption is randomized (it is deterministic by
design); that the tag is secret (it is public, and Thm 3 does not need it to be).

---

### 4.10 The interaction inventory: why the combination adds no assumption of its own

This is the answer to the question "does putting ChaCha20, HChaCha20 and BLAKE3 together in
*this* way create a problem that none of them has alone?". The answer is a proof obligation,
not an opinion, and it has three parts: enumerate every use, enumerate every value that crosses
between uses, and show that each crossing is either a composition the L1 theorems already cover,
a *structural* disjointness, or a bounded-probability event. The enumeration has to be complete,
so the completeness argument is stated last and it is the part that is mechanised (a test).

**The five uses.** Every cryptographic call in the non-test source is one of these, and the
inventory test (`tests/construction_inventory.rs`) fails if the set changes.

| # | Call | Key | Input | Output | Consumed next by |
| --- | --- | --- | --- | --- | --- |
| U1 | `hchacha20` | `K` | `N₁` (16 B) | `subkey` (32 B) | U2 |
| U2 | `chacha20_keystream_raw` | `subkey` | `"XSIV" ‖ N₂`, counter 0 | `mat` (64 B) | split into U3's and U4's keys |
| U3 | `blake3_keyed_multi` | `mac_key = mat[0:32]` | `"XSIV-TAG" ‖ K ‖ N ‖ len ‖ A ‖ M` | `T` (65 B) | U4, and the wire |
| U4 | `blake3_keyed_xof` | `enc_seed = mat[32:64]` | `"XSIV-ENC" ‖ T` | `enc_key`, `enc_nonce` | U5 |
| U5 | `chacha20_keystream` | `enc_key` | `enc_nonce`, counters 0… | keystream | XOR with `M` |

**The values that cross.** `subkey` (U1→U2), `mat` (U2→{U3,U4}, split on arrival into
`mac_key` and `enc_seed`), `T` (U3→U4, and U3→the wire), and the pair `enc_key`, `enc_nonce`
(U4→U5) — five values, or six if the two halves of `mat` are counted separately. Nothing else
is passed between the calls, and that is a statement about the code which the inventory test
pins. So the case analysis below is over a finite, known set: no crossing can be missed by
construction.

**Pairwise separation.** For each pair of uses that could in principle share a key, an input
point, or an output, the table says what keeps them apart and what kind of argument that is.

| Pair | Could they collide? | Separation | Kind |
| --- | --- | --- | --- |
| U1, U2 | no | `subkey` is U1's output and U2's key: this is XChaCha20's own structure | composition, L3.2 then L3.1 |
| U2, U5 | yes, probability `2^-352` | both are ChaCha20 at counter 0; separated by key *and* nonce, not by counter (§4.1). The event needs `enc_key = subkey` **and** `enc_nonce = "XSIV"‖N₂`, both of which are secret-derived, so no one without `K` can compute or detect it | **bounded event, requires K** |
| U3, U4 | no | different keys (`mac_key` vs `enc_seed`, jointly pseudorandom by Thm 1) **and** input strings that differ in their first 8 bytes | structural (prefix) + Thm 1 |
| U2, U3 | no | `mac_key` is used only as U3's key; `mat`'s other half goes to U4 | structural (disjoint purposes) |
| U2, U4 | no | `enc_seed` only keys U4 | structural |
| U4, U5 | not a collision but a *composition* | U4's output **is** U5's key; nothing is reused | by construction |
| U3, U5 | no | `T` is public and U5's key is not derived from it in any invertible way: U5's key is `B3(enc_seed, DOM_ENC‖T)`, a PRF value under an unknown key | L3.3 |
| U1, U3/U4/U5 | no | `subkey` never leaves U2 | structural |
| U3, U3 (across two messages, same nonce) | yes, `q²/2^257` | tag collisions (§4.5) — the SIV term, not a composition term; the birthday is over the 256-bit chain value, not over the 520-bit output, and a collision here is also the two-time-pad event of §3's Corollary | L1.1 term |
| U4, U4 (two distinct tags, same nonce) | yes, `q²/2^257` | dominated by the tag collision above: two *distinct* tags collide in the derived pair only through the KDF's own 328-bit state (`2^164`), and a tag collision implies this event, so the tag's `2^128` is the binding number — not the generic `q²/2^353` of the 352-bit output | L1.2/L1.3 term |

**Two structural lemmas worth stating on their own**, because both are proved by inspection and
neither depends on a primitive being strong:

*Lemma S1 (the two BLAKE3 input spaces are disjoint).* U3's input begins with
`DOM_TAG = "XSIV-TAG"` and U4's with `DOM_ENC = "XSIV-ENC"`; both are 8 bytes and they differ in
their third byte, so no byte string is both a tag input and a KDF input. Even in the impossible
case `mac_key = enc_seed` — one 64-byte block split in half, so a `2^-256` event — the two BLAKE3
families remain separated by *input space* rather than by key. ∎

*Lemma S2 (no cross-scheme keystream reuse with XChaCha20-Poly1305).* For the same `(K, N)`,
HChaCha20 gives both schemes the *same* subkey (both use `HC(K, N₁)` with the same `N₁`), so the
separation has to come from the second half of the nonce. XChaCha20-Poly1305's first data block
is `CC(subkey, 0⁴ ‖ N₂, 0)`; this crate's key-material block is `CC(subkey, "XSIV" ‖ N₂, 0)`.
The two nonces differ in four fixed bytes, so these are evaluations of ChaCha20 at **different
points of its domain** — a structural separation, not a probabilistic one. This is why the label
sits in the *nonce* rather than the counter, and why it is a fixpoint of the format (§4.3). ∎

**Completeness.** The case analysis is exhaustive because (i) the five uses are all the
cryptographic calls in the construction — mechanically checked — and (ii) the set of values that
flow between them is exactly the six listed, so any interaction is a pair in the table above.
There is no interaction that the table does not cover, and the table's rows are each discharged
by one of: an L1 theorem, a lemma proved in §3, an inspection-level structural fact, or a
probability bound.

**Therefore the combination introduces no *joint* assumption about the two primitives.** Every
joint use is covered by the L1 reductions, which need the primitives only with *independent
keys*; the keys are derived and their independence is a theorem (Thm 1) rather than a hope; and
the one place where two uses share a point of a primitive's domain (U2/U5, counter 0) needs the
master key even to detect. Nothing in this construction requires a joint assumption about
ChaCha20 and BLAKE3 — no "these two are unrelated" conjecture, no "this key is safe to use in
both" conjecture.

**The one assumption the *encoding* adds, named rather than folded in.** The tag's input contains
`K` as well as being keyed by `K`'s derivation, and that is a property of this construction's
chosen layout, not of BLAKE3 — so it is a seventh thing to assume and it is stated as L3.6 in
§2.1, with its separation and its falsifier. It is deliberately *not* counted as a composition
hazard, because it is a statement inside a single primitive: no ChaCha20 object and no BLAKE3
object are related by it. It is named here so that the sentence above means "no assumption that
relates the two primitives" rather than the weaker and less useful "no assumption at all". The
layout that creates it was a choice: putting `K` in the head removes the `2^256`-birthday route
to a non-committing ciphertext that runs through the key derivation (Thm 2), and the price of
removing it is this assumption. A revision that dropped `K` from the head would delete L3.6 and
re-open that route — the trade, not a free win.

**What this does *not* prove, stated plainly.** It does not prove that ChaCha20 and BLAKE3 are
secure, and it cannot rule out a future cryptanalytic relation between them: if someone found a
relation that made this cascade break, that would be a break of L3.3 (the keyed BLAKE3 PRF
assumption) or of L3.1/L3.2, not a flaw in the composition — but the distinction would matter to
a user, so it is written here rather than left to be inferred. "No unknown problem" is not a
theorem anyone can prove about any construction; what is proven here is the weaker and precise
statement that *the composition adds no conjunct of its own that relates the two primitives*.
L3.6 is the one conjunct that the layout does add, and it is stated, separated and falsifiable
rather than counted as zero.

## 5. Falsification programme

A security claim that cannot say what would refute it is not a claim. Each row states the
refutation, and the status of the attempt.

| # | Claim | What would refute it | Status |
| --- | --- | --- | --- |
| 1 | A1, A2, A3 (PRF security of the primitives) | A distinguisher for ChaCha20 / HChaCha20 / keyed BLAKE3 | **Not attempted, and not attemptable by test**: these are open problems in cryptanalysis. The evidence is the primitives' standing, their published test vectors (replayed here), and the fact that the construction's use of them is standard |
| 2 | Tag is a PRF over `(N,A,M)` | Two distinct `(N,A,M)` with equal tags under one key | A *fixed* pair is out of reach (`2^-520`); *searching* for a pair is the chain-value birthday, `q²/2^257` (§4.5), also out of reach. *Structural* variants tested: length ambiguity, A/M swap, trailing zeros, single-byte changes in A and M, key and nonce reaching the tag. Not testable: both numbers are bounds on computation |
| 3 | Key commitment | A `(C,T)` that opens under two keys | Against a given `(C,T)` this is a target and stays out of reach (`2^520` per attempt); the *birthday* level for a colliding pair is `2^128` (§4.5), which an invisible-salamander attack against a fixed ciphertext cannot use. *Mechanism* tested: the tag binds `K` directly (`test_tag_binds_the_key_directly`) and Kani proves `K` reaches the hash in the specified layout |
| 4 | Keystream is tag-dependent | `ct₁ ⊕ ct₂ = M₁ ⊕ M₂` under one nonce, or `ct` invariant under an AAD change | **Tested**: `nonce_reuse_does_not_reuse_the_keystream` (message change, AAD change, first-block check, attached and in-place paths) |
| 5 | The two ChaCha20 uses are separate | The key-material block equals the message keystream | **Tested**: `the_key_material_block_is_not_the_message_keystream` (16 trials, key, nonce and keystream compared); the residual is §4.1 |
| 6 | The KDF consumes the whole tag | A tag byte that does not move the derived key | **Proved + tested**: Kani (all 65 bytes consumed), `test_every_tag_byte_reaches_the_ciphertext` |
| 7 | The encoding is unambiguous | Two quadruples with the same encoding | **Proved by inspection** (§4.4) + `test_aad_message_split_is_unambiguous` |
| 8 | The counter cannot wrap inside a message | A message length above the bound that still encrypts | `const` assertion (build failure), `tests/counter_range.rs`, Kani |
| 9 | Nonce reuse leaks only equality | Two distinct `(A,M)` under one nonce with the same tag or keystream | Tested at the keystream level (#4); the tag collision that would *additionally* give `C₁ ⊕ C₂ = M₁ ⊕ M₂` is a `2^128` search (§4.5, §3 Corollary), so that half is a bound rather than a test |
| 10 | Cross-scheme separation | Keystream agreement with XChaCha20-Poly1305 for one `(K,N)` | Tested at the derivation level: the label is in the nonce, not the counter (`test_subkey_domain_occupies_nonce_not_counter`) |
| 11 | The implementation matches the design | A divergence between `src/lib.rs` and the specification above | Differential testing against an independent Python reference, published KATs (RFC 8439, the XChaCha draft, BLAKE3's official keyed vectors), the independent implementation in `src/witness.rs` under `ultra`, and the Kani layout harnesses |
| 13 | **The combination needs no joint assumption** (§4.10) | A sixth use of a primitive, or two uses sharing a key/domain/point in a way the table does not list | **Mechanised**: `tests/construction_inventory.rs` counts the cryptographic call sites in the non-test source and fails if the set changes, and pins the two structural lemmas (S1: the BLAKE3 input spaces are disjoint by their 8-byte prefixes; S2: this crate's key-material block is at a different ChaCha20 point than XChaCha20-Poly1305's first data block, for the same key and nonce) |
| 14 | U2/U5 share counter 0 (§4.1) | The key-material block equals the message keystream for one `(K,N,M)` | **Tested** for a spread of inputs (`the_key_material_block_is_not_the_message_keystream`); a real collision needs the master key to compute, so it is a probability statement (`≈2^-352`) rather than an attack |
| 12 | An adversary cannot get unverified plaintext | A decryption failure that returns bytes, or that returns them for a moment the caller can observe | `tests/security.rs`, the wipe contracts, and `tools/fi_check.sh`'s `wipe-skipped` row |
| 15 | **L3.6**: the tag is a PRF in the master key even though the master key is also in its input (§2.1) | A distinguisher for `K ↦ B3(D(K), … ‖ K ‖ …)` that is not a distinguisher for `x ↦ B3(k, x)` at a fixed input | **Not attempted, and not attemptable by test**: it is a statement about a primitive's internal structure. The evidence is BLAKE3's design (the key words *are* the initial state, the keyed mode is flag-separated, no feed-forward carries message words into the key schedule), a separation showing the black-box reduction cannot exist, and the fact that every `H(k ‖ m)`-shaped MAC rests on the same assumption |
| 16 | The tag-collision birthday is `2^128`, not `2^260` (§4.5) | An argument that some state other than the 256-bit chain value binds the tag; or a collision search cheaper than `2^128` | **Derived here, not tested**: it is a bound on computation. What the harnesses do pin is the premise — that the tag is exactly the root XOF of the encoded input — through the published keyed-BLAKE3 KATs, the differential reference implementation, and `src/witness.rs` under `ultra` |

Rows 1, 15 and 16 are the honest boundary: **no test in this repository, and none that could be
written, falsifies or establishes them.** Rows 1 and 15 are the standing bet that every
symmetric scheme makes (plus the one the layout adds); row 16 is a bound derived by hand, and the
tests around it check the premises of the derivation rather than the number.

### 5.1 The falsification procedures: what an attacker runs, and what it costs

The table above says what would refute each claim; this says *how* someone would go about
refuting it, so that "out of reach" is a number attached to an algorithm rather than a feeling.
Per-attempt costs are in primitive calls (one HChaCha20, one ChaCha20 block, one BLAKE3 tag), and
the numbers are work, not wall-clock.

| Target | Procedure | Per attempt | Where it dies |
| --- | --- | --- | --- |
| **Confidentiality** (fresh nonce, no plaintext oracle) | guess the key: for each `K′ ∈ {0,1}^256`, recompute the tag of one known `(N, A, M)` and compare; on a hit, decrypt everything | ≈ 4 calls (HC, CC, tag, first keystream block) | `2^256` attempts; `2^256/Q` for an attacker satisfied with any of `Q` devices (§3, multi-key) |
| **Forgery** | submit `(N, A, C, T)` guesses to the decryption oracle, or search the key space and then forge *legitimately* | 1 verify (oracle) or ≈ 4 calls (key search) | `2^-520` acceptance per fresh tag (L3.6), or `2^256` key search — the *minimum* is the key search, which is what "forgery is bounded by the key" means. Note the offline variant needs the key: without it an attacker cannot even test a guess without the oracle |
| **Key commitment** (a second key that opens a *given* ciphertext) | for each candidate `K′`: derive `(enc_key, enc_nonce)` from the *given* `T`, decrypt `C`, recompute the tag over the recovered `M′`, compare with `T` | ≈ 4 calls | the chance that any one candidate works is `2^-520`, so enumerating the whole `2^256` key space succeeds with probability `≈ 2^-264`: no second key is in reach. **With a 32-byte tag the same procedure expects `≈ 1` success** — this row is what the 65-byte width buys (§4.5) |
| **Tag collision** (the two-time-pad event of §3's Corollary) | *with the key*: fix `N`, `A`, the lengths and the final block; vary the prefix; hash until two prefixes collide in the 256-bit chaining value. *Without the key*: wait for the birthday event in the traffic | 1 hash per candidate (with the key); zero (without) | `2^128` by birthday. The keyless variant is the one to fear, because at the moment it happens the two-time pad costs the observer *nothing* |
| **The derivation route to a non-committing ciphertext** (the one the layout closes) | choose `K₁ ≠ K₂` and search for two keys with equal 512-bit key-material blocks | 1 HC + 1 CC per candidate key | `≈ 2^256` candidates produce a collision by birthday — **and the attack still fails**, because `K` is 32 bytes of the tag input, so the two tags differ in their head. Falsifying the falsifier: the cheapest route we know is closed by 32 bytes of input, not by a wider tag (Thm 2, §4.10) |
| **Encoding and parsing** (length ambiguity, `A`/`M` re-split, trailing zeros, a tag byte that does not reach the ciphertext) | the differential suite's byte-position scans, the KATs, the Kani layout harnesses | — | §4.4 proves injectivity; §7 names the harnesses; §4.7 records the one member of this class that *was* real (a 28-byte tag truncation) |
| **The implementation** (a divergence from the specification, a secret-dependent branch, a skipped wipe) | `tools/ref_impl.py` differential, `src/witness.rs` under `ultra`, ctgrind, the fault campaign, Kani | — | §7 and `tests/README.md` |

### 5.2 What we cannot run, and in what order the argument would fall

Four programmes are out of reach here, and it is worth naming what each would take down, so the
weight of the claims is visible:

1. **A full-round distinguisher for ChaCha20, HChaCha20 or keyed BLAKE3.** Kills L3.1/L3.2/L3.3 and
   with them every claim in this document. Published cryptanalysis reaches 7–8 of ChaCha20's 20
   rounds and reduced-round BLAKE2/BLAKE3 only; a full-round result would be a major one.
2. **A concrete distinguisher for the composed tag map** — the L3.6 gap. Nothing in this document
   can rule it out (there is a separation showing no black-box reduction from L3.3 exists), and
   it is the one place where "BLAKE3 is a PRF" is *not* the whole of what is assumed. §6 lists
   what fails with it.
3. **A collision attack on BLAKE3's 256-bit chaining value cheaper than `2^128`, that can be
   mounted with the final block held fixed.** Kills the collision bound, and with it the
   nonce-reuse story (the two-time pad stops being negligible) — this is the most attractive
   target for a practical attacker, because `2^128` is the smallest number in §4.5's table.
4. **Anything that makes the `2^520` target cheap** — structure in BLAKE3's key-versus-message
   separation that a target search could exploit. That is the same structure L3.6 is about, from
   the other side: L3.6 says the composed map is *unpredictable*; this would say it is
   *invertible*.

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
  inherited proof. L3.6 (§2.1) is part of that exposure: it is a *stronger* statement about
  keyed BLAKE3 than the PRF assumption alone, introduced by putting `K` in the tag's input.
  **If L3.6 fails, everything that depends on the tag fails together** — forgery resistance, both
  commitment properties, and the per-tag key separation that makes nonce reuse survivable — since
  all of them are statements about `(N, A, M) ↦ T`. What does *not* depend on it is the keystream
  primitive itself (`C = M ⊕ KS(enc_key, …)` is the A1/A3 part), which is why the blow-up is
  "all tag-derived properties" rather than "the scheme is an XOR cipher". There is no partial
  failure here: the tag is one object and the assumption is about that object.
* **Collision properties are 128-bit, not 260-bit, and that is a corrected bound rather than a
  new weakness.** The tag's 65 bytes are a view of a 256-bit chain value (§4.5), so a tag
  collision costs a `2^128` birthday search and the two-time-pad leak of §3's Corollary rides
  on the same event; `q²/2^257` is `2^-129` at `q = 2^64`. Forgery and commitment-against-a-given
  tag are target problems and remain where they were — `2^520` per attempt for commitment, `2^256`
  for forgery — because commitment was never a birthday property, so the width still governs it
  (a 32-byte tag would be enumerated in the key space, §4.5). An earlier
  revision of this document and of `README.md` advertised `2^260`; that number was wrong, the
  mechanism is written out in §4.5, and the falsifier is row 16 of §5.
* **The counter-0 coincidence** (§4.1): probability `≈ 2^-352`, not computable without the
  key, not exploitable. A future revision could remove it structurally at the cost of the
  wire format.
* **Determinism and length** (§3 Corollary): equal `(K,N,A,M)` ⇒ equal ciphertext forever,
  and the ciphertext length equals the message length. Both are properties of the mode, not
  defects, and both are documented in `README.md`.
* **Beyond the model.** Side channels, fault injection, a debugger, cold boot, a hostile
  hypervisor: out of scope here and covered where they belong.
* **What "no unknown problem" can and cannot mean.** A break of this construction must be a
  break of L3.1–L3.6 or of an L1 composition theorem; §4.10 proves that the *combination* adds
  no conjunct of its own *that relates the two primitives*, and names L3.6 as the one the
  encoding adds. But a proof that no unknown cryptanalytic relation exists between
  ChaCha20 and BLAKE3 is not something any document can supply — such a relation, if found,
  would present itself as a break of one of those primitive conjectures. The distinction is
  worth stating because the two failures would look identical from the outside and have
  different fixes: a composition flaw is this crate's to fix, a primitive break is not.
* **Not claimed:** that this is a standard, that it has been cryptanalysed by anyone else, or that
  the tag width makes forgery harder than `2^256` — it does not, because forgery is bounded by the
  key: key search dominates whatever the tag length is, and a 32-byte tag would be guessed at
  exactly the key-search level. Nor does the width raise the *collision* level: 65 bytes and 32
  bytes both collide at `2^128`, because both are functions of the same 256-bit chaining value
  (§4.5). What the width *does* buy is the target commitment, and the two sentences coexist
  because they are about different attacks: a second key that opens a *given* ciphertext costs
  `2^520` with 65 bytes, and would cost only `2^256` — the key-search level, i.e. not committing
  at all — with 32. So the width is load-bearing, and the fact that the wire format is frozen is
  the second reason it stays rather than the only one.

**The strongest true sentence about this construction.** It is worth writing the whole audit's
conclusion as one paragraph, because it is easy to read the rest as more than it is:

> Given the six conjectures of §2.1 — with L3.6 the only one that this construction's own layout
> introduces — the scheme is a secure MRAE/DAE authenticated encryption: its confidentiality,
> authenticity, and both commitment properties follow from those conjectures by the reductions
> in §3, its collision-limited properties sit at `2^128` and its target-limited ones at `2^520`
> or the key's own `2^256`, the composition adds no joint assumption about ChaCha20 and BLAKE3
> (§2.3, §4.10), and the reduction's hybrid chain is valid under nonce repetition as well as
> under nonce uniqueness (§3's lemma).

There is *no* proof of security in the standard model, and there cannot be one: the six
conjectures are statements about the infeasibility of computation on primitives nobody has
proven anything about, and a document that claimed otherwise would be wrong for a reason no
amount of internal consistency can repair. What the document establishes is the other half — that
the *construction* is not where the risk is: every risk is one of six named conjectures, each with
a falsifier, and four of the six are about single primitives rather than about this scheme.

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
| The set of primitive uses, and the separations between them | `tests/construction_inventory.rs` |
| The premise of the §4.5 bound — the tag is exactly the root XOF of the encoded input, with no extra step that could add entropy | `test_tag_matches_blake3_over_the_documented_input`, the published keyed-BLAKE3 KATs, `src/witness.rs` under `ultra`, and the Kani layout harnesses |
| The one layout choice that adds an assumption (`K` in the head), with its reason and its caveat | `derive_tag`'s doc comment in `src/lib.rs`, §2.1 (L3.6), §4.10's closing paragraph, and `test_tag_binds_the_key_directly` |
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
| Meet-in-the-middle / dissection | key recovery | there is no key schedule to split: every derived key is a PRF output, so the generic cost is `2^256` (or `2^128` time with `2^128` memory via a classical trade-off) — the same as exhaustive search |
| Related-key | key schedule | **not applicable**: the construction is keyed by one uniformly random 256-bit key, and the per-message keys are PRF outputs of distinct nonces (Thm 1). No key class is exposed |
| Length extension | Merkle–Damgård padding | **not applicable**: BLAKE3 finalises with a flag, and the encoding carries explicit `|A|`/`|M|` (§4.4). Its real descendants — re-splitting `A ‖ M`, trailing zeros — are defeated by A4 and pinned by `test_aad_message_split_is_unambiguous` |
| Collision (incl. Joux multicollisions, herding) | the tag | `2^128` by birthday over the 256-bit chain value, via the fixed-tail procedure of §4.5; no tag width raises it |
| Commitment: invisible salamanders (CMT-1), context commitment (CMT-3) | a ciphertext that opens under two keys or contexts | **`2^520` per attempt** — a target, not a birthday; the `K`-in-input binding closes the derivation route (Thm 2) |
| Forgery (tag guess, second preimage) | the tag | `min(2^256 key search, 2^520 tag guess)` = the key search; the fault-assisted variants are §8.2's subject |
| Two-time pad | a tag collision between two messages | the same `2^128` event; when it happens the observer pays nothing (§3's Corollary) |
| Nonce misuse (related nonce, IV reuse) | SIV's misuse model | **by design**: reuse degrades to equality plus the collision term above; a keystream derived from `(K, N)` alone would leak `M₁ ⊕ M₂` always (`nonce_reuse_does_not_reuse_the_keystream`) |
| Quantum: Grover (key) | key search | `2^128` (§4.5) |
| Quantum: BHT (collisions) | the 256-bit state | ≈`2^85`, model-dependent (§4.5) |
| Quantum: claw-finding (commitment) | the `2^520` target | no structure is known that would help; the target bound is unaffected |

### 8.2 Implementation and physical classes — this is where the configurations differ

| Class | `opt-out` | `hardened` | `ultra` | Evidence |
| --- | --- | --- | --- | --- |
| Timing: branch or index on a secret | defended — constant-time by construction | defended; more constant-time work | defended | ctgrind in three configurations, `tests/variable_latency.rs`, the timing screens (advisory in CI, strict under `verify.sh --deep`) |
| Cache-timing (Prime+Probe, Flush+Reload, Evict+Time) | defended — no tables, no secret-dependent indices | same | same | `tools/cache_profile.sh` (counts invariant for two keys, both phases) |
| Microarchitectural / speculative (Spectre family, port contention, execution-unit timing) | not defended | not defended | not defended — **and the crate contributes no gadget** | Two statements, kept apart because they are different claims. (i) *Here*: the constant-time discipline leaves no secret-dependent index or memory access, and the one secret-dependent branch (the decision) has a **public** outcome, so speculating past it reveals what the caller learns anyway — there is no `if (secret_index < len) { table[secret_index] }` shape to build a gadget from (ctgrind, `cache_profile.sh`). Software measures for gadgets — index masking (`array_index_nospec`), `lfence`/`csdb` barriers, LLVM's Speculative Load Hardening — exist and are the right answer *for code that has a gadget*; adding a barrier here would serialize a comparison whose result is already public. (ii) *Elsewhere*: no library can bound the CPU's speculation in other code, nor the non-speculative microarchitectural channels (port contention, and the Hertzbleed-class power/frequency channel that constant-time code does not address at all) |
| Power / EM (SPA, DPA, CPA, templates) | not defended | not defended | not defended, **but partly by construction** | needs proximity and equipment, and software algorithms for it exist — §8.5 names them (masking, hiding, fresh re-keying, leakage-resilient designs) with the model each is proven in. One of them is *already the shape of this construction*: every message runs under a key derived from its own tag, so an attacker cannot average traces of the payload cipher across messages at all (the same nonce and message replay one trace; a different message is a different key). That is fresh re-keying (Medwed–Standaert), the standard software mitigation, arrived at here for other reasons. The residual attackable surface is the per-nonce derivation — roughly 1.5 ChaCha20 blocks under the **master** key — which is repeatable and therefore the honest target. No leakage assessment has been run, so this is a structural argument, not a measured claim |
| Single fault, decision *value* | **not defended** — accepting sites exist | defended: two gates, separate branches, fail-closed | defended | README fault table; `tools/fi_check.sh` rows per configuration |
| Single fault, decision *instruction* (skip or corrupt a byte/bit) | **not defended** (3 accepting in the bit model, inside the decision) | 0 | 0 | `tools/fi_instruction.sh`, both models |
| Fault that rewrites the stored tag | not defended | not defended | **defended** (`dual-mac`: an independent recomputation compared against both values) | `dual-mac-blocks-tag-substitution` row |
| Fault in the *shared derivation* (tag, keyed BLAKE3, SIMD) | not defended | not defended | **detected** by the second implementation — with a stated boundary: both decrypt paths and the allocating `encrypt`; the in-place encrypt carries no cross-check | README "What the witness is"; `tests/ultra.rs`'s source-shape test |
| Two independent faults, synchronized glitch, laser injection | not defended | not defended | not defended | software redundancy (which `ultra` has twice over) cannot cover a fault that hits both computations or the arithmetic beneath them. Software algorithms in this class do exist — infective computation, randomised scheduling, tamper-resilient encodings, key ratcheting with destructive read-out (§8.5) — and each is proven only in a *model* (bounded faults, unknown location); an attacker with precise, repeated faults defeats any of them, and validation needs a fault bench. Not claimed here |
| Fault-assisted key recovery (DFA) | not defended | not defended | not defended, **with a reduced payoff by construction** | same software caveats as above, plus a structural fact worth stating: classic DFA recovers *long-lived* round keys, and nothing in this construction is long-lived beyond the master key. Every intermediate an attacker could recover by faulting the payload path — `enc_key`/`enc_nonce`, `mac_key`, the tag — is **per message** (Thm 3), so it decrypts exactly that message and nothing else; the honest DFA targets are the per-nonce derivation (`HChaCha20(K, N₁)`, one ChaCha20 block) and the tag pass, where the master key is in use. Faulting those is faulting `ultra`'s *witness* territory and is §8.2's row above |
| Combined fault + side channel | not defended | not defended | not defended | the composition of two out-of-scope models |
| Rowhammer-class hardware faults | not defended | not defended | **detected in the stored key**: `LockedKey` keeps an 8-byte BLAKE3 tag beside the key and verifies it (constant time) on every use, so a flipped key page panics at first use instead of decrypting with a key that is not the caller's (+42 ns per use, measured). It does not stop the flips — ECC or TRR does — and a fault that rewrites the tag as well is invisible |
| Swap / hibernation exposure of a key | not defended | not defended | `locked`: `mlock` on the `LockedKey` page | `tests/locked.rs`, read back from the kernel's `VmLck` |
| Core dumps | not defended | not defended | `locked`: `MADV_DONTDUMP`, and `MADV_DODUMP` restores inclusion on unlock | the `VmFlags` test |
| Cold boot / memory remanence | not defended | not defended | not defended | memory encryption at rest, or a key that never exists in the host's RAM (an HSM). The *userspace software* attempt exists — TRESOR and its descendants keep the key in CPU debug registers so it is never in DRAM — and it does not hold on a general-purpose OS: a debug register is readable by any tracer and the kernel may clobber it at a context switch, so it needs kernel cooperation to be sound. The window can be narrowed (wipe early, lock, refuse debugging) and is not closed |
| Debugger, ptrace, `/proc/<pid>/mem` | not defended | not defended | **opt-in defence**: `locked::deny_debugging()` sets `PR_SET_DUMPABLE = 0`, after which the kernel refuses `PTRACE_MODE_ATTACH` and `/proc/<pid>/mem` even for the same user without `CAP_SYS_PTRACE`. Not automatic — it is process-wide policy that also removes core dumps — and root (or `CAP_SYS_PTRACE`, or a hypervisor) is unaffected | `deny_debugging_is_enforced_by_the_kernel_and_reversible`, which reads the flag back from the kernel and observes `/proc/self/mem` being refused |
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
| Commitment break (`2^520` target, `2^-264` over the key space) | out of reach | none |
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
  index or memory access, so it presents no known Spectre-v1 gadget, and the one secret-dependent
  branch has a public outcome. What remains is not this crate's to fix (the CPU's speculation, the
  OS's mitigations, other code in the process), so a barrier added here would be theatre.
* **Power / EM** — *software mitigations exist and are not claimed*: masking with fresh
  randomness is the known answer, at 10–100x cost, with the compiler free to undo it, and with a
  claim whose falsification needs a leakage-assessment lab (§8.5 — the earlier revision of this
  bullet said "unfalsifiable", which was wrong: TVLA and ISO 17825 exist, this repository just
  has no hardware to run them on). The one mitigation that *is* here needs no lab to see: the
  per-tag key derivation is fresh re-keying, so payload traces cannot be averaged.
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
| Power / EM (DPA, CPA) | Boolean and arithmetic **masking** (ISW, threshold implementations, domain-oriented masking); **hiding** (operation shuffling, random delays, dummy rounds); **fresh re-keying** / key ratcheting; leakage-resilient designs | Masking is proven in the **probing model** and evaluated by **TVLA / ISO 17825** on real hardware — so it *is* falsifiable, with a lab | Cost 10–100x; the compiler can undo a software mask (needs asm barriers or a masked-type discipline); validation needs a scope. **One of these is already in the construction** (see the table row above): fresh re-keying is what per-tag key derivation *is* |
| Faults (single, multi, laser, DFA) | **Infective computation** (Prouff–Giraud: on detection, randomise the output rather than reject); **redundancy with diversity** and randomised scheduling; **tamper-resilient encodings** and **AMD codes**; key ratcheting with destructive read-out; non-malleable codes for continuous tampering | Proven under models: bounded faults, unknown location, no fault in the verifier, encoded secrets. A bench (laser/EM) is what falsifies a claim | `ultra` already has diversity twice over, and a **stored-secret integrity check** (the `LockedKey` tag, above) is the implemented part of the AMD-code idea. Infectivity is deliberately *not* adopted: this crate's detected faults are rejections rather than randomised outputs, because a rejection is what keeps a fault on the encryption side from becoming a ciphertext the caller cannot distinguish from a good one, and because the payoff of a recovered intermediate here is one message (the row above). The rest — encoded secrets, randomised scheduling, non-malleable codes — needs a bench and a redesign of the key path, not a flag |
| Speculative execution | `array_index_nospec`-style index masking, `lfence`/`csdb` barriers, LLVM **Speculative Load Hardening**, retpolines, dual-page mitigations | Falsified by a PoC gadget on the target microarchitecture | This crate has no gadget to harden (no secret index, no secret-dependent access) and the one secret-dependent branch has a public outcome; a barrier here would serialize a comparison the attacker already knows the result of |
| Cold boot / remanence | **TRESOR** and descendants (key lives in CPU debug registers, never DRAM), Sentry/AESSE-style page encryption, sealed-key suspend | Soundness depends on the OS: debug registers are readable by any tracer and clobbered at context switches, so it needs kernel cooperation | A library cannot hold a key out of RAM on a general-purpose OS; the honest measures are deployment-level (encrypt the image, lock and wipe early) |
| Rowhammer | Guard-page allocators that keep secrets off vulnerable rows, periodic re-touch to force refreshes, **integrity checks** on stored secrets | Falsified by a flip that also lands in the redundancy; ECC/TRR is the only prevention | **The integrity check is implemented**: `LockedKey` stores an 8-byte BLAKE3 tag beside the key and verifies it on every use (+42 ns, measured), so a corrupted page fails loudly at first use. Guard pages and refresh loops are not, because they cannot be validated here and would not stop flips |
| Debugger / ptrace | `PR_SET_DUMPABLE = 0`, `PR_SET_PTRACER`, seccomp/Yama; **tracer detection** (`TracerPid` in `/proc/self/status`) with key destruction on attach | Enforced by the kernel up to `CAP_SYS_PTRACE` | The first is **implemented** (`locked::deny_debugging()`); detection-and-destroy is deliberately not: it races the tracer (who reads the key first), it fires on legitimate profilers, and it is the behaviour of malware rather than of a library |
| Supply chain | Reproducible builds, pinned SHAs, `cargo-deny`, signed releases | Falsified by a divergence between source and artefact | Applied — see the workflow headers |

The pattern to take away: for each of these the question is not "*can* software do something" but
"**is the guarantee unconditional, and can it be falsified here**". Masking, tamper-resilient
encodings and TRESOR are real answers with real models, and none of them is verifiable in this
repository — no scope, no fault bench, no kernel cooperation. That is a statement about what this
project can *claim*, not about what cryptography can do.

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
