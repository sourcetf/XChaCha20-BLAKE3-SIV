# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, through GitHub's "Report a
vulnerability" button on this repository (Security → Advisories) rather than in a
public issue. Include, as far as you can, the commit or version, a minimal
reproduction, and what you expected instead.

We aim to acknowledge a report within **7 days**, and to reach an assessment
(confirmed / not a vulnerability / needs more information) within **30 days**.
Credit is offered in the advisory unless you prefer otherwise.

## What is in scope

Anything that breaks the properties claimed in `README.md`:

- recovering the plaintext or the key from ciphertext, tag, AAD and nonce;
- forging a tag, i.e. having a message accepted that the key holder did not produce;
- breaking key or context commitment — two different `(key, nonce, aad, message)`
  tuples with the same tag;
- a **secret-dependent branch or memory access in this crate's own code**. In the
  **AEAD path** the README documents exactly one tolerated decision — the SIV
  accept/reject, which cannot be removed because SIV has to decrypt before it can
  verify — and it lives in a function of its own (`accept_or_reject`), which `ultra`'s
  encrypt-side witness cross-check also goes through rather than branching at its own
  call site. `tools/ctgrind.sh` is the mechanical check for it, including for the claim
  that the tolerance covers nothing else *in the code ctgrind runs*, which it verifies
  by planting a secret-dependent branch inside `decrypt` and requiring the run to fail.
  It runs in three configurations — default, `--no-default-features`, and `--features
  ultra` — and the third is what caught the encrypt-side branch when it was written as
  an `if`. It does **not** exercise `locked`'s fail-stop: `LockedKey::as_bytes`
  branches on an integrity tag of the stored key and panics when it differs
  (`check_integrity`, `src/lib.rs`), and `tests/ctgrind.rs` drives only the AEAD entry
  points with no `LockedKey` in sight. The crate header names that branch, alongside
  the decision and the witness fold, as one of the three secret-dependent branches it
  tolerates, and documents why it reveals no key bit under no-fault operation;
- a reachable panic, or an unbounded allocation, from attacker-controlled input;
- unsoundness in the `unsafe` blocks — see `README.md` for what Miri, Kani and the
  sanitizer runs cover, and note that every block carries a `// SAFETY:` comment
  that a CI lint now enforces.

What is *proven*, what is *assumed*, and what would *refute* the claims above is
written out in [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md): the construction as a
tuple of functions, the assumptions as games, the SIV/DAE reduction with its bound, the
composition hazards one by one, and a falsification table. A report that shows one of
those theorems is wrong is the most valuable kind this project can receive.

## What is explicitly not in scope

Listed so that a report is not needed for them. Everything under "What is not
defended against" in `README.md`:

- **fault injection**, including the residual attacks that the `hardened`
  feature does not cover (two independent faults, a targeted fault inside the tag
  computation, key recovery by differential fault analysis, extracting unverified
  plaintext after a skipped wipe). Nothing here has been validated on a real
  fault-injection bench;
- **physical side channels** beyond the constant-time code paths — power, EM, and
  cache-timing measurements on real hardware;
- **denial of service**, which no countermeasure in this crate attempts;
- **nonce reuse by the caller**, and the application's own protocol. The
  construction is misuse-resistant, which is a fail-safe for an occasional slip,
  not a licence to reuse a nonce;
- **replay, and the freshness of a message.** Decryption is a deterministic
  function of `(K, N, A, C, T)`, so a byte-identical retransmission authenticates
  again, forever: a legitimate retry and an attacker's replay are the same bytes,
  and no symmetric AEAD can tell them apart. "It authenticated" means "someone
  holding the key produced this at some point", never "this is new". Freshness
  needs protocol-layer state — a counter, a challenge, a timestamp window — and
  an application that treats authentication as freshness has a replay hole.
  `README.md` lists this under "What this crate cannot fix for you";
- "it differs from scheme X". The README's first section says this is **not a
  standard** and is not interoperable with anything.

## Versions

The byte format is **frozen at construction revision `v0.3`** — it will not change
without a revision bump, a `CHANGELOG` entry and the known-answer vectors updated in
the same commit (see README, "Wire format: frozen by revision, and the crate is
0.x"). What is *not* frozen is the Rust API: the crate is `0.x` until a deliberate
1.0, so pin an exact version rather than a range. (An earlier version of this file
pointed at a README section called "Wire format is not frozen", which no longer
exists and whose claim is no longer true. Revision `v0.3` moved the format once — the
tag became two-level and the key-dependent-input assumption L3.6 was removed — which
is exactly the bump-plus-CHANGELOG-plus-vectors procedure this paragraph describes.)
There are no maintained release branches:
security fixes land on `main`, and the version currently in `Cargo.toml` is the only
supported one.
