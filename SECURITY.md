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
- a **secret-dependent branch or memory access in this crate's own code**. The
  README documents exactly one tolerated decision (the SIV accept/reject on
  decryption), it lives in a function of its own (`accept_or_reject`), and
  `tools/ctgrind.sh` is the mechanical check for it — including for the claim that
  the tolerance covers nothing else, which it verifies by planting a
  secret-dependent branch inside `decrypt` and requiring the run to fail;
- a reachable panic, or an unbounded allocation, from attacker-controlled input;
- unsoundness in the `unsafe` blocks — see `README.md` for what Miri, Kani and the
  sanitizer runs cover, and note that every block carries a `// SAFETY:` comment
  that a CI lint now enforces.

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
- "it differs from scheme X". The README's first section says this is **not a
  standard** and is not interoperable with anything.

## Versions

The wire format is **not frozen** before 1.0 (see README, "Wire format is not
frozen"). There are no maintained release branches: security fixes land on `main`,
and the version currently in `Cargo.toml` is the only supported one.
