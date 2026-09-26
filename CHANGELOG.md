# Changelog

Short, and deliberately about **the wire format** first: this construction is not a
standard, so a consumer needs to know when the bytes move. Versions below refer to
construction revisions; the crate version in `Cargo.toml` is `0.1.0` and no release
tags have been cut yet.

## Unreleased

### Input bounding, and where the warning lives

- **`decrypt_bounded(key, nonce, aad, ciphertext, tag, max_len)`**: the caller's
  length policy, checked *before* the plaintext buffer is allocated, returning
  `Error::MessageTooLong` and allocating nothing when it refuses. `decrypt` allocates
  as large as its ciphertext argument (up to `MAX_MSG_SIZE`, 256 GiB), which is the
  most likely way to turn a remote request into memory exhaustion, and a warning in an
  error variant's documentation is not where a caller looks.
- The warning is now on the README's first page and in `decrypt`'s first paragraph,
  next to the entry point it is about; the crate-level API list names
  `decrypt_bounded`; and `Error::MessageTooLong` documents both limits (the format's
  and the caller's).

### `hardened` is the default

- The `hardened` feature is **on by default** (`default = ["hardened"]`). A hardening
  property that most callers never enable is a hardening property most callers do not
  have, and the measured cost is +10.8% at 64 bytes, +8.9% at 256, +3.6% at 1 KiB and
  below +4.5% from 4 KiB up (against `--no-default-features`). The opt-out is
  `default-features = false`; it stays measured, tested, and covered by its own CI
  runs (`tools/ctgrind.sh --no-default-features`, `tools/fi_check.sh`'s `*-plain`
  rows).
- Every tool that assumed "hardened means `--features hardened`" was updated to the
  new axis: `tools/fi_check.sh`'s rows (including a `clean-plain` row),
  `tools/fi_instruction.sh`'s two scans (now `plain (no hardened)` vs
  `hardened (default)`, both 0 accepting bytes), the ctgrind CI step, and
  `tools/mutation_check.sh`, whose `ct_eq` -> `==` mutation is compiled only in the
  opt-out build and therefore runs there now.

### Release hygiene

- `mutants.out/` is refreshed from HEAD and is now documented as evidence that must
  match it (tests/README.md). Refreshing it immediately found three **uncaught**
  mutants in the new `decrypt_bounded` bound check: the mutation run named only
  `--test decision`, and the suite that witnesses the bound is `tests/security.rs`.
  The run now covers both suites, and is 9 mutants / 7 caught / 2 unviable / 0
  uncaught.
- A doc comment that had been split by an inserted test (`src/lib.rs`, the
  contiguous-buffer tag test) is repaired rather than left as a fragment.
- `.gitignore`: `fuzz/fuzz-*.log` in addition to `/fuzz-*.log` — the fuzz runs write
  their per-worker logs into `fuzz/`, which the old pattern did not match.
- The README now keeps the two version numbers apart explicitly: **construction
  revision** (the bytes, `v0.2`) and **crate version** (the Rust API, `0.1.0`), with
  the freeze and pinning policy stated in both places.

### Gates that were weaker than they claimed

- **The mutation run now covers the decision, and stops discarding killable mutants.**
  Its filter was `decrypt|passed_gates` — `passed_gates` does not exist in the tree, and
  the part that still matched (`decrypt`) had stopped containing the branches when the
  decision moved into `accept_or_reject`. The filter names the decision now, and the
  exclusion is `&` → `|` only: `x | x == x & x` is equivalent, but `x ^ x == 0` makes a
  gate reject everything, which the decision test kills — so the old `[|^]` exclusion
  discarded four killable mutants and the reason given in the README was wrong for half
  of them. Measured after the fix: 13 mutants, 11 caught, 2 unviable, 0 uncaught.
- **`tools/gate_selftest.sh`, and the exit-3 convention it checks.** `tools/ctgrind.sh`
  answered `SKIPPED: valgrind not found` with exit 0, and `verify.sh` — which only
  skipped when the script file was missing — counted the stage as *run and passed*, so
  `--deep` could report a complete run without the constant-time check having executed.
  "Could not run" is now exit 3 in every tool that can say it (ctgrind, cache_profile,
  mutation_check), `verify.sh` maps it to a skipped stage, and the new self-test proves
  it by hiding the tooling (a non-executable `valgrind` stub first on `PATH`, so it
  works on runners that do have a system valgrind).
- **The instruction-level scan's criterion is absolute**: it required
  `hardened ≤ plain`, so 50 accepting bytes in each build would have passed as "no
  worse than". It now requires **zero** accepting bytes in both, which is what the
  README claims.
- **The timing screen is split**: `timing-instrument` blocks on the detectability
  control (`timing_screen_can_detect_a_real_difference`, asserted `t > 10`, measured
  3244) on every push, and the two statistical *screens* stay advisory — the same
  measurements as before still rule out gating them on a shared runner, but an
  instrument that has rotted no longer passes silently.
- **The coverage job is a gate**: `--all-features` (the `hardened` and `rng` paths were
  absent from the statistics entirely), a **95%** line floor against a measured 97.46%
  (1458/1496 on the development host), and no `continue-on-error`. The floor is global
  on purpose — a per-target threshold would need exclusions, and a gate satisfiable by
  editing its exclusions is not a gate.
- **`--quick` instruction-level sweep on every push.** The CHANGELOG promised "branches
  on every push" and the tool's header claimed it ran in the mutation job; it only ran
  in the weekly `wide` job. Now it runs in both.

### Claims that did not match the implementation

- `tools/gen_test_vectors.py` now calls `ref_impl.self_check()` before emitting
  anything. Its docstring, `tests/differential_reference.rs` and `tests/README.md` all
  said the reference is self-checked before vectors are produced; only `verify.sh`
  arranged that, so a direct run of the generator produced a fixture from an unanchored
  reference.
- **Two tests are renamed to what they assert.** `test_nonce_misuse_resistance` checked
  that two nonces give two tags (nonce *sensitivity*, not misuse resistance) and
  `test_key_commitment` that two keys give two tags (not commitment). The first is now
  `test_message_swap_under_a_reused_nonce_is_rejected`, which checks the property SIV
  actually provides — a ciphertext must not authenticate under another message's tag —
  and the second is `test_tag_changes_when_only_the_key_changes`, with a pointer to
  `test_tag_binds_the_key_directly` for the mechanism commitment rests on.
- **`kat_regression_lock` is described as a lock, not a witness.** It is a second copy
  from the same generator: it catches an expectation edited in-crate, and its
  independence ends there; the independent witness is the differential fixture against
  `tools/ref_impl.py`.
- **The fuzz loop asserts its own docstring.** `Ok(_) => {}` in the unstructured branch
  is now `panic!("a random tag authenticated")` (2^-520, so it is unreachable), and in
  the structured branch an `Ok` must equal the plaintext that was encrypted.

### Coverage ceilings, written down

`tests/README.md` now records what the checks do not reach: the exhaustive
byte-position scans stop at msg_len ≤ 300 and aad_len ≤ 130 (above that the coverage is
sampling), the differential fixture is 55 vectors and a lock rather than a sample (the
sampling is the scheduled 4000-vector differential and the fuzzing), there is no
performance gate (and why), and the coverage floor is global rather than per-path.

### The call site, and the strongest fault model

Two single-fault attacks that the previous hardening did not cover, both now either
defended or measured:

- **The caller's accept decision was one branch on one value.** Disassembly of the
  previous revision shows exactly what that means: `call accept_or_reject`,
  `cmpb $0xff,0x20(%rsp)`, `je` — one corrupted value, or one flipped bit in that
  jump's opcode (`je` 0x84 / `jne` 0x85), and a forgery is accepted. The decision now
  writes **two slots, one per gate, each written by its own gate's flow**, and the
  caller has **two checks in series that each jump to the rejection**: accepting is
  the fall-through of both. A corrupted value leaves the other slot saying "rejected";
  a corrupted branch opcode lands on the other check; `tools/fi_check.sh`'s new
  `one-check-neutralised` row is that attack and it is rejected, while
  `both-checks-neutralised` (two faults) is accepted and pinned. The wipe moved to the
  caller, so a skipped call still wipes the plaintext it never verified.
- **What is left is measured, not claimed away.** `tools/fi_instruction.sh --bits`
  flips every bit of the decision and its call sites instead of neutralising bytes —
  the symmetric fault model, which the header and the README used to wave at the
  second gate. It runs `--quick` on every push and in full in the scheduled job.
  Result, full sweep: the **default (hardened) build accepts none of 44856** single-bit
  faults; the **opt-out build accepts exactly one**, on the opcode of the decision's own
  arm selection (the `je`/`jne` adjacency), because a single gate has nothing behind it.
  The tool pins that count at 1 — a change that makes it two fails — and the README's
  table records the site. Until this ran, the README *claimed* the second gate covered
  the symmetric case; now the claim is a number, and the number says the claim was right
  for the default build and wrong for the opt-out one.
- The decision's slots are written **inside branch arms**, not selected from a
  tainted condition: `*out = if cond { Ok } else { Err }` compiles to a
  `setcc`/`cmov` on the secret-derived condition, which makes the discriminant
  secret-derived itself — and then the caller's check on it is a secret-dependent
  branch *outside* the one function `tests/ctgrind.supp` permits (measured: six
  memcheck reports against `decrypt`). Written as arms, the byte that lands in a slot
  is a constant each path writes, and ctgrind stays clean in both configurations.
- **`computed_tag` replaced by a constant or by the received tag** is the strongest
  model in the table and it defeats the two gates *together* — they compare the same
  two values, so making them equal satisfies both. The README's row now says that
  plainly, and says what would be needed instead (a second, independent tag
  computation, i.e. a second MAC pass per message) rather than implying the gates
  cover it.

### Release policy

- **The byte format is frozen at construction revision `v0.2`.** It will not change
  without a revision bump, a `CHANGELOG` entry and the known-answer vectors updated in
  the same commit; `kat_regression_lock` re-asserts the published bytes from a fixture
  no in-crate change can edit, so the promise is mechanical rather than stated. (Two
  version numbers are in play and are kept apart: the **construction revision**
  `v0.2` is the bytes, and the **crate version** `0.1.0` is the Rust API. The
  construction has changed once, v0.1 -> v0.2.)
- **The crate is `0.x` until a deliberate 1.0**, because the Rust API is not frozen:
  consumers should pin an exact version rather than a range, and treat the API (not
  the bytes) as the unstable part. It is not interoperable with any standard and no
  specification exists for it.
- `hardened` is **on by default**: a hardening property that most callers never enable
  is a hardening property most callers do not have. The opt-out (`default-features =
  false`) exists, is measured, and is covered by the same CI runs as the default.
- **Bound untrusted input before `decrypt`.** It allocates as large as its ciphertext
  argument; `decrypt_bounded(..., max_len)` enforces a caller policy before the
  allocation, `MAX_MSG_SIZE` is public for the pre-read check, and the README states
  this on its first page rather than in an error variant's documentation.

- **The decision is one function body, not two `#[cfg]`-selected definitions.** The
  `hardened` gates now live inside the same `accept_or_reject` the default build
  compiles, with the second gate under `#[cfg(feature = "hardened")]`. Reasons, in
  order of how much they mattered: `cargo mutants` does not evaluate `cfg`, so the
  variant that was not compiled in a run read as an *uncaught mutant* — and a filter
  that still matched the two entry points had already let the decision fall out of
  that campaign silently (`-F 'decrypt|passed_gates'` names a function that no longer
  exists). One body means the hardened build contains every mutatable line the
  default build has, so one ~20-second run covers both: 5 mutants, 4 caught, 1
  unviable, none uncaught. The default build passes the same `Choice` for both gates,
  so it computes one comparison and not two.
- `tests/decision_scope.rs` grew the assertions this needs: exactly one definition,
  exactly two branches of which exactly one is the opt-in gate, and no
  `#[cfg(not(hardened))]` branch of its own.

- **The accept/reject decision is fail-closed.** The outcome is written through a
  parameter the caller initialises to a rejection, instead of being returned by
  value: a fault that *skips the decision call* then accepts nothing, where before
  it accepted whatever the ABI left in the return slot. Found by measurement, not
  reasoning — `tools/fi_instruction.sh` reported six single-byte faults in `decrypt`
  that accepted a forgery with a returned outcome, and none with this shape. It is
  also what makes the `hardened` gates reachable: one skipped call used to bypass
  both of them at once.
- **`random::generate_key` returns a `Key` that zeroizes on drop** (it used to
  return `[u8; 32]` and leave that array to the caller). `Key` derefs to
  `[u8; KEY_LEN]`, so existing call sites are unchanged; `Debug` prints no bytes and
  no fingerprint of them; `Zeroize`/`ZeroizeOnDrop` are implemented. **API change**
  (pre-1.0), and it is the one secret this crate generates that has no other copy
  anywhere.
- **`MAX_MSG_SIZE` is public**, `Error::AllocationFailed` exists, and the plaintext
  buffer is allocated fallibly (`try_reserve_exact`): an allocator refusal is now an
  error a service can report rather than a process abort. `Error` is
  `#[non_exhaustive]` so the next variant is not a breaking change. This does not
  bound the input for the caller — a request the kernel *accepts* can still be
  OOM-killed while it is written to — which is exactly why the constant is public.
- **The `hardened` second gate is guaranteed to be a recomputation**, not a copy:
  both operands are re-read with a volatile read. The two gate expressions are
  identical, so an optimizer was entitled to merge them into one comparison, which
  would have left a single fault carrying both gates. `tests/decision_scope.rs` pins
  the mechanism, and `tools/fi_check.sh` gained the row that makes the claim
  behavioural: with the second gate replaced by a copy of the first, the fault that
  the `gate0-value-forced` row survives now accepts the forgery.
- New tests: `Key` wipe-on-drop (read back out of its storage after an in-place
  drop) and its redacted `Debug`; the fallible allocation; `MAX_MSG_SIZE` reachable
  from outside the crate; the fail-closed decision shape; the volatile re-read of
  the second gate. The control-flow tripwire in `tests/variable_latency.rs` moved
  from 13 to 15 `if`s for the two `if decision.is_ok()` branches it found — the
  tripwire doing its job.
- README: a new "What this crate cannot fix for you" section — deterministic
  encryption, revealed message length, the scope of zeroization (volatile-store
  level: not swap, not core dumps, not cold boot), input bounding, the destroyed
  buffer after a failed in-place decryption, distinguishable length errors, and the
  unfrozen wire format — each stated with where the answer belongs instead.
- The instruction-level fault-scan counts were re-measured after the changes above:
  3920 bytes in the default build, 5680 in the hardened one, none accepting.

- **Fixed: ctgrind's suppression covered whole entry points, not the decision.**
  `tests/ctgrind.supp` named `decrypt` and `decrypt_in_place_detached`, and a
  valgrind entry permits *every* conditional jump in the function it names — so a
  secret-dependent branch added inside `decrypt` passed the check (measured on a
  copy: 6 reports with no suppression file, 0 with it). The decision now lives in
  `accept_or_reject`, a function of its own that both entry points call and that
  returns a `Result` so no caller branches on it a second time; the suppression
  names that function and nothing else. **No wire-format change**, and the decision
  itself is unchanged in structure (including the `hardened` gates, whose
  instruction-level fault scan was re-run: 3920 bytes in the default build and 5680
  in the hardened one, none accepting).
- `tools/ctgrind.sh` now refuses to run unless every suppression entry names
  `accept_or_reject`, and plants a secret-dependent branch inside `decrypt` and
  inside `decrypt_in_place_detached` in a throwaway copy and requires its own check
  to *fail* — the control for the scope of the suppression. It also no longer dies
  silently when it cannot find its test binary (a failed `grep` under
  `set -o pipefail` killed the script before the diagnostic could print).
- `tools/fi_check.sh` and `tools/fi_instruction.sh` follow the decision into its
  own symbol, so both still target it; `tools/mutation_check.sh`'s `ct_eq` → `==`
  mutation is still caught.
- New tests: `tests/decision_scope.rs` (the suppression file may name only the
  decision; the suppressed function's body holds only the decision's branches) and
  a control-flow inventory in `tests/variable_latency.rs` that fails when the crate's
  branch counts change, so the numbers in `README.md` and `SECURITY.md` cannot go
  stale unnoticed — which is how the previous count was found to be stale.
- **Fault-injection hardening** (`hardened` feature, **on by default**): the
  accept/reject decision becomes two independently recomputed checks with separate
  branches, written fail-closed, and the second gate is a guaranteed recomputation
  rather than a copy (see the entries above). **No wire-format change**; the KATs and
  both differential fixtures replay unchanged. Measured cost of the default build
  against `--no-default-features`: +10.8% at 64 bytes, +8.9% at 256, +3.6% at 1 KiB,
  below +4.5% from 4 KiB up.
- **Fault-injection check** (`tools/fi_check.sh`) plus its detector
  (`tests/decision.rs`), and a CI step for both.
- **Large-message reference vectors** (`tests/vectors_differential_large.txt`):
  six sizes from 2 KiB to 1 MiB as digests, so the sizes above the tag's
  contiguous-buffer threshold are witnessed against the reference implementation
  rather than only against this crate's own two call shapes.
- Lint gates: `clippy::undocumented_unsafe_blocks`, and `missing_docs` for the
  library. `unsafe_op_in_unsafe_fn` is recorded in `Cargo.toml` as deliberately
  pending.
- `SECURITY.md`, and a scheduled "wide audit" job for the checks that are too slow
  or too noisy to gate every push.

## v0.2

- Replaced the v0.1 Poly1305/CTX-tag construction with keyed BLAKE3 and a 65-byte
  tag, and added the contiguous-buffer fast path for mid-sized messages.
  **Wire format changed**: v0.1 ciphertexts and tags do not decrypt.

## v0.1

- Initial construction: XChaCha20 nonce extension (HChaCha20 subkey), Poly1305 with
  a CTX-transformed 32-byte tag.
