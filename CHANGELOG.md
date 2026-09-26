# Changelog

Short, and deliberately about **the wire format** first: this construction is not a
standard, so a consumer needs to know when the bytes move. Versions below refer to
construction revisions; the crate version in `Cargo.toml` is `0.1.0` and no release
tags have been cut yet.

## Unreleased

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
- **Fault-injection hardening, opt-in** (`hardened` feature): the accept/reject
  decision becomes two independently recomputed checks with separate branches.
  **No wire-format change**; the KATs and both differential fixtures replay
  unchanged. Measured cost +10.8% at 64 bytes, below +4.5% from 1 KiB up.
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
