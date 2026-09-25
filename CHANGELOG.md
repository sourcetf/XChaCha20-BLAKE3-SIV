# Changelog

Short, and deliberately about **the wire format** first: this construction is not a
standard, so a consumer needs to know when the bytes move. Versions below refer to
construction revisions; the crate version in `Cargo.toml` is `0.1.0` and no release
tags have been cut yet.

## Unreleased

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
