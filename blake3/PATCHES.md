# Vendored BLAKE3 1.8.7 — local patches

Source: the crates.io `blake3 1.8.7` package (published 2026-08-20), copied verbatim
except for the changes below. The parent `Cargo.toml` reaches this copy through
`[patch.crates-io]`.

| Report ID | File(s) | Change |
| --- | --- | --- |
| D-01 (Medium) | `src/platform.rs` | `Platform::hash_many` sends complete SIMD groups to the kernels and the remainder (fewer than one full group) to `portable::hash_many`. The AVX2/AVX-512 2/4-wide tail loaded from `inputs[0]` at +16/+32/+48; reproduced with a guard page (`cargo run --release --example blake3_guard_probe` in the parent) as `STATUS_ACCESS_VIOLATION` at `n=2` on AVX512. Empty input is now a no-op (D-09's `blocks == 0` shape). |
| D-02 (Low) | `src/platform.rs` | Multi-block `xof_many` uses the documented `compress_xof` loop instead of unix AVX-512 assembly that does not zero-extend `block_len`/`flags`. Single-block output is unchanged. |
| Parent audit D1 (Medium) | `src/platform.rs` | A non-multiple-of-64 `xof_many` output (1..=63 bytes) is computed with `compress_xof` and copied as a prefix. The single-block AVX-512 path wrote a full 64-byte block in release (up to 63 bytes past the caller's slice), where the `debug_assert` was compiled out. |
| D-04 (Low) | `src/lib.rs` | `Hasher::reset` clears `initial_chunk_counter` (set by the hazmat `set_input_offset`). Reproduced as a `finalize` assertion failure before the fix. |
| D-05 (Low) | `src/hazmat.rs` | `left_subtree_len` uses `div_ceil(2)`, so `u64::MAX + 1` no longer wraps. Reproduced as `1` instead of `1 << 63`. |
| D-06 (Low) | `src/lib.rs` | `OutputReader::position` uses saturating arithmetic at the end of the addressable stream. |

Regression tests live in the parent, `tests/blake3_fork_equivalence.rs`: `hash_many`
against portable for 0..=17 inputs and both counter modes, `xof_many` for 1..=4 blocks,
short `xof_many` outputs canaried for 1..=63 and compared with portable for 0..=130,
`reset` after a hazmat offset, and `left_subtree_len(u64::MAX)`. The fixed and
unfixed `hash_many`/`xof_many` outputs are byte-identical for valid inputs; the
parent's 64 KiB/1 MiB/16 MiB keyed-hash tags were also identical, and steady-state
throughput was unchanged within host noise.

**Publication caveat.** A crates.io package does not carry this `[patch]`; the parent
`cargo package` resolves `blake3 = "1.8"` from crates.io. Publishing the fixed crate
requires publishing this fork under its own package/version and switching the parent
dependency to that package. The parent README and `Cargo.toml` state this.

**Not patched.** D-03 (narrow `block_len`/`flags` ABI arguments in the unix
SSE2/SSE4.1 assembly) remains: normal Rust/C callers zero-extend, and only a
hand-written FFI caller with dirty high bits can observe it. D-09's explicit
`Platform` variants remain constructible without a CPU check, as upstream documents
("for benchmarks"); the parent never calls them. D-07 (upstream published-crate test
dev-dependency) and D-08 (riscv64-musl getrandom) are outside this fork's use.
