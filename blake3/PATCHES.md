# Vendored BLAKE3 1.8.7 — local patches

Source: the crates.io `blake3 1.8.7` package (published 2026-08-20), with the source
changes below. Packaging metadata differs from the published archive (`Cargo.toml.orig`,
`.cargo_vcs_info.json`, and the absent `.cargo-ok`/`Cargo.lock`), and this file is new.
The parent `Cargo.toml` reaches this copy through `[patch.crates-io]`.

| Report ID | File(s) | Change |
| --- | --- | --- |
| D-01 (Medium) | `src/platform.rs` | `Platform::hash_many` sends complete SIMD groups to the widest kernel; on AVX-512 an 8..=15-input tail peels one safe 8-wide `hash8` group, and the final 1..=7 inputs use the 4-wide SSE2/SSE4.1 kernels (portable elsewhere). The AVX2/AVX-512 2/4-wide tail loads at +16/+32/+48 cross the end of the **last 64-byte block of any input** (the guard-page reproducer used `n=2` on AVX512; the 16-byte SSE and AVX-512 8-wide loads end exactly at +64). Empty input is a no-op. The first fix sent every tail to `portable::hash_many`; that was safe but made 4 KiB keyed BLAKE3 ~3.3x slower (an audit measured it), so the tail now uses the safe SIMD kernels. |
| D-02 (Low) | `src/platform.rs` | Multi-block `xof_many` uses the documented `compress_xof` loop instead of unix AVX-512 assembly that does not zero-extend `block_len`/`flags`. Single-block output is unchanged. |
| Parent audit D1 (Medium) | `src/platform.rs` | A non-multiple-of-64 `xof_many` output (1..=63 bytes) is computed with `compress_xof` and copied as a prefix. The single-block AVX-512 path wrote a full 64-byte block in release (up to 63 bytes past the caller's slice), where the `debug_assert` was compiled out. The same prefix calculation also fixes the under-write the audit found for 65..=127-byte outputs (134 of 137 non-multiples). |
| D-04 (Low) | `src/lib.rs` | `Hasher::reset` clears `initial_chunk_counter` (set by the hazmat `set_input_offset`). Reproduced as a `finalize` assertion failure before the fix. |
| D-05 (Low) | `src/hazmat.rs` | `left_subtree_len` uses `div_ceil(2)`, so `u64::MAX + 1` no longer wraps. Reproduced as `1` instead of `1 << 63`. |
| D-06 (Low) | `src/lib.rs` | `OutputReader::position` uses saturating arithmetic at the end of the addressable stream. |
| V-03 (Low, debug) | `src/portable.rs`, `src/rust_sse2.rs`, `src/rust_sse41.rs`, `src/wasm32_simd.rs`, `src/platform.rs`, `src/lib.rs` | `hash_many`/`xof_many` and `OutputReader::fill_one_block` use wrapping counter increments. `counter += 1` panicked in debug at `u64::MAX` while the assembly kernels wrapped silently. |

Regression tests live in the parent, `tests/blake3_fork_equivalence.rs`: `hash_many`
against portable on every backend the host can execute (portable, SSE2, SSE4.1, AVX2,
and `detect()`'s widest) for 0..=40 **distinct** inputs at both 64 B and 1 KiB, both
counter modes; a Linux guard-page test that puts each input at a `PROT_NONE` boundary
for the tail, the 8-wide AVX-512 peel and full-group sizes; `hash_many` at counter
`u64::MAX` with distinct lanes; `xof_many` for 1..=4 blocks against independently
computed `compress_xof` blocks; short `xof_many` outputs canaried for 1..=63 and
compared with the same independent reference for 0..=130; `reset` after a hazmat
offset; and `left_subtree_len(u64::MAX)`. The fixed and unfixed `hash_many`/`xof_many`
outputs are byte-identical for valid inputs. Throughput after the D-01 routing is back
within the registry build at 1 KiB/16 KiB/64 KiB/1 MiB; the 4 KiB cell is ~10-15%
behind the registry (see `performance.md` and its fresh table), and the restored
AVX-512 8-wide tail keeps 8..=15-chunk batches on `hash8`.

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
