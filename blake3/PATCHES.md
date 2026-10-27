# Vendored BLAKE3 1.8.7 — local patches

Source: the crates.io `blake3 1.8.7` package (published 2026-08-20; archive
SHA-256 `6d9e454fc11f76977dc803893aff6304ed33d6a26efae8696573bea74baa27ae`).
The parent `Cargo.toml` depends on this directory **directly by path**; there is no
`[patch.crates-io]` and no crates.io `blake3` dependency to silently fall back to.

Packaging differences from the published archive:

- `Cargo.toml` and `Cargo.toml.orig` set `publish = false` and `rust-version = "1.85"`.
  Publishing this patched tree under upstream's name and version would present local
  changes as pristine `blake3 1.8.7`.
- `.cargo-ok` (a cargo-extraction marker that is not part of the `.crate`) and
  `.cargo_vcs_info.json` (which names the pristine upstream commit and would therefore
  describe this patched tree as unmodified) are removed.
- `Cargo.lock` is tracked so the fork's own test suite is reproducible; it includes the
  path dev-dependency below and is not part of the parent's build graph.
- `repository` and `documentation` name the parent repository and this patch file, not
  upstream's docs.rs page: `cargo metadata`/SBOM output otherwise attributes this patched
  tree to pristine `blake3 1.8.7`.
- `reference_impl/` and `test_vectors/` are from the upstream git repository at
  `f3149ec5bb5449af877ba20377a11008ff499fa2` (the commit named by the published
  `.crate`). They restore the published crate's missing test dev-dependency
  (`reference_impl`) and the C test vectors, so the fork's own suite can run.

| Report ID | File(s) | Change |
| --- | --- | --- |
| D-01 (Medium) | `src/platform.rs` | `Platform::hash_many` sends complete SIMD groups to the widest kernel; on AVX-512 an 8..=15-input tail peels one safe 8-wide `hash8` group, and the final 1..=7 inputs use the 4-wide SSE2/SSE4.1 kernels (portable elsewhere). The AVX2/AVX-512 2/4-wide tail loads at +16/+32/+48 cross the end of the **last 64-byte block of any input** (the guard-page reproducer used `n=2` on AVX512; the 16-byte SSE and AVX-512 8-wide loads end exactly at +64). Empty input is a no-op. The first fix sent every tail to `portable::hash_many`; that was safe but made 4 KiB keyed BLAKE3 ~3.3x slower (an audit measured it), so the tail now uses the safe SIMD kernels. The AVX2 tail falls back to portable if SSE4.1 is absent, so an explicit `Platform::avx2()` cannot execute an unsupported SSE4.1 instruction. |
| C library D-01 (Medium) | `c/blake3_dispatch.c` | The C API used to pass arbitrary `num_inputs` to the AVX2/AVX-512 kernels, selecting their over-reading 2/4-wide tails. It now keeps only complete SIMD groups (16 AVX-512, 8 AVX2) on those kernels, routes 4-wide remainders to SSE, and sends 1..3 to SSE/portable. Checked against Python BLAKE3 for every CPU-feature mask, 0..2048 bytes. |
| C library D-03 (Low) | `c/blake3_sse2_x86-64_unix.S`, `c/blake3_sse41_x86-64_unix.S`, `c/blake3_avx512_x86-64_unix.S` | Zero-extend the narrow `block_len`/`flags` arguments (`movzx`) before packing or broadcasting them. Normal C/Rust callers already zero-extend; this removes the hand-written-FFI ABI hazard too. |
| C library hygiene | `c/CMakeLists.txt`, `c/blake3_avx2.c` | Reject NEON on big-endian targets (`TestBigEndian`), use `list(APPEND ...)` for the C++20 flags, and type the AVX2 `storeu` destination as 32 bytes. |
| D-02 (Low) | `src/platform.rs` | Multi-block `xof_many` uses the documented `compress_xof` loop instead of unix AVX-512 assembly that does not zero-extend `block_len`/`flags`. Single-block output is unchanged. |
| Parent audit D1 (Medium) | `src/platform.rs` | A non-multiple-of-64 `xof_many` output (1..=63 bytes) is computed with `compress_xof` and copied as a prefix. The single-block AVX-512 path wrote a full 64-byte block in release (up to 63 bytes past the caller's slice), where the `debug_assert` was compiled out. The same prefix calculation also fixes the under-write the audit found for 65..=127-byte outputs (134 of 137 non-multiples). |
| D-04 (Low) | `src/lib.rs` | `Hasher::reset` clears `initial_chunk_counter` (set by the hazmat `set_input_offset`). Reproduced as a `finalize` assertion failure before the fix. |
| D-05 (Low) | `src/hazmat.rs` | `left_subtree_len` uses `div_ceil(2)`, so `u64::MAX + 1` no longer wraps. Reproduced as `1` instead of `1 << 63`. |
| D-06 (Low) | `src/lib.rs` | `OutputReader::position` uses saturating arithmetic at the end of the addressable stream. |
| V-03 (Low, debug) | `src/portable.rs`, `src/rust_sse2.rs`, `src/rust_sse41.rs`, `src/rust_avx2.rs`, `src/wasm32_simd.rs`, `src/platform.rs`, `src/lib.rs` | `hash_many`/`xof_many` and `OutputReader::fill`/`fill_one_block` use wrapping counter increments. `counter += 1` panicked in debug at `u64::MAX` while the assembly kernels wrapped silently. |
| D-09 (Medium, safety) | `src/platform.rs` | `Platform` is now an opaque struct over a private implementation enum. Upstream exposes the enum variants publicly, so safe code could pass `Platform::AVX512` to a safe method on a CPU without AVX-512 and execute an unsupported instruction. The checked constructors (`detect`, `portable`, `sse2`, `sse41`, `avx2`, `avx512`, `neon`, `wasm32_simd`) are unchanged in name, and the parent's use of `detect()` is unaffected. The enum-to-struct change is a deliberate API break for the doc-hidden benchmark interface; code that matched on `Platform::AVX512` must use the checked constructors instead. |
| Safe-API length checks | `src/platform.rs`, `src/lib.rs` | `Platform::hash_many` now asserts that `N` is a whole number of 64-byte blocks and that `out.len() >= inputs.len() * 32`. Both were `debug_assert!`/documentation-only, so a safe caller with a short `out` could trigger an out-of-bounds write in release. The deprecated `guts::ChunkState::update` rejects input longer than its remaining 1024-byte chunk, and `Output::root_hash` uses `self.counter` like `root_output_block` instead of hard-coding zero. |
| Small-stack DoS | `src/io.rs` | `copy_wide`'s stack buffer is 16 KiB instead of 64 KiB, so a safe `update_reader` call cannot require 64 KiB of thread stack. |

Regression tests live in the parent, `tests/blake3_fork_equivalence.rs`: `hash_many`
against portable on every backend the host can execute (portable, SSE2, SSE4.1, AVX2,
and `detect()`'s widest) for 0..=40 **distinct** inputs at both 64 B and 1 KiB, both
counter modes; Linux `PROT_NONE` and Windows `PAGE_NOACCESS` guard-page tests that put each input at a page boundary
for the tail, the 8-wide AVX-512 peel and full-group sizes; `hash_many` at counter
`u64::MAX` with distinct lanes; `xof_many` for 1..=4 blocks against independently
computed `compress_xof` blocks; short `xof_many` outputs canaried for 1..=63 and
compared with the same independent reference for 0..=130; `reset` after a hazmat
offset; and `left_subtree_len(u64::MAX)`. The fixed and unfixed `hash_many`/`xof_many`
outputs are byte-identical for valid inputs.

The fork's own upstream suite can also be run now:

```sh
cargo test --manifest-path blake3/Cargo.toml
```

It includes the per-backend `hash_many`/`xof_many`/compression tests, the upstream
reference implementation comparison, and the C test vectors. CI runs it in a dedicated
job; the parent's equivalence tests remain the primary guard for the tail fix because
they run on the parent's actual feature set.

Throughput after the D-01 routing is back within the registry build at
1 KiB/16 KiB/64 KiB/1 MiB; the 4 KiB cell is about 10-20% behind the registry depending
on host load (the audit measured 17-20% at load about 10, inside its noise floor; see
`performance.md`), and the restored AVX-512 8-wide tail keeps 8..=15-chunk batches on
`hash8`.

**Distribution policy.** The parent is source-only (`publish = false`) and depends on
this directory directly by path. A git checkout carries the fork. Do not replace the
path dependency with a registry version; that would remove every fix listed above.
The upstream-sync workflow's comparison branch contains `blake3/upstream-sync/`; the
parent's `build.rs` refuses that directory, so the candidate cannot be built or mistaken
for a merge candidate. `cargo package` is likewise refused by `build.rs` because Cargo
would rewrite this path dependency to unpatched crates.io BLAKE3. `cargo package
--no-verify` writes an archive without running that guard; no such archive is ever
published or attached, and it is untrusted if produced locally.

**The reviewed public C API paths have no known memory-safety or ABI defect in this
tree.** The C dispatch splits groups, the unix compress/xof assembly zero-extends its
narrow arguments, and the C library's own tests run in CI (`make test` and
`make test_asm`). The backend symbols (`blake3_hash_many_avx512`, etc.) are internal;
a caller invoking them directly bypasses the safe dispatch and its grouping contract. D-08
(riscv64-musl getrandom) is outside this fork's use. The Rust build still uses only
the assembly kernels through the patched Rust dispatcher; the C library is now a
patched copy too, not merely an unreachable upstream copy.
