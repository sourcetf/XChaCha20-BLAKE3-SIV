# Audit response — four third-party reviews of revision `8ae80ce`, plus the §5 line-by-line report against `92c85ad`, the §6 dependency report against `01348ab`, and the §7 incremental pass over `7ce256e4`

Four reports were produced against revision `8ae80ce` (construction `v0.3`), and this document
records what was done with each finding: what was **fixed** (with the commit and the evidence),
and what was **not changed**, with the reason. It is written to be checkable — every disposition
names a file, a test, a command, or a commit, and "responded" never means "ignored". §5 applies the
same treatment to the fifth report, the independent line-by-line pass against `92c85ad`, §6 to the
sixth, the dependency line-by-line report against `01348ab`, and §7 to the seventh, the incremental
pass over `7ce256e4`.

| # | Report | Pages | Findings | Disposition |
| --- | --- | --- | --- | --- |
| 1 | `逐行验证审计报告` (line-by-line audit) | 179 | 366 (41 marked DEFECT; 高 12 / 中 47 / 低 165 / 信息 31 / 未标注 112) | the DEFECT-class and 高/中 items are fixed (indexed in §1); the notes and informational items are answered in §2 |
| 2 | `增量攻击测试报告` (incremental) | 27 | 26 (0 高, 2 中, 14 低, 9 信息, 2 unlabeled) | both 中 fixed (§1.D); 低 fixed or answered |
| 3 | `增量攻击测试报告·完整版` (complete) | 32 | 58 (0 高, 3 中, 13 低, 25 信息, 18 unlabeled) | the three 中 fixed (§1.D); the rest fixed or answered |
| 4 | `增量攻击测试报告·第三轮` (third round, rebuilt with its Miri unit) | 18 | 32 (0 高, 1 中, 5 低, 14 信息, 12 unlabeled) | two 低 fixed (§1.C); the 中 is the documented opt-out boundary (§2.2); the refusal-path test it found missing was added (§1.B); the Miri unit's four findings are tool/environment facts (§2.9); the rest answered |

Everything below is against the tree that carries this file. The commits that make up the
response, in order, are:

```
a778ee9  Gate defects: a self-test that corrupted its own artifact, and three rows that could pass without running
e4ff7c9  CI: give the fault campaign room for its per-row builds
e0e1950  fi_instruction and mutation_check: ask cargo for the binary instead of globbing the deps dir
8dcc09e  Third audit round: the context commitment route, and harnesses that could not fail
4f246c7  Say in §4.5 that forgery strength is the minimum of key search and tag guess
fa48744  Fix a flaky whole-buffer assertion, and keep the timing screen out of the MSRV job
943c913  Fix a reachable abort in the 2-64 KiB window, and a lock failure path that un-dumped a locked page
efdcae2  Disclose the fork boundary, and the Deref/RAII hazards the attack review listed
ff9ca9b  Note what a const-built static Key means: never dropped, bytes in the data segment
4e52680  Work the audit and attack reviews through in parallel: residue, gates, and tests that could not fail
c907e47  Fix the sweep that failed 3/3, and the counts it published one short per shard
753efb9  Keep the timing screen out of the coverage job too
b9ca53f  Give Key and LockedKey constant-time PartialEq, closing the Deref fallback trap
63e27e7  Record two measurements the third-round review added to the docs
22fab2b  Skip the locked equality test on targets without the locking syscalls
e2ef4f4  Widen the residue note: the same dead frames hold short k_out/enc_seed fragments
ddb5ddb  Record the measured cost of the refused-buffer fallback
13caa0e  Fix cache_profile.sh --trace: lackey's load/store lines carry a leading space
77b18ac  Correct the constant-tag row: the byte-level probe is profile-dependent
a488b36  Give the trace mode a determinism control, after its first CI run failed
f9a5d3d  Re-measure the ultra cost table after the witness's residue-wipe pass
ea56caf, 956c816, 6efac1f  trace-step message, changelog order, riscv64/debug/opt-out notes
eca9ff3  Give the lock refusal path a witness, and four third-round corrections
76935ea, 17b311e, 5c53d2e  claim tightening, the allowance-boundary and zero-limit cases, re-wrap
```

`CHANGELOG.md`'s `Unreleased` sections are the detailed record of each of these; this document
is the map from the reports to them.

---

## 1. Findings that were correct, and what was done

### 1.A Gate verdicts that depended on a stale or foreign artefact

The first report's central class, and the one with the highest severity: a check whose verdict is
not about the current source.

| Finding | Fix | Evidence |
| --- | --- | --- |
| `tools/ctgrind.sh`'s self-test left its planted-leak binary in the *main* deps directory under the clean build's name; the next run's `ls -t … \| head -1` picked it up, so a second consecutive run on unchanged source failed (measured: run 1 PASS, run 2 eight decrypt leaks in 0.8 s; the repo's own `target/` already held one) | the self-test builds into its own target directory; both the main check and the self-test ask cargo (`--message-format=json`) for the executable instead of globbing; the main build removes any pre-existing `ctgrind-*` first, healing an already-contaminated tree | `a778ee9`, `e0e1950`; two consecutive runs now both exit 0 |
| `tools/ctgrind.sh`'s and `tools/tsan.sh`'s PASS did not check that the named tests ran at all — a zero-match filter makes libtest print `ok. 0 passed` and exit 0 | both now require the run to show the named tests (`test result: ok. 4 passed` / the test's own line) | `c907e47`, `a778ee9` |
| `tools/cache_profile.sh`'s self-test's planted binary went into the caller's target dir; its counts-mode verdict depended on the example harness's value-dependent hex guard (so it failed on a pristine tree) | the plant is private, the self-test uses a private target dir, and the example's hex check is value-independent (two comparisons instead of a per-byte scan) | `4e52680`, and the analysis in `CHANGELOG` ("Gate defects…") |
| `tools/cache_profile.sh --trace` had **never run**: lackey prints ` S <addr>,<size>` with a leading space, so the `^[ILSM] ` filter kept only instruction lines, the load/store count was zero, and the mode answered "valgrind here cannot start the lackey tool" for years | filter fixed to `L`/`S`/`M` (instruction fetches excluded on purpose), plus a **determinism control**: the same input is run twice and those traces must match before keys are compared | `13caa0e`, `a488b36`; the first runs after the fix measured 170,874 / 274,664 identical accesses (default) and 372,519 / 987,842 (`ultra`) — pre-loader-trim figures, superseded by 196,920 / 360,644 at the default of 12 vectors and 324,283 / 937,082 under `ultra` (`tests/README.md` carries the current row); `--selftest --trace` catches its planted leak; on a CI runner the control correctly reports "layout is not reproducible" and the step skips |
| The same mode's verdict also depended on the example's value-dependent hex guard, so the third round predicted it would still fail on a pristine tree "even with the filter fixed" (+5,544 instruction lines measured between a `00…` and an `ff…` key, from `from_str_radix`'s letter branch) | the guard is gone (it is now two comparisons, value-independent) *and* instruction lines are excluded from the comparison by construction — that mode compares memory accesses, which is what it exists for | re-measured on this tree: `--trace` (4 vectors) and counts (8 vectors) both PASS on a pristine tree — 131,292 accesses enc / 179,611 round trip; 13 counters identical |
| `tools/cache_profile.sh --trace`'s comparison included the dynamic loader's startup accesses, so its determinism control tripped on every run on this host — glibc's loader indexes a class table with the run's `AT_RANDOM` byte when a stack string's terminator lands against it, thousands of lines before the client runs (an audit mapped the differing addresses into `ld.so`'s text and reproduced it without this crate) | the comparison now starts at the client's first instruction fetch (the minimum `I` address, which is the client under `--addr-no-randomize`), so the mode measures this crate's accesses | re-measured 68,938/117,281 at `--trace 4`, 123,543/227,381 at `--trace 8`, 324,283/937,082 under `ultra`; passes three runs out of three where it previously failed every run, and `--selftest --trace` still detects its planted leak |
| `tools/fi_instruction.sh`'s full `--bits` sweep aborted 3/3 (ETXTBSY on the restore reopen; `UnicodeDecodeError` on a crashed binary's non-UTF-8 output) | the reopen retries a transient `ETXTBSY`; the run captures bytes and decodes with `errors="replace"` | `c907e47`; the full `--bits` sweep and the default (`nop`) sweep now complete and gate correctly |
| The sweep's published "total" undercounted by one per shard file with entries (no trailing newline, `cat … \| grep -c .` merged adjacent files: 4 printed as 3, 15 as 7) | files always end with a newline; the documented residuals re-measured | `c907e47`; the auditor's own independent fix reproduced the same correction |
| `check.sh`'s final-artefact check hardcoded `target/release/…` (ignored `CARGO_TARGET_DIR`, accepted any file) | the path is derived from `CARGO_TARGET_DIR` and the file must be newer than a stamp taken at start | `a778ee9` |
| `tools/ctgrind.sh`'s binary lookups globbed (`ls -t … \| head -1`), so a stale or planted binary could be executed | cargo's own JSON report is parsed instead (`e0e1950`, `tools/fi_instruction.sh` and `tools/mutation_check.sh` too) | `e0e1950` |
| `verify.sh` could report "all requested checks passed" while a stage it was asked to run had been skipped; `--kani` had no availability guard; `stack_residue`'s exit 3 was absorbed | explicit-stage bookkeeping (`EXPLICIT_KEYS`/`SKIPPED_KEYS`), a Kani guard that records a skip, and exit 3 mapped to a skip | `a778ee9`, `e0e1950` |
| `tools/gate_selftest.sh` asserted the exit-3 convention by grepping for its implementation text (an equivalent rewrite reported false failure), its coverage was narrower than its conclusion, and it false-failed on machines with a system valgrind | it now checks *behaviour* (hides the tooling, observes exit 3; runs `verify.sh` and requires failure when a named stage is skipped; requires `fi_check.sh` to fail with a failing cargo), with a fake `HOME` and a recursion guard | `a778ee9`, `4e52680`; runs in 0.4 s |
| `tools/mutation_check.sh`: an unappliable mutation counted as "caught"; an unknown selector ran nothing and exited 0; `rc=1` was swallowed by `exit 3`; the KAT row mapped any non-zero cargo exit (including a compile error) to "caught" and had no clean baseline | explicit "the mutation could not be applied" error, selector validation, a summary that lets "NOT caught" win, and a baseline for every row | `a778ee9`, and the tool's own self-tests |
| `tools/fi_check.sh`'s `expect=fail` rows could pass when the patch failed to compile; its rows shared one target directory (so freshness decided which binary ran); its `wipe-skipped` patch did not compile (`let _ = &mut buffer;`, E0596), so nothing was testing the wipe | per-row and per-baseline private target directories, a build guard per row, a cached clean baseline for `expect=fail`, and a compiling patch (`let _ = buffer.len();`) | `a778ee9`, `e4ff7c9` |
| `tools/check_kani_cfg.sh`'s diagnostic pipeline exited early under `set -e`/`pipefail`; its PASS did not prove any `#[cfg(kani)]` code was compiled | `\|\| true` on the pipeline, and a negative control that plants a type error inside `#[cfg(kani)]` and requires the check to fail | `4e52680` |
| `tools/broad_differential.py` accepted `count 0`/negative as vacuous PASS and never called the reference's self-check; `tools/mutation_evidence.py` treated degenerate evidence as PASS and a schema change as exit 1 instead of "could not run" | `count < 1` is an error, the self-check is called, non-numeric arguments are rejected; shape/schema errors exit 3 | `4e52680` |
| `tools/stack_residue.sh`'s header said it was not wired into CI (it is), its unknown options were ignored, and its PASS text claimed more than its table showed | header corrected, unknown options rejected with usage, PASS text scoped to what the table shows | `4e52680` |
| `tools/kani_shards.py` missed a harness whose attributes were on one line; `tools/ref_impl.py` compared only the first half of the RFC 8439 §2.3.2 block | both fixed (the reference now compares all 64 bytes) | `4e52680` |

### 1.B Assertions that could not fail (or were weaker than their own documentation)

| Finding | Fix | Evidence |
| --- | --- | --- |
| Kani tag harnesses: nothing asserted the full 65-byte output, so a tag truncated past byte 40 passed; a swapped `k_in`/`k_out` passed all four | the stub now asserts the *width* of every output buffer (32/44/`TAG_LEN`), and a new harness, `tag_matches_the_model_on_a_concrete_input`, reconstructs the expected tag through the model and compares all 65 bytes | `8dcc09e`; measured: clean 83 s SUCCESSFUL, swap FAILED in 78 s, `&mut tag[..40]` FAILED in 9 s |
| `tests/counter_range.rs`'s name-table scan: `use … as` aliases, a space before `(`, multi-line calls, `//` inside string literals, `/* */` scanned as code, and a `>= 11` floor that a renamed `chacha20_block` slipped under | a real comment/string scanner, whitespace- and newline-tolerant matching, alias rejection, and an **exact** per-name census (13 sites) | `4e52680`; verified against four evasions on copies |
| `tests/decision_scope.rs`: `fun:` lines only had to *contain* `accept_or_reject`; counts ran over raw text including comments and the test module | every count runs on comment-stripped non-test source; the suppression file must be exactly its five lines with a mangled symbol ending in the decision (v0 length prefix), and other valgrind line kinds are rejected | `4e52680`, `8dcc09e` |
| `tests/mac_commitment.rs`'s early-return arm passed while asserting nothing (any `encrypt` failure satisfied it) | the arm asserts the only legitimate cause (`ultra`'s witness disagreeing → `AuthenticationFailed`) and panics outside `ultra` | `4e52680` |
| `tests/security.rs` exercised the in-place failure contract only in the unstructured (random-tag) rounds, never on the "valid tag, corrupted input" rounds it exists for; its allocation-order test compared only the first allocation | the in-place contract runs on the structured rounds too; every `alloc_zeroed(` in the three allocating entry points must precede the first derivation | `4e52680` |
| `tests/decision.rs` swept all 65 tag bytes through `decrypt` but only the last byte through the in-place path | both entry points get the full sweep; the campaign counts in its header were corrected (eleven `--test decision` rows of fourteen) | `4e52680`, `8dcc09e` |
| `fuzz/fuzz_targets/roundtrip.rs`: the in-place wipe was checked only `if … .is_err()` (a wrong `Ok` skipped it); `encrypt` errors returned silently; the tamper index was confined to the first 86 bytes | the rejection is now required, errors assert, and the index is drawn from two input bytes | `4e52680` |
| `tests/timing.rs`: `welch_t` returned 0.0 — the *passing* side — for two perfectly constant classes with different means, and the three loops ran in parallel | `+inf` for that case, and a mutex serialises the loops | `4e52680` |
| Differential fixture floors (`>= 40`, `>= 10`, `>= 5`) let whole rows be deleted silently | exact counts (49 rows, 40 swept, 5871 positions, 16 AAD rows, 9 large sizes) | `4e52680` |
| `random::fill`'s test asserted "some byte changed" (a one-byte fill passed); the AAD/message coverage test claimed "any bit" while flipping bit 0 of every byte; `locked`'s in-crate test returned silently when the kernel refused to lock | the first requires every byte to be overwritten (with a documented ~6e-6 false-failure bound), the second rotates the flipped bit, the third fails on a runtime refusal unless `XSIV_ALLOW_UNLOCKED=1` | `fa48744`, `4e52680` |
| `tests/differential_reference.rs`'s large fixture replayed only the allocating pair; the scan caps' line references drifted; the fixture's boundary was described as "64 KiB / 65 537" (the switch is on `48 + aad + msg`) | the in-place pair is replayed too, the caps are described by test name, and the boundary is stated as 65488/65489 | `4e52680`, `8dcc09e` |
| The instruction-level fault campaign's totals were the only published numbers and the "decision-scoped" count was mixed with them | the comparable (decision-scoped) count is what the tool gates on, and the README says why the raw totals are not comparable across configurations | `8dcc09e`, `c907e47` |
| `tests/locked.rs`'s per-mapping check (added to close the decoy-lock hole) degraded silently under a tight `RLIMIT_MEMLOCK`: its probe locked a heap `Vec` whose page alignment is luck, so at `ulimit -l 12` it cost two pages, failed, and the test fell back to the process-wide counter a wrong-address lock satisfies (an audit measured the test passing a decoy-lock mutant there) | the probe takes a page-aligned 4 KiB slice inside an over-allocated buffer, so it costs what a `LockedKey` costs | re-run against the same mutant: fails at 8, 12, 16 and 32 kB |
| The `locked` refusal path had no witness: every test skipped when the kernel refused (`lock_or_skip`), so an implementation returning `Ok` with an unlocked page, or keeping the lock while reporting an error, would have been reported as "not applicable on this host" (third round) | `tests/locked.rs` exhausts `RLIMIT_MEMLOCK` through the public API (one page per key, the limit read with its unit off `/proc/self/limits`), then asserts the refusal is *reported* and the accounting returned: each holder charged exactly one page, a refused call charged nothing, `VmLck` returns to its baseline, the call that failed succeeds again with nothing held, and no descriptor leaked. Mutant-checked: a `lock_range` whose error is ignored fails the test with "the allowance is spent … and yet `LockedKey::new` kept succeeding" | `eca9ff3`, `17b311e`; runs in 0.6 s holding 64 MiB for its window on this host, and passes under `qemu-aarch64` (1.5 s for the file) and `qemu-i386` (where locking is unsupported and it skips) |

### 1.C Claims that measurement contradicted

| Claim (where) | What the measurement showed | Fix |
| --- | --- | --- |
| "the detached entry points never allocate themselves" (`src/lib.rs`) | `derive_tag`'s concatenated path allocated a bounded buffer | corrected (`a778ee9`/`4e52680`); the path now uses `try_reserve_exact` and *falls back* to the three-part hash on refusal, so no allocation in the crate aborts (see 1.D) |
| "every allocation goes through `alloc_zeroed`" | the fast path and `locked`'s page allocation are the counterexamples | corrected |
| "no allocation in this crate aborts the process on refusal" | true only after 1.D's fix | the fix came first, then the wording |
| "no copy of the MAC key survives the call" | dead stack frames hold `k_in` (32 B with LTO on, a 16–24 B prefix with LTO off), readable across threads, thread-stack reuse and `fork`; the same region holds 4-byte prefixes of `k_out`/`enc_seed` | corrected, with the profile dependence and the fragment shapes written down (`4e52680`, `e2ef4f4`, `63e27e7`) |
| The comparison row's "two faults still defeat both" was stated without numbers | the audit's matrix quantified it: two site pairs are invisible one at a time and jointly accept everything in all three configurations; `i1+a` accepts 0.37–0.43% on `hardened`, 0 of 2,000,000 on `ultra` | the README rows now carry those numbers |
| "a fault that replaces the computed tag with a constant … not defended by `hardened`" | the *source-level* fault is pinned by the campaign row, but the byte-level probe is profile-dependent (LTO off accepts, the shipping profile does not) | the row now says which evidence pins what (`77b18ac`) |
| Context commitment quoted `2^-520` per candidate key and "the width is what sets it" | the context enters the tag's hash input, not its key: a key-holder target is `≈ 2^256`, and in the attacker-chosen game two chosen contexts collide at `2^128` with immediate completion | README, `SECURITY-ANALYSIS.md` (Thm 2, §4.5, §5 row 17, §5.1, §8.1) and the crate docs now carry all three routes (`8dcc09e`) |
| "Commitment to the nonce and the lengths: same argument, byte for byte" | false for the context components (same reason as above) | rewritten (`8dcc09e`) |
| "the completion step is a fixed point" (as a general statement) | only the different-message route is; the key and context routes complete immediately with the same plaintext | rewritten as three routes (`8dcc09e`); the third is priced by construction, without searching the tag space (see §4) |
| `enc_seed` "bound into the tag's derivation" (README) | `enc_seed` keys the KDF *whose input is the tag* — the opposite direction | corrected |
| CHANGELOG's "reopens a complete invisible-salamander at `2^128`" | the route forces equal material, hence identical plaintexts: a key-commitment break, not a salamander | withdrawn in place (`8dcc09e`) |
| `random::fill`'s "a sandbox that blocks `getrandom(2)`" | the `getrandom` crate falls back to `/dev/urandom` on `EPERM`/`ENOSYS` | the example now says both must be blocked |
| `decrypt_bounded`'s `max_len` as a policy limit | it bounds the ciphertext (allocation), not the AAD or the work | documented |
| `Cargo.toml`'s `i686-unknown-linux-musl` note | with no i686 C toolchain BLAKE3 falls back to Rust backends and the plain build works; nothing on i686 runs this crate's SIMD | corrected |
| `.cargo/config.toml`'s "riscv64 linking does not work" | it links with an alias, `-C link-self-contained=yes`, a `self-contained` `-L`, and a non-PIE link; the suite then runs under `qemu-riscv64` — and the one test that still hung was a weak `libc::getrandom` symbol LLD resolves to the current PC, fixed by forcing the archive member (§2.7) | corrected (`6efac1f`), completed this round; riscv64 execution is now wired into `verify.sh --cross-exec` and the `cross-exec` job |
| "Miri, which cannot execute C — hence `pure`" | `pure` is belt-and-braces on x86_64 (Miri's CPU-feature detection reports nothing, so the C kernels are never dispatched) | softened in `Cargo.toml` and `tests/README.md` (`63e27e7`) |
| Kani cost figures (≈320 s per permutation, "well over 25 minutes") | on the current toolchain the real-permutation harness runs in 37 s and the whole 13-harness set in ~875 s | marked as history in `src/proofs.rs` (`63e27e7`), and the required flags (`-Z stubbing -Z unstable-options`) are spelled out in `tests/README.md` |
| CI coverage percentages and counts (96.71% / 88 of 2181, 97.92% / 116 of 5573) | three runs of the same command gave 96.51 / 96.66 / 96.71% of lines and 97.71 / 97.92% of regions | the comment now quotes the floor and points at the job's output (`63e27e7`); the counts had already gone (`c907e47`) |
| The qemu run was described as `qemu-x86_64 -cpu Nehalem` (SSE2-only) | no such runner exists in the repository | removed from the crate docs, `tests/README.md` and `bench` texts (`4e52680`) |
| The avalanche test implied it covered the ChaCha20 round function | corrupting the round constant leaves it green (the KATs catch that) | the test says what it does and does not cover |
| The stack-requirement test implied it locks the 16 KiB constant | `need` is 0 without `dual-mac`, and the margin is 4–64× the constant | documented |
| The fixture/campaign counts (6 sizes/55 vectors, "thirteen rows", etc.) | 9 sizes/58 vectors, fourteen rows | corrected everywhere (`4f246c7`, `8dcc09e`) |
| CHANGELOG's pre-`v0.3` `hardened` cost quoted in present tense | re-measured as +25/24/23/11% | marked superseded |
| "no release tags have been cut yet" | the release job publishes rolling `sha-<short>` tags | corrected |
| `tests/README.md`'s timing command pointed at `--test security`; the dependency count said 108 where the lockfile has 110 | corrected (the timing screen's own target, and the count from `Cargo.lock`) | `4f246c7`, `63e27e7` |
| The key-material-block test's rationale ("make `derive_enc` ignore the tag … collapse") | that change alone does not collapse them (the two keystreams are keyed differently) | the rationale now names the refactors that would |
| An orphaned half-sentence of a doc comment sat on the length-guard test | removed | `4e52680` |

### 1.D Availability and robustness defects (all reproduced before the fix)

| Defect | Fix | Evidence |
| --- | --- | --- |
| An **unauthenticated** ~2 KiB input reached `derive_tag`'s contiguous-buffer branch, whose `Vec::with_capacity` aborts the process on refusal; the abort also skipped every wipe (the audit's core dumps held recovered plaintext and `k_in`/`k_out`/`enc_seed`) | the arm uses `try_reserve_exact` and falls back to the three-part hash, which needs no buffer and hashes the same bytes | `943c913`; A/B with a refusing allocator: old shape SIGABRT (134), new one completes a legitimate 60 KiB round trip and rejects a forgery with the buffer zeroized |
| `decrypt_in_place_detached` returned `Err(AllocationFailed)` without zeroizing the caller's buffer, contradicting its own promise | both failure arms zeroize first | `943c913`; measured: `Err(AllocationFailed)` with the buffer all zero |
| `unlock_range` restored `MADV_DODUMP` even when `munlock` was refused, leaving a page **locked and dumpable** with the `VmLck` charge never returned (the audit reproduced it under a syscall filter) | the advice is restored only on a successful unlock; a refused unlock keeps the dump exclusion and the lock accounting stands | `943c913` |
| `tools/fi_instruction.sh`'s full `--bits` sweep aborted 3/3 (see §1.A) | see §1.A | `c907e47` |
| `tools/cache_profile.sh --trace` never ran (see §1.A) | see §1.A | `13caa0e`, `a488b36` |
| A flaky whole-buffer assertion I introduced (demanding zero sentinel matches fails ~22% of the time on a correct fill) turned two CI jobs red | a count with a ~6e-6 false-failure bound | `fa48744`; 300 local runs, 0 failures |
| The MSRV job and the coverage job ran the statistical timing screen, which is advisory **by measurement** (a hosted runner reports `t ≈ 11` with no possible cause; under `cargo llvm-cov` instrumentation `t = 13.78` and `51.14`) | both jobs now skip it, as the blocking matrix already did | `fa48744`, `753efb9`; locally the coverage figure is unchanged (95.65% either way, and the report contains only `src/lib.rs` and `src/witness.rs`) |
| The `locked` equality test I added panicked on i686/powerpc64 (where the locking syscalls are not wired) and turned those qemu jobs red | it checks `SUPPORTED` first and prints a skip; a genuine runtime refusal still fails | `22fab2b` |

### 1.E API consistency

| Finding | Fix |
| --- | --- |
| `Key` and `LockedKey` had no `PartialEq`, so `key_a == key_b` compiled anyway through `Deref` coercion and short-circuited — the same trap `Plaintext`'s impls exist to close | constant-time `PartialEq` (and the by-reference spelling) for both; `LockedKey`'s goes through `as_bytes`, so a corrupted page still fails stop; two tests name `PartialEq::eq` directly so removing an impl is a compile error (`b9ca53f`) |
| `key.clone()` silently produces an unprotected `[u8; 32]`; `Key::from_bytes` is `const` and can build a never-dropped `static`; `mem::forget`/`Box::leak` leak the lock quota | all three are now written down where a reader meets them (`efdcae2`, `ff9ca9b`) |

---

## 2. Findings that are **not** defects, and the response to each

### 2.1 The reports' own scope-mapping errors

Two 高-severity rows in report 1 are the auditor's mapping errors, not code findings, and the
report says so itself: the unit "`src/lib.rs` 1241-1870" did not contain the nine functions the
task named. There is nothing to fix; the next revision of that task should name the ranges the
functions actually live in.

### 2.2 The fault model is single-fault, and the opt-out build is the control

Three reports quantify faults that defeat every configuration when applied as **two** faults
(`c2+ini1`, `ci0+ci1` — individually invisible, jointly 100% acceptance), and report 4 shows a
fault *inside* the 65-byte comparison loop that gives 100% acceptance on
`--no-default-features`. Both are outside what the design claims:

* `README.md`'s fault rows state the model: "a single corrupted decision value or instruction",
  with the two-fault residual named as the boundary ("two faults, one in each derivation, or one
  aimed at the arithmetic both derivations share, still defeat it — that is a synchronized
  two-glitch bench"). Report 3's numbers are now quoted in those rows, so the boundary is
  quantified rather than implied.
* The opt-out build (`--no-default-features`) is the campaign's *control*: it keeps one
  comparison shape, its accepting sites are reported by `tools/fi_instruction.sh`, and the
  decision-scoped count is required to be non-zero there and zero in `hardened`/`ultra`. A fault
  that removes the comparison's accumulator is what "one shape, one fault" means; the README row
  now carries the 100% figure.

No code change: adding a third independent comparison would raise the single-fault bar further
at a per-message cost, and the honest record of what the layers buy is already the table's
subject.

The third round adds one more fault of that class, on the *wipe* rather than the decision:
patching the two `zeroize_slice(buffer)` sites on `decrypt_in_place_detached`'s rejection path
leaves the caller's buffer holding 64 bytes of unverified plaintext, while every return value
and every assertion in the campaign's A1–A6 looks exactly as before — only the runtime replay
check (their `ipassert`, this repository's `tests/security.rs` replay) notices. That is what the
sites are for, and a single-fault model cannot require two independent wipes to both survive;
what the finding does show is that the *source-scanning* assertion
(`every_allocation_happens_before_any_derivation`) passes under a binary patch, because it reads
`src/lib.rs` — which is why the runtime replay exists alongside it.

### 2.3 Dependency-internal behaviour

* **`blake3`'s XOF temporaries / `Hasher::zeroize` coverage** (reports 1 and 2): the crate's own
  copies are wiped; the dependency's by-value temporaries are not reachable from here, and
  `ultra`'s `scrub_stack` covers them. Documented in `blake3_keyed_multi`'s comment and
  `src/witness.rs`. There is no in-crate fix short of not using the dependency.
* **`getrandom`'s `/dev/urandom` fallback**: documented (the example now says both the syscall
  and the file must be blocked); the fallback is still an OS CSPRNG, so there is no security
  defect. The third round measured the details through real seccomp filters and they are now in
  `random::fill`'s docs: only `EPERM`/`ENOSYS` trigger the fallback (`EACCES`/`EIO` are returned
  as they are — that crate's policy, not this crate's), the file is opened with `openat(2)` under
  glibc and `open(2)` under static musl, so a filter that means to close the fallback has to name
  both (plus `openat2(2)` for a caller that uses it), and the all-zero buffer on failure is this
  crate's `fill_from`, not the dependency's doing (measured: calling the dependency directly
  leaves the caller's bytes untouched).
* The `blake3` C-kernel backend is never dispatched under Miri, which is why `pure` is
  belt-and-braces (§1.C).

### 2.4 API and design decisions that are kept

* **No `Clone` for `Key`/`LockedKey`** — the deref-coercion hazard is documented, and the
  intended copy is `Key::from_bytes`. (`PartialEq` *was* added, §1.E.)
* **`LockedKey` panics on a corrupted page** — deliberate fail-stop, documented; a fault in the
  key must not surface as "authentication failed".
* **`Key::from_bytes` stays `const`** — it is how a test vector is written; the `static` hazard
  is documented rather than the signature changed.
* **`Deref` stays** — it is what makes `as_bytes()`-style borrowing ergonomic, and the two
  hazards it creates (`.clone()`, `==`) are documented/handled.
* **The timing screen stays advisory in CI** — the measurement (`t = 10.96` with no possible
  cause against a threshold of 10) is in the file and in the workflow comments; strict runs are
  `verify.sh --deep` on a quiet host. Note the instrument itself *is* gated (its own blocking
  job).

### 2.5 `fork`, `exec`, and lock semantics are Linux's, not this crate's

Reports 2–4 measure that a forked child inherits the key bytes and `MADV_DONTDUMP` but not the
`mlock` (`VmLck` is per-process), that its copy can reach swap after a COW write, and that
`execve` resets the dumpable flag. None of that is a defect in the crate; what was missing was
the disclosure, and it now exists in `LockedKey`'s docs, README's boundary list and
`SECURITY-ANALYSIS.md` §8.2, with the measured rows (`efdcae2`).

### 2.6 Debug builds are development-only, and now with a size

Report 4 measured that an opt-level-0 build spills whole secrets to dead frames (up to six
copies of `k_out`, five of `enc_seed`), where the shipping profile shows none. The crate docs
already said debug is not for real secrets (for `subtle`'s `debug_assert!`s); they now say this
too (`6efac1f`). No code change: an unoptimised build is not a deployment profile, and the
guarantees are stated for release.

### 2.7 riscv64: executed now, and what the old "hang" actually was

The link recipe is verified and the suite runs under `qemu-riscv64` — 61/61 lib, 15/15
security, 10/10 locked, 8/8 ultra, 6/6 differential, 3/3 timing (383 s here), and the other
binaries as well (`ctgrind` is the one exclusion, as on every cross target: it shells out to
valgrind, which cannot run under qemu). The old note in `.cargo/config.toml` ("linking does not
work … the scalar fallback is therefore not executed here") was wrong and was corrected in an
earlier round; what this round found is that the one test that still seemed to hang was not an
emulator interaction at all.

`tests/ultra.rs::every_layer_answers_correctly_in_the_ultra_build` asks for OS entropy, and the
`libc` crate declares musl's `getrandom` as a **weak** symbol. A weak undefined reference does not
make the linker extract the archive member that defines it, so the symbol stays unresolved in the
self-contained link. On riscv64, LLD materialises the *address* of an undefined weak symbol as the
current program counter, and the `getrandom` crate passes that address as a function pointer — so
the call jumps to itself. Measured: the executed instruction stream is a single
`auipc ra, 0; jalr ra` pair (15.3M executions of one guest PC, which is why the thread looked
stuck). Forcing the member in (`-C link-arg=--undefined=getrandom`) fixes it; aarch64's binary
defines `getrandom` (something in that link references it strongly), which is why only riscv64
showed the symptom, and why the third round's `--features pure` run did not: that configuration
does not enable `rng`.

riscv64 is now wired into `verify.sh`'s cross-execution stage and into the `cross-exec` CI job,
with the complete recipe — unwinder alias, `-C link-self-contained=yes` (without it the link
succeeds but produces entry point 0), the self-contained `-L`, a non-PIE link, and the forced
`getrandom` member — in `.cargo/config.toml` and in both entry points. The scalar backend is the
reference every other target's tests compare against; executing it was the point of the recipe.

### 2.8 Environment-dependent stages

Stages that need valgrind, Miri, qemu, Kani or a nightly toolchain answer **exit 3** ("could not
run") when the tooling is absent, and the callers record a skipped stage rather than a pass;
`--deep`/`--all` fail if a stage they named was skipped. This is deliberate and is the subject of
`tools/gate_selftest.sh`. Reports that were run in environments without those tools therefore
record skips, not passes — and the reports' own measurements are the substitution.

### 2.9 Informational results that need no change (a representative list)

* Constant-time evidence, negative: lackey address traces identical for two keys (now measured,
  §1.A); memcheck clean apart from the documented `accept_or_reject`; instruction counts and
  branch counts identical across mismatched tag positions; the timing screen's tag comparison
  shows no position dependence (and its positive control detects one).
* Differential/fuzz: tens of thousands of entry-consistency vectors, hundreds of thousands of
  tamper attempts, the window corpus, AAD/message extremes, and libFuzzer runs — all negative.
* Feature matrix: every configuration builds, tests and produces identical wire bytes; i686 and
  aarch64 execute under qemu; `overflow-checks` changes nothing observable.
* Verification tools: Kani 19/19 SUCCESSFUL (the twelve the reports measured plus the concrete tag comparison in `8dcc09e` and the later witness/zeroization harnesses); Miri with no UB (including full `--lib` and
  per-test runs); TSAN clean with its control detected; `cargo-audit`/`cargo-deny` clean; the
  coverage floor passes.
* Structural scale experiments (a 352-bit equality from one call chain, `b0`/`b1` segment
  equality, a ~2^144 claw across two *known* keys): informational, explicitly not vulnerabilities
  — they require the keys and are not attacks on an unknown one.
* CPU/resource notes: per-byte cost is not monotonic in length (BLAKE3's tree), unauthenticated
  decrypt pays the full cost (SIV computes the tag over the plaintext), `decrypt_bounded`'s
  bound is on the ciphertext — all inherent, and now stated.
* The third round's cgroup measurement (a 64 KiB input is `SIGKILL`ed at a `memory.max` where a
  65537-byte, zero-allocation input completes; a small request served from charged heap returns
  normally) is a deployment property of `memory.max`'s page-granular accounting, not something a
  `Result` can carry — the crate cannot be told about the kill. It is now written into
  `decrypt`'s `# Allocation` section, with the recommendation the audit itself gives: admission
  control on the request size (`MAX_MSG_SIZE`, or `decrypt_bounded`'s `max_len`) is where this
  becomes a reportable error.
* Build-to-build timing spreads: the third round's own harness put `dual-mac` at 1.69–1.81x
  where this repository's states +30–40%, and `ultra`'s 1 KiB allocating decrypt at 4.62x where
  the table says 3.96x, without attributing the gap to either side. `performance.md` now carries
  the numbers and the rule: the *direction* each mechanism predicts is the claim (a fixed
  per-call scrub is largest at the small end, the second tag pass grows with the message, the
  witness is per byte); the constants are one host's. Its `LockedKey::new`-to-drop figure
  (26.6 µs) is not in tension with the README's "~7 µs per range" — the latter is `mlock` +
  `unlock` alone, and the former is the whole lifecycle.
* Coverage columns: the `report`-side *function* count comes with llvm-cov's
  "N functions have mismatched data" warning, so `deep.yml` now says in one line that it is
  only meaningful alongside that caveat; the region/lines disagreement was already handled by
  quoting no exact figure there (§1.C).
* Miri's long-run behaviour (libtest executes the tests serially under it, so one slow test
  starves the rest; `-Zmiri-report-progress`'s interval is basic blocks, not seconds) is a
  property of the tool and of how it is invoked, not of the crate — and it is why this
  repository's Miri stage is run per test target and per test, which is what gives each test
  its own verdict instead of one whole-target verdict. The third round's long-cap per-test
  rerun bears that out and is worth recording as evidence *for* the crate: with 40-minute and
  2-hour caps, `differential_reference` finished **6/6** (every-position 2231 s,
  large-vectors 4680 s) and `security` **14/15** — all PASS, zero UB — and the one test it
  could not finish is `security::fuzz_decrypt_never_panics_and_never_returns_plaintext`
  (20 000 rounds; 3.75G basic blocks in 2 h without ending). That test is not in this
  repository's Miri filters either, for the same reason (`tests/README.md` says the CI runs are
  narrow filters, not whole targets), and it runs normally under a compiled `cargo test`.
* Residue shapes (third round): the set of secrets and their lengths left in dead frames varies
  by profile, feature and backend — `pure` leaves a 16-byte `k_out` half, the release/no-default
  decrypt paths leave 8–12 bytes of `enc_nonce` that an 8-byte-anchored scan cannot see at all.
  `blake3_keyed_multi`'s comment now says this, and that no configuration probed left *both* a
  whole `k_in` and a whole `k_out` in reach (release keeps `k_in` whole and `k_out` short, debug
  the reverse), so the offline-forgery consequence is unchanged.
* The `2^256` / `2^128` family: after §1.C's corrections the documents' statements match the
  derivations (target `≈ 2^-256` per candidate key — the 256-bit `subkey` preimage, so `≈ 1`
  second key over the key space at key-search level; attacker-chosen key and context routes
  `2^128` with identical plaintexts; different-message
  salamander priced by construction at the key-search level, its bound not derived). **An eighth
  round (2026-10-08) corrected this line again**: the target
  figure had been `2^-520` per candidate key and `≈ 2^-264` over the key space, which prices only
  the *pure tag-collision* route and is dominated by the `subkey` one. See `CHANGELOG.md`'s
  eighth-round entry.

---

## 3. Verification of the tree that carries this response

* `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`: clean.
* `cargo test --release` in default, `--all-features`, `--no-default-features`, `--features
  rng,locked`, `--features ultra`: all green.
* Cross-target type-checks: aarch64 (gnu + musl), riscv64gc, i686, powerpc64, thumbv7em; MSRV
  1.85 builds.
* Gates: `tools/gate_selftest.sh`, `tools/ctgrind.sh` (all three configurations),
  `tools/fi_check.sh` (14/14 rows), `tools/fi_instruction.sh` (full `--bits`, and the default `nop` model),
  `tools/check_kani_cfg.sh`, `tools/stack_residue.sh`, `tools/broad_differential.py`,
  `tools/cache_profile.sh` (counts, trace, and both self-tests — re-run on a pristine tree for
  the third round's prediction, both modes PASS).
* Third-round additions: the `locked` refusal-path test (passes in 0.6 s; a mutant that ignores
  `lock_range`'s error fails it), `cargo fmt --check` and clippy clean with the new test.
* Kani: the tag shard and the concrete-comparison harness verified on CI.
* CI at the commit that carries this document: the `CI` workflow green; `Formal verification`
  and `Deep checks` green at the two commits before it and re-running for it (their results are
  visible on the commit page).
* riscv64: the test binaries executed under `qemu-riscv64` (all green, `timing` included,
  `ctgrind` excluded for valgrind as on every cross target), and the target now runs in
  `verify.sh --cross-exec` and the `cross-exec` job.

## 4. What would settle the items left open

* **The different-message salamander** (`SECURITY-ANALYSIS.md` §5 row 17): a *bound* on the route
  the documents now price by construction — fix `k_out₁ = k_out₂`, choose `M₁`, search for the
  256-bit inner-digest equality at ≈`2^256` candidates — or a cheaper break of it. The price is
  key-search level; the documents claim neither `2^520` nor that `2^256` is optimal.
* **A synchronous two-fault bench** (§2.2): the residual the README names is a hardware
  countermeasure question, not a software one.

## 5. The line-by-line report against `92c85ad` (the fifth review)

That report's own independent measurement came back clean on the construction: 5,411 differential
comparisons against a self-written reference across three configurations with **0 mismatches** (34
lengths × 7 AAD lengths, the 1999/2000/65488/65489 boundaries and 8 MiB among them), the witness's
independence confirmed adversarially, 19/19 Kani harnesses with no vacuity, and its own conclusion
that no implementation defect breaks confidentiality or integrity. Everything it raised was in the
verification apparatus and the documents. Every item below was **reproduced in this tree** before
being accepted, and every fix was verified in both directions — the mutation must fail, the clean
tree must pass. The full record, including the commands and the counters, is in `CHANGELOG.md`'s
entry for this round.

### 5.1 Adopted and fixed (17 of the 19)

| Item | Substance | What was done |
| --- | --- | --- |
| H-1 | ctgrind's shipped recipe (`+crt-static -C strip=none`, no `-C debuginfo`) attributes a branch inlined *into* `accept_or_reject` to `accept_or_reject`, which the single suppression entry then covers silently | `-C debuginfo=2` added to both build sites. An `#[inline(always)]` probe with a secret-dependent loop: rc 99 and the helper named; the same tree with the flag removed passes again; clean tree unchanged (one suppressed decision, rc 0) |
| H-2 | `witness_tag.copy_from_slice(&computed_tag);` before either `ultra` comparison makes the agreement vacuous, suite still 128/0/7 | `the_witness_outputs_reach_the_agreement_unwritten`: the binding the witness result arrives in may be mentioned nowhere between the call and the agreement. Four variants (both directions, the plaintext operand, the third site in `encrypt`) now fail it |
| H-3 | `verify.sh --kani-only` with zero harnesses printed "all requested checks passed" and exited 0 | Harness-count guard in the Kani stage: source count, cross-check against `check_kani_cfg.sh`'s `COMMITTED_HARNESSES`, and Kani's own zero-harness output. Explicit → rc 1, implicit → rc 3; real run unchanged (13/13, rc 0) |
| H-4 | The position screen cannot fail for the leak it names (its ~24 ns/op resolution is the order of the effect) | Renamed to `timing_tag_position_screen_finds_no_gross_difference`, docstring rewritten to lead with the bounds; CI's blocking existence-check follows. Its blocking status is *answered*, not adopted — see §5.2 |
| H-5 | The tamper sweeps are exhaustive only up to 300 bytes; a mask on `ct[60000]`'s bit 4 is accepted (reproduced — and the reason is that `pt_for(60000) = 235` has that bit clear, so only a *different* bit is caught) | New `differential_long_rows_sampled_positions_are_authenticated`: all eight bits at a deterministic position set over the 16 rows above the caps (297 positions, 2,376 comparisons), each anchored against the reference; the mask now fails it |
| H-6 | The stack-residue lists omit the whole 32-byte `k_in` (measured 32/32, plus 16/44 of `enc_key ‖ enc_nonce`, 4/32 of `k_out`; `pure` 16/32) | `README.md`, `SECURITY-ANALYSIS.md` and `scrub_stack`'s rustdoc corrected, attributed as `blake3_keyed_multi`'s own comment already did (the dependency's by-value temporaries); the quoted no-copy claim is scoped to what the crate can name |
| H-7 | The salamander's "cheapest known route `≈ 2^520`" is an overestimate by `2^264`: equal `k_out` first (≈`2^128.5`-key birthday), then a *chosen* message makes the tag satisfy the first opening by construction, leaving a 256-bit inner-digest equality at ≈`2^256` candidates | Corrected at every live site in both documents, `AUDIT-RESPONSE.md` and four rustdoc sites, keeping the distinction the report also keeps: a priced **route**, not a proven **bound**. Every remaining `2^520` is a tag-guess/forgery number |
| B-1 | Not on crates.io (404) while the README's two dependency snippets say `version = "0.1"`; no docs.rs metadata, so the gated API is invisible on a default doc build | Both snippets now say so and give the working `git` line; `[package.metadata.docs.rs] features = ["ultra"]` added, with a default `cargo doc` measured to render neither `locked` nor `random` and the `ultra` build to render both. The *publishing* part is §5.2 |

| Item | Substance | What was done |
| --- | --- | --- |
| M-1 | A shadow constant (`let acc = 0u64;`) makes `ct_eq_independent`'s fold tautological while the pinned lines survive | `the_fold_accumulator_is_the_compared_value`: one binding, four mentions, compared against zero after the last accumulation |
| M-2 | `XSIV_ALLOW_UNLOCKED` read with `is_ok()`, so `=0` meant "allow"; skips invisible under captured output | `allow_unlocked()` accepts only `1`/`true`/`yes`, an unrecognised value is loud and *not* consent, and every skip prints `SKIPPED [<test>]`. Matrix measured: unset, `1`, `0`, empty, `TRUE`, `maybe`. The same `is_ok()` in `src/lib.rs`'s `refuse_skip` (not named by the report) was fixed too |
| M-3 | The zero-test guard summed over the whole invocation, so emptying one target stayed green | Per-target counts for every suite invocation, with documented exclusions; emptied and deleted targets each fail |
| M-4 | Cross-execution with `QEMU_*=/bin/true` reported "executed 12 … under qemu" and passed | Emulator identity (basename `qemu-*` **and** a QEMU-mentioning `--version`) plus a per-binary `test result:` requirement; `/bin/true` now exits 1 before any build, real qemu unchanged |
| M-5 | The 8-byte threshold missed a 4+4 split and a 7-byte run | Split rule (two runs totalling ≥8 bytes) and a 7-byte rule, each with its own positive control. A global 4-byte threshold was measured at ~1 false FAIL per 12 runs over the 1 MiB paint region and rejected in the comment rather than adopted |
| M-6 | `fi_instruction.sh`'s `nop` model reported zero counts for an empty scan set and exited 0 | Per-shard and driver-level scan-count guards (exit 3 = could not run); empty set now rc 3, clean runs unchanged in `nop` and `bits` |
| M-7 | `counter_range.rs` bypassed by a function-pointer alias, by a call after `mod tests {`, and by counter arithmetic spelled differently | All three reproduced (the literal `wrapping_add(1)` form was *not* green even before, as reported honestly) and closed: standalone mentions panic, post-module code is scanned, and the ordered counter-arithmetic lines are pinned with an exact total of `.wrapping_add(` |
| M-8 | `locked.rs`'s asserted wipes could be moved into `if black_box(false) { … }` and the file stayed 10/10 | Brace-depth guard (each wipe an unconditional top-level statement, no preceding `#[…]`), plus a new behavioural test that corrupts the live key page through `/proc/self/mem` and requires the integrity check to panic |
| M-9 | `#[cfg(any())] { zeroize_array(…) }` deadened wipes survived 96/96 and 128/128 | Recursive constant-`cfg` rejection across `src/lib.rs` and `src/witness.rs` (spacing evasions proven caught, `cfg_attr` correctly excluded), applied at every wipe the count table relies on; the tree has no legitimate constant `cfg` to carve out |
| M-10 | The primitive census counted literal `name(` text, so a function pointer added an eighth live call invisibly | `the_counted_primitives_are_never_taken_as_values`: every occurrence of a counted name in non-test source must be a call or the definition the census skips. The guard states its own residual scope (assembled identifiers, code from outside the scanned text) instead of claiming the class is closed |
| M-11 | `detect_avx2` read CPUID leaf 7 without checking the maximum basic leaf (SIGILL on Sandy/Ivy Bridge — availability, not a silent wrong answer) | Standard guard: leaf 0 first, `max_basic_leaf < 7` returns false. Verified by the SIMD suite on this host and demonstrated synthetically for the faulty-hardware case, which this CPU cannot present |

### 5.2 Answered rather than changed (2 of the 19)

* **H-4's second half — "and it is in no blocking CI job".** True as stated, and deliberately so.
  The CI job's comment carries the measurement behind it: two hosted-runner runs with no possible
  causal difference reported `t = 10.96` (release) and `t = 11.89` (debug) against a real order
  artefact's `t = 35.6`, i.e. the runner biases the comparison by ~0.8% between classes. A screen
  sharpened enough to see tens of nanoseconds would therefore fail on CI for reasons that are not the
  crate's. The property it names is held by clock-free gates instead — ctgrind (H-1's fix makes it
  stronger), `tools/fi_instruction.sh`'s byte and bit sweeps of the compiled decision, and the
  source-shape pins — and the screens themselves run strictly in `verify.sh` (stage 3c) on every
  invocation. What the report was right about is the *claim*, and that is what changed.
* **B-1's framing as a defect to be fixed before 1.0.** The documentation half was a real defect and
  is fixed (§5.1). The remainder is not a defect but a release decision: publishing to crates.io is
  irreversible, requires the maintainer's credentials, and is not something CI should do on a push —
  this repository's release job attaches three source-built configuration bundles to a
  GitHub Release instead (no `.crate` is produced), and the README now says exactly that.
  The version (`0.1.0`) and the `Unreleased` changelog heading are
  consequences of not having released, not evidence of a mistake.

### 5.3 Found by this round, beyond the report

* **`non_test_source()` truncated at the first line of `mod tests {` in six test files**, hiding
  production code appended *after* the test module from every scan those helpers feed (measured: a
  helper calling `chacha20_keystream` with a fixed counter, appended and called from `encrypt`, left
  `tests/security.rs` green). All six now brace-match the module body and blank it; five of them are
  demonstrated to fail on an appended probe that they used to miss, with the old cut as the control.
* **Three more instances of the same truncation** in `tests/variable_latency.rs`'s inventories.
* **`refuse_skip`'s `is_ok()`** in `src/lib.rs` — M-2's defect, one file outside where the report saw it.
* **The control-flow census drifted 38 → 39** when the CPUID guard went in; the table, the row in
  `tests/README.md` and the guard moved together, which is what that table exists to force.

### 5.4 The state this section describes

The tree carries all of it: `check.sh --fast` green, and `verify.sh --ctgrind --tools --kani` green
(stages 1–4, Kani 19/19 with the new count guard, ctgrind, the mutation campaign with every mutation
caught, the fault-injection campaign, and the tool-level gates), `Deep checks` dispatched for the
commit. What is *not* claimed: the 4000-vector wide differential, the Miri Tree-Borrows sweep, the
fuzz soak and the cross-execution matrix were not re-run here — they are the scheduled job's, and its
dispatched run was still in the instruction-level sweep when this was written (ten of eleven jobs
green, including the ASan step whose failure started this stretch).

---

## 6. The dependency line-by-line report against `01348ab` (the sixth review)

This report audits **the dependency graphs**, not the construction: every one of the 120
`(crate, version)` entries of the three lockfiles (root 85, `blake3/` 65, `fuzz/` 19, deduplicated),
read line by line or by a declared method (structure check / generative provenance), with the
non-covered parts listed explicitly rather than upgraded. Its own supply-chain facts and the
per-item coverage claims are honest about their limits; what follows is the disposition.

Nothing here was taken on the report's word. Four independent passes re-derived the findings from
the installed sources under `~/.cargo/registry/src/`, reproduced the behavioural ones in offline
scratch crates, and re-ran the supply-chain commands; two of the report's statements did not survive
that (§6.3), one of its open questions was settled with a proof (§6.4), and one gap it named was
still open in a place it did not look (§6.1).

### 6.1 Adopted (2)

| Item | Substance | What was done |
| --- | --- | --- |
| Report F-07/F-08/F-09, one workflow short | The report found that `blake3/`'s and `fuzz/`'s `cargo deny check` runs fail (`bans`: the `reference_impl` path dev-dependency without a version; `bans` + `licenses`: the fuzz crate unlicensed and `libfuzzer-sys`'s `(MIT OR Apache-2.0) AND NCSA` not allowed) and that CI ran deny only at the root, so neither was ever exposed. Both claims are **exactly true at `01348ab`** (reproduced: `blake3/` exit 2 on `bans FAILED`, `fuzz/` exit 6 on `bans`+`licenses`). `ci.yml` and `verify.sh --deny` were fixed by `8ba999e`; **`deep.yml` was not**, and that is the workflow the release job polls — its `deny` job ran `cargo deny check` at the root only, and its `audit` job audited the root lock only | `deep.yml`'s `deny` job now runs the check in `.`, `fuzz/` and `blake3/` (`deny.toml` is found by walking up; cargo-deny has no `--manifest-path`), and its `audit` job scans the fuzz and blake3 locks with `--file`, mirroring `ci.yml:977-1000`. Today all three graphs answer `advisories ok, bans ok, licenses ok, sources ok` (measured with `cargo deny --offline check` in each directory); the only two warnings are `license-exception-not-encountered` / `unmatched license allowance`, which are inherent to sharing one `deny.toml` across three graphs |
| Report F-03 (the one shipped-closure item) | `subtle::Choice`'s 0/1 invariant is a `debug_assert!`, so a release build accepts any `u8` in `Choice::from(x)`; `conditional_select` then returns neither operand (measured `u8::conditional_select(1, 2, Choice::from(2)) == 3`) and upstream's open soundness issue is that path into `Ordering::conditional_select`, where the result is an invalid enum discriminant. This crate is correct today (two `Choice::from` sites, both the literal `1`; every other `Choice` comes from `ct_eq`), but `subtle` is the **only** report item in the shipped closure, and "correct by construction" is what a guard is for | `tests/security.rs::the_constant_time_selection_api_is_absent_and_choice_constants_are_literal`: the crate's own non-test sources (`src/lib.rs`, `src/witness.rs`, comments stripped) may not name `conditional_select`, `ConditionallySelectable` or `CtOption`, and every `Choice::from` argument must be the literal `1` (`["1", "1"]` for `src/lib.rs`, `[]` for `src/witness.rs`). Both directions measured: `Choice::from(u8::from(true))` fails with the argument list printed, and a `#[cfg(any())]`-gated `use subtle::ConditionallySelectable as _;` fails naming the API; the clean tree passes |

### 6.2 Verified as non-issues (the report's own verdicts, re-derived)

| Item | Report's verdict | Re-derived evidence | Actionable? |
| --- | --- | --- | --- |
| F-01 `cipher 0.4.4` `try_apply_keystream_partial` counts `len % bs` instead of `ceil(len / bs)` | Upstream defect, unreachable here | Reproduced (`len=64/rem=0`, `len=128/rem=0`, `len=129/rem=2` all `Ok` where `Err` is correct); this crate's AEAD goes `chacha20poly1305` → `StreamCipher::apply_keystream` → `stream_wrapper.rs:79-106 check_remaining`, never through the partial path; `cipher` is dev-only and not in the release closure | No — a fork of a benchmark-only crate would buy nothing |
| F-02 `cpufeatures 0.2.17` gates `"avx"` on XCR0 bit 1 instead of bits 1+2 (fixed in 0.3.1) | Upstream blemish, dev-only, never queried | Both installed sources read (`0.2.17/src/x86.rs:123` vs `0.3.1/src/x86.rs:116`); nothing in the graph asks for `"avx"` — the requested set is `sse2`, `sse4.1`, `avx2`, `avx512f`, `avx512vl` | No |
| F-04 `poly1305 0.8.0`'s `zeroize` `Drop` is not compiled | Correct conclusion, **wrong mechanism** — see §6.3 | The feature is not enabled on the only path that pulls poly1305 (`chacha20poly1305 0.10.1` takes poly1305 with default features); poly1305 is dev-only, absent from `-e normal` | No — and per §6.3, enabling it would be worse than leaving it off |
| F-05 `chacha20 0.9.1` `XChaChaCore::new`'s derived `subkey` local is not wiped | Correct, dev-only | Read at `chacha20-0.9.1/src/xchacha.rs:53-60`; reachable only from `benches/compare.rs` and `tools/stack_residue.sh`; the `zeroize` feature *is* on for chacha20 here, but it wipes `ChaChaCore::state`, not that local. The vendored `0.10.2` has the same shape, so an upgrade does not fix it | No — dev paths only, and it is upstream's local to wipe |
| F-06 `generic-array 0.14.7`'s `LowerHex`/`UpperHex` panic when `precision > 2*len` | Panic surface, unused | `src/hex.rs:33,46,52` read; this tree never names `GenericArray` and never formats with a precision (`{:.1}`/`{:.2}` appear only on `f64` in `tests/timing.rs`) | No |
| F-10 `zerocopy 0.8.57` has a FIXME about a missing SAFETY comment | Correct in substance, **wrong line** — see §6.3 | Dev-only through `half`/`ppv-lite86` safe APIs; the function the FIXME is on (`new_box_zeroed`) is not called | No |
| F-12 `zeroize 1.9.1` writes no field padding and has no fence | Correct where it matters; two sub-assertions imprecise — see §6.3 | Enumerated every wipe in `src/`, the fork and the runtime closure; no type with a secret-holding field has padding, and the crate's own secrets are wiped with its own whole-object volatile writes (`src/lib.rs`'s `zeroize_array`/`zeroize_slice`/`zeroize_raw`, with the trailing `compiler_fence`) | No |
| F-13 `arrayvec`'s `Zeroize` spare-capacity coverage | Correct (after first hedging) | `arrayvec-0.7.8/src/arrayvec.rs:887-911`: `iter_mut().zeroize(); clear(); self.xs.zeroize();` — the whole `[MaybeUninit<Z>; CAP]` backing array, spare capacity included; the fork's `Hasher::zeroize` does call `cv_stack.zeroize()` | No |
| F-14 `block-buffer 0.12.1`'s `Clone` SAFETY comment claims no `Drop` while `Drop` is implemented unconditionally | Correct, stale comment | `src/lib.rs:109-116` (`ptr::read`) vs `:433-439`; the only drop behaviour is an idempotent zeroize, so the bit-copy is not UB; compiled only in the fork's own test build, never in the root closure | No — upstream's comment |
| W7 anchors `anstyle 1.0.14` (`from_utf8_unchecked`) and `either 1.18.0` (`Pin` projection) | Both SAFETY arguments hold | Read both: anstyle's writes are valid UTF-8 into a private 19-byte buffer; `Either` has no `Drop`, no manual `Unpin`, no unpinned `&mut` field exposed | No |

### 6.3 Where the report is wrong

1. **F-04's mechanism** — "an optional dependency referenced by no feature, so the `Drop` wiping code is never compiled". An optional dependency creates an *implicit* feature of the same name when the manifest does not use `dep:` syntax, and `poly1305 0.8.0`'s manifest does not. Measured: a scratch crate with `poly1305 = { version = "=0.8.0", features = ["zeroize"] }` compiles and pulls `zeroize 1.9.1`. The conclusion (this tree does not enable it) stands, and the correction sharpens the disposition: `poly1305 0.8.0`'s `Drop` (`src/backend/autodetect.rs:97-105`: `&mut *(self as *mut State as *mut [u8; SIZE])` then `zeroize()`) is the reference-to-bytes transmute of a union-containing state that the upstream issue describes, and **0.9.1 removed it** — verified by extracting `poly1305-0.9.1.crate` from the local registry cache, whose `autodetect.rs` contains no `zeroize` and no `Drop` impl at all. So **turning the feature on is the harmful direction**. The report's phrasing invites the opposite action.
2. **F-10's line number** — the `FIXME(#429)` about a missing `SAFETY` comment is at `zerocopy-0.8.57/src/lib.rs:3645` and `:3651` (and `impls.rs:157`, `:209`), not `src/lib.rs:461`, which is a doc comment on a derive. The substance (comment only, no wrong safety argument) is right.
3. **§5.5's "the only drift is three build-only crates"** — true for the runtime closure and false as a statement about the locks. The locks also differ in dev-only versions (`chacha20 0.9.1`/`0.10.2`, `cipher 0.4.4`/`0.5.2`, `crypto-common 0.1.7`/`0.2.2`, `inout 0.1.4`/`0.2.5`, `rand 0.9.5`/`0.10.3`, `rand_core 0.9.5`/`0.10.1`), and the root lock's `libc 0.2.191` arrives through the dev chain rather than the build graph. The claim that matters — every normal-dependency version and checksum is identical across the locks — was re-derived and holds.
4. **F-12's sub-assertions** — "only `zeroize_flat_type` and `[MaybeUninit<Z>]` cover whole objects" is incomplete (`Option<Z>`, `DefaultIsZeroes` and the tuple/array impls write whole objects too), and "no `fence`" describes the impls, not the crate: 1.9.1 ships `optimization_barrier` and `zeroize_stack`. The operand the report cared about — the fork's field-wise wipes — was re-checked and its open boundary closed: the four fork types that hold key material have trailing padding (`ChunkState` 4, `Output` 5, `Hasher` 4, `OutputReader` 7 bytes, measured with `-Zprint-type-sizes`), the key field itself is a padding-free `[u32; 8]`, and nothing memcpy's a whole struct through a zeroizing path, so the unwritten bytes hold no secret.
5. **F-13's hedging** — the report prints two statements for `arrayvec`'s `Zeroize` coverage and declines to rule. There is one: `self.xs.zeroize()` is the line immediately after `self.iter_mut().zeroize()`, and no ledger in the report concluded otherwise. Recorded here as a single fact.

### 6.4 Upstream issues: confirmed, and one settled

| Issue | The report's judgement | What this round adds |
| --- | --- | --- |
| `subtle` #155 (`Choice::from` + `Ordering::conditional_select`, OPEN) | Unreachable here | Confirmed at source level *and* now guarded (§6.1): two literal-`1` construction sites, no selection API named anywhere in the crate's own sources, no non-0/1 `Choice` constructible from `ct_eq` |
| `libc` #5187 (manual `PartialEq`/`Hash` reading uninitialized union memory, OPEN) | Unreachable here | **Stronger than the report states**: every such impl is behind `#[cfg(feature = "extra_traits")]`, which this tree never enables (42 gates; `libc/Cargo.toml`'s `extra_traits` is off in all three locks), so those impls do not even compile here. This crate's own libc use is `mprotect`/`PROT_*` in tests and examples |
| `constant_time_eq` #12 (`black_box` fallback is not recommended for security, OPEN) | Target-related, low | Quantified: the fallback is gated on `not(inline_asm_is_stable)`/miri, and `build.rs` sets `inline_asm_is_stable` for x86/x86_64/aarch64 (among others), so x86_64-linux and aarch64-linux take `sse2.rs`/`neon.rs` assembly. `--no-default-features` changes `no_std`, not the backend. Only targets this crate does not ship (wasm, and architectures outside the build script's list) reach it |
| `poly1305` #342 (unsound `Drop` over a union, CLOSED in 0.9.1) | Not triggered (feature off) | Confirmed, plus §6.3.1: the feature *can* be turned on, and must not be |
| `zeroize` #653 (`Option<T>` wipe, OPEN, disputed) | Theoretically present | **Not instantiable here**: all five `impl Zeroize` in the fork destructure fields (none has an `Option`), the derive is not enabled in any lock, and this crate's own secrets use its own helpers. The generic `Option<Z>` impl has no call site to monomorphize |
| `cpufeatures` #1510 (CPUID leaf 7 read without checking the maximum basic leaf) | "Cannot determine whether it remains" | **Settled: it cannot mis-detect any feature this tree asks for.** `sse2`/`sse4.1` read leaf 1 only. `avx2` requires the `ymm` XCR0 gate, which `__xgetbv!` guards behind `CPUID.1:ECX` bits 26|27 (XSAVE + OSXSAVE) *and* leaf-1 ECX bit 28 — features that only exist on CPUs that also have leaf 7. `avx512f`/`avx512vl` require the `zmm` XCR0 bits, which likewise need XSAVE. An unconditional `cpuid(7)` on a CPU without that leaf is architecturally defined (it returns the highest basic leaf), not UB. This crate's own AVX2 detection (`src/lib.rs:4399-4490`) checks the maximum basic leaf itself, so it is stricter than the dependency |

Also re-derived: the three lockfiles scan clean with `cargo audit --no-fetch` (0 advisories each), there is no `[patch]`/`[replace]`/`[source]` override anywhere, `fuzz/` builds the local path fork (`fuzz/Cargo.toml:22-24`, and the `blake3` entries in all three locks carry no `source`), and **116/116** cached `.crate` archives match their lock checksums (root: 83/83). One claim could not be re-derived offline: "103 pinned versions are not yanked", because yank status needs the crates.io index, which `cargo audit --no-fetch` does not consult.

### 6.5 What was not done: no new fork

Every candidate for a local patch was rejected on evidence, and the contrast with `blake3/` is the
reason. That fork exists because **shipped** code needed patches — the AVX2/AVX-512 2/4-wide tail
over-read, the multi-block `xof_many` ABI, the short-output write, and (this round) the zero-block
write. None of this report's items reach shipped code:

* `cipher 0.4.4` (F-01) is a benchmark-only crate, is not reachable even in the dev graph, and 0.5.2
  already carries the fix;
* `poly1305 0.8.0` (F-04) and `chacha20 0.9.1` (F-05) are dev-only, and for poly1305 the correct
  action is to keep the feature off rather than to vendor the crate — enabling it would activate the
  construction upstream removed;
* `subtle 2.6.1` (F-03) is in the shipped closure but has no defect in this crate's use, and forking
  a constant-time primitive library to add a release build assertion would replace reviewed upstream
  code with ours on the one axis (constant-time correctness) where upstream review is worth most;
  the guard in §6.1 pins this crate's side of the contract instead;
* `cpufeatures` #1510, `libc` #5187, `constant_time_eq` #12 and `zeroize` #653 are proven
  unreachable or non-instantiable for this tree, so a fork would have nothing to fix.

### 6.6 The state this section describes

Everything above is in the tree at the commit that carries this section: `deep.yml`'s `deny`/`audit`
jobs cover all three graphs, and `tests/security.rs` has the `subtle` guard (negative-controlled in
both directions). The full record of the fixes, with the measurements, is in `CHANGELOG.md`'s
`## Unreleased` entry for this round. What is *not* claimed here: the report's own line-by-line
reading of the 116 registry packages was not repeated — this section verifies its *findings*, its
verdicts on the upstream issues, and its supply-chain facts, not its per-file coverage claims.

---

## 7. The incremental pass over `7ce256e4` (the seventh review)

This one audits the five commits from `01348abe` to `7ce256e4` as one increment. It reports no
high or medium finding, and all four of the low/observation items are in the *previous* round's
own new artifacts — a guard it added last round, and the changelog entry describing it. Its
re-verification of that round's shipped fixes reproduces clean here: `deep.yml`'s new
`audit`/`deny` steps really do cover the three graphs (and on the baseline the fuzz and blake3
graphs really did fail, exit 6 and exit 2), the zero-block `xof_many` guard matches upstream
`master` and goes red when `jb 4f` is deleted, and the bounded `EINTR` retry's control-flow
inventory matches the code (one `loop`, no new `if`).

### 7.1 Adopted and fixed (4 of the 4)

| Item | Substance | What was done |
| --- | --- | --- |
| F-01 | `the_constant_time_selection_api_is_absent_and_choice_constants_are_literal` matched the *text* `Choice::from(`, and the report measured three spellings that walked past it: `use subtle::Choice as C; C::from(2)`, `<subtle::Choice as From<u8>>::from(2)`, `Choice :: from(2)`. Each removed the site from the count while the assertion stayed green — the class the `syn` closure guard closed for wipes, in a file that already reads the AST elsewhere | Rewritten as a `syn` walk: no identifier in the non-test sources may be `conditional_select`/`ConditionallySelectable`/`CtOption`; every call whose path (or whose `qself` type) names `Choice` must take a literal `0`/`1`; `use … Choice as <other>` and `type X = …Choice…` are rejected. Six injections now fail — the report's three, the two the text version already caught (`Choice::from(u8::from(true))`, a `#[cfg(any())]`-gated `use subtle::ConditionallySelectable as _;`), and `type _C = subtle::Choice;`. Two residuals are documented rather than claimed (`syn` does not resolve names): an alias of an alias, and a conversion whose type is inferred at the call |
| F-02 | The guard's failure message called the second literal-`1` construction "the witness's `ultra`-off operand", but `src/witness.rs` has no `Choice::from` at all (`grep -c` = 0) | The message now names the two real sites (`src/lib.rs:3550`, `:3834`), and the pinned count is per file (2 and 0) |
| F-03 | This document's §6/`CHANGELOG.md` said the six stale copies of `find_cfg_test_attribute` "call the robust scanner". They were **seven byte-identical copies with no shared function** — the drift that produced the six stale ones was still one edit away, and nothing enforced the copies staying identical | The function moved to `tests/common/mod.rs` (with the history of why it is shared), and the seven targets call `crate::common::find_cfg_test_attribute`. The `CHANGELOG.md` entry was corrected to say what happened |
| Obs-04 | Both the macro guard and the `Choice` guard scanned `src/witness.rs` with `strip_comments` alone, so a wipe or a `Choice` inside the witness's own `mod tests` would have been rejected — stricter than `src/lib.rs`, which uses the test-module cut (over-strict, not a hole) | Both now use `non_test_source_of`, the same cut; `src/proofs.rs` has no test module and stays whole, which the comment now states |

### 7.2 Confirmed by this round, nothing to change

The report's §3 (the three-graph supply-chain work), §4 (the zero-block `xof_many` guard, its
upstream comparison and its delete-and-go-red control), §4.4 (the `storeu` declaration widths are
documentation only — an array parameter decays), §5 (the `EINTR` bound's semantics, placement in
the exit test rather than after it, and the inventory change), and §6.3/§7 (the remaining test,
tool and document claims) all re-derive as stated. Its three negative controls for the guard
match the ones this round re-ran, and its §6.1 reading of the guard's strengths — the three API
*names* cannot be spelled around, only the argument rule could — is the reason the fix went to
the AST rather than to a whitespace-normalising string scan.

### 7.3 What this round does not claim

The report's own three residuals are ours too: BLAKE3's issue tracker was unreadable through the
proxy for both of us (the vendored-tree diff against upstream `master` is the substitute, and the
stronger one — it reads the code we ship); yank status is outside `cargo audit --no-fetch`; and
`deep.yml`'s execution on a GitHub runner is not reproducible locally, so what is verified here is
that the same three commands are green on this tree and were red on the baseline, plus the CI run
for the commit that carries them.

### 7.4 The state this section describes

Everything above is in the tree at the commit that carries this section: the `Choice` guard reads
the AST, `tests/common/mod.rs` holds the one scanner, both guards cut the witness's test module,
and `CHANGELOG.md`'s entry for the round describes the merge accurately. No wire-format or
construction change accompanies any of it.
