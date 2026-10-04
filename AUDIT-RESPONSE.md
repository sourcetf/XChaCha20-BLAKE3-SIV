# Audit response — the four third-party reviews of revision `8ae80ce`

Four reports were produced against revision `8ae80ce` (construction `v0.3`), and this document
records what was done with each finding: what was **fixed** (with the commit and the evidence),
and what was **not changed**, with the reason. It is written to be checkable — every disposition
names a file, a test, a command, or a commit, and "responded" never means "ignored".

| # | Report | Pages | Findings | Disposition |
| --- | --- | --- | --- | --- |
| 1 | `逐行验证审计报告` (line-by-line audit) | 179 | 366 (41 marked DEFECT; 高 12 / 中 47 / 低 165 / 信息 31 / 未标注 112) | the DEFECT-class and 高/中 items are fixed (indexed in §1); the notes and informational items are answered in §2 |
| 2 | `增量攻击测试报告` (incremental) | 27 | 26 (0 高, 2 中, 14 低, 9 信息, 2 unlabeled) | both 中 fixed (§1.D); 低 fixed or answered |
| 3 | `增量攻击测试报告·完整版` (complete) | 32 | 58 (0 高, 3 中, 13 低, 25 信息, 18 unlabeled) | the three 中 fixed (§1.D); the rest fixed or answered |
| 4 | `增量攻击测试报告·第三轮` (third round) | 16 | 26 (0 高, 1 中, 4 低, 10 信息, 11 unlabeled) | two 低 fixed (§1.C); the 中 is the documented opt-out boundary (§2.2); the rest answered |

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
a488b36  Give the trace mode a determinism control, after its first CI run failed
77b18ac  Correct the constant-tag row: the byte-level probe is profile-dependent
f9a5d3d  Re-measure the ultra cost table after the witness's residue-wipe pass
ea56caf, 956c816, 6efac1f  trace-step message, changelog order, riscv64/debug/opt-out notes
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
| `tools/cache_profile.sh --trace` had **never run**: lackey prints ` S <addr>,<size>` with a leading space, so the `^[ILSM] ` filter kept only instruction lines, the load/store count was zero, and the mode answered "valgrind here cannot start the lackey tool" for years | filter fixed to `L`/`S`/`M` (instruction fetches excluded on purpose), plus a **determinism control**: the same input is run twice and those traces must match before keys are compared | `13caa0e`, `a488b36`; runs now: 170,874 / 274,664 identical accesses (default), 372,519 / 987,842 (`ultra`); `--selftest --trace` catches its planted leak; on a CI runner the control correctly reports "layout is not reproducible" and the step skips |
| `tools/fi_instruction.sh`'s full `--bits` sweep aborted 3/3 (ETXTBSY on the restore reopen; `UnicodeDecodeError` on a crashed binary's non-UTF-8 output) | the reopen retries a transient `ETXTBSY`; the run captures bytes and decodes with `errors="replace"` | `c907e47`; full `--bits` and `--nop` sweeps now complete and gate correctly |
| The sweep's published "total" undercounted by one per shard file with entries (no trailing newline, `cat … \| grep -c .` merged adjacent files: 4 printed as 3, 15 as 7) | files always end with a newline; the documented residuals re-measured | `c907e47`; the auditor's own independent fix reproduced the same correction |
| `check.sh`'s final-artefact check hardcoded `target/release/…` (ignored `CARGO_TARGET_DIR`, accepted any file) | the path is derived from `CARGO_TARGET_DIR` and the file must be newer than a stamp taken at start | `a778ee9` |
| `verify.sh`'s binary lookups globbed (`ls -t … \| head -1`), so a stale or planted binary could be executed | cargo's own JSON report is parsed instead (`e0e1950`, `tools/fi_instruction.sh` and `tools/mutation_check.sh` too) | `e0e1950` |
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
| "the completion step is a fixed point" (as a general statement) | only the different-message route is; the key and context routes complete immediately with the same plaintext | rewritten as three routes (`8dcc09e`) |
| `enc_seed` "bound into the tag's derivation" (README) | `enc_seed` keys the KDF *whose input is the tag* — the opposite direction | corrected |
| CHANGELOG's "reopens a complete invisible-salamander at `2^128`" | the route forces equal material, hence identical plaintexts: a key-commitment break, not a salamander | withdrawn in place (`8dcc09e`) |
| `random::fill`'s "a sandbox that blocks `getrandom(2)`" | the `getrandom` crate falls back to `/dev/urandom` on `EPERM`/`ENOSYS` | the example now says both must be blocked |
| `decrypt_bounded`'s `max_len` as a policy limit | it bounds the ciphertext (allocation), not the AAD or the work | documented |
| `Cargo.toml`'s `i686-unknown-linux-musl` note | with no i686 C toolchain BLAKE3 falls back to Rust backends and the plain build works; nothing on i686 runs this crate's SIMD | corrected |
| `.cargo/config.toml`'s "riscv64 linking does not work" | it links with an alias, a `self-contained` `-L`, and a non-PIE link; the suite then runs under `qemu-riscv64` | corrected, with the recipe and the one caveat in §2.7 (`6efac1f`) |
| "Miri, which cannot execute C — hence `pure`" | `pure` is belt-and-braces on x86_64 (Miri's CPU-feature detection reports nothing, so the C kernels are never dispatched) | softened in `Cargo.toml` and `tests/README.md` (`63e27e7`) |
| Kani cost figures (≈320 s per permutation, "well over 25 minutes") | on the current toolchain the real-permutation harness runs in 37 s and the whole 12-harness set in ~875 s | marked as history in `src/proofs.rs` (`63e27e7`), and the required flags (`-Z stubbing -Z unstable-options`) are spelled out in `tests/README.md` |
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

### 2.3 Dependency-internal behaviour

* **`blake3`'s XOF temporaries / `Hasher::zeroize` coverage** (reports 1 and 2): the crate's own
  copies are wiped; the dependency's by-value temporaries are not reachable from here, and
  `ultra`'s `scrub_stack` covers them. Documented in `blake3_keyed_multi`'s comment and
  `src/witness.rs`. There is no in-crate fix short of not using the dependency.
* **`getrandom`'s `/dev/urandom` fallback**: documented (the example now says both the syscall
  and the file must be blocked); the fallback is still an OS CSPRNG, so there is no security
  defect.
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

### 2.7 riscv64 execution: possible, not yet wired, and why

The link recipe is verified (alias + `self-contained` `-L` + non-PIE) and the suite passes under
`qemu-riscv64` — 61/61 lib, 15/15 security, 9/9 locked, and every other target — **except one
test**, `tests/ultra.rs::every_layer_answers_correctly_in_the_ultra_build`, which hangs in the
emulator available here (three threads in `futex_wait_queue`; reproducible with that test alone,
while the same sequence in a dependent test crate passes). Until that is understood, riscv64
stays type-checked rather than executed, and `.cargo/config.toml` carries both the recipe and
this caveat (`6efac1f`). The old claim that it could not be linked at all was wrong and is fixed.

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
* Verification tools: Kani 12/12 SUCCESSFUL; Miri with no UB (including full `--lib` and
  per-test runs); TSAN clean with its control detected; `cargo-audit`/`cargo-deny` clean; the
  coverage floor passes.
* Structural scale experiments (a 352-bit equality from one call chain, `b0`/`b1` segment
  equality, a ~2^144 claw across two *known* keys): informational, explicitly not vulnerabilities
  — they require the keys and are not attacks on an unknown one.
* CPU/resource notes: per-byte cost is not monotonic in length (BLAKE3's tree), unauthenticated
  decrypt pays the full cost (SIV computes the tag over the plaintext), `decrypt_bounded`'s
  bound is on the ciphertext — all inherent, and now stated.
* The `2^520` / `2^256` / `2^128` family: after §1.C's corrections the documents' statements match
  the derivations (target `2^-520` per candidate key; key-space enumeration `≈ 2^-264`;
  key-commitment and context routes `2^128` with identical plaintexts; different-message
  salamander not derived).

---

## 3. Verification of the tree that carries this response

* `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`: clean.
* `cargo test --release` in default, `--all-features`, `--no-default-features`, `--features
  rng,locked`, `--features ultra`: all green.
* Cross-target type-checks: aarch64 (gnu + musl), riscv64gc, i686, powerpc64, thumbv7em; MSRV
  1.85 builds.
* Gates: `tools/gate_selftest.sh`, `tools/ctgrind.sh` (all three configurations),
  `tools/fi_check.sh` (14/14 rows), `tools/fi_instruction.sh` (full `--bits` and `--nop`),
  `tools/check_kani_cfg.sh`, `tools/stack_residue.sh`, `tools/broad_differential.py`,
  `tools/cache_profile.sh` (counts, trace, and both self-tests).
* Kani: the tag shard and the concrete-comparison harness verified on CI.
* CI at the commit that carries this document: the `CI` workflow green; `Formal verification`
  and `Deep checks` green at the two commits before it and re-running for it (their results are
  visible on the commit page).

## 4. What would settle the items left open

* **The different-message salamander** (`SECURITY-ANALYSIS.md` §5 row 17): a proof or a break of
  the `T = tag(K₂, N, A, C ⊕ KS₂(T))` completion. Nothing in these reports claims a cheaper
  route; the document does not claim `2^520` is optimal.
* **The riscv64 hang** (§2.7): a multiarch debugger or a different emulator version would say
  whether it is qemu's or the test's.
* **A synchronous two-fault bench** (§2.2): the residual the README names is a hardware
  countermeasure question, not a software one.
