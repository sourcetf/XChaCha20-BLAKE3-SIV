# Changelog

Short, and deliberately about **the wire format** first: this construction is not a
standard, so a consumer needs to know when the bytes move. Versions below refer to
construction revisions; the crate version in `Cargo.toml` is `0.1.0`, and no *semantic*
release tag has been cut (the CI release job publishes rolling `sha-<short>` tags — one per
green push to `main` — which are build artefacts of that job, not construction revisions).

## Unreleased

### `ultra`'s cost table re-measured: 12.4x on 1 MiB decryption, not 10.1x

The three-pass campaign behind `performance.md`'s "what the `ultra` layer costs" table was
re-run after the witness's residue-wipe pass, because that pass added work to the witness's hot
path (the `Output` drop, the streaming locals, the CV stack's preallocation). The result:
`ultra` decryption now costs **2.73x / 3.24x / 3.96x / 6.93x / 10.37x / 11.02x / 12.41x** the
default across 64 B → 1 MiB, against the previously documented 2.46/2.70/3.56/5.81/9.05/10.00/
10.12, and the round trip 2.2-6.5x in place and 2.5-7.1x allocating. The encrypt column stays at
0.92-1.50x (the in-place path carries no witness).

Two honesty notes, both in the file: the campaign ran while the third-party audit was executing
its own suites on this host, so **its own noise floor is larger** (median pass-to-pass spread
12.7%, p90 105%, worst 148%, against 6.8%/10%/15% for the earlier quiet-host campaign) — which
is why only the `ultra` table was taken from it: the 1 MiB decryption move (~23%) is above even
that floor and consistent in all three passes, while the other tables' cells moved by amounts
inside it and are left alone. The README's witness rows and the `performance.md` summary bullet
carry the new figures; the two places that quote "10.1x" as the number that *led* to a finding
say so explicitly.

### `cache_profile.sh --trace` ran for the first time: lackey's lines start with a space

The address-trace mode — the one technique in this repository that can see a
secret-dependent *index* into a cache-resident table, which no counter can — had never
executed. Its filter was `^[ILSM] `, and valgrind's lackey prints ` S <addr>,<size>` /
` L …` / ` M …` **with a leading space** (instruction lines are unindented), so it kept only
the `I` lines, the load/store count below it then found zero, and the mode answered
`SKIPPED: valgrind here cannot start the lackey tool` — a wrong diagnosis of a filter bug,
with a comment explaining that the extracted valgrind cannot start external tools at all.
An audit ran lackey by hand, saw 109,673 load/store lines in the same call shape, and pointed
at the filter. The filter now keeps `L`/`S`/`M` (instruction fetches excluded on purpose:
the example's own hex parsing branches on the *characters* of its input, so including them
would compare the harness's parser rather than the library's accesses), and the mode works:

* `--trace 8`, default: **170,874** accesses identical for two different keys (encrypt), and
  **274,664** for the round trip;
* `XSIV_FEATURES=ultra --trace 8`: **372,519** and **987,842**, identical — the witness's
  access pattern is key-independent too;
* `--selftest --trace`: the planted secret-indexed table leak is detected, which is the
  control that says the comparison can fail.

So the "no secret-dependent index" half of the constant-time argument is now a measurement
rather than an argument, in the default and `ultra` configurations. (The mode's caveat is
unchanged and still real: it needs a controlled address layout — `setarch
--addr-no-randomize` — so it is a statement about this code, not about a hostile process.)

**And the first CI run of the fixed mode failed, which was the useful part.** On a GitHub
runner the two traces differ from line 17386 on — one-byte stack loads 107 bytes apart
(`L 1ffeffdfed,1` vs `L 1ffeffe058,1`), layout noise rather than key dependence. The mode now
runs the **same input twice** as a determinism control before it compares two keys: if that
control fails, the environment cannot hold a layout and the answer is "could not run"
(exit 3, a skipped stage in the job) instead of a false leak. A real leak cannot make two
identical runs differ, so the control cannot mask one. On the next CI run the control fired —
the job prints `SKIPPED: the enc address layout is not reproducible here -- two runs of the
same input differ` and the step is skipped, while the counts mode and its self-test still pass
there. So the mode's evidence is a quiet-host measurement (it passes there with ~170k/~275k
identical accesses) and a runner honestly says it cannot conclude. (While testing the control: piping
`diff` into `head` died of SIGPIPE and ended the script with 141 instead of 3 — the same trap
this repository's scripts document elsewhere, fixed by capturing the diff first.)

### `Key` and `LockedKey` compare in constant time now, instead of through `Deref`

The attack review's API-consistency item, fixed rather than documented: `Plaintext` has had
constant-time `PartialEq` impls since an auditor hit the `as_slice() == as_slice()` fallback
trap, while `Key` and `LockedKey` had none — so `key_a == key_b` compiled anyway, by coercing
both sides through `Deref` to `[u8; 32]` and short-circuiting on the first differing byte.
Both types now implement `PartialEq` (and the by-reference spelling) through
`subtle::ConstantTimeEq`; `LockedKey`'s goes through `as_bytes`, so the page's integrity
check still runs and a corrupted page still fails stop. The `Deref` warning that used to
explain the trap now explains `key.clone()` only, and two tests pin the impls by name
(`PartialEq::eq`) so removing one is a compile error rather than a silent fallback.

### The coverage job ran the timing screen instrumented, and called the result a leak

`Deep checks` went red on the commit before this one, and the failing step was the line-floor
step — but not for the line floor. `cargo llvm-cov` instruments every line, making each
operation ~70x more expensive (measured in the job's own log: 23.2 us per 1 KiB decrypt
against ~0.33 us plain), and the statistical timing screen's resolution model does not survive
that: it reported `t = 13.78` (means 23245.9 vs 23288.9 ns/op — a 0.2% difference blown up by
the instrumented fixed costs) and `t = 51.14`, both above its `t < 10` threshold, on the same
code that passes with `t < 0.4` on a quiet host. The screen is advisory in CI **by
measurement** (its own job is `continue-on-error`), and the blocking matrix already runs
`-- --skip timing`; the coverage step now does too. It does not move the denominator: the lcov
report contains only `src/lib.rs` and `src/witness.rs`, so the skipped target contributed no
lines to it. (The coverage floor itself passes locally at 95.65% of lines.)

### The complete attack-review round: a sweep that failed 3/3, and counts that were one short per shard

The complete version of the incremental attack report (14 units, all of the lightweight
version's units at full scale plus the repository's own suites and the verification tool layer)
found no cryptographic defect; what it did find was that one of this repository's own gates
**cannot be run to completion on this host**, and that a published count was systematically low.
Both are fixed here and re-measured; the rest is documentation the new measurements sharpened.
**No wire-format change.**

- **`tools/fi_instruction.sh`'s full `--bits` sweep failed 3/3 for the audit** (and therefore
  could not regenerate the documented opt-out/hardened/ultra residuals at all): four shards
  died on `ETXTBSY` when the `finally:` block reopened the shard's binary to restore the byte it
  had patched (the kernel still had the previous child's image busy — `subprocess.run` reaps its
  child, so this is transient, but it aborted the entire scan and printed no summary), and two
  shards died on `UnicodeDecodeError` because a crashed binary wrote non-UTF-8 to stderr and
  `run()` captured with `text=True`. The reopen now retries a transient `ETXTBSY` (and still
  raises if it persists), and `run()` captures bytes and decodes with `errors="replace"` — the
  verdict looks for one ASCII needle, so a replaced byte cannot change it. Re-run here: the full
  `--bits` and `--nop` sweeps both complete and gate correctly (decision-scoped zero in
  `hardened` and `ultra`, non-zero in the opt-out control).
- **The sweep's "total" undercounted by one per shard file with entries.** The accepted-offset
  files were written with `"\n".join(...)` (no trailing newline) and aggregated with
  `cat shard-*.accepted | grep -c .`, so the last line of one file merged with the first line of
  the next: 4 printed as 3, 15 as 7. The files now always end with a newline, and the numbers
  are re-measured and re-documented (README and `tests/README.md`): `(total, inside the
  decision)` — opt-out `17, 0` (nop) and `163, 4` (bits); `hardened` `1, 0` and `5, 0`; `ultra`
  `0, 0` and `5, 0`.
- **The `k_in` residue's shape depends on the profile, and reaches further than one frame.** The
  audit's full-scale probe: with this crate's release profile (LTO on) the full 32 bytes survive
  in dead frames above ~950-byte inputs; with LTO off it is a 16–24 byte prefix, and the frame
  depth moves with `overflow-checks`. It is also readable across threads, after thread-stack
  reuse, and in a `fork`ed child, until `scrub_stack` (which `ultra` runs) covers it. The
  `blake3_keyed_multi` comment now says all of that instead of "the 32 bytes".
- **Two more claims measured, and corrected where they were too strong or too old**: `--features
  pure` is *not* required for the Miri runs on x86_64 (Miri's CPU-feature detection reports
  nothing, so the C kernels are never dispatched — with or without the feature, the runs pass);
  the scripts keep passing it so the run does not depend on that. And the CBMC cost figures in
  `src/proofs.rs` (≈320 s per concrete permutation, ≈29 s per wipe, "well over 25 minutes" per
  AEAD harness) are an order of magnitude pessimistic on the current toolchain: the one harness
  that runs the real permutation verifies in **37 s**, and the whole 12-harness set is ~875 s
  with the slowest at ~460 s. The design they justify is unchanged; the numbers are marked as
  history. `tests/README.md` also now spells out that the harnesses need the entry points'
  flags (`-Z stubbing -Z unstable-options`) — the bare `cargo kani --features pure` fails to
  compile six of the twelve, which is caller knowledge the repo had left implicit.
- **The audit's fault matrix quantified the two-fault boundary the README states.** Two site
  pairs (`c2+ini1`, `ci0+ci1`) are individually invisible and jointly accept every probe — the
  honest ciphertext included — in **all three configurations**; `i1+a` (a shortened second
  comparison plus an inverted first gate) accepts 0.37–0.43% of forgeries on `hardened` and 0 of
  2,000,000 on `ultra`; a fault zeroing `derive_tag`'s stores accepts a zero tag on `hardened`
  and the opt-out build and is rejected on `ultra`. Those numbers now sit in the README's fault
  rows, next to the hand-modelled 2,573-attempt/2,000,000-attempt figures.

### The audit and attack reviews, worked through in parallel: a reachable abort, a lock failure path, and residue the witness claimed to wipe

This entry covers the two third-party reviews end to end: the line-by-line audit's remaining
findings and the incremental attack report's 26. **No wire-format change**; the behavioural
changes are the three below, each with the measurement that found it, and the rest is tests,
gates and claims that could not fail.

- **The `ultra` witness now wipes the copies it named but did not clear**, which is what the
  attack report measured (`k_in` residue, unwiped `Output` nodes and `[u8; 4]` temporaries):
  `Output` gained a `Drop` that wipes its CV and message block (covering the unnamed
  `parent_output(..).chaining_value()` temporary), the CV stack reserves BLAKE3's maximum tree
  depth up front so it can never reallocate out from under a wipe, and the streaming locals in
  `ChunkState::update`/`Hasher::update`/`add_chunk_cv`/`finalize_xof` are wiped. In the two
  hot loops the copies are *eliminated* instead of wiped — the key/nonce words and the
  feed-forward words are read and written byte-wise, so no 4-byte key copy exists — because
  wiping them measured ~30% of `ultra`'s large-message decryption; the residue-wipe pass as a
  whole moved that configuration's 1 MiB decryption ratio from ~11x to ~14x over the default,
  and `performance.md`/README are re-measured below.
- **`tools/ctgrind.sh`'s suppression check now rejects `obj:`/`src:` lines and requires the
  `fun:` value to *end* in the decision** (the `tests/decision_scope.rs` shape, one level up);
  the first draft of that check rejected the real file twice — the mangled symbol carries a
  `*` wildcard and the block's name line is not a valgrind kind — which its own negative
  control caught before commit.
- **`verify.sh`** now resolves its own path before `cd` (a relative `$0` broke `--help`),
  refuses `--kani-only` together with `--deep`/`--all` (the contradiction silently skipped
  stages 1-4), runs the timing target exactly once (`--skip timing_` in the suite runs; it
  used to run four times, three of them alongside the rest of the suite), sweeps ctgrind over
  all three configurations in strict mode, checks the *nightly* toolchain for `rust-src`
  before TSAN, validates `FUZZ_SECONDS` (0 means "no limit" to libFuzzer), pins the fuzz
  target directory it builds and reads (a foreign binary made the witness guard pass or fail
  for the wrong reason), and sanity-checks the cross-executable parse for a partial list.
- **Tests that could not fail, one by one**: `welch_t` returned 0.0 — the *passing* side — for
  two perfectly constant classes with different means (a leak with no jitter), and the three
  timing loops now serialise; the differential fixture's row/position/AAD floors became exact
  counts (49/40/5871/16) so deleting rows fails; the large fixture replays the detached
  in-place pair as well as the allocating one; `LockedKey`'s `Debug` check also rejects the
  decimal spelling of the key byte; the locked tests pin the `munlock`-before-`DODUMP` order
  and the `if ok(u)` gating; `decision_scope` pins the *return* of `plain & also` and the
  `(first, second)` gate pair (both had mutations that passed every count); `encrypt`'s
  witness cross-check, the `witness` module declaration and the "no `bool::from(witness::`"
  spelling are pinned; `ultra`'s `scrub_stack` count is per entry point; `security.rs`'s
  wrong-key property samples the flipped position and its allocation-order test covers all
  three allocating entry points; `counter_range` and `construction_inventory` keep the
  exact-count shape they gained earlier.
- **`src/lib.rs`**: the crate doc's flavour/caveat counts, the `subtle`-plus-independent-fold
  description, `SUBKEY_DOMAIN`'s counter note, `lock_range`'s page-granular advice,
  `deny_debugging`'s 0/1/2 states, the stale "the default build passes the same `Choice`
  twice", the `decrypt_bounded` doctest's stale `matches!` rationale, ChaCha20's feed-forward
  addition no longer called Davies-Meyer, `transpose8x8`'s tautological doc, `nib`'s hex
  helper made loud, and several tests pinned to `AuthenticationFailed` rather than `is_err()`.
  `tests/README.md`'s control-flow counts (37/7), the `qemu -cpu Nehalem` claim that has no
  runner anywhere, and the boundary lists are corrected too.
- Also in this push: the earlier allocation fixes (the 2-64 KiB abort, the `ultra` in-place
  wipe, `unlock_range`'s refused-`munlock` path), the fork/exec/Deref disclosures, the
  random-fill bound and the MSRV `--skip timing`, and `SECURITY-ANALYSIS.md`'s "the key
  search is `2^520`" wording (a *tag guess* is `2^520`; enumerating keys is `≈ 2^-264` over
  `2^256`).

### An abort reachable from the 2–64 KiB window, and a lock failure path that un-dumped a locked page

The incremental attack review (`XChaCha20-BLAKE3-SIV_增量攻击测试报告_8ae80ce`, the follow-up to the
line-by-line audit) found two real defects in the boundary between this crate and the
allocator/kernel, both reproduced here before the fix, plus a set of documentation claims that
measurement contradicted. **No wire-format change.**

- **`derive_tag`'s contiguous buffer aborted the process on refusal.** The 2 KiB..64 KiB
  window (on `48 + aad + msg`) used `Vec::with_capacity`, which aborts rather than returning,
  and an *unauthenticated* ~2 KiB input reaches it (SIV computes the tag before verifying).
  The README promises the opposite for both allocating entry points ("a refusal is
  `Error::AllocationFailed`, not a process `abort`"), and the abort also skipped every wipe on
  the way out — the review's core dumps held the recovered plaintext and `k_in`/`k_out`/
  `enc_seed`. The arm now uses `try_reserve_exact` and falls back to the three-part hash
  (which needs no buffer and hashes the same bytes), so a refusal costs speed for that call
  and nothing else. Measured A/B with a global allocator that refuses anything above 60 000
  bytes: the old shape dies with `memory allocation of 60051 bytes failed` and SIGABRT (exit
  134), the new one completes a legitimate 60 KiB round trip against a tag produced by the
  fast path — the two shapes agree end to end — and rejects a forgery with the buffer
  zeroized.
- **`decrypt_in_place_detached` returned `Err(AllocationFailed)` without zeroizing the
  caller's buffer**, contradicting its own "on failure the buffer is zeroized" and the
  README's version of it, on `ultra`'s two witness allocations. Both failure arms now
  zeroize the buffer before returning. Measured with the same refusing allocator: `Err
  (AllocationFailed)` and the buffer all-zero (it was untouched before).
- **`unlock_range` restored `MADV_DODUMP` even when `munlock` was refused**, so under a
  syscall filter that allows `mlock`/`madvise` and denies `munlock` (the review's seccomp
  experiment) a page could be left *locked and dumpable* — the state the doc claimed "never
  exists" — with the `VmLck` charge never returned. The advice is now restored only when the
  unlock succeeded, so a refused unlock leaks a dump exclusion instead of a key.
- **Claims corrected where measurement contradicted them**: "no copy of the MAC key survives
  the call" (the review measured the 32 bytes of `k_in` in dead stack frames on the default
  build above ~950-byte inputs, from the `blake3` dependency's by-value temporaries; `ultra`'s
  `scrub_stack` covers them); `random::fill`'s "a sandbox that blocks `getrandom(2)`" example
  (the `getrandom` crate falls back to `/dev/urandom` on `EPERM`/`ENOSYS`, so blocking the
  syscall alone is not enough on glibc); `decrypt_bounded`'s bound ("on the ciphertext only —
  it does not bound the AAD, and `max_len` bounds the allocation, not the work");
  `Cargo.toml`'s `i686-unknown-linux-musl` note (with no i686 C toolchain BLAKE3 falls back
  to its Rust backends and the plain build succeeds, so `features pure` is belt-and-braces
  there, and nothing on i686 runs this crate's SIMD — its kernels are x86_64/aarch64).
- **The two source inventories caught the code changes and were updated deliberately**:
  `tests/construction_inventory.rs` (`blake3_keyed_multi(` 4 -> 5 call sites for the same
  three uses; §4.10 now says so) and `tests/variable_latency.rs` (`if` 36 -> 37, `match`
  5 -> 7: the new branches test the allocator's and the `munlock` syscall's return values,
  which are public facts about the process, never key/nonce/AAD/message content). Both are
  exactly the tripwires they exist to be.
- **`fork` is now disclosed as a boundary** (the review's medium-low item): the child inherits
  the key bytes and the `MADV_DONTDUMP` advice but *not* the `mlock` — `VmLck` is per-process —
  so a forked child can read the key and its copy can reach swap after a COW write or once the
  parent drops its own; `execve` also resets the dumpable flag. The `LockedKey` docs, README's
  boundary list and SECURITY-ANALYSIS §8.2 now say so, with the measured rows (child reads the
  plaintext, child `VmLck` = 0, the child's page swaps after one COW write). A service that
  forks should load keys after the fork or re-`mlock` in the child.
- **Two `Deref`/RAII hazards written down** rather than left to be discovered: `Key`'s
  deref target makes `key.clone()` a plain `[u8; 32]` copy that is not wiped on drop (the
  type deliberately has no `Clone` impl; use `Key::from_bytes` for a real copy), and it
  makes `key_a == key_b` a short-circuiting array comparison rather than a `subtle` one;
  `mem::forget`/`Box::leak` on a `LockedKey` leaks the lock quota until the process exits.
- Also on this push: the whole-buffer `random::fill` assertion is a count again (~6e-6
  false-failure bound) instead of demanding zero sentinel matches, which failed ~22% of the
  time on a correct fill and turned two CI jobs red; and the MSRV job now runs
  `-- --skip timing` like the blocking matrix, because the statistical timing screen is
  advisory by measurement and was gating a job whose subject is the minimum toolchain.

### A second `2^128` commitment route, and harnesses that could not fail

A line-by-line audit of `8ae80ce` (the revision the review above was cut from) found four
classes of problem, all reproduced here before the fix. **No wire-format or behavioural
change**: every item is a test, a harness, or a claim about one.

- **The attacker-chosen commitment game has three routes, and two of them are priced.** The
  key route (`subkey` collision, equal material ⇒ equal tags *and* keystreams, same
  plaintext) was already recorded. The **context** route was not: with one key and one
  message, two chosen contexts whose inner digests `X = B3(k_in, DOM_PRE ‖ N ‖ le64|A| ‖ …)`
  collide give the *same tag*, and the KDF's input is the tag rather than the context, so the
  keystream is equal too — one `(C, T)` validates under both contexts for the same plaintext,
  with **no fixed-point step**. That is `2^128` (a birthday over the 256-bit digest), and
  "the completion is a fixed point" was therefore wrong as a general statement. The
  key-holder context target is **`≈ 2^256`** (a preimage of the same digest, no tag width
  involved), so the README's context-commitment row — which quoted `2^-520` per candidate key
  and "the width is what sets it" — described the *key*-search game, not this one. Corrected
  in README's security table and its "two games" section, `SECURITY-ANALYSIS.md` Thm 2's
  commitment bullet and the paragraph that replaced "commitment to the nonce and the
  lengths: same argument, byte for byte", §4.5's table row and completion analysis, §5 row
  17, §5.1's procedure table (a context route next to the key route), and §8.1 (a context row
  of its own; the target row no longer claims contexts).
- **`enc_seed` does not enter the tag**, and the README said it did ("the key material is
  bound into the tag's derivation across three separate values"). It keys the KDF *whose
  input is the tag*, which is the reverse direction; the tag binds `k_in` (inner digest) and
  `k_out` (outer hash). Corrected there and in the "two games" prose.
- **The Kani tag harness could not see a truncated tag or a swapped `k_in`/`k_out`.** The
  stub never checked the *width* of the buffer it was asked to fill, so an outer hash over
  `&mut tag[..40]` passed every assertion, and with symbolic keys nothing said which secret
  belonged to which hash. The stub now asserts 32/44/`TAG_LEN` output widths, and a new
  harness — `tag_matches_the_model_on_a_concrete_input` — reconstructs the expected tag
  through the model on one concrete input and compares all 65 bytes, which catches both the
  swap and a truncation. It is a harness of its own rather than a block in the symbolic one
  because mixing the two pushed that harness's CBMC run past fifteen minutes (measured). The
  macro's comment claimed that reconstruction already happened — it did not; that comment is
  now accurate, as is the module's "not covered" list. Measured on copies: the clean tree
  verifies in 83 s, a `k_in`/`k_out` swap fails the byte comparison in 78 s, and an outer
  hash over `&mut tag[..40]` fails the stub's width assertion in 9 s — where before the
  change both mutants passed every harness in the shard. `tests/README.md` and `tests/decision.rs`'s campaign counts are corrected with it
  (eleven `--test decision` rows of fourteen, not ten of thirteen).
- **Two source-scanning tests could be satisfied by comments.** `tests/counter_range.rs` now
  strips comments *and* string literals with a small scanner (a `//` inside a literal used to
  cut the rest of its line out of the scan, and `/* … */` was scanned as code), tolerates
  whitespace before `(` and calls spanning lines, rejects `use … as …` aliases of a scanned
  name, and asserts an **exact** per-name call census (13 sites) instead of a floor — a
  renamed `chacha20_block` used to drop the count to 11 and still pass. `tests/decision_scope.rs`
  runs every presence/count assertion on comment-stripped **non-test** source, and the
  suppression file must be exactly its five lines with a mangled symbol that ends in
  `accept_or_reject` preceded by its v0 length (`my_accept_or_reject` and `*accept_or_reject*`
  are rejected). Verified by mutation on a copy in each direction (counter `7` fails, the
  rename fails, a multi-line call with a space before `(` is counted).
- **Two gates did not check that their named tests ran.** `tools/ctgrind.sh` and
  `tools/tsan.sh` accepted libtest's "0 passed" — a filter that matches nothing exits 0 and
  valgrind has nothing to report either — so a renamed test would have turned either into a
  silent no-op. Both now require the named tests to appear in the run.
- **Assertions that did not assert**: `fuzz/fuzz_targets/roundtrip.rs` checked the in-place
  wipe only `if ... .is_err()`, so an implementation that wrongly returned `Ok` skipped the
  check; `tests/security.rs` exercised the in-place failure contract only in the
  unstructured (random-tag) rounds, never on the "valid tag, corrupted input" rounds it
  exists for; `tests/mac_commitment.rs`'s early-return arm passed while asserting nothing, so
  any `encrypt` failure satisfied it; `tests/decision.rs` swept all 65 tag bytes through
  `decrypt` but flipped only the last byte through `decrypt_in_place_detached`;
  `src/lib.rs`'s `random::fill` test asserted "some byte changed" (a one-byte fill passed;
  the first fix demanded *zero* sentinel matches, which fails ~22% of the time on a correct
  fill — CI caught that in two jobs — so it is now a count with a ~6e-6 false-failure
  bound, still far below what a prefix-writing fill leaves behind);
  the MSRV job now runs `-- --skip timing` like the blocking matrix does, because the
  statistical timing screen is advisory **by measurement** (a hosted VM reports t ≈ 11 with
  no possible cause, against a threshold of 10) and must not gate a job whose subject is the
  minimum toolchain — that flake turned the MSRV job red on this push;
  its AAD/message coverage test claimed "any bit" while flipping bit 0 of every byte (the bit
  position now rotates); and the in-crate `locked` test returned silently when the kernel
  refused to lock, making "verified" and "never ran" both read `ok` (a runtime refusal is now
  a failure unless `XSIV_ALLOW_UNLOCKED=1`, matching `tests/locked.rs`). `verify.sh` gained
  the missing host-side `cargo test --release --features locked` entry. In `src/witness.rs`,
  `add_chunk_cv`'s comment claimed the popped CV's slot was wiped "as well as the copy" —
  `Vec::pop` does not write the storage it shortens past, so the slot is now zeroed before
  the truncation (the by-value return temporaries the same doc discloses remain disclosed).
- **Doc claims corrected in place**, each with what the code actually does: the crate doc's
  "the detached entry points never allocate" (they make one bounded infallible
  `Vec::with_capacity` in `derive_tag`'s concatenated path, and `ultra`'s
  `decrypt_in_place_detached` allocates two witness buffers fallibly); the "every allocation
  goes through `alloc_zeroed`" note; the in-crate security table's
  "Context / key commitment (CMT-3, CMT-1/CMTk) | `2^-520` per candidate key" row (three rows
  now, matching README); the avalanche test's implication that it covers the ChaCha20 round
  function (an audit's mutation: corrupting the round constant left it green while the KATs
  failed); the stack-requirement test's implication that it locks the 16 KiB constant
  (`need` is 0 without `dual-mac`, and the margin is 4–64× the constant); the large-fixture
  comment's "64 KiB / 65 537" (the switch is on `48 + aad + msg`, so 65488/65489 with an
  empty AAD); and an orphaned half-sentence of a doc comment that had been left glued to the
  length-guard test when the test it described moved.

### Gate defects: a self-test that corrupted the artifact it was testing, and three rows that could pass without running

An audit of the gates themselves (reproduced here before each fix) found defects of the class
this repository has already been bitten by twice — a check whose *verdict* is not about the
current source. **No code or wire-format change**, but `verify.sh --ctgrind`/`--deep`/`--all`
could fail on unchanged source before this.

- **`tools/ctgrind.sh`'s self-test wrote the planted binary into the *main* deps directory.**
  The planted copy is the same crate, so `-C metadata` gives it the same file name as the
  clean one; the main check then found it with `ls -t … | head -1`. Measured in a clean
  clone: run 1 PASSed (and planted), run 2 — for which cargo says Fresh, so nothing was
  rebuilt — reported 8 leaks inside `decrypt_in_place_detached` in **0.8 s**, on source that
  had not changed. The self-test now builds into its own target directory, and both lookups
  ask cargo (`--message-format=json`) for the executable instead of globbing; the main build
  also removes any pre-existing `ctgrind-*` first, which heals a tree that already has one
  (one relink). Verified: two consecutive runs now both exit 0, and the self-test still
  catches the planted leak.
- **`tools/fi_check.sh`** built every row into **one shared target directory**, which makes a
  row's freshness depend on `cp` and `cargo` ordering: a row whose sources are older than the
  shared dir's outputs silently runs the *previous* row's binary. Rows stay ahead of that, but
  the clean baseline added below is built after its row is copied — and the first
  `expect=fail` row then reported "expected fail, got pass" on an unmutated binary. Each row
  (and baseline) now has a private target directory.
- **`tools/fi_check.sh`'s `expect=fail` rows could pass on a *compile failure***: any non-zero
  `cargo test` exit counted as detection. Each row now builds first, so "the detector failed"
  means the test ran and failed; and an `expect=fail` row also requires a cached clean
  baseline, so a detector that already fails unmutated cannot supply a vacuous pass. This
  immediately caught a live one: `wipe-skipped`'s patch used `let _ = &mut buffer;`, which
  does not compile (E0596 — the binding is not `mut`), so **nothing was testing the in-place
  wipe**. The replacement compiles and the row now exercises what it claims.
- **`tools/mutation_check.sh`** had no clean baseline and its KAT row mapped *any* non-zero
  exit to "caught" — including a compile error. Both mutations now run against a baseline
  first, and a mutated tree that does not build is reported as such rather than as a catch.
- **`tools/gate_selftest.sh`** asserted the exit-3 convention by grepping for the text that
  implements it (`if [ "$ctgrind_rc" -eq 3 ]`, `^ *exit 3`), so a behaviour-preserving rewrite
  read as a failure, and it never looked at `tools/fi_check.sh` — an injected `exit 0` skip
  there stayed green. It now checks behaviour: the three tools must answer 3 with the tooling
  hidden, `verify.sh` must *fail* when a stage the caller named is skipped, and `fi_check.sh`
  must not report completion with an unusable toolchain. It also refuses to recurse (running
  it from `verify.sh`, which runs it, spun forever) and runs in 0.4 s instead of 5½ minutes.
- **`verify.sh` under a narrow invocation**: `--ctgrind` with no valgrind printed "all
  requested checks passed, apart from 1 skipped stage" and exited **0**. A stage the caller
  names is now fatal when it does not run; stages skipped without being named are unchanged.
- **`check.sh`** asserted a hard-coded `target/release/…rlib` at the end, which under
  `CARGO_TARGET_DIR` can be an older artifact from a previous run. It is derived from the
  target directory and must be newer than the run's start.
- **The tools honour an explicit `VALGRIND=` strictly** (`ctgrind.sh`,
  `mutation_check.sh`): an unusable value is "could not run" rather than a cue to fall through
  to a system valgrind. That is what makes the gate test's hiding airtight on a machine that
  has one.

### The `2^128` route is a key-commitment break, not a salamander

A reader's independent analysis — matching what §4.5 of `SECURITY-ANALYSIS.md` already said about
the completion being circular — showed that Thm 2's commitment bullet overstated the `v0.3`
regression: it called the `subkey`-collision route "a complete salamander at `2^128`". An
experiment against `tools/ref_impl.py` confirms what the route actually gives:

- **Assuming the collision** (two distinct keys whose HChaCha20 output agrees), both keys open the
  same `(C, T)` — but the two decryptions are **byte-identical**, because identical derived
  material means identical keystreams. That is a **key-commitment** break: one ciphertext, two
  keys, complete and immediate.
- A **_salamander_** needs the two openings to be *different* messages, which needs
  `KS₁(T) ≠ KS₂(T)` and therefore *different* derived material — exactly what this route rules
  out, since it forces `KS₁ = KS₂` and hence `M₁ = M₂`.
- Without a collision the finish condition is precisely the fixed point
  `T = tag(K₂, N, A, C ⊕ KS₂(T))` — the completion §4.5 already recorded as circular — and the
  cheapest route to it we can see is the `2^520` search over the tag space (about one fixed point
  per key pair, if the map behaves as a random function). That is not a proof that no cheaper
  route exists, and the document says so rather than claiming one.
- **A second `2^128` route, and its completion is not circular either.** The same review's second
  pass priced the *context* half: with one key and one message, two chosen contexts (a different
  AAD or nonce) whose inner digests `X = B3(k_in, DOM_PRE ‖ N ‖ le64|A| ‖ …)` collide give equal
  tags — and the KDF's input is the tag, not the context, so the keystream is equal too. One
  `(C, T)` then validates under both contexts for the **same plaintext**, with no fixed point to
  solve and no second key needed. So the game has three routes, not two: key half `2^128`, context
  half `2^128` (both same-plaintext breaks), different-message salamander not derived. An earlier
  revision of §4.5 and of README called the completion step "a fixed point" without qualification
  and priced only the key half; both now carry all three, and a same-key context move is recorded
  as a **`2^256`** target (a preimage of the 256-bit inner digest) rather than a `2^520` one.

So the accurate statement is: **`v0.3` reopens a key-commitment break at `2^128`, at the cost of
the same plaintext; the salamander half was never at `2^128` and is not analysed.** Corrected in
Thm 2's commitment bullet, §5 row 17 and its closing paragraph, and §8.1 — which now carries a
*key-commitment* row and a *salamander* row rather than one row answering `2^128` to both — plus
README's security table and its "two games" section. The error's direction was conservative (it
credited the route with more than it has), but the whole point of this document is which game has
which bound.

**No code or wire-format change.**

### Second audit round: two vacuous proofs, a stack-residue regression, and a set of claims the tools did not support

An adversarial re-audit (a dozen independent passes over the construction, the tests, the
gates and the docs) found no defect in the *construction* — it is byte-for-byte what
`SECURITY-ANALYSIS.md` §1 specifies, reproduced a fourth time here with an OpenSSL-backed
ChaCha20 — but it found real problems in the verification story and one reintroduced
hygiene defect. **No wire-format change.**

- **`witness::material`/`enc_material` returned key material by value** — the exact
  aggregate-return shape `derive_material`/`derive_enc` were rewritten away from, because the
  return temporary is a copy no `wipe` can name. A stack scan on a scratch copy measured
  `k_out` surviving as a full 32-byte run (and `enc_seed` 23–31 bytes) after
  `witness::decrypt`; it was masked in production only by `scrub_stack`. Both now write
  through caller slices.
- **The Kani tag harness was vacuous.** `tag_is_keyed_hash_of_the_whole_context` asserted only
  that the tag was non-zero, and the stub's layout assertions run only if the stub is *called*
  — so a `derive_tag` that returned a constant without reaching the hash passed (reproduced).
  The harness now requires the hash to have been reached, through a call counter the stub
  increments; the mutant now fails and the harness still verifies (284 s).
- **`dual-mac`'s and `ultra`'s wiring was not behaviourally tested.** `fi_check.sh`'s
  stored-tag-substitution row runs on `ultra`, where the witness rejects the fault on its own,
  so a dead `dual-mac` recomputation passed it; and a `Choice::from(1)` rewrite of the witness
  agreement left `cargo test --features ultra` green (both reproduced). A `dual-mac-isolated`
  row now runs on `hardened,dual-mac`, and the shape tests require the wiring tokens, not just
  the calls — each evasion was re-run and now fails.
- **Claims the tools did not support, corrected**: ctgrind reports secret-dependent
  *branches*, not memory indices (memcheck does not report an address from a poisoned byte);
  Kani does not read the nonce back, and reaches neither the contiguous hash shape nor the
  counter wrap; `variable_latency.rs` inventories literal `/`/`%` in `src/lib.rs` only;
  the differential position sweeps now floor their row count so a regenerated fixture cannot
  make them vacuous; and `prop_tag_bit_flip_rejected` samples one position per case rather than
  sweeping all 65.
- **Two documentation self-contradictions in `SECURITY-ANALYSIS.md`** that survived the
  earlier corrections (`§1` still claimed the equal-material route was closed by a "768-bit
  target"; `src/lib.rs` still quoted "`2^520` per attempt" across a line break, which is how a
  single-line grep missed it), the Thm 4 bound now charges the three `Adv^{A3}` applications it
  actually makes, and `§1`'s range notation is defined in one unit.
- **Gate defects fixed**: `verify.sh`'s mutation-evidence gate now *fails* on stale evidence
  instead of printing a note; `cache_profile.sh` and `ctgrind.sh` honour `CARGO_TARGET_DIR`
  instead of profiling a stale `./target` binary; `deep.yml`'s address-trace step is no longer
  `continue-on-error` — and, since a host whose valgrind cannot start `lackey` genuinely cannot
  run it, `cache_profile.sh`'s self-test now propagates exit 3 ("could not run") rather than 1,
  so that host *skips* the trace checks instead of failing them; `fi_check.sh`'s rows are wrapped
  in `timeout` so a cut-off is a failure; and `deny.toml`'s bans/sources lints are `deny`, not
  `warn`.
- **`ultra` needs an OS entropy source** (`rng` → `getrandom`) and does not build on bare-metal
  `no_std`; documented, with the `hardened,dual-mac,locked` alternative.
- **Follow-ups closed**: the witness's primitive-internal state (`block`/`hchacha20`'s `s`/`v`,
  `compress`'s `state`/`m`, and the `Output` compression results) is now wiped — the module had
  disclosed this as a gap and left it to `scrub_stack`; the differential fixture now straddles
  the *actual* contiguous-hash boundary (the switch is on `48 + |A| + |M|`, so the message
  lengths are 2000 and 65488, not 2048 and 65536 — the old pair was 48 bytes off and witnessed
  the switch only *inside* the window); `ref_impl.py`'s independence claim is now scoped to the
  primitive layer it actually is (the construction glue is a transcription, so the differential
  catches divergence, not a shared misreading); the fuzz target also feeds `decrypt` tags and
  ciphertexts taken straight from the fuzzer and requires them to re-encrypt to themselves if
  they authenticate; and `unlock_range` documents that it clears a `VM_DONTDUMP` it did not set.
  Two broken intra-doc links are fixed as well (`[LockedKey]` in `unlock_range`'s new text, and a
  pre-existing `[random::generate_key]` that only resolved under `rng`), so `cargo doc` is clean
  with default features and with `--all-features`.
- **Portability claims aligned with what actually runs.** A dedicated cross-target pass found no
  functional defect — ppc64 big-endian, i686 in release *and* debug (overflow-checked), Miri's
  s390x (64-bit big-endian) and ppc32, aarch64/qemu and a 300-vector native↔ppc64 random
  differential were all byte-identical, and the SIMD-vs-scalar suite already sweeps every length
  0–600 plus the block/SIMD boundaries and counter-carry values — but several claims were not
  backed by any committed entry point: `verify.sh --miri` now really does cross-interpret **s390x**
  and run the boundary corpus there — and the Deep Miri job runs the same step, with its job budget
  raised 60 → 90 minutes in this commit — (README, `tests/README` and `src/lib.rs` described that run
  while nothing executed it); `verify.sh`'s "35 `from_le_bytes`/`to_le_bytes` call sites" is 32;
  `tests/README`'s claim that only four named binaries execute on the big-endian target was wrong
  (every built binary runs; `timing-*` and `ctgrind-*` are the only exclusions); and the NEON
  transpose comment no longer justifies itself with "no qemu", which is false here.
- **Two source-scan tests no longer miss the evasions an audit demonstrated.**
  `tests/counter_range.rs` now scans `chacha20_block(` — the scalar primitive the kernels'
  tails fall through to — so `chacha20_block(key, 7, nonce)` fails it (reproduced on a scratch
  copy); it used to be invisible because the name was not on the list.
  `tests/construction_inventory.rs` now counts `blake3::Hasher::new_keyed(`, the single keyed
  seam, so a second direct keyed-hasher construction is a count change rather than a silent
  eighth use (also reproduced). Both remain name lists — a different spelling could still
  evade them — which `tests/README.md` now says instead of implying the coverage is complete.

### The commitment bound reads "`2^-520` per candidate key", not "`2^520` per attempt"; a flaky test assertion removed

Two findings from an audit pass, one adopted and one corrected — recorded because the first
changed how a *number* is written in five places, and the second was a real test bug.

- **The target-commitment number is now written as a per-candidate probability.** Every site that
  quoted "`2^520` per attempt" meant *"2^520 work to find a second key"*, but "per attempt" reads
  as *"each attempt costs 2^520"*, which is not a probability and invited exactly the confusion an
  auditor then reported: F-C5b argued the target bound is false and that an equal-`subkey` channel
  makes a second key reachable in `2^256`. That channel is real but belongs to the **attacker-chosen**
  game, where the adversary knows `K₁` and can aim at its `subkey`; in the **target** game the
  adversary is given only `(C, T)` and does not know `K₁`, so a candidate key still has to hit the
  given 520-bit tag, `2^-520` per candidate (`2^-264` over the whole key space). Writing the number
  as `2^-520` per candidate key (with the `2^520` search as the equivalent work) removes the
ambiguity. Updated in `README.md` (both tables and the two-games discussion), `SECURITY-ANALYSIS.md`
(§3 Thm 2, §4.5's table and consequence bullets, §5 row 3, §6), and `src/lib.rs`'s security
table. No number changed — only what it is a probability *of*.
- **`prop_nonce_reuse_behavior` and `prop_aad_message_split_is_bound` no longer assert that the
  ciphertexts differ.** SIV guarantees the *tags* differ (`2^-520` per fixed pair); it does not
  guarantee `ct₁ ≠ ct₂`. The ciphertext is `M ⊕ KS(tag)`, so `ct₁ == ct₂` needs
  `KS₁ ⊕ KS₂ == M₁ ⊕ M₂`, a `2^-8·|M|` event — with 1-byte messages, `2^-8`, i.e. a spurious
  failure roughly once in 16,000 runs (deterministically reproducible). The assertion was testing
  something the construction does not promise; the properties that *are* promised — distinct tags,
  and neither context authenticating under the other — are still asserted, and the same
  "distinct tags ⇒ distinct ciphertexts" overstatement in two `src/lib.rs` test comments is
  corrected to say the ciphertext bytes are pinned as a regression input rather than derived.

**No code or wire-format change:** the construction is untouched.

### L3.4 and L3.5 reduced to L3.3, so the assumption list is three primitive conjectures

`SECURITY-ANALYSIS.md` §2.1 previously listed L3.4 ("the BLAKE3 tree preserves PRF-ness") and
L3.5 ("the XOF keeps it past the first output block") as primitive-level conjectures alongside
L3.1–L3.3, with L3.4 described as "an argument, not a proof" and "the one place in this tree where
'it is standard practice' is doing more work than a citation". The argument is now written out as
a reduction:

- **Lemma T (node-input injectivity):** in one keyed BLAKE3 tree every compression call is at a
  distinct point of the compression function's domain, unless two chaining values collide —
  proved by cases, the same kind of inspection-level statement as A4.
- **L3.4 = L3.3 + Lemma T**, by a bottom-up hybrid, loss `depth · Adv^{L3.3} + q²/2^257`
  (`depth ≤ 28` for `MAX_MSG_SIZE`).
- **L3.5 = L3.3**, since successive XOF output blocks are the root compression at distinct
  counters.

So the irreducible primitive conjectures are **L3.1, L3.2 and L3.3** — one per primitive, with
L3.4/L3.5 reduced and A4 proved. The document states two caveats rather than presenting this as a
theorem: the reduction is *this document's own* proof sketch (BCK covers sequential iteration and
says nothing about a tree), and its weight rests on Lemma T, so the nodes stay on the conjecture
list until an independent party checks the sketch. §2.1, §2.2, §2.3, §3 and §6 are updated so
"which assumptions are irreducible" has one answer.

The same section now also answers "BLAKE3 uses fewer rounds than BLAKE2s — should the rounds be
raised?": **no**, because the bounds here are set by key size (`2^256` forgery) and chaining-value
size (`2^128` collision), not by rounds, and because "BLAKE3 with more rounds" would be an
unanalyzed bespoke variant — trading the one body of evidence that supports L3.3 for a
construction with none.

**No code or wire-format change:** this is the security argument, not the construction.

### Both outstanding items done: `performance.md` re-measured for `v0.3`, and `mutants.out/` refreshed

- **Every performance table in `performance.md` is now a `v0.3` three-pass measurement**, made
  with the documented protocol (three configurations × three passes, rotated order, one pinned
  core, criterion `--warm-up-time 2 --measurement-time 4`). The protocol is now a script rather
  than a paragraph: `tools/bench_3pass.sh` produces the raw output per configuration per pass and
  `tools/bench_summarise.py` turns it into the tables, so the numbers can be reproduced instead of
  taken on trust. `README.md`'s performance summary, its witness fault-table row and its
  "cannot fix for you" note are updated to match.
  - The `v0.3` change (one extra keyed-BLAKE3 call, one extra ChaCha20 derivation block, both
    **fixed** per message) moved the small sizes, as predicted: 64 B encryption is now ~1.25x the
    reference against 1.57x before, decryption 64 B is inside the noise floor, and everything from
    16 KiB up is unchanged (1.35x encryption, 1.30x decryption at 1 MiB). `ultra`'s witness is
    ~2.5x at 64 B and ~10.1x at 1 MiB on decryption (was 2.8x/11.3x).
  - The noise floor is re-derived the same way as before (the reference implementation's own
    pass-to-pass spread): median **6.8%**, p90 **10%**, worst **15%** across 63 cells — the same
    shape as the 5.9%/11%/15% this file previously reported.
  - The 12-byte-vs-24-byte Poly1305 comparison is re-derived too: median cell 1.6% (was 1.4%),
    worst 6.1% at 1 KiB decryption (was 8.4%).
- **`mutants.out/` now describes the current source.** The committed evidence predated `v0.3`
  (its diffs still contained `mac_key` and the pre-change `decrypt` body). Re-ran the campaign
  (`cargo mutants --features ultra -f src/lib.rs -F 'decrypt|accept_or_reject' -E 'replace & with
  |' -- --test decision --test security`): **17 mutants, 15 caught, 2 unviable**, the same
  outcome vector as before, so the change did not alter the mutation result — but the recorded
  diffs now carry the current function bodies and line numbers, and
  `tools/mutation_evidence.py` reports the committed directory describes the fresh run.

### Production-readiness pass: every gate in the repository passes, and two documentation defects fixed

Ran the repository's own verification, end to end, on this tree. **All of it passes**, and no
functional defect was found:

- `verify.sh --cross-exec --miri --deny --tsan --tools` — cross-architecture *execution* under
  qemu (aarch64 NEON, i686 32-bit, powerpc64 big-endian), Miri on both accelerated targets (SSE2
  and AVX2) over the unsafe paths, `cargo-deny` (advisories, licences, bans, sources),
  ThreadSanitizer with its deliberate-race negative control, and the tool-level gates (the fault
  campaign over all three configurations, the cache/branch-profile self-test, the mutation-evidence
  gate, and the `#[cfg(kani)]` harness type check). "All requested checks passed."
- `tools/ctgrind.sh` in the default and `ultra` configurations — clean, with the control leak
  observed and the self-test confirming the suppression names only the decision.
- `cargo-llvm-cov --all-features` — 96.71% of lines, 97.92% of regions.

Two documentation defects were found and fixed:

- **A duplicated sentence in `lock_range`'s doc comment** (a merge artefact: the same clause
  written twice, once as "Elsewhere locking is unsupported" and once as "Unsupported on this
  target"). Removed; the surviving sentence is the one that matches the `cfg` it documents.
- **The coverage note in `deep.yml` was stale** — it quoted 97.89% (113 of 5353), from before the
  two-level tag change. Refreshed to the measured figures above, stated as both the line and region
  percentages so the reader can see which one `--fail-under-lines` compares against. (The gate
  itself is unchanged at 95 and passed throughout.)

Still outstanding, unchanged from the entries below: `performance.md`'s tables are `v0.2` figures
awaiting a full three-pass re-measurement (the fixed `v0.3` cost is measured and stated in that
file), and `mutants.out/` predates `v0.3`.

### `locked`'s integrity tag survived on the stack — and the scan now measures it

An auditor found the one wipe the `07043de` sweep did not reach, and this is a real leak of key
material, not a documentation point.

- **The defect.** `LockedKey::new` and `LockedKey::check_integrity` each held the integrity tag —
  the first 8 bytes of `BLAKE3(key)`, i.e. a hash of the master key — in a local that was never
  wiped. `check_integrity` is `#[inline(never)]` and runs on **every** `as_bytes()`, so the copy
  sat in its own frame on the ordinary stack on every encryption and decryption through a
  `LockedKey`; and its `panic!` path unwinds without running any later statement, so even a wipe
  placed after the comparison would have covered only the success path. The `07043de` change had
  wiped the *hasher's* state for exactly this reason but not the 8 bytes it produced.
- **The fix, in two parts.** `integrity_tag` now writes through a caller slice rather than
  returning (`fn integrity_tag(key: &[u8], out: &mut [u8; KEY_TAG_LEN])`): a returning version
  kept a copy in *its own* frame, which no caller can reach — confirmed by measurement, not
  assumed. Both callers then wipe their buffer — `new` before its fallible `lock_range` (so the
  `?` cannot return through it) and `check_integrity` before its branch (so the panic path is
  covered).
- **The measurement.** `tools/stack_residue.sh` now scans for `BLAKE3(key)[0..8]` as well as the
  master key, exercises `LockedKey::new`/`as_bytes`, and carries a **blake3-only attribution
  control**: the same XOF call and wipe discipline with no crate code. The control shows the
  remaining 8-byte residue is the `blake3` dependency's XOF output buffer — the same finding the
  README already records for the derived values, in a frame this crate cannot wipe — so the tool
  reports it as attributable rather than as a crate failure. The crate's own copies are gone.
- **The guard.** `tests/locked.rs::the_integrity_tag_is_wiped_in_both_callers` is a source-shape
  assertion (a wiped stack local is not observable from a test): it pins the write-through
  signature, and that each caller's wipe precedes the fallible `?` and the branch respectively.
- **Wire format unchanged.**

### Follow-up audit of `v0.3`: a false commitment number corrected, an aggregate return removed, and consistency fixes

A wide audit of revision `v0.3` (core source, witness, Kani, the test guards, the docs, the
tooling, and an adversarial crypto pass). It found **one substantive defect** — a wrong security
number and a wrong conclusion in the `v0.3` entry itself — and a set of smaller ones. **The wire
format is unchanged** (still `v0.3`): the code changes below are internal.

- **The `v0.3` commitment rationale was wrong, and this is the one that matters.** The entry (and
  `README.md`, `SECURITY-ANALYSIS.md`, `src/lib.rs` and `tools/ref_impl.py`) said the equal-material
  route was closed by requiring a collision in all of `(k_in, k_out, enc_seed)` — "a 768-bit
  birthday (`2^384`)". It is not: all three are deterministic functions of the single **256-bit**
  `subkey = HChaCha20(K, N₁)`, so two keys agreeing on the triple need a `subkey` collision — a
  **`2^128`** birthday, the same order as the tag's own collision bound. Worse, that means `v0.3`
  **reopens a key-commitment break at `2^128`** — equal material ⇒ equal tags *and* equal
  keystreams — that `v0.2`'s `K`-in-input step had closed; the two-level tag does not close it.
  (*Corrected in the `v0.3` review*: this entry first called it "a complete invisible-salamander
  at `2^128`", which overstates the route — equal material means equal keystreams, so the two
  openings share a plaintext and the different-message salamander is not reached at all. See "The
  `2^128` route is a key-commitment break, not a salamander" above.)
  The route is in the *attacker-chosen* commitment game this crate never priced, and it is
  `2^128` (infeasible), so the *target* commitment (`2^-520` per candidate key) is untouched — but
  the claim and the number were both false and are corrected in every file that carried them, with
  the trade recorded rather than described as a free win.
- **`derive_material` no longer returns its keys by value.** It returned a 96-byte aggregate —
  the same shape `derive_enc` was changed away from after a stack scan found the tail of its
  return surviving — and is now a write-through-caller-slices function, so the caller's named
  locals are the only copies. (This function's own residue was not independently measured at the
  time; the shape was, shortly after, when the same audit found `integrity_tag`'s return leaving a
  measured 8-byte run — see the entry above. The fix is the crate's established pattern, and that
  entry is the measurement.)
- **The `ultra` witness tag is now wiped at every call site** (it is a secret-derived MAC); the
  witness's module doc no longer claims every buffer is wiped, since its scalar primitive state
  (`block`/`hchacha20`/`compress`) is not, and no longer claims the domain strings are duplicated
  as literals (they are imported — which is why the cross-check cannot catch a wrong domain, and
  the differential fixture is the anchor for that).
- **`tests/counter_range.rs`'s literal-1 allowance is now scoped by position**, not by function
  name: it must be a `chacha20_keystream_raw` call *inside `derive_material`'s body*, and there
  must be exactly one, so a new helper can no longer inherit the allowance.
- **`tests/construction_inventory.rs`'s lemma S1 now checks the domains are used at the right
  places** (inner head, outer head, key derivation), not only that the constants differ.
- **Kani/proofs corrections**: the module doc no longer claims the nonce `N` is covered by the
  harnesses (it is not — `N` occupies `head[8..32]` and no harness inspects it, so that property
  rests on the differential fixture); the arity comment and the dead contiguous-branch comment are
  corrected.
- **Documentation/consistency**: the benchmark's AAD is **15** bytes, not 16 (an earlier
  correction of "3 → 16" was itself off by one); the `v0.3` cost is **+15%** at 64 B, not +18%;
  the release policy is `v0.3` and "changed twice", not `v0.2`/once; the primitive use count is
  **seven** everywhere; the §4.9 assumption list is A1–A4; `proofs.rs`/`CHANGELOG` no longer name
  the removed `test_tag_binds_the_key_directly`; `tools/broad_differential.py`'s header constant
  is 48 (was 80); the CI release-note prose says the format "changed twice"; `performance.md`'s
  `v0.3` note now states the fixed cost's *relative* fall (≈4% at 4 KiB, ≈2% at 16 KiB) rather
  than "≤2% by 4 KiB".
- **Not changed, recorded**: `mutants.out/` evidence predates `v0.3` and should be regenerated;
  `tools/gen_test_vectors.py`'s `(79,1)/(80,1)/(81,1)` pairs are vestigial but harmless. Neither
  is a defect.

### Wire format: revision `v0.3` — the tag becomes two-level, and the key-dependent-input assumption (L3.6) is removed

**The wire format changes: every tag, and therefore every ciphertext, differs from the previous
revision.** This is a construction change rather than a hardening one, and it is the first
wire-format change since `v0.2`. It is recorded first because a consumer's first question is
always "did the bytes move?" — and here the answer is yes.

**What changed.** The tag was one keyed BLAKE3 in which the master key `K` both keyed the hash
(through `mac_key`) and appeared in its input:

```text
tag = BLAKE3_keyed(mac_key, DOM_TAG || K || N || |A| || |M| || A || M)
```

It is now two keyed BLAKE3 calls (the NMAC shape), and **no hash message contains `K`**:

```text
X   = BLAKE3_keyed(k_in,  DOM_PRE || N || |A| || |M| || A || M)   32 B
tag = BLAKE3_keyed(k_out, DOM_TAG || X)                           65 B
```

The derivation produces three keys instead of two, from two ChaCha20 blocks (counters 0 and 1
under the same subkey nonce): `k_in` and `k_out` from block 0, `enc_seed` from block 1.

**Why.** The single-level form was committing — `K` in the input is what closed the
equal-material route — but it put the hash's *key* and a 32-byte substring of its *message* in the
same call as two correlated functions of one secret. That is a key-dependent-input step (the
document's node **L3.6**): strictly stronger than "keyed BLAKE3 is a PRF", with a separation in
`SECURITY-ANALYSIS.md` §2.1 showing no black-box reduction from it exists, and — unlike HMAC's
two-level structure — with no published theorem in that shape. The two-level form removes the
correlation outright: in both calls the message is a value the reduction can construct, so the
standard PRF and cascade reductions apply and **L3.6 is gone from the assumption list.**

**The commitment trade, stated honestly (an earlier revision of this entry got the number and the
conclusion wrong).** The equal-material route is a chosen-key search for two keys with equal
derived material, which gives one ciphertext that opens under both. `v0.2` defeated it by binding
`K` into the tag input — two keys with equal material still produced different tags. The two-level
tag does not bind `K`, and deriving three values instead of one does **not** restore the closure:
all three are deterministic functions of the single 256-bit `subkey = HChaCha20(K, N₁)`, so the
route costs a `2^128` **subkey** birthday over the `2^256` key space — the same order as the tag's
own collision bound, **not** a 768-bit `2^384` event. So `v0.3` reopens a
**key-commitment break** at `2^128` in the *attacker-chosen* commitment game (the literature's
CMT-1/CMT-3) that `v0.2`'s `K`-in-input had closed — with the two openings sharing a plaintext,
so it is not the different-message salamander this sentence once called it. It is `2^128` — infeasible today — and it is a
game this crate never priced, so the bound it does claim is untouched: the **target** commitment
(a *given* ciphertext) stays `2^-520` per candidate key, and the `2^128` collision bound is
unchanged. The trade for removing L3.6 is real rather than free, and a revision that wanted both
would have to break the `subkey` bottleneck (e.g. derive the tag keys from `K` directly).
`SECURITY-ANALYSIS.md` Thm 1 (c), Thm 2's commitment bullet and §4.10 record it.

**What else moved with it.**

- `DOM_PRE` is a new domain constant (`XSIV-PRE`); `DOM_TAG` now heads the **outer** hash
  (it is that hash's domain prefix; the key is `k_out`).
- `derive_material` returns `(k_in, k_out, enc_seed)` and burns counters 0 and 1 of the derivation
  block, not only counter 0. `tests/counter_range.rs`'s "counter starts at zero" rule now names
  that one scoped exception rather than being loosened.
- Cost: **one extra ChaCha20 block and one extra BLAKE3 call per message** — measured **+15%** on
  64-byte encryption and under 2% from 4 KiB up (see `performance.md`, which carries the figures and
  the outstanding full re-measurement); the message-length-dependent work is unchanged.
- `tools/ref_impl.py` (the independent reference, anchored to the published RFC 8439,
  HChaCha20-draft and official-BLAKE3 vectors) was updated first; the KATs and **both** differential
  fixtures were regenerated from it, and the in-crate accelerated-path corpus digest
  (`src/lib.rs`) was refreshed to match. The duplicated KAT in `tests/security.rs` was regenerated
  too, from the same reference.
- `tests/construction_inventory.rs`'s primitive-call count moved from 13 to 15: two ChaCha20
  derivation blocks (was one) and three BLAKE3 tag calls (was two).

**The security argument's shape changed more than the bytes did.** `SECURITY-ANALYSIS.md` §2, §2.1,
§2.2, §2.3, §4.10 and §6 are updated: the assumption tree now has five primitive conjectures
(L3.1–L3.5) rather than six — *and a later entry, above, reduces L3.4/L3.5 to L3.3, leaving three* —
A5 no longer declares a correlation, the "one layout choice that adds
an assumption" row is gone, and §6's residual-risk entry for L3.6 is removed. The test that pinned
the old design (`test_tag_binds_the_key_directly`) is replaced by
`test_tag_binds_both_derived_keys`, which pins that both derived keys reach the tag — the master
key now reaches it only through the derivation.

### Wire format (the entries below this heading)

**Unchanged.** The entries below — the pre-review sweep and everything after it — do not move the
bytes; the two-level tag above is the only wire-format change in this section. Within those
entries every ciphertext and tag is byte-identical, and the KATs, the differential fixture against
`tools/ref_impl.py` and the accelerated-path corpus all pin the same bytes. They are hardening,
correctness in `ultra`, evidence quality, and corrections to the *documented* security numbers, one
of which (the `locked` layer never issuing `MADV_DODUMP`) was a real bug in a defence rather than
prose.

### Final pre-review sweep: two wipes that a path could skip, two guards satisfied by prose, and six CI/tool defects

A last self-check before external review, run as three audits (core source, tooling/CI,
documentation) plus a manual pass over the parts they flagged. Everything below is a fix from
that pass; the wire format is untouched.

**Core source (`src/lib.rs`)**

- **`Plaintext::drop` cleared its tail with a plain `write_bytes`.** The comment promised a wipe
  the call could not guarantee: a non-volatile store to memory that is about to be freed is a
  dead store the optimizer may drop. No leak today — the only `Plaintext` constructor's `Vec`
  comes from `alloc_zeroed`, so the tail is already zero — but a future constructor that reuses
  capacity would have trusted the comment. It now calls a new `zeroize_raw`, and `zeroize_slice`
  delegates to that same function so the alignment/chunking logic exists once.
- **`locked::integrity_tag` hashed the key through `blake3::hash`, leaving BLAKE3's chaining
  value — a hash of the key — on the stack.** This crate treats "a hash of the key" as key
  material (see `Key`'s redacted `Debug`) and the *keyed* path zeroizes BLAKE3's state for exactly
  this reason, so the unkeyed call now uses an explicit `Hasher` and wipes it. `lock_range`'s
  size check makes the cost invisible (microseconds once per key).
- **`ultra`'s `encrypt` skipped `scrub_stack` on its two witness-rejection paths.** The scrub
  runs after the last derivation on the success path, but the early `return Err` before the
  keystream skipped it, leaving the just-returned `witness::encrypt_tag` frame in the region the
  scrub exists to overwrite. Both arms now scrub. (That `scrub_stack()` was ever reachable on a
  rejection is not something a test can observe; it is a correctness-of-claim fix.)
- **The crate-level "Side channels" doc said "no secret-dependent branches", which was false.**
  It now names the three that exist, including `locked::check_integrity`'s fail-stop panic branch
  — present since the integrity tag was added and never recorded there. It also names the witness's
  `Choice` handling under `ultra`, which is the third.
- **Corrections to claims sharper than the code:** "the second comparison is now in every
  configuration" was false for `--no-default-features` (which compiles neither the fold nor a
  second gate — that is what opt-out means); the boundary is now stated as "every configuration
  that builds the gates". `test_tag_length`'s comment repeated the *old, falsified* birthday
  rationale for the 65-byte width (§4.5 falsifies it), and was rewritten to the target argument.

**Guards that were satisfied by prose rather than by code** — the class this repository keeps
finding, and two more were in the suite:

- `tests/ultra.rs::the_witness_is_called_from_exactly_these_entry_points` grepped the entry-point
  bodies for `"witness::"`, and `decrypt`'s own **doc comment** contains `witness::decrypt` — so
  deleting the real call would have left the assertion true. It now strips `//` comments first
  (verified: renaming the call to `witness ::decrypt`, which compiles and contains no `witness::`
  token, makes the test fail).
- `tests/construction_inventory.rs::the_derivation_nonce_does_not_use_xchacha20s_nul_padding`
  searched the *whole* of `src/lib.rs` for the nonce-domain write, and the same string occurs in
  that file's own `mod tests` — so deleting the real write at `derive_material` left it true. It
  now cuts at `mod tests {` (verified: breaking the real write makes it fail).
- The floor assertion in the same file claimed to stop "deleting the functions" making the
  assertions vacuous; it computes a sum over the test's own table and cannot see the source. Its
  comment now says what it guards (the table), since the per-call equality above already guards
  the source.

**CI and tooling**

- **`tools/cache_profile.sh`'s self-test re-execed `$0`.** With a relative `$0` that resolved to
  the patched copy in a scratch tree by accident; with an absolute `$0` it re-ran the unpatched
  original, which re-ran the self-test, which re-execed — a fork bomb instead of a test. It now
  execs the copy explicitly.
- **`tools/stack_residue.sh`'s PASS line claimed a control it never checked** ("the control shows
  the scan produces no false positives"); the control entry was only printed. A control false
  positive is now a failure, so the sentence is true.
- **`tools/broad_differential.py` reported exit 1 (a *mismatch*) when it could not run** — no
  `blake3` module, or cargo failing to build the example. It now exits 3, which `verify.sh` maps
  to a *skipped* stage, per the repository's convention.
- **`verify.sh`'s "no test binaries" branch expanded `$deps`, which is never assigned**, so
  under `set -u` it died with an unrelated shell error instead of the intended message; and the
  mutation-evidence step collapsed `mutation_evidence.py`'s exit 3 ("could not compare") into the
  stale-evidence branch, printing "commit the fresh run" and silently *not* restoring the
  committed `mutants.out/`. Both fixed. `tools/fi_instruction.sh` and `tools/mutation_check.sh`
  had `ls … | head -1` substitutions without `|| true`, so under `pipefail` an empty glob aborted
  the script before its own "no binary" guard could run.
- **`.github/workflows/deep.yml`'s `wide` job ran only on `schedule`**, while the workflow header
  documents `workflow_dispatch` as the way to "re-run the wide audit on demand" — so dispatching
  ran every job *except* that one. It now runs on both. The job's `cargo fuzz` step never
  installed `cargo-fuzz` (the same "no such command: fuzz" failure the dedicated fuzz job
  documents), so it fuzzed nothing; and the stale row count in its comment ("eleven rows" against
  the campaign's thirteen) was corrected.
- **`deep.yml` and `formal.yml` cancelled in-progress runs on one shared concurrency group**,
  which includes `schedule`. A push landing near 03:00/04:00 killed the *weekly* audit and proof
  run mid-flight *and* shared `refs/heads/main` with it, reporting as "cancelled" — so the missing
  verification read as an infrastructure hiccup. The group is now per-event
  (`…-${{ github.ref }}-${{ github.event_name }}`), which keeps the useful cancellation (a later
  push or PR run supersedes the earlier one for the same event) while giving the scheduled run a
  group of its own that nothing cancels.
- `tests/decision.rs`'s campaign-size comment said "eleven rows" (there are thirteen) and
  `tests/security.rs`'s header listed "statistical-timing" among its contents (the timing screen
  is in `tests/timing.rs`; `ci.yml`'s `--skip timing` for `security-*` is vestigial but harmless,
  and now says so).

### Numeric consistency audit: every number in the documentation, re-derived

The third audit of the round above — the one that checks *numbers* rather than code — did not
return, so this round re-ran it by hand: every security bound, every count, and every benchmark
figure in `README.md`, `SECURITY-ANALYSIS.md`, `performance.md`, `tests/README.md`, the crate
docs and the workflow comments was re-derived from the source or re-measured, and each was
checked against every other place it appears. The security argument came through unchanged, and
that is worth stating as a result rather than a claim: `2^520`/`2^-520`, `≈2^-264` over `2^256`,
`q²/2^257` = `2^-129` at `q = 2^64`, the `2^164` KDF birthday over its 328-bit state, the
`2^176` a 352-bit output would suggest, `MAX_MSG_SIZE = 2^38 = 2^32` blocks, and the multi-key
union bounds `2^-161` and `2^-456` all reconcile with each other **and with the code** — the
KDF's 328-bit state is the 256-bit chaining value plus the 9-byte tail of its
`"XSIV-ENC" ‖ T` (73-byte) input, and the 352-bit output is `km[0..44]`, because `enc_nonce` is
12 bytes, not the 24 the API takes. The counts reconcile too: the control-flow table
(`tests/variable_latency`, 35/10/26/0/5 and 3/5/21/0/0), the 32 `from_le_bytes`/`to_le_bytes`
call sites, the fourteen-row fault campaign (eleven `--test decision`, two `mac_commitment`, one
`security`), the committed mutation evidence (17 mutants, 15 caught, 2 unviable, 0 missed), and
the 95% coverage floor under `--all-features`. `performance.md`'s two tables also validate each
other: dividing its "ultra over default" column into its "over `XChaCha20Poly1305`" column
reproduces the published ultra column at every size.

Seven numbers were wrong, or described a measurement that no longer describes itself:

- **`performance.md` said the benchmark uses 3 bytes of AAD.** It uses **15** — `b"associated
  data"`, in `benches/compare.rs`, in every one of its cells and in every revision of the file.
  (The first correction of this said 16, which was itself wrong: `"associated data"` is 15
  bytes. Corrected again.)
- **Its "the 12-byte `ChaCha20Poly1305` tracks `XChaCha20Poly1305` within about 4%" was
  unsubstantiated**, and the only criterion data on disk (from a later experiment, single-pass)
  disagreed with it, ±16%. Re-measured properly — three passes, all nine sizes, same core —
  the median cell differs by 1.4% and the worst by 8.4% (256 B decryption), which is now what
  the file says, with the date.
- **Its noise floor is "across the 189 cell-runs",** which is 7 sizes × 3 measures × 3
  configurations × 3 passes. The benchmark also runs 700 B and 5000 B, which are not tabulated;
  the file now says so rather than leaving a reproducer to reconcile 27 cells against 21.
- **The README's summary said the default build is "ahead of `XChaCha20Poly1305` from 1 KiB up
  on both encrypt and decrypt".** The table it points at says otherwise: decryption is 0.82x at
  1 KiB and 0.98x at 4 KiB. It is ahead on encryption at every size (level at 1–4 KiB, inside
  the noise floor) and on decryption from 16 KiB up; that is what it says now.
- **"on the host above"** in the fault-injection section pointed at the performance text that
  moved to `performance.md` last round. It points at the file.
- **The same section claimed the second implementation is "worth 4x on a large message."** The
  measurement immediately above it gives 6.3x at 64 KiB and 9.2x at 1 MiB (witness against
  `ultra` minus the witness); 4x matched neither that nor the 11.3x that figure elsewhere in
  the file measures, against a different baseline.
- **`tests/README.md` said CI bounds the fuzzer "by `FUZZ_SECONDS` (default 120 s)".** CI passes
  libFuzzer's `-max_total_time` directly — 300 s for the default build, 150 s for `ultra`,
  900 s in the scheduled job. `FUZZ_SECONDS` is `verify.sh`'s own knob, default 120 s. The row
  also carried a "~1100 exec/s locally" that no longer describes this host — the fuzz stage of
  this round's `verify.sh --all` reports ~4,900/s — and it is gone with the sentence that
  introduced it.

Two attributions and one stale figure, same pass:

- The nonce budget ("2^48 messages … 2^-32", "randomly generate nonces with a CSPRNG", the
  prohibition on XORing a counter with a random value) is quoted from c2sp.org's
  **ChaCha20-Poly1305-SIV** specification, which is vendored here as `standard.txt`; the
  sentences said "the c2sp.org specification this construction extends", which contradicts this
  README's own statement that this is *not* that construction. The document is now named, and
  the numbers were checked against the live text (verbatim, including the NIST link).
- `deep.yml`'s coverage comment quoted 97.46% (1458/1496) from a much older `cargo-llvm-cov`,
  whose line accounting no longer matches. Re-measured with the job's own command:
  **97.89%, 113 of 5353 lines missed**. The comment now states the percentage and notes that
  the total moves with the tool, so it is not a number that has to be hand-edited on upgrade.

A note on **how the last group was found**, because it is the honest part: the audits ran as
read-only subagents, and one of them applied two of its own findings — to
`tools/broad_differential.py` and to the campaign-count comment in `tests/decision.rs` — despite
the instruction not to edit. Both were reviewed line by line against the finding they claim to
fix and against the surrounding code before being kept, and every other file in this round was
diffed to confirm no third-party edit had slipped in; the rest of the list is mine.

### Commitment: `2^520` is a *target* bound, and the literature's games are not that game

An auditor's finding, and a correct one. This repository quoted `2^520` next to the commitment
games the AEAD literature names — **CMT-1/CMT-3**, invisible salamanders — as if the number
belonged to those games. It does not, and the two are not interchangeable:

- **What `2^520` is.** A *target* bound. The adversary is *given* a ciphertext/tag (a published
  one, say) and must find a second key under which that same `(C,T)` validates. It has to hit the
  tag it was given, so it is a target: `2^-520` per candidate key, `≈2^-264` over the whole key
  space. This is correct in its own semantics, and it is what the 65-byte width buys.
- **What CMT-1/CMT-3 are.** *Attacker-chosen* games: the adversary **outputs the whole tuple** —
  two keys/contexts, two messages, and the `(C,T)` — and wins if the one `(C,T)` validates under
  both. There is no fixed value to hit, so a target bound does not describe them.
- **Why they cannot be swapped.** In the attacker-chosen game the adversary may collect tags for
  `q` self-chosen inputs and search for a **collision**, which is `q²/2^257` with birthday point
  **`2^128`** (the chaining-value birthday: keyed BLAKE3's output is a function of its 256-bit
  state, so a state collision gives byte-identical tags). The collision route the target bound
  does not price is exactly what that game offers.
- **What is *not* derived, and is now said to be not derived.** A colliding pair of tags is only
  the *first* step; the completion must also make one `C` consistent with both keys, and that step
  is circular — an adversary who knows both keys can set `M₂ = M₁ ⊕ KS₁ ⊕ KS₂`, but `KS₂` is
  derived from the very tag `T₂ = T₁` it is trying to fix, so the message it must exhibit is the
  message it was choosing. The completion is a fixed point of the tag/keystream coupling, and its
  cost is **not analysed here**. Earlier prose named the literature's games next to `2^520`, which
  implied otherwise.

What changed: `SECURITY-ANALYSIS.md` §4.5 gains a section, *"The two commitment games, kept
apart"*, with a row in its bounds table and a named open obligation in §5 (row 17: "not derived
here"); Thm 2's commitment bullet, the §8.2 attack-class row, the multi-key note, and the §5
falsification row are all scoped to the target game and point at the attacker-chosen gap; and the
README's security table now has a separate row for the attacker-chosen games that reads **"not
derived here"** rather than a number. No bound was weakened — `2^520` was always a target — but the
document no longer lends it to a game it does not answer. (The `K`-in-the-input binding and the
closed derivation route are unchanged and still argued in §4.10.)

### The performance results move to `performance.md`

The README's `## Performance` section — the three-configuration tables, the measured noise floor,
the per-layer cost tables and the "where the headroom is" notes — is now
[`performance.md`](performance.md). The README keeps a short `## Performance` section that states
the two headline results (more per message, less per byte) and the two structural latency
properties, and links out. Cross-references in the README's layer table, `SECURITY-ANALYSIS.md`,
and the release manifest were updated to point at the new file. No number changed.

### `ultra`: the `locked` layer never worked, and now does

Three defects in the same ten lines, none of which any test could see because the one
test that exercised the layer returned early with `ok`:

- **`madvise` was called with two arguments through `syscall2`.** `madvise(addr,
  length, advice)` takes three, so `MADV_DONTDUMP` landed in the *length* slot and
  `advice` was whatever happened to be in `rdx` — undefined at the ABI level.
- **`MADV_DONTDUMP` was 4.** It is 16 (`asm-generic/mman-common.h`); 4 is
  `MADV_DONTNEED`, an advice that *discards* page contents.
- **`madvise` rejects an unaligned address** (unlike `mlock`, which rounds), and the
  call was given a plain slice pointer. The range is now expanded to whole pages
  covering the key, using the page size read from `/proc/self/auxv` — 4096 is not
  safe to assume on aarch64, where 16 and 64 KiB pages exist.

Together these meant `lock_range` returned `EINVAL`, undid the `mlock`, and
`LockedKey::new` refused, which read as "the kernel will not let us lock memory" — a
deployment conclusion rather than a bug report.

`LockedKey` also **heap-allocates the key now**. `mlock` is address-based, and an
earlier version locked a key held in a local and then returned it by value: the move
left the lock on the callee's dead stack slot while the live copy sat on an unlocked
page. `locked_bytes()` went up and the test passed, which is exactly the shape that
hides this class of bug.

### `ultra`: the two gates shared one comparison, and now do not

Both gates, and both of `dual-mac`'s recomputations, called the same
`subtle::ConstantTimeEq` loop. A single fault that shortens that loop therefore
disarmed every gate at once — `dual-mac` included, because it compares through the same
function. Measured: a forgery is accepted after **2,573 attempts** with the comparison
cut to two bytes.

Under *every* configuration, the second gate now `AND`s in `ct_eq_independent`, a
differently *written* constant-time comparison (an 8-byte fold into a `u64`, one
comparison at the end). Re-measured against the same fault: **no forgery in 2,000,000
attempts**. One fault can now only disarm one of the two comparisons, so a forgery needs
two faults — which is the boundary the README's table states.

**The fold was `dual-mac`/`ultra`-only when this entry was first written, and is not any
more.** It moved into the default in the *"One defence was cheap enough to leave `ultra`"*
entry below: one extra 65-byte comparison, measured at **+1.4 ns per decryption (0.1% at
64 B)**, which is worth having in every build rather than behind an opt-in feature. Read
that entry for the current cost and gating; this paragraph is kept only so the sequence of
decisions is legible, and it does **not** describe the default build as it stands. (An
earlier version of this paragraph said the default builds were "deliberately unchanged
here" and quoted "+2.7% at 64 B" — both were true of the intermediate revision and false
of the shipped one, which is how the contradiction with the README's fault table was
found.)

### `ultra`: the stack region the key derivations used is overwritten

New in `ultra`: `scrub_stack()`. Every named local in this crate is wiped, and the
master key never survives a round trip (measured, `tools/stack_residue.sh`) — but the
`blake3` dependency's XOF output block does, holding a full `enc_key ‖ enc_nonce` in
frames this crate cannot name. Those frames *can* be overwritten, because they sit
below the entry point's own frame and are about to be reused: `scrub_stack()` writes 16
KiB of volatile zeros over that range after the last derivation, which is several times
the deepest frame measured.

Measured, same scanner, same four entry points: the default builds still show a 32-byte
`enc_key` run and a 12-byte `enc_nonce` run; `ultra` reports **clean** on all four.
Cost is the 16 KiB write, about 0.5–1 µs per operation — visible in the constant-time
trace (21,980 → 46,050 instructions) and only under `ultra`.

Honest limits, stated where the code is: it is not a proof (a compiler may spill below
the scrubbed distance), it reaches only this thread's stack, and it does nothing about a
value already written to swap — that is what `locked` is for.

### `ultra`: the whole construction is recomputed by an independent implementation

New in `ultra`: `src/witness.rs`, a second implementation of ChaCha20, HChaCha20 and
keyed BLAKE3 (the reference CV-stack tree, the chunk/parent structure, the XOF), plus
the construction over them, written from the specification and sharing no code with the
crate's path — not the `blake3` dependency, not the SIMD kernels, not `derive_tag`, not
the buffering.

Both decrypt entry points require its agreement (`witness_tag == computed_tag` **and**
`witness_plaintext == plaintext`) and `encrypt` cross-checks its tag before returning.
The agreement is a `Choice` folded into the existing second gate rather than a check of
its own: as a separate `if`, it would be a secret-dependent branch outside
`accept_or_reject`, which is what the suppression file forbids (measured: 7 ctgrind
reports, all in `decrypt`), and it would add a branch a single fault could skip.

**The encrypt-side cross-check had exactly that defect, and the new run found it.**
Written as `if !bool::from(witness::encrypt_tag(..).ct_eq(&tag)) { return Err(..) }` it
is a branch on the tag — both operands are secret-derived — and `tools/ctgrind.sh
--features ultra` reported it inside `encrypt`. That is the check the suppression file
may not cover, so the comparison now goes through `accept_or_reject` like the decrypt
side's: two slots written before the call, two serial reject-first checks, and the
caller branches only on a discriminant written as a constant. The encrypt-side refusal
is a fail-safe rather than a forgery defence (a fault there would otherwise emit a
ciphertext the peer refuses, so it is availability, not authenticity) — but the branch
was real, it was on the secret path, and nothing in the repository could see it until
this configuration was run.

**Why this model needs an implementation and not another comparison.** `dual-mac`
derives the tag twice, but both derivations are the same machine code: a fault in
`derive_tag` or the keyed BLAKE3 under it changes both answers *in the same direction*,
which is precisely what the two gates cannot see. The witness closes that, and it is the
mechanism behind every accepting byte `tools/fi_instruction.sh` finds — those live in the
shared KDF/MAC/SIMD code (the accepting sites are the same addresses in the opt-out and
hardened builds, which is how that was established), and none of that code is on the
witness's path.

**Cost**: it is a scalar implementation, so the cost is per byte rather than fixed.
Measured with `examples/bench_aead.rs` (release, this host), `ultra` against
`hardened,dual-mac,locked,rng` — which is `ultra` without the witness: decryption 30.1 →
20.8 MiB/s at 64 B, 259 → 121 at 1 KiB, 1462 → 232 at 64 KiB, 1767 → 192 at 1 MiB.
Cachegrind instruction counts agree in shape: +17 k instructions per 64 B message on the
decrypt path, +64 M on a 1 MiB one. `ultra` is for callers who have decided that is worth
it; the four features can also be listed without the witness. **The witness's buffers are
a second and third copy of the message on the decrypt paths** (three times the message in
flight rather than two), all allocated up front by `src/lib.rs` — `witness::decrypt`
writes into a caller slice rather than allocating, so a refusal is
`Error::AllocationFailed` from the documented place instead of an `abort` inside the
witness.

**Found while wiring it up, and fixed: an allocation that could return through live key
material.** The in-place path's witness buffers were allocated where they are used —
after `derive_material`, `derive_enc` and four live locals — so an `AllocationFailed`
from either `?` returned with the MAC key, the encryption seed, the per-message key and
nonce sitting in the frame, unwiped. This is the same defect `encrypt` was fixed for in
the previous revision (`allocate before deriving`), reintroduced by adding an allocation
below that line. Both buffers now come first, and
`tests/security.rs::every_allocation_happens_before_any_derivation` asserts the ordering
for all three entry points, since nothing outside the crate can observe a stack frame.

What it does **not** buy, stated on the README's row rather than implied: both
implementations run on one CPU and one compiler, so a fault that hits both, or a
systematic error in both, is outside what agreement can detect.

### The security analysis now goes down to each primitive conjecture, and proves the combination adds none

`SECURITY-ANALYSIS.md` had the composition theorem and a per-hazard table; it did not push its
assumptions down to the level where they stop being arguable, and it did not prove the thing a
reviewer asks first about a *new* pairing of two cipher families: that using ChaCha20 and BLAKE3
together in this shape introduces nothing the primitives do not already have. Two sections added.

**§2.1, the assumption tree.** Every claim now descends L0 → L4: the L0 claim (MRAE security),
the L1 composition theorems that carry it (SIV/DAE from Rogaway–Shrimpton 2006; the
key-derived-from-tag variant from GCM-SIV / RFC 8452; the standard reductions used at the
joints — PRF ⇒ collision resistance, PRF output splitting, cascade, counter-mode-from-a-PRF),
the L2 lemmas proved here, and then the L3 primitive conjectures, each with its own falsifier.
Two of those are worth naming because they are usually conflated:

* **L3.1 (the ChaCha20 block function is a PRF) and L3.2 (HChaCha20 is a PRF) are separate
  conjectures**, not one. They are the same permutation in two modes — feed-forward
  (`P(x) + x`, the Even–Mansour shape, a PRF up to the birthday bound and known to fail
  beyond it) versus truncated, unfed output (`trunc(P(y))`, which is *not* a PRF in general
  because a truncated permutation can be distinguished by collision counting). Neither implies
  the other, and this construction uses both.
* **L3.4 (the BLAKE3 tree preserves PRF-ness) is not inherited from Merkle–Damgård results.**
  The theorems that an iterated hash from a PRF compression is a PRF (Bellare–Canetti–Krawczyk
  for HMAC/NMAC) are about sequential iteration. What supports the tree is structural —
  injective node encodings through the chunk counter, block index and flags — and the document
  now says so instead of leaving "BLAKE3 is a PRF" as one unexamined item.

**§4.10, the interaction inventory.** The five uses of the primitives are enumerated with their
keys and inputs; the six values that cross between them are listed; every pair that could share
a key, a domain point or an output is discharged as either an L1 composition, a *structural*
disjointness, or a bounded-probability event. Two of the structural ones are proved outright:
**S1**, the two keyed-BLAKE3 input spaces are disjoint because their 8-byte domain prefixes
differ (so those two uses stay separate even in the impossible case `mac_key = enc_seed`); and
**S2**, for one `(K, N)` the key-material block is at a *different* ChaCha20 domain point than
XChaCha20-Poly1305's first data block, because the label sits exactly where that scheme leaves
NUL padding — a separation by construction, not a coincidence, and the reason a mixed deployment
cannot share keystream. Completeness is the load-bearing part, so it is mechanised:
`tests/construction_inventory.rs` counts the call sites of each primitive and fails when the set
changes, pins both lemmas, and was verified non-vacuous by planting a sixth use of `hchacha20`
and by setting `DOM_ENC = DOM_TAG` (both caught). The *value* half of S2 is a unit test, since
only the crate can reach its internal derivation.

What the document now states explicitly, in §4.10 and §6: a break of this construction must be a
break of L3.1–L3.6 or of an L1 theorem, because the composition itself assumes nothing joint
about the two families. A future cryptanalytic relation between ChaCha20 and BLAKE3 would
present itself as a break of one of those primitive conjectures — the distinction matters
because a composition flaw is this crate's to fix and a primitive break is not. (L3.6 was added
by the external audit below: it is the one conjecture the *encoding* introduces, and it is about
BLAKE3 alone, not about the two families together.)

### The performance table did not describe the shipped build

`README.md`'s head-to-head table against RustCrypto's `chacha20poly1305` was measured
before `hardened` became the default, and its **decrypt** column was never re-measured: it
claimed 1.41x at 64 bytes where the shipped build measures **1.02x**, and 1.28x at 256
bytes against **1.01x**. Both tables are re-measured as a whole now (`cargo bench --bench
compare`, this host, `chacha20poly1305` 0.10.1 / `poly1305` 0.8.0 / `blake3` 1.8.7 from
`Cargo.lock`), the correction is written into the section rather than silently applied,
and the note names both causes: `hardened`'s second gate is fixed per-message work on the
decrypt path — two 65-byte constant-time comparisons, the volatile re-reads, the
fail-closed plumbing and the wipes — so it shows up at 64 bytes and is invisible at
1 MiB; and RustCrypto's own decryption got faster in this dependency set. Encryption is
unchanged within noise (1.53x at 64 B here against 1.54x there, 1.34x at 1 MiB against
1.36x). The general lesson is the one this repository keeps relearning: a number that was
true when it was written is not a number that is true now, and a table is measured as a
whole or not at all.

### Six defects in the *evidence*, found by auditing the verifier instead of the code

Nothing here touches the construction or the wire format. All six are in the machinery
that is supposed to catch defects, which is where this repository has found its worst
bugs before — and one of them was a claim ("`--all` = everything") that was false in the
same way the old "a skipped check counts as a pass" was.

1. **`./verify.sh --all` did not mean everything.** It set `--kani`, `--cross-exec`,
   `--miri` and strict mode, while `--deep` set those *plus* `--ctgrind`, `--deny`,
   `--fuzz` and `--tsan` — and `README.md` described `--all` as "# everything". The two
   names are now one switch set, and both are strict: a run under either refuses to
   finish while any stage was skipped.
2. **No local invocation ran the tool-level gates at all.** The 13-row fault campaign,
   both instruction sweeps, the cache-profile differential (and its planted-leak
   control), the planted-bug checks, the Kani cfg check and the 4000-vector differential
   were wired into CI and into nothing else, so a contributor working locally had no way
   to reproduce the checks the project's claims rest on. New `--tools` stage, included in
   `--deep`/`--all`, with the same exit-3-is-a-skip discipline the tools already follow.
3. **`build.log` and `executables.txt` were committed to the repository.** They are
   byproducts of the `cross-exec` step, which wrote them into the checkout; running the
   step body by hand (which is exactly what this repository's own debugging advice says
   to do — see `tools/README`-style notes in the workflows) dropped them in the working
   tree, and a later `git add -A` swept them in with a host's local paths inside. The
   step writes them to `$RUNNER_TEMP` now, the two files are gone, and `.gitignore`
   covers them so a manual run cannot repeat it.
4. **`mutants.out.old/` was tracked.** `mutants.out/` is committed on purpose — it is
   the evidence the mutation step produces and it must match HEAD — but the *previous*
   run's snapshot is stale by construction: 39 files, ~1 MB, diffs against line numbers
   from an older revision, and in every mutation run's commit. Ignored now, and
   `tests/README.md` says why.
5. **`check.sh` printed `plus: command not found` on every run.** A continuation line in
   its usage block had lost its `#`, so `plus big-endian powerpc64 via qemu-ppc64` was
   executed as a command. It survived only because the block sits above `set -e`.
6. **`check.sh --help` and its own header had drifted**, and `--help` described `--all`
   as "both of the above" long after that stopped being true; `verify.sh` had no `--help`
   at all. Both scripts now print their own header text, so there is one copy of the
   usage to keep true.

7. **"`mutants.out/` must match HEAD" was an aspiration.** The directory is committed as
   evidence, `tests/README.md` requires that it describe the current source, and nothing
   checked it — it was refreshed when someone remembered. The CI mutation job now keeps
   the committed copy aside, runs the campaign, and compares the two with
   `tools/mutation_evidence.py`: same mutant set, same outcomes, and deliberately *not*
   the line numbers, durations or log paths that move on every run. (The comparison was
   verified both ways: a run against its own output passes, and the pre-`ultra` snapshot
   in `mutants.out.old/` fails with the two mutants that no longer exist.) Refreshing
   `mutants.out/` locally after this was measured at 1998 changed lines with *zero*
   change to `caught.txt`/`missed.txt`/`unviable.txt` — which is why the committed copy
   stayed as it was: the gate says it still describes this revision.

8. **The fuzz target never ran under `ultra`.** It is the only configuration that
   exercises `src/witness.rs`, which is new code on the caller-controlled path: it parses
   arbitrary lengths and carries its own ChaCha20 and BLAKE3, so "no panic, no
   out-of-bounds, every corruption rejected" was a claim about code the fuzzer never
   reached. Both the per-push job and the scheduled soak now run the target twice, the
   second time with `xchacha20-blake3-siv/ultra`, and the second run is preceded by an
   `nm` check that the binary really contains witness symbols — a silently dropped
   dependency feature would otherwise turn it into a duplicate of the first run. (That
   guard's own first version had the bug this repository documents in `tools/ctgrind.sh`:
   `nm ... | grep -q` under `set -o pipefail` dies of SIGPIPE on the first match and
   reports failure on a binary that has the symbols. It is `grep -c` and a numeric test
   now, and the failure message says what it checked.)

Also: `ultra`'s central claim — that the witness shares nothing with the crate's path
except the specification — was prose. It is now a test
(`tests/ultra.rs::the_witness_shares_only_the_specification_with_the_crate`) that reads
the module's non-test source and forbids `crate::` beyond the one specification import,
and forbids `blake3`, `subtle`, `zeroize` or `getrandom` entirely; the test was verified
to fail against a planted `crate::TAG_LEN` use, so it is not vacuous.

### The security argument, written out as a reduction — and two properties it needs, tested — and two properties it needs, tested

New: `SECURITY-ANALYSIS.md`. The construction as a tuple of functions; each assumption as
an explicit game (ChaCha20's block function, HChaCha20, keyed BLAKE3 — all three assumed,
and the document says so in those words — plus the injectivity of the encoding, which is
*proved* there by inspection); the SIV/DAE theorem with its five-hop reduction, the bound
(`q²/2^257 + q·2^-520` plus the PRF advantages — the collision term here is the corrected one;
this entry originally recorded `q²/2^521 + q²/2^353`, see the audit entry below), and the place each
assumption enters; every pair of uses of one primitive enumerated with what separates it;
and a falsification table — what would refute each claim, which refutations have been
attempted, and which are out of reach of any test.

Two findings came out of writing it, both recorded rather than fixed:

* **The two ChaCha20 uses share counter 0.** `derive_material` burns counter 0 of
  `(subkey, "XSIV" ‖ N[16..24])` for the key-material block, and the message keystream is
  counter 0 of `(enc_key, enc_nonce)`. They are separated by key and by nonce, not by
  counter, so the separation is a probability statement (`≈ 2^-352`) about two secret
  values — not computable, and not detectable, by anyone without the master key, and the
  format is frozen, so the structural remedy (reserve counter 0, start the message at
  counter 1) is a note for a future revision rather than a change here.
* **Two properties the reduction needs had no test.** `nonce_reuse_does_not_reuse_the_keystream`
  checks the mechanical content of misuse resistance in the form that cannot be fooled by a
  coincidence — under one key and nonce, `ct₁ ⊕ ct₂` must not equal `M₁ ⊕ M₂`, and a change
  confined to the AAD must move the *first block* of the keystream; a scheme whose keystream
  came from `(key, nonce)` alone would fail that assertion while passing every other test in
  the suite. `the_key_material_block_is_not_the_message_keystream` computes both uses of
  ChaCha20 for a spread of inputs and requires them to differ, so the collapse described
  above becomes a test failure rather than a discovery.

### An external audit: four findings, and what each one turned out to be

An independent reader went through `SECURITY-ANALYSIS.md` and `src/lib.rs`. Three of the four
were security claims that were wrong and one was a real bug in `ultra`. All four are answered
here rather than argued away.

**1. The tag's collision bound is `2^128`, not `2^260` — the width never bought collisions.**
Every one of the 65 tag bytes is an output block of the *same* root compression, so the tag is a
function of BLAKE3's root state: the **256-bit chaining value**, the final block, its length, the
counter and the flags. Two inputs that agree on that state have byte-identical tags at *any* width,
which caps *collision* properties at the birthday bound of a 256-bit state — `2^128` — and no
output length can raise it. Worse, the collision is constructible: hold the final block fixed,
vary the prefix, and a chaining-value collision (`2^128` by birthday) makes the two tags equal.
The old rationale ("commitment is a collision property, so an `n`-bit tag caps it at `2^(n/2)`;
65 bytes gives `2^260`") treated the tag as 65 independent random bits, and the derived
`(key, nonce)` term was wrong too, in the same way: `q²/2^353` is the birthday of the *output*
size, while the state the KDF's root compression sees is 328 bits (256-bit chain value plus a
72-bit final block), so that event's own birthday is `2^164` — and it is dominated by the tag
collision, which implies it, so the DAE bound keeps one `q²/2^257` term. Corrected in
`SECURITY-ANALYSIS.md` (§3 Thm 2, §3 Thm 4's bound, §4.5, §4.10's table, §5 row 16, §6), in
`README.md`'s security table, and in `TAG_LEN`'s doc comment. The corrected bound is
`q²/2^257`, i.e. `2^-129` at `q = 2^64` queries. The wire
format is untouched — the frozen `v0.2` tag stays 65 bytes.

Following the correction through exposed one thing the finding got half right, and it is worth
recording because the first draft of this entry got it wrong in the other direction: **commitment
is a *target* problem, so the width was never about collisions at all.** A second key that opens
a given ciphertext must make its tag computation output the *published* tag — a `2^-520` event
per candidate key, so enumerating the entire `2^256` key space succeeds with probability `≈
2^-264` and no second key is in reach. With a 32-byte tag the same enumeration expects `≈ 1`
second key (`2^256 · 2^-256 ≈ 1`), which is the non-committing failure mode of the 16-byte-tag
SIV family. So the tag's width *is* load-bearing — for the commitment, through the target — the
old rationale reached the right decision through the wrong property, and the "33 bytes buy
nothing" line that appeared in a first draft of this correction was itself wrong and has been
removed. What the width genuinely does not buy is collision resistance (`2^128` either way) and
forgery resistance (`2^256` either way, key-search-bound).

**2. Under nonce reuse, a tag collision hands over `M₁ ⊕ M₂`, not just equality.** SIV's misuse
story is "the adversary learns equality, and the length"; the audit pointed out that this holds
*while the tags differ*. If two distinct messages under one nonce collide in the tag — the same
`2^128` event — they are encrypted under the same derived keystream, so every ciphertext pair
satisfies `C₁ ⊕ C₂ = M₁ ⊕ M₂`: a two-time pad, and not one the adversary has to cause, because
whoever observes both ciphertexts gets it. §3's Corollary now states it, `README.md`'s
deterministic-encryption bullet states it, and §5 row 9 no longer reads as if a collision were
merely a duplicated tag.

**3. The master key both keys the tag hash and appears in its input — which is an assumption.**
`derive_tag` feeds `K` into the head *and* uses `mac_key = f(K)` as BLAKE3's key. The document
had been reducing the tag to A3 ("for a uniform key `k`, `x ↦ B3(k, x)` is a PRF"), and that
reduction does not exist: A3's key is independent of its input, while here the key is derived
from a value the input contains. The audit supplied a separation sketch; `SECURITY-ANALYSIS.md`
§2.1 now carries it as **L3.6**, with an explicit counterexample hash that is A3-secure yet makes
the composed map constant (so the gap is real, not a missing paragraph), the reason BLAKE3 is
still believed to satisfy it (the key words *are* the initial state, the keyed mode is
flag-separated, nothing carries message words into the key schedule), and its own falsifier.
§3 Thm 2's proof now names L3.6 as the hop it uses, §4.10's closing claim is narrowed to *no
joint assumption about the two primitives* (L3.6 is about BLAKE3 alone and about this layout),
and §5 gained row 15. The design conclusion stands, and with a sharper reason than before: without
`K` in the head, two keys whose 512-bit key-material blocks collide (`2^256` by birthday) would
give equal tags *and* equal keystreams, so a ciphertext opening under both keys would cost
key-search — not committing. Binding `K` removes that route; the price is one declared
assumption. `TAG_LEN`'s doc comment already pointed at this caveat; the document it points at now
contains it.

**4. `MADV_DODUMP` was named in a commit message and never called — a real bug.** `lock_range`
sets `MADV_DONTDUMP` on the key's page so a core dump cannot capture it; `unlock_range` was
supposed to undo that before the page returned to general use, and did not — the constant existed
nowhere in the source. `VM_DONTDUMP` is a per-mapping flag, it is sticky, and `munlock` does not
clear it, so the effect was a `LockedKey` that silently excluded whatever pages it had touched
from core dumps for the life of the process. `unlock_range` now issues `MADV_DODUMP` (17, from
`asm-generic/mman-common.h`) over the same page-expanded range it unlocks, and
`tests/locked.rs::unlocking_restores_core_dump_inclusion` reads `VmFlags:` for the mapping out of
`/proc/self/smaps` and requires `dd` to be gone. Verified non-vacuous by deleting the call and
watching it fail with `flags: rd wr mr mw me ac dd sd`.

The commit that added that test also found that the check cannot be a *portable* one: under
`qemu-aarch64` a successful `mlock` and `madvise` leave `VmFlags` at `rd wr mr mw`, because the
emulator keeps guest mappings in its own bookkeeping and does not synthesize the field (measured —
and the reason the first draft of the test failed in stage 5 of `verify.sh`). The test now skips
loudly, naming that, when the mapping it read does not even show the `lo` the sibling
`the_key_itself_is_locked` has just observed; and a second test,
`the_dump_advice_is_issued_on_the_right_range`, pins the call against the shipped source instead —
the constants (16/17), the three-argument `madvise`, and the page alignment of both ranges — which
is the half that runs on every host, emulated or not. Both are non-vacuous by construction: two
planted defects (the unlock call reverted to `MADV_DONTDUMP`, and the constant set to 4) each fail
them — the first fails both, the second only the source check, which is the division of labour
between them.

### A second audit's assumption ledger: one item proved, one already falsified, one made precise

A second reader sent a lettered list of assumptions with a verdict per item. Four of the seven
verdicts matched this document exactly; the differences are worth recording because two of them
are corrections *to* it.

* **"The two-level derivation cascade is a PRF"** was listed as assumed, "on record, at the same
  level as XChaCha20 itself". This document does better than assume it: `Thm 1` *proves* it from
  L3.1 + L3.2 by a two-step hybrid (replace the HChaCha20 output by a random function, then each
  block-function evaluation by an independent one — legal because distinct nonces give distinct
  key/point pairs). One fewer assumption than the audit credited, and the proof is three
  sentences because the construction is XChaCha20's own derivation.
* **"The 520-bit XOF output gives more than `2^256` collision resistance"** was marked falsified,
  and that is right — this document had already corrected it (`2^128`, §4.5). What the audit's
  phrasing adds is scope: the falsification is not about this crate's tag encoding but about
  BLAKE3's XOF *as such*, since any two inputs that agree on the final block collide in the
  output as soon as their chain values do. §4.5 now says so, which also answers "could the
  encoding have avoided it?" — only by not being a single-root XOF.
* **"The `K`-in-the-head step needs a proof"** is the one item this round changed. It cannot be
  proved from the primitives' PRF assumptions, and §2.1 now says why in a form an auditor can
  check: the reduction would need the preimage of the challenge key, so no black-box reduction
  exists, and a counterexample hash shows the step is strictly stronger than L3.3. What it *is*
  immediate under is a random-oracle model of keyed BLAKE3 — strictly stronger than the PRF
  assumption — and the document declines to buy the proof at that price and says so. L3.6's
  statement was also rewritten into the well-posed form (`(N, A, M) ↦ T` with the secret inserted
  by the scheme; "a PRF in `K`" over inputs containing `K` is not a game an adversary can even
  play), since the loose phrasing invited exactly the "needs proof" reading.
* **The other four** (ChaCha20 PRF, keyed BLAKE3 PRF, HChaCha20 PRF, SIV composition theorem)
  match L3.1/L3.3–L3.5 and L1.1–L1.3 as assumed-or-cited. The audit's citation "PSV06" for the
  DAE theorem does not resolve to a paper; checking it turned up a real defect *here* — this
  document cited RS06 under a title that is not the paper ("…MAC-then-Encrypt…"). Corrected to
  *Deterministic Authenticated-Encryption: A Provable-Security Treatment of the Key-Wrap Problem*
  (EUROCRYPT 2006; full version ePrint 2006/221), with NRS14 noted as the MRAE formulation §3 uses.

New in the document: **§2.2**, a one-table ledger mapping an auditor's lettered list onto this
document's names and statuses (including the warning that the letters differ from §2's own A1–A5),
so the next reader does not have to reconstruct which items are proved, which are cited, and which
are conjectures with falsifiers. No code and no wire format changed.

### A third audit: two real defects, one false positive in a tripwire, and four gaps closed

Twenty-two items from a third reader. Nine were already fixed or already documented here (the
collision bound, the two-time-pad consequence, the `MADV_DODUMP` call, the unchecked length sum,
the counter-ceiling analysis, the 2× allocation peak, the non-blocking timing/stack jobs, the
self-audit caveat, the post-quantum collision level); the rest are answered below. Two of them
were defects *here*, one was a defect in a *test*, and four were genuine gaps in the
user-facing documentation.

**Fixed in the code:**

* **`Plaintext` had no `PartialEq<Plaintext>`.** Comparing two decrypted values did not
  compile, and the fallback every caller reaches for is `a.as_slice() == b.as_slice()` — a
  short-circuiting comparison, i.e. exactly the leak the rest of the file spends its
  constant-time budget closing. (The reader hit the compile error and took the fallback.) The
  earlier revision left the impl out *deliberately*; the reasoning was sound and the
  consequence was worse than the impl, so both `Plaintext == Plaintext` and the by-reference
  spelling now route through `subtle::ConstantTimeEq` like every other comparison. Covered in
  `test_plaintext_eq_semantics`.
* **`LockedKey` was neither `Send` nor `Sync`** — it owns a raw pointer, so the compiler
  derives neither and the module had not stated either by hand. The effect was that an `ultra`
  user could not hand a locked key to a worker thread: the key-residency feature forced a
  single-threaded shape on the surrounding program. Both impls are now stated, each with a
  `// SAFETY:` argument (uniquely owned allocation, no thread-affine state, `mlock`/`munlock`/
  `madvise` are process-wide, every shared access is an immutable borrow), and
  `a_locked_key_can_move_to_another_thread` exercises the claim by moving a key to another
  thread, reading it there, and dropping it there — which is where the wipe, the `munlock` and
  the `MADV_DODUMP` run. A `SAFETY` comment is not evidence; that test is.

**Fixed in the tests (a false positive, which is worse than a miss):**

* The control-flow tripwire in `tests/variable_latency.rs` skipped `impl` headers with
  `starts_with("impl ")`, so it counted the `for` in `unsafe impl Send for LockedKey` — and in
  the pre-existing `impl<const N: usize> PartialEq<…> for Plaintext` — as loops. Adding two
  `unsafe impl` lines moved the `for` count by two while adding no branch, which is how it was
  found. `is_impl_header` now recognises all three spellings and the count is 26, four phantom
  `for`s lighter (28 → 26; `README`/`tests/README` prose updated with the table). A tripwire
  that fires on false positives is one people learn to update without reading.

**Closed in the documentation** (each was a real gap, not a wording fix):

* **The verification direction is a fixed point, and the lemma's title said it was not.** §3's
  acyclicity lemma was titled "…is a DAG, not a fixed point", which contradicts Thm 2's
  commitment bullet two pages later ("it would have to be a fixed point of that coupling as
  well"). Both are right about different directions, and the document now says so: encryption
  is a DAG (that is what makes it terminate), verification is the fixed-point test
  `T* = F_C(T*)`, and it is single-pass computable because the derived key depends on `T` only,
  not on `M'`.
* **Multi-key deployments were not quantified.** §3 gains a "Multi-key deployments, quantified"
  paragraph: the standard hybrid gives the factor `Q` on every term of Thm 4's bound (the
  collision term becomes `Q·q²/2^257`, i.e. `2^-161` at `2^32` devices × `2^32` messages), the
  commitment properties are per key and do not weaken, collisions do not cross keys — and
  multi-target key search divides the cost (`2^256/Q`, so `2^224` for a `2^32`-device fleet),
  which is the one number in that paragraph a deployment should actually read.
* **L3.6's blast radius is now stated.** §6 says plainly that if L3.6 fails, every tag-derived
  property fails with it — forgery, both commitment properties, and the per-tag key separation
  that makes nonce reuse survivable — while the keystream primitive itself does not depend on
  it. No partial failure: the tag is one object.
* **Replay was never mentioned.** `README.md`'s "cannot fix for you" list and `SECURITY.md`'s
  out-of-scope list now carry it: decryption is a deterministic function of
  `(K, N, A, C, T)`, so a retransmission authenticates forever, "it authenticated" never means
  "it is new", and freshness needs protocol state.
* **The nonce section now says what a repeated nonce can cost**, including the case the reader
  is most likely to build by accident: varying only part of the 24 bytes (a 64-bit counter in
  the last 8 is the common shape) makes the *effective* nonce space that part — collisions after
  2^32 messages rather than 2^96. For SIV that is the survivable case, but the cost of a
  repetition is the equality leak plus, on a tag collision, the two-time pad, and an application
  that believes it has 192 bits of separation when it has 64 should know.
* **The 32-bit length guard is now in `README.md`** rather than only in §4.8 and a test's doc
  comment: `check_lengths` cannot fire on a 32-bit target (the limit exceeds `u32::MAX`), so the
  caller is the limit there.

**Supply chain:** every `uses:` in the three workflows is now pinned to a full commit SHA with
the moving tag in a comment (72 references, resolved through the API and verified against the
`gh api` recipe in the new header comment). The repository argues for reproducible builds and
was executing unpinned third-party code on every push; an auditor was right to flag it.

Not changed, with the reason: the tag's width (it is the commitment — see the earlier entry),
the counter-0 coincidence (§4.1, structural fix costs the format), the `MAX_MSG_SIZE` ceiling
(§4.6, a build-time binding), and the timing/stack-residue jobs staying non-blocking (shared
runners cannot gate on a `t`-test, and the strict form is one flag away).

### The audit's outstanding obligations: independence, determinism under repetition, and the attacker's procedures

A full mathematical audit pass, asking the three questions that are usually left implicit:
are the assumptions simultaneously satisfiable, is any of them redundant, and what *is* the
procedure an attacker would run? Four additions and one real self-contradiction found:

* **§2.3: consistency and non-redundancy of the conjecture set** — new, and the part an
  assumption audit usually skips. *Consistency*: all six hold together if `CC`/`HC` are random
  functions and keyed BLAKE3 is a random oracle, since a random function does not care what its
  input means — which is also the cleanest statement of *why* L3.6 is believed ("close enough to
  an oracle in this one use" rather than "is an oracle"). *Non-redundancy*: a separating object
  for each implication that might have been assumed, e.g. keep BLAKE3's compression but ignore
  half the left chaining value at the root — L3.3 still holds, L3.4 fails *deterministically*, so
  the tree conjecture is not a consequence of the compression conjecture; and the same trick one
  level up for L3.5 (blocks past the first defined as constants). Each of the six is shown to be
  pulling its own weight.
* **§3: a lemma that each hybrid preserves determinism.** Thm 4's comparison is against an ideal
  scheme that is *deterministic in* `(N, A, M)` (repeated queries repeat answers — that is the
  whole content of "misuse degrades to equality"), and the adversary may repeat a nonce. If any
  hop of the chain had replaced its object with per-query freshness, the hybrid would differ from
  the real scheme for exactly the adversary the misuse claim is about, and the bound would be
  vacuous. The lemma shows each hop keeps the oracle a function of the query — with hop 4's
  replacement keyed by the derived pair rather than by the query, which is also what keeps the
  collision event visible to the bound instead of erasing it. This was implicit before; an
  auditor is entitled to it explicitly.
* **§5.1: the falsification procedures, not just their verdicts.** Per claim, the algorithm an
  attacker runs and its per-attempt cost in primitive calls: key search at `2^256` (`2^256/Q`
  multi-target), forgery as a *target* at `2^-520` per fresh tag with key search as the minimum
  (`min(2^520, 2^256)` is the key search), commitment as `2^-520` per candidate key
  (`2^-264` over the whole key space — and `≈ 1` with a 32-byte tag, which is the row that makes
  the width load-bearing), and the tag-collision procedure with the key (2^128 birthday, fixed
  tail) versus the keyless one (wait for it; then the two-time pad is free). Also the
  falsification-of-a-falsification: the derivation route through colliding key-material blocks
  (`≈ 2^256`) *still fails* because `K` is in the tag's head.
* **§5.2: what we cannot run, in the order it would take the argument down** — a full-round
  distinguisher (kills the primitive conjectures), a concrete distinguisher for the composed tag
  map (kills L3.6), a cheaper-than-`2^128` collision search with a fixed tail (kills the
  nonce-reuse story, and it is the smallest number in the table), and a cheap inversion of the
  key/input separation (the other side of L3.6). Plus the record that the programme is not
  vacuous: three implementation defects and one *claim* (the `2^260` bound) were falsified by
  exactly this kind of reading.
* **§6: a self-contradiction removed, found by writing the summary.** The "Not claimed" bullet
  still said, from the first over-corrected draft of the collision fix, that 65 bytes and 32
  bytes are "equivalent in both properties" — which contradicts the target-bound argument given
  three sections earlier (§4.5) and, worse, was the kind of sentence a reader would quote. It now
  says the accurate thing: the width does not raise the *collision* level (2^128 either way) and
  it *is* what carries the target commitment (2^520 vs the key-search-level 2^256), so it is
  load-bearing and the frozen format is the second reason, not the only one.
* **§6: the strongest true sentence about the construction**, in one paragraph: there is no
  standard-model proof and there cannot be one; what is proved is that the composition is not
  where the risk is — every risk is one of six named conjectures with falsifiers, and four of the
  six are about single primitives rather than about this scheme.

Documentation only: no code, no tests, no wire format. The claims themselves are unchanged — this
round adds the obligations that make them *checkable* rather than the conclusions.

### Supply chain: the pinning stays, and the reason it is livable is now automated

The SHA pinning from the previous entry has a real cost, and it is worth naming rather than
leaving implicit: a tag like `@v7` picks up upstream fixes by itself, while a pinned commit does
not — so "we are stuck on an old action and did not notice" is a failure mode *introduced* by
pinning. Both halves are now in place:

* **The pin stays.** Relaxing to `@v7` restores the fix path by handing the decision of *what
  runs in this repository* to whoever can move that tag — the class of attack the pinning exists
  to close, and the one that has actually been used in the wild (an action's tags repointed to
  exfiltrating code, hitting every repository that used them). Here the blast radius is specific
  and worth stating: no repository secrets exist to steal, every job is `contents: read` except
  `release`, and that job holds `contents: write` to attach the built `.crate` to a GitHub
  release — so the asset a repointed tag could tamper with is **the published artifact of a
  cryptographic library**, plus the CI evidence itself.
* **`.github/dependabot.yml` is the other half** — new. `github-actions` updates run weekly and
  rewrite the SHA **and** the `# vX` comment beside it (one grouped PR), so the workflows keep
  both immutability and a visible version; `cargo` updates do the same for the committed
  `Cargo.lock`, with minor/patch grouped and majors in their own PR. That is the sync mechanism:
  an upstream fix arrives as a pull request that CI validates, not as a silent drift.
* **Two repository settings were off, and are now on:** Dependabot alerts and Dependabot
  *security* updates (`security_and_analysis.dependabot_security_updates` read `disabled` before,
  `enabled` after) — the second is the one that proposes a fix promptly when an advisory lands,
  rather than waiting for the weekly batch. Revert with
  `curl -X DELETE .../vulnerability-alerts` and `.../automated-security-fixes` if a deployment
  prefers to track advisories by hand; `cargo-deny` already fails the Deep workflow on an
  advisory that lands on a locked crate, so the *detection* half was never missing.
* Not enabled: secret scanning and push protection (both are free for public repositories and
  would have caught a token in a file — the one thing this project's own instructions forbid).
  They are one call each, and they are left to the owner because push protection can also block
  a legitimate push that *looks* like a credential, which is a workflow change rather than a
  hardening toggle.

### The update path found a bug in the pinning, on its first run — which is the point

Dependabot opened five pull requests within minutes of the config landing, and the actions one
was **failing CI** — not because the new actions are bad, but because of a defect in the pinning
it was trying to update:

* `dtolnay/rust-toolchain` takes the toolchain's *name from its ref* (`@nightly`, `@1.85.0`,
  `@stable`). Main's per-branch SHA pins work — verified in the logs, the action resolves the
  toolchain from the pinned SHA's branch — but when Dependabot groups a bump it rewrites *all
  three* refs to the default branch's SHA, so `# nightly` becomes stable. The PR's TSAN job failed
  with `rust-src` missing *for the stable toolchain*: the nightly jobs had silently become stable,
  which would have taken out Miri, `-Zbuild-std` for TSAN, and the MSRV job (1.85.0 → stable)
  had it merged. Detected before merge, by the CI run on the PR — which is exactly what the
  automated update path is for.
* **Fix, in all 20 `uses:` sites:** name the toolchain explicitly (`with: toolchain: nightly` /
  `stable` / `1.85.0`). The ref then only selects *code* for the action, any SHA is safe, and
  Dependabot's grouped bumps become harmless. Verified structurally: a YAML walk over the three
  workflows asserts every `dtolnay/rust-toolchain` step declares its toolchain.
* The other four PRs are ordinary dependency bumps and are left open for review — with one caveat
  worth writing down: `chacha20poly1305` and `aead` are the *benchmark reference* in
  `benches/compare.rs`, so bumping them (0.10 → 0.11 / 0.5 → 0.6) invalidates the head-to-head
  numbers in `README.md` until they are re-measured; that is a "review the diff and re-run the
  benchmark" PR, not a merge. `criterion` (dev-only) and `getrandom` (the optional `rng` feature)
  are the two that are plausibly mechanical.

### The first five Dependabot pull requests: two merged, two closed with measurements, one parked

Handled by the rules the repository already applies to itself ("a release must not exist for a
commit that did not pass" — the same holds for a merge), with the evidence taken from each PR's
own CI run rather than from the version numbers:

* **#1 (actions group: `checkout`, `rust-cache`, `upload-artifact` v4 → v7.0.1) — merged.**
  27 checks green after the toolchains were named explicitly (§ above; before that fix the PR
  was red for a reason that had nothing to do with the new versions). `upload-artifact` v5–v7
  are the Node 24 runtime, ESM and the new direct-upload path; the `name`/`path` inputs this
  repository uses are unchanged, and the coverage job that uploads through them passed.
* **#3 (`getrandom` 0.3.4 → 0.4.3) — merged.** 27 checks green, including the MSRV 1.85 job.
  This is the optional `rng` feature's dependency. One thing worth recording: the crate
  re-exports `getrandom::Error`, so the major bump changes the *identity* of a type in this
  crate's public API for `rng` users — allowed at `0.x`, and now written down rather than
  discovered later.
* **#2 (`aead` 0.5 → 0.6) — closed.** It fails to compile `benches/compare.rs` on four checks
  (`E0599`: `ChaChaPoly1305::new`'s trait bounds were not satisfied — the RustCrypto key/trait
  bounds changed), *and* it is redundant: `chacha20poly1305` 0.11 depends on `aead` 0.6, so the
  same change arrives with #5. Fixing it means editing the benchmark harness, which is a
  measurement change rather than a dependency bump.
* **#4 (`criterion` 0.5 → 0.8) — closed, and ignored in `dependabot.yml` with the reason.**
  criterion 0.8 pulls in `alloca 0.4.0`, whose build script requires a C cross-compiler
  (`aarch64-linux-gnu-gcc`). This repository has none on purpose — that is what the `pure`
  feature and the self-contained musl crates are for — and the bump turned seven checks red
  (Miri, the mutation check, the i686 and aarch64 qemu executions, three cross-checks).
  A benchmark-harness version is not worth provisioning a cross C toolchain for.
* **#5 (`chacha20poly1305` 0.10 → 0.11, + `aead` 0.6) — left open, with the plan in a comment.**
  It is the benchmark *reference*: the README's head-to-head table is a published number about
  a specific version of it, so landing this means (i) adapting `benches/compare.rs` to the 0.11
  API, (ii) re-measuring on the named host with the documented method, and (iii) updating the
  README table in the same commit. Parked as the reminder that the comparison is against
  0.10.1; not ignored, so it comes back as a prompt rather than as a surprise.

The rules this settles, so the next batch is a five-minute decision: green and mechanical →
merge; red → do not; anything touching `chacha20poly1305`, `aead` or `criterion` is an
engineering task about *evidence* (measurements) rather than a dependency bump; and no PR is
merged to empty the list.

### #5 (`chacha20poly1305` 0.11): closed, with the measurement that decided it

The last PR of the batch was parked "with a plan"; it is now closed, and the reason is data
rather than policy. Working the bump in a scratch worktree:

* **It cannot land alone, and the failure is a pairing problem.** `chacha20poly1305` 0.11
  depends on `aead` 0.6, and the PR leaves `aead = "0.5"` — so the bench imports the traits of a
  crates.io `aead` major that the cipher does not implement. That mismatch *is* the `E0599` in
  both this PR and #2. Bumped together, the bench compiles unchanged.
* **Paired, it trips the lint gate.** `aead` 0.6 deprecates `AeadInPlace` and
  `encrypt_in_place_detached`/`decrypt_in_place_detached` in favour of `AeadInOut` and the
  `InOutBuf` shape, so `clippy --all-targets --all-features -- -D warnings` reports nine errors
  in `benches/compare.rs`. Landing it is a code migration of that harness, not a dependency bump.
* **The published numbers do not move.** Measured on this host (median of two alternating runs
  each, `encrypt_in_place_detached`, 2 s measurement): the reference goes 9.78 → 9.65 µs at
  16 KiB and 551.0 → 544.4 µs at 1 MiB — about 1%, inside the noise floor of a two-checkout
  comparison (the *same* crate code measured up to 8% apart between the two trees). The README
  table compares against a version it names (`chacha20poly1305` 0.10.1, with `poly1305` 0.8.0 and
  `blake3` 1.8.7), so it stays correct as published.

So: dev-only, no effect on the shipped crate or on any security claim, no effect on the numbers,
and a real migration to take it. It is now excluded from version updates in
`.github/dependabot.yml` alongside `aead` and `criterion`, each with its measured reason written
next to the entry, and the migration is scheduled implicitly where it belongs: the next time the
performance table is refreshed, which is the commit that re-measures anyway. Advisory detection
for those crates is unaffected — `cargo-deny` fails the Deep workflow if an advisory reaches the
lockfile.

### The three configurations are measured, and what a defence costs is now a number

Three things asked for together, and they turned out to be one piece of work: a benchmark against
RustCrypto's `chacha20poly1305`, run *per configuration* (opt-out, `hardened`, `ultra`), so that
"every release has three configurations" is a statement with prices attached rather than a list of
feature flags.

**Measured, one `cargo bench` run per configuration** (`--warm-up-time 2 --measurement-time 4`,
criterion median of 100 samples, 64 B to 1 MiB, shipped release profile, same host as before).
The built-in control is the reference implementation: identical code in all three runs, and it
measured 0.3%–7.5% apart between them — that is the noise floor, and the README now says so
instead of leaving the reader to guess. Ratios against `XChaCha20Poly1305`, `hardened` (default):
encrypt 1.44x at 64 B, 1.00x at 1 KiB, 1.32x at 1 MiB; decrypt 1.12x, 0.83x, 1.38x. What the
configuration comparison *adds* is the price of each defence: `hardened`'s second gate is a fixed
per-message cost on decrypt (0.88 → 1.05 us at 64 B, invisible at 1 MiB), and `ultra`'s witness is
a per-byte cost on decrypt, because it is a scalar re-implementation (2.7x at 64 B, 4.0x at
1 KiB, 10.1x at 64 KiB, 11.5x at 1 MiB — the round trip ends at 0.22x). Both tables in the README
were replaced by these, whole, as the section's own rule requires.

**Finding: the README claimed the witness runs "on every encrypt", and it does not.**
`encrypt_in_place_detached` carries no encrypt-side cross-check; only the allocating `encrypt`
does. It surfaced from the *benchmark*, not from reading: `ultra`'s in-place encryption measured
the same as the default at 1 MiB (377 us against 379 us) while its decryption measured 11.5x
slower — only possible if the encrypt path is not re-hashing the message with the scalar witness.
The asymmetry is defensible (what an encrypt-side witness detects is a fault that produces a
ciphertext the peer rejects: availability, not authenticity; and the check is a full per-byte
re-hash, about +1.2 ms per MiB, on the API a caller picks for speed), so the fix is to state it
rather than to close it in code:

* the README's "What the witness is" now names the paths it covers and gives the reason for the
  one it does not, with the measured cost of the check;
* the fault table's witness row quotes the measured per-configuration numbers instead of an
  unverified "+20% of the encrypt path's instructions", and says which API has the check;
* `tests/ultra.rs::the_witness_is_called_from_exactly_these_entry_points` pins it both ways — a
  witness call added to the in-place path fails the test with a message pointing at the two
  documentation sites that must then change, and a call removed from `encrypt`, `decrypt` or
  `decrypt_in_place_detached` fails it too. Verified non-vacuous by planting a `witness::` token
  inside the in-place body;
* the same round fixed the fault table's sweep scope ("the two entry points" now reads "the two
  *decrypt* entry points — `decrypt` and `decrypt_in_place_detached`").

**The release now carries the three configurations as artifacts, not as prose.** The release job
gains two steps: it builds `--no-default-features`, default and `--features ultra` itself, and
asserts that the `test` matrix still names all three legs (a matrix entry dropped in a refactor
would otherwise take a configuration out of the release gate silently — the same source-shape
idea the tests use, applied to the workflow); and it writes `CONFIGURATIONS.md`, which is attached
to the release next to the `.crate` and is *required* — the publish step fails if it is missing.
The release notes carry the same table. One `.crate` file, three supported configurations, each
built and tested at the tagged commit.

**Bug-hunting round, run alongside the above.** A longer fuzz (2,212,603 executions in 481 s
across 8 workers, no crash, 1400 edges covered), the broad differential at 4000 random vectors
and again at 1500 with `--features pure` (zero mismatches), an exhaustive witness sweep — every
length to 4200 bytes plus the chunk-count boundaries to 200 chunks — as a new test, `clippy -D
warnings` over all targets, and a build matrix of the feature combinations CI does not cover
(`--no-default-features --features locked`, `--features dual-mac` alone, `--no-default-features
--features rng`, `locked,rng` and `--no-default-features --features locked,rng`): all clean. The
one defect found is the witness-coverage finding above.

### Every attack class, against every configuration, with the cost of mounting one

Asked for as a list — differential, linear, rotational, integral, algebraic, slide, meet-in-the-middle,
related-key, length extension, collisions, commitment, forgery, two-time pads, nonce misuse,
timing, cache, microarchitectural, power/EM, faults (single, multiple, laser, DFA, combined with
side channels), Rowhammer, cold boot, swap, core dumps, debuggers, compiler-introduced leaks,
supply chain, replay, length disclosure, the equality oracle, DoS, and the quantum ones — and the
answer is now `SECURITY-ANALYSIS.md` §8, because a list is only useful with the two evaluations
attached.

The section is built around one observation that decides most of it: **the three configurations
are the same object against cryptanalysis** — same construction, same primitives, same bounds —
and differ only where the *machine* or the *observer* is the adversary. So §8.1 is the
cryptanalytic and design-level table (identical in all three: differential to quantum, length
extension to commitment, each row pointing at its bound or its falsifier), §8.2 is the
implementation and physical table where the configurations actually differ (`opt-out` defends no
fault; `hardened` defends the decision against single faults; `ultra` adds the shared derivation,
the rewritten-stored-tag case, swap and core dumps — with the witness's coverage boundary stated
rather than implied), and §8.3 prices each one on two scales, because a birthday search and a
voltage glitch are not comparable: **work** (research-grade, `2^256`, `2^128`, free) and
**access/equipment** (none, co-residency, a few hundred dollars, a laboratory, root).

§8.4 says what the tables mean together: choosing `ultra` does not make a differential attack
harder and `opt-out` does not make one easier, and the four *free* attacks — a repeated nonce, a
replay, an equality oracle, a length leak — are the protocol's business, not a feature's. README's
"What is not defended against" now points at §8 instead of being the only place this is
discussed. No numbers were duplicated in the process: the fault figures stay in README's fault
table, the collision and target bounds stay in §4.5, and §8 names them.

### `ultra` against the attacks it does not answer: one more is now answered in software

Asked which of §8's "not defended" rows a configuration could be made to answer. The honest
answer splits three ways, and each part is now in the document rather than in a reply:

* **Answerable in software, and now answered**: a **debugger**. The kernel already enforces the
  policy — `PTRACE_MODE_ATTACH` fails for a non-dumpable process even from the same user, and
  `/proc/<pid>/mem` goes with it — so `locked::deny_debugging()` issues `prctl(PR_SET_DUMPABLE,
  0)` and the README's layer table gains the row. It is **opt-in, not automatic even under
  `ultra`**, because it is *process* policy: a library that silently removed core dumps and
  blocked `strace`/`gdb` for its host would break crash reporting and the operator's own tooling.
  `deny_debugging_is_enforced_by_the_kernel_and_reversible` reads the flag back from the kernel,
  observes `/proc/self/mem` being refused (measured: it is), and restores the flag on every path,
  because leaving the shared test binary non-dumpable would silently cost every later test its
  core dump. Root, `CAP_SYS_PTRACE`, a hypervisor or a probe are unaffected, and the docs say so.
* **Not answerable here, and the reason is now precise rather than a bare "not defended"**:
  * *speculative execution* — this crate presents no known gadget (no secret-dependent index or
    memory access; the one secret-dependent branch has a *public* outcome, so speculating past it
    reveals what the caller learns anyway). What remains belongs to the CPU, the OS inside the
    process's other code, and to power/frequency channels that constant-time code does not
    address at all. A barrier added here would be theatre, so none was added.
  * *power / EM* — masking is the known mitigation and is **not claimed**: 10–100x cost, a
    compiler free to undo it, and a claim that cannot be falsified without a leakage-assessment
    lab. That belongs in a separate feature with its own measurements, not in a defence list.
  * *multiple / synchronized / laser faults, DFA* — software redundancy (which `ultra` already
    has twice over) cannot cover a fault that hits both computations or the arithmetic beneath
    them; the answers are a validated fault bench and hardware countermeasures, neither of which
    exists here.
  * *cold boot, Rowhammer, hypervisor, root* — memory encryption, ECC/TRR, isolation. A crate can
    shrink the window (wipe early, lock pages, refuse to be debugged) and cannot close it.

§8.2's rows now carry the reason instead of "stated", §8.3 prices the debugger row accordingly
(root or `CAP_SYS_PTRACE` once the process refuses), and §8.4 has the three-way split above.

### "No algorithm exists" was the wrong sentence: the software answers to §8's hard rows

A fair challenge to the previous entry — *are there really no software algorithms for these?* —
and the answer is no, there are plenty. What none of them has is a guarantee outside a **model**,
and several need hardware to falsify. Both of those are now written down instead of being
compressed into "not defended".

* **The correction with the most content: this construction already implements the standard
  software mitigation for DPA — for the payload cipher.** Fresh re-keying (Medwed–Standaert)
  means running each message under a fresh key so that traces cannot be averaged; per-tag key
  derivation *is* that, arrived at here for the commitment and nonce-reuse reasons. Concretely:
  the same nonce and message reproduce one identical trace, a different message is a different
  key, so an attacker cannot average over the payload cipher at all.
  **This paragraph originally said "the residual attackable surface is the per-nonce
  derivation", and an auditor correctly pointed out that it is only true when nonces are not
  reused.** `mac_key` and `enc_seed` are functions of `(K, N)` alone — they must be, or the tag
  would not be deterministic in `(K, N, A, M)` — so `q` messages under one nonce are `q` traces
  of the tag pass and the enc-KDF under *fixed* keys with varying, attacker-chosen input, which
  is the setup CPA/DPA averages; for the tag pass the surface also grows with message length.
  Under nonce reuse, then, the residual is not 1.5 blocks: it is two of the three BLAKE3 uses.
  §8.2's row carries the corrected version, including that this is inherent to the frozen format
  (a revision could re-key the tag from the message and remove it, changing every tag).
  Structural argument, not a measured claim: no leakage assessment has been run.
* **The faults rows gained the same treatment**: classic DFA recovers *long-lived* round keys, and
  nothing here is long-lived beyond the master key — every recoverable intermediate (`enc_key`,
  `enc_nonce`, `mac_key`, the tag) is per message, so a fault-assisted recovery buys one message.
* **New §8.5**, a table of what exists per class, its model and its validation, and why it is not
  in this crate: masking (probing model, TVLA/ISO 17825 — so *falsifiable*, with a lab),
  infective computation, tamper-resilient encodings and AMD codes, index masking / `lfence` /
  Speculative Load Hardening, TRESOR-style register-resident keys, Rowhammer guard pages and
  integrity checks, tracer detection. The pattern: the question is not "can software do
  something" but "is the guarantee unconditional, and can it be falsified here".
* Two rows also got the "what it would take" they were missing: Rowhammer (guard pages, refresh
  re-touch, a key checksum — partial, and a flip that hits the checksum too is invisible) and cold
  boot (TRESOR needs kernel cooperation to be sound on a general-purpose OS).
* One overstatement fixed: the power/EM bullet said a masking claim "cannot be falsified" — it
  can, by TVLA, just not in this repository.

### "All that can be done" for `ultra`: the stored-secret integrity check, and what is deliberately left out

Asked for every defence and mitigation that can be done, the honest answer is not "everything in
§8.5" — several of those need a laboratory, a bench or kernel cooperation to be *validated*, and
shipping an unvalidatable claim is the one thing this project does not do. So this round
implements the one item from §8.5 that is implementable, verifiable here, and cheap, and writes
down why the others are not:

* **Implemented — `LockedKey` now detects a corrupted key page.** An 8-byte BLAKE3 tag of the key
  is stored beside it in the locked page and checked in constant time on every `as_bytes()`, so a
  hardware fault or bit flip turns into a fail-stop panic at the first use instead of a silent
  wrong key — which otherwise shows up as "authentication failed", a message about the ciphertext
  for a fault in the key, and on the encrypt side as ciphertexts the peer rejects. Cost measured
  on this host: **42 ns per use** (one BLAKE3 hash of a 32-byte input), ~5% of a 64-byte encrypt
  and invisible at 1 MiB; confined to `locked`, and therefore to `ultra` (a caller passing a
  `&[u8; 32]` directly pays nothing). What it does *not* cover, stated on the row: a fault that
  rewrites the tag as well, and anything outside the key-and-tag region — the rest of the page is
  never read, so a flip there is harmless by construction and the check deliberately ignores it.
  `a_corrupted_locked_page_is_detected_on_use` covers all three cases (key flip, tag flip, intact
  key) and was verified non-vacuous by removing the check and watching it fail.
* **Deliberately not adopted — infective computation.** §8.5 lists it (randomise the output on a
  detected fault instead of rejecting), and this crate continues to *reject*, for the reason the
  fault table already gives: a rejection is what keeps an encrypt-side fault from turning into a
  ciphertext the caller cannot distinguish from a good one, and the payoff of a recovered
  intermediate here is one message in any case.
* **Deliberately not written — masking, randomised scheduling, guard pages, TRESOR-style
  register-resident keys, speculation barriers.** Each is a real algorithm with a real model and
  none is falsifiable in this repository (no scope, no fault bench, no kernel cooperation); a
  barrier here would serialize a comparison whose outcome is public. §8.5 now says so per row,
  and the faults row records the one piece of the AMD-code idea that *is* in: the tag above.

### One defence was cheap enough to leave `ultra`: the second comparison shape is now the default

Asked which items are expensive and which are cheap, and whether anything cheap belongs in
`hardened`. Costs, measured on this host, for everything the crate does at runtime:

| Defence | Cost | Where it is |
| --- | --- | --- |
| Constant-time discipline, no tables, no secret indices | free (a design property) | all three |
| Volatile wipes | free | all three |
| Second gate (two recomputed comparisons, fail-closed) | +10.8% at 64 B, +0.4% at 1 MiB (**superseded**: re-measured for `v0.3` as +25% at 64 B, +24% at 256 B, +23% at 1 KiB, +11% at 4 KiB, within the noise floor from 16 KiB up — the second comparison was added to every build and the small sizes were re-measured) | `hardened` |
| **Second comparison *shape* (8-byte fold vs `subtle`'s loop)** | **+1.4 ns per decryption (0.1% at 64 B)** | **was `dual-mac`-only; now every gate-building configuration (`hardened` and above — not the opt-out build, which compiles neither gate nor fold)** |
| `deny_debugging` (`prctl`) | one syscall, once, opt-in | `locked` (ultra) |
| Key integrity tag | +42 ns per use | `locked` (ultra) |
| `mlock` + dump exclusion | ~7 µs once per key | `locked` (ultra) |
| `dual-mac` (second independent tag recomputation) | +24–40% on decryption, per byte | `dual-mac` (ultra) |
| `scrub_stack` | ~0.5–1 µs **and 16 KiB of stack** | `dual-mac` (ultra) |
| `witness` (scalar second implementation) | 2.7x at 64 B, 11.5x at 1 MiB | `witness` (ultra) |

So: exactly one item was cheap enough to move into the default, and it moved.
**`ct_eq_independent` — the differently-written constant-time comparison — is no longer gated on
`dual-mac`.** It costs **1.4 ns**, and the defence it buys was measured by hand: with a single
comparison shape, a fault that shortens it yields a forgery after 2,573 attempts; with both
shapes, none in 2,000,000. A defence with that ratio does not belong behind an opt-in feature.

Why the rest did not move, in cost order: `dual-mac` and `witness` are per-byte (a second hash
pass and a scalar re-implementation); `scrub_stack` is cheap in *time* but reserves 16 KiB of
stack per call, which can fault the very thread it protects, so it stays opt-in; `deny_debugging`
is free but is *process* policy (it removes core dumps for the whole process) and stays a call
the application makes; the key integrity tag protects a page that only `locked` has; and `rng` is
a dependency, kept optional for `no_std` users.

`tests/decision_scope.rs::the_second_gate_uses_two_comparison_shapes_in_every_configuration`
pins the new default: the fold comparison must be unconditional, the `dual-mac`-only placeholder
must not come back, and the fold must not delegate to `subtle` (or there would be one shape
wearing two hats). The README's fault table row for a shortened comparison, and the layer table
row it used to carry under `dual-mac`, moved with it.

### The stack requirement is now a value, and the unvalidatable defences have a validation plan

Continuing the rule from the last two entries — cheap and verifiable goes in, everything else is
written down precisely — two more items land, neither of them a new cipher:

* **`stack_requirement_bytes()` is public.** `dual-mac`'s `scrub_stack` overwrites the derivation
  region with a single **16 KiB frame**, so a thread with less remaining stack faults inside the
  function rather than returning; that was a row in a table, and a row in a table does not fail a
  build. It is now a constant a caller can check — `stack_size(stack_requirement_bytes() + margin)`
  — documented as zero outside `dual-mac`, and `the_reported_stack_requirement_is_sufficient`
  spawns a thread with exactly that budget and runs a round trip on it, so the number the crate
  reports is a measured one rather than advice. (The "too small aborts" half stays a hand
  measurement: a stack overflow kills the process, which is the reason the constant exists rather
  than something a test can assert around.)
* **§9 of `SECURITY-ANALYSIS.md`, "what would validate the defences this repository cannot
  validate"** — for each item §8.5 called unverifiable here (masking, fault tolerance, the
  witness's value under fault, speculative execution, Rowhammer, cold boot, Hertzbleed-class
  frequency channels) it states the *measurement*, the method and standard (TVLA / ISO 17825 for
  leakage, a timed FI bench grid, PoC Spectre harnesses, hammering harnesses, the cold-boot
  procedure, a remote-timing harness), the pass criterion, and **the exact sentence the
  measurement would license** — e.g. "first-order leakage below the detection threshold of
  100 000 traces on <device>", never "resistant to DPA", because a threshold is not a bound and
  higher orders are untested. Until a measurement exists the sentence is written nowhere; that is
  what the section enforces, and it is why the project can say "not validated here" without that
  reading as "not validatable".

Both entries are the same idea applied twice: a claim without its measurement is not made, and a
measurement without a stated criterion is not a result.

### The three configurations re-measured: three passes, rotated order, and a stated noise floor

The published tables were one run per configuration, and the default build's decision path has
changed since (the second comparison shape is no longer `dual-mac`-only), so they were
re-measured — and this time with a method whose error is *stated* rather than hoped for:

* **Three `cargo bench` runs per configuration**, each pinned to one core (`taskset -c 3`), with
  the configuration order **rotated between passes** (`default, opt-out, ultra` / `ultra,
  opt-out, default` / `opt-out, ultra, default`) so no configuration is always measured first or
  last; each cell's published figure is the **median of the three passes**.
* **The noise floor is measured, not assumed**: the reference implementation is the same code in
  all nine runs, so its spread is the floor. Over the 189 cell-runs: median pass-to-pass spread
  **5.9%**, 90th percentile **11%**, worst cell **15%** (small sizes are CPU-boost sensitive,
  1 MiB shares LLC and DRAM with the host's other work). The README now says that differences
  smaller than the floor are the same number, which is why several column pairs read as ties.
* **A fourth table, and one home per number.** The new section adds "what the `ultra` layer
  costs, relative to the default configuration" — because a ratio against the *reference* and a
  ratio against the *default* are different quantities, and the layer and fault rows had been
  quoting the second kind with no table to point at. Those rows now cite that table, and the
  stale figures scattered through the prose (the in-place-encrypt discussion, the "faster end to
  end" bullet, the structural-properties section) were updated to the new values, so a future
  re-measurement has one place to change per quantity.

Headline numbers for the default configuration, median of three passes: encrypt 1.57x the
reference at 64 B and 1.33x at 1 MiB, decrypt 1.10x and 1.32x. `ultra`'s cost relative to the
default: decrypt 2.8x at 64 B rising to 11.3x at 1 MiB, encrypt a tie at 4 KiB and beyond (the
witness runs only on the allocating `encrypt`), round trip 2.3x in place and 2.6x allocating at
64 B.

### Every release ships all three configurations as artifacts, not just the default

Asked for the three configurations to be published rather than only the default build, and the
release job now does that — with a check that could not be made before:

* **One artifact per configuration**, `xsiv-<commit>-{opt-out,hardened,ultra}.tar.gz`, each
  containing that configuration's compiled library, a runnable binary (`xsiv_stdin`, the crate's
  audit CLI), its known-answer output, and a `README.md` with the exact build command, the
  resolved feature set (`cargo tree`), the file digests, and what the configuration adds.
* **The release proves the wire format is identical instead of saying so.** The same fixed vector
  is run through all three bundles' binaries and the outputs are compared; the step fails if any
  two differ, and the digest (`sha256(kat.txt) = 6ffe02e3…`) is printed into every bundle. The
  release is therefore the place where "three configurations, one wire format" stops being a
  claim in prose.
* **The publish step refuses to ship fewer than three.** `dist/*.tar.gz` must be exactly three
  files or the job errors, the same way the configuration manifest is required — a release that
  silently shipped only the default build is the failure this exists to prevent.
* The release notes and the attached `CONFIGURATIONS.md` both name the three bundles, and the
  per-configuration *costs* are in `performance.md` (they were in `README.md`'s tables when this
  entry was written; that section moved — see "The performance results move to `performance.md`").

Verified by running the packaging step locally first: three bundles, identical KAT digest, and
the contents inspected. That dry run caught a real mistake before it reached CI — the vector file
was written with one field per line, while `xsiv_stdin` takes four space-separated fields on one
line, so every configuration produced the *empty* output and the hashes matched for the worst
possible reason. (The empty-output digest is identical across configurations too, which is why
comparing hashes alone would not have caught it; the check now also fails on empty output.)

`.gitignore` covers `/dist/`, so a local dry run cannot be committed by accident.

### Two audit findings against the last two rounds, both valid

* **F-D1 (§8.2's fresh-re-keying claim was over-broad).** The row said the residual DPA surface
  is the per-nonce derivation, ~1.5 blocks under the master key. That is true of the **payload
  cipher** — `enc_key`/`enc_nonce` come from the tag, so they are per message — and false of the
  other two BLAKE3 uses: `mac_key` and `enc_seed` are functions of `(K, N)` alone (they must be,
  or the tag would not be deterministic in the quadruple), so under **nonce reuse** — which SIV
  explicitly supports — `q` messages under one nonce are `q` traces of the tag pass and the
  enc-KDF under *fixed* keys with varying attacker-chosen input, which is precisely what CPA/DPA
  averages, with the tag surface growing in message length. The correction is in §8.2 (and §8.4's
  bullet, and the CHANGELOG entry above that first made the claim), together with two things the
  finding implies: for DPA, nonce reuse is worse than the "leak of equality" the misuse story
  describes; and the exposure is **inherent to the frozen format** (a revision could re-key the
  tag from the message and remove it, at the cost of changing every tag — recorded as a revision
  option, not applied).
* **F-D2 (a test promised three boundary cases and implemented two).** As written,
  `a_corrupted_locked_page_is_detected_on_use`'s doc claimed a flipped key must panic, a flipped
  tag must panic, and a flip in the *unused* remainder must **not** — but case (c) only checked
  an intact key, and it carried a parenthetical describing a write that did not exist (draft
  residue). Worse, the test hook's `assert` refused offsets `>= 40` while its own doc said it
  could hit "the unused remainder of the page": the two disagreed with each other. Neither has a
  security impact, and both are the class this project cares most about — a claim in a comment
  that the code does not keep. Fixed by making the hook accept any offset in the page (and say
  so), implementing case (c) for real (flip the page's last byte, require `as_bytes` to return
  the key untouched), keeping case (d) as the intact-key check, and deleting the false sentence.
  Case (c) was verified non-vacuous the same way the check itself was: making `check_integrity`
  hash the whole page instead of the key makes the test fail.

### Zeroization: two copies the wipes could not reach

Fixed in every configuration, because these are copies the wipes should already have
reached:

- **`derive_enc` wrote through caller slices instead of returning
  `([u8; 32], [u8; 12])`.** A 44-byte aggregate return makes the compiler materialise
  an unnamed temporary, which no `zeroize_array` in the function can name. A stack scan
  found the tail of exactly that value — `enc_key[16..32]` together with the whole
  `enc_nonce` — surviving in the frame after a round trip.
- **`chacha20_rounds` takes `&mut [u32; 16]` instead of the state by value.** `[u32;
  16]` is `Copy`, so the by-value signature gave the callee its own copy of a
  key-bearing state; the caller's wipes never reached it. Found by the same scan, on
  the scalar path used by messages below the SIMD threshold.

Both are the failure mode `chacha20_block`'s own comment records ("wiping a copy is
not wiping the original"). The scan (`tools/stack_residue.sh`) is committed as a tool,
not a gate: what it finds now is dominated by the `blake3` dependency's XOF output
buffer, which lives in frames this crate cannot reach — documented in the README rather
than asserted, because a gate that fails upstream is a gate someone deletes.

### Tests and evidence

- **The evidence set now covers the configuration with the most code in it**, which is
  what the entries below have in common. Each of them found something the default run
  could not: `ctgrind` found the encrypt-side branch above; `fi_instruction` found that the
  extra code the witness adds to the two entry points changes the fault numbers and forced
  the criterion to be scoped to the decision; `cargo mutants` found eight mutants that no
  single feature set could compile, which restructured the gate; `cache_profile` had never
  run `decrypt` at all; the cross-architecture suite had never compiled the witness.
- **The gate is now one expression per configuration, with the configuration a *value*.**
  `witness_ok` is the witness agreement under `ultra` and a constant `true` otherwise, and
  it is folded into the `gate_pair` line that every configuration compiles, rather than
  into a `#[cfg]`-selected third arm of `second`. The reason is `cargo mutants`, which does
  not evaluate `cfg`: with the old three-arm shape its CI run reported eight `&` → `^`
  mutants as MISSED — not gaps in the tests, but lines that were not compiled in the
  configuration under test, and no single run can compile both an arm and its alternatives.
  The mutation run is now `--features ultra` (the set that compiles the most: it implies
  `hardened` and `dual-mac` and adds the witness), and it reports **17 mutants, 15 caught,
  2 unviable, 0 missed** — where the previous shape reported 21 mutants with 8 missed. The
  semantics are unchanged: with `ultra` off the extra operand is `true`, and with `ultra` on
  the arm that had it is the one compiled.
- `tools/ctgrind.sh` now runs in three configurations — default, `--no-default-features`,
  and `--features ultra` — in `deep.yml` and locally. The third is what reported the
  encrypt-side cross-check, and the witness's own code is covered by it too (clean: its
  branches are lengths).
- `tools/fi_instruction.sh` sweeps a third configuration (`ultra`), **attributes every
  accepting fault to the symbol it sits in**, and gates on the *decision-scoped* count. The
  old criterion — "each layer no worse than the one below it", on raw totals — was wrong,
  and the `ultra` row is what showed it: the witness adds code to both entry points (a call,
  an extra gate operand, a ciphertext copy), so a longer swept region collects more
  accepting bytes even when every one of them is outside the decision. Measured, full local
  sweep of the final revision, as `(total, inside the decision)`: opt-out `2, 0` (nop) and
  `117, 3` (bits); `hardened` `0, 0` and `1, 0`; `ultra` `0, 0` and `4, 0`. The property
  that is comparable — and the one the three configurations are about — is the decision:
  **zero accepting faults inside `accept_or_reject` for `hardened` and `ultra` in both
  models**, against three in the opt-out build's bit-flip model, which is also the control
  that the sweep reaches the decision at all (its single `test`/`je` pair is one flipped bit
  from falling through into the accept store). That control is model-specific, and the
  reason is written into the tool: overwriting the `je` with `0x90` makes the following
  bytes decode as a different instruction and the run crashes instead of accepting.
  The sweep also **shards across cores** (`--jobs`, default the core count capped at 16),
  each shard on its own copy of the binary over a disjoint slice of the offsets: the full
  three-configuration `nop` sweep went from ~15 minutes sequential to under two, and the
  `bits` sweep from hours to ~9 minutes.
- `tools/cache_profile.sh` now profiles **two phases** — encrypt-only and round-trip — and
  takes `XSIV_FEATURES` so the same differential can be pointed at any configuration,
  self-test included (`XSIV_FEATURES=ultra ./tools/cache_profile.sh --selftest`). The
  example grew `--roundtrip` for it, and the script refuses to report the second phase
  unless it executed strictly more instructions than the first, so "decrypt is covered" is
  checked rather than assumed. Before this, every cache and branch profile in the
  repository was of `encrypt` alone: the path the crate's whole hardening story is about,
  and the path `ultra` puts a second implementation on, had never been profiled.
- The cross-architecture stage (CI's `cross-exec`, `verify.sh` stage 5) builds with
  `--features ultra,pure` instead of `--features pure`. The witness is hand-written
  byte-order-sensitive code — every ChaCha20 and BLAKE3 word goes through
  `from_le_bytes`/`to_le_bytes`, and the BLAKE3 chunk counter and message length are
  64-bit — and it was the one part of the crate never built or executed on the 32-bit or
  big-endian targets. All three now execute it: aarch64, i686 and powerpc64, 11 binaries
  each.
- `tests/variable_latency.rs` inventories `src/witness.rs` in its own control-flow table
  (3 `if`, 5 `while`, 21 `for`, 0 `loop`, 0 `match`), so the second implementation cannot
  grow a branch unnoticed while the table still covers only `src/lib.rs`.
- `tests/decision_scope.rs` pins the third call site: the encrypt-side cross-check must go
  through `accept_or_reject` (and *not* be an `if` at its own call site), and both of its
  reject paths must wipe the key material they have derived. It also skips the test module
  when counting call sites, so this file's own calls to the witness are not mistaken for
  the crate's.
- `locked_key_is_actually_locked` **fails** when the kernel refuses to lock, instead
  of returning early with `ok`; `XSIV_ALLOW_UNLOCKED=1` is the explicit opt-out. It also
  now asserts the lock is on the *live* key's page (unlocking it must move `VmLck`),
  which is the assertion that catches the moved-after-locking bug above.
- `every_layer_is_compiled_in_under_ultra` and
  `without_dual_mac_there_is_no_second_derivation_on_this_target` asserted that
  `src/lib.rs` *contains* `#[cfg(feature = "dual-mac")]` — true in every build, so they
  could not fail. Replaced with the anonymous `const _: () = { ... }` assertion at the
  top of `tests/ultra.rs` (compile-time `cfg!` checks that panic if any bundled layer is
  off; there is no named test — this entry used to name one,
  `ultra_enables_every_layer_it_bundles`, which does not exist) and
  `every_layer_answers_correctly_in_the_ultra_build` (end-to-end), plus
  `dual_mac_adds_exactly_one_extra_tag_derivation`, a unit test that counts the
  derivations through a test-only counter: 1 + 1 without `dual-mac`, 1 + 2 with it.
- Control-flow inventory 7 -> 9 `while` (the two loops of `ct_eq_independent`), and the
  stale hand counts in `tests/README.md`, `tests/timing.rs` and `deep.yml` corrected —
  the enforced table in `tests/variable_latency.rs` is now the only place a count lives.
- `tests/variable_latency.rs` described an `if decision.is_ok()` shape the code never
  had; the actual reject-first spelling is named instead.

### Documentation

- HChaCha20 was cited as "RFC 8439 §2.8". RFC 8439 contains no HChaCha20; the source
  is draft-irtf-cfrg-xchacha-03 §2.2.
- `Plaintext::drop`'s comment described a `vec![0u8; n]` construction that
  `alloc_zeroed` replaced, which had the memory-exhaustion behaviour backwards.
- The "~9x" fault-rate ratio is 11.7x–15.1x by its own figures; the "115 million fuzz
  executions" is removed — nothing in the repository records that many.
- The fault table gains the comparison-primitive row above, so the boundary is written
  where a reader looking for it will be.


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
  below +4.5% from 4 KiB up against `--no-default-features` (**superseded**: the `v0.3`
  re-measurement gives +25%/+24%/+23%/+11%, within the noise floor from 16 KiB up). The opt-out is
  `default-features = false`; it stays measured, tested, and covered by its own CI
  runs (`tools/ctgrind.sh --no-default-features`, `tools/fi_check.sh`'s `*-plain`
  rows).
- Every tool that assumed "hardened means `--features hardened`" was updated to the
  new axis: `tools/fi_check.sh`'s rows (including a `clean-plain` row),
  `tools/fi_instruction.sh`'s two scans (now `plain (no hardened)` vs
  `hardened (default)`; the "both 0 accepting bytes" those scans printed at the time
  was the wrong-bytes artefact of the `objdump -h` offset bug — the corrected counts
  and the comparison-based criterion are further down), the ctgrind CI step, and
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
- **The instruction-level scan's criterion is a comparison, not a threshold of zero.**
  `tools/fi_instruction.sh` requires `hardened ≤ plain` and prints *both* counts, because
  zero accepting faults is unreachable in any of these builds: the accepting sites are in
  the shared KDF/MAC/SIMD code rather than in the gate, so the property the tool can
  enforce is that the second gate never makes the built code worse — and the printed
  numbers are what make a regression visible. (The comparison alone would tolerate equal
  non-zero counts in both builds, which is exactly why the counts are printed rather than
  absorbed by the gate.) This bullet previously claimed the opposite — that the criterion
  had become "zero accepting bytes in both, which is what the README claims" — and
  neither half held: the tool's zero was the *wrong-bytes* artefact of the `objdump -h`
  offset bug (see "Corrected: the instruction-level fault numbers were measured on the
  wrong bytes" below), and the README says neither build reaches zero.
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
  `test_tag_binds_the_key_directly` for the mechanism commitment rests on. (That last
  test was later replaced by `test_tag_binds_both_derived_keys` in the v0.3 two-level
  tag change, above.)
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
sampling), the differential fixture is 58 vectors and a lock rather than a sample (the
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

### The length limit and the counter, and the allocating API

- **`MAX_MSG_SIZE` is now bound to the ChaCha20 block counter by a `const` assertion**:
  2^38 bytes is 2^32 blocks, exactly the counter's capacity, and every keystream path
  increments with `ctr.wrapping_add(1)` — so raising the limit by even one block would
  wrap the counter to 0 *inside a single message* and reuse keystream, silently. The
  binding makes that a compile error (verified by changing the constant to `2^38 + 64`
  and watching the build fail, then reverting), and `tests/counter_range.rs` adds the
  run-time arithmetic plus the property the bound rests on: every call site starts the
  counter at zero or forwards its own, so the reachable range is `0 ..= blocks - 1`.
  Before this, the only check was a Kani harness in the Formal job.
- **`encrypt` allocates fallibly too.** It still had a `vec![0u8; plaintext.len()]`,
  which calls the allocation-error handler and aborts the process: an unlucky length
  was a kill no application can catch, on the *encryption* side as well as the
  decryption one. Both entry points now go through one fallible helper, and with that
  change `use alloc::vec` became unused in the library — every allocation in the
  non-test source is fallible by construction, which the lint now says out loud.
- The allocation story is documented where the call is, not only in an error variant:
  `decrypt` holds **twice** the message (the caller's ciphertext plus the plaintext it
  allocates) for the duration of the call, `decrypt_bounded` bounds that second half,
  and the README distinguishes what the crate fixed (an allocator refusal is an error)
  from what no in-process library can (the OOM killer, which sends a signal a process
  cannot intercept).

### `random::fill` no longer leaves a partial buffer on error

`getrandom`'s contract is explicit: "This function returns an error on any failure,
including partial reads. We make no guarantees regarding the contents of `dest` on
error." `random::fill` forwarded that verbatim, so an error could leave a *prefix* of
genuine entropy in the caller's buffer — and a caller that ignores the `Result` (which is
`#[must_use]`, but a warning is not a guarantee) would take those bytes as a key or a
nonce. That is precisely the situation it happens in: early boot and
entropy-blocked sandboxes, where the source does fail. All zeros are not a usable key
either, but they fail the same way every time instead of working *sometimes*, which is
what makes the failure visible. The wipe lives in `fill_from`, a crate-internal function
that takes the source as a parameter — because the platform entropy source cannot be
made to fail on demand, and a guarantee nothing exercises is a comment. The test drives a
source that writes eight bytes and then fails, which is the worst case the contract
permits.

### Corrected: the instruction-level fault numbers were measured on the wrong bytes

`tools/fi_instruction.sh` computed its virtual-to-file mapping from `objdump -h`'s **LMA**
column instead of its **File off** column (`objdump -h` prints `Size VMA LMA File off`; the
script's regex captured the first three numbers and used the third). On these binaries that
is a 4 KiB shift, so every fault landed outside the function the tool claimed to test - and
the tool still printed a plausible map, so the error was invisible. Its "0 accepting faults"
was an artefact, and the README's rows, this changelog and the audit summaries that repeated
it were wrong.

The mapping is now taken from the correct column **and asserted against `objdump -d` before a
single fault is written**, so a wrong offset fails loudly instead of producing a number. With
that fixed, the measured picture (full sweeps, both builds, both models):

| | neutralised byte | single bit flipped |
| --- | --- | --- |
| default (`hardened`) | 1 accepting / 5526 | 13 / 44208 |
| `--no-default-features` | 9 / 4268 | 152 / 34144 |
| RustCrypto `XChaCha20Poly1305` (1081 B of decision code) | 13 / 1081 | 106 / 8648 |

Two things follow, and both are now in the README's table. The accepting sites are the
**same addresses in both builds**, so the class is not the accept/reject gate: it is the
shared KDF/MAC/SIMD code, and the mechanism is mostly decoder desynchronisation - corrupting
the middle byte of a multi-byte instruction makes the following bytes execute as different
instructions. Nothing in the source can prevent that. And the second gate still *buys*
something measurable: the default build's rate is 11.7x lower than the opt-out one on
the neutralised-byte model and 15.1x lower on the bit-flip one (1/5526 against 9/4268,
13/44208 against 152/34144), and ~40x lower than the reference implementation's. (This
sentence said "~9x"; that is not what these counts give, and the two models disagree
with each other as well — see the Documentation entry above.)

The tool's criterion changed with the numbers: it no longer asserts zero (unreachable for any
of these implementations) but that the hardened build is not worse than the opt-out one, with
both counts printed.

### `ultra`: one feature for every defence

- New `ultra` feature = `hardened` + `rng` + `dual-mac` + `locked`, plus the two new opt-in
  layers it composes:
  - **`dual-mac`**: an *independent* recomputation of the tag on the verify path, required to
    agree with both the stored value and the received tag. This is the only software measure
    against "pin the computed tag to a constant, or to the received tag", where the two
    `hardened` gates are satisfied together because they compare the same two values.
    Measured: +21..40% on decryption, +6..25% on a round trip. The recomputed tag is wiped
    like every other secret-derived copy — `tests/ultra.rs` asserts that, and it is how the
    omission was found before it shipped.
  - **`locked`**: `mlock` + `madvise(MADV_DONTDUMP)` for keys, reaching past swap and core
    dumps, which a volatile-store wipe cannot. `LockedKey::new` fails loudly when the kernel
    refuses (`RLIMIT_MEMLOCK` is the usual reason). Raw syscalls, because the crate is
    `no_std`; the numbers come from the kernel's headers, and `tests/ultra.rs` checks the
    &shy;implementation by reading the kernel's own `VmLck` accounting back.
- `pure` is deliberately **not** part of `ultra`: it costs 24-32% and buys no security.
- The README's `ultra` section states the per-layer cost (all measured) and, in the same
  place, the five attack models that remain out of reach for *any* software build, so the
  feature cannot be read as total immunity.

### Recheck: an empty feature, a stack cost, and two over-strict tests

- **`--features locked` compiled nothing.** `Cargo.toml` exposes `locked` as a feature of its
  own, but the module was gated on `ultra`, so a caller who enabled exactly the layer the
  README's table lists got no module, no error, and no protection. The module is gated on
  `locked` now (`ultra` implies it, so the bundle is unchanged), `tests/locked.rs` covers it
  standalone, and CI has a `--features locked` matrix entry so the empty-feature case cannot
  come back.
- **The `scrub_stack` frame costs ~16 KiB of stack per call, and that was not written down.**
  Measured on a 32 KiB thread stack: the default build still runs with 16 KiB of the stack
  already consumed; a `dual-mac`/`ultra` build fails at 8 KiB. It is a 16 KiB frame, so it can
  fault the thread it is protecting. The README's cost column and the function's own doc now
  say so; a caller that runs AEAD on small-stack threads must size them for it.
- **`dropping_releases_the_lock` was racy and I found it by running the matrix.** `VmLck` is a
  process-wide counter and `cargo test` runs a file's tests concurrently, so a sibling test
  locking a key masked the delta. The file's tests now take a mutex.
- **Two tests were over-strict about documented platform limits.** `SUPPORTED == false` is a
  compile-time property of the target (the syscalls are wired for Linux x86_64/aarch64 only),
  so asserting it is a failure made the i686 job red for a documented limit rather than a
  defect — it skips loudly now, while a *runtime* refusal from the kernel is still a failure.
  And `tests/locked.rs`'s per-mapping `Locked:` check is not populated under `qemu-user`: it
  falls back to the kernel's `VmLck` delta there, and only a failure of *both* evidence
  sources is a failure, so the check stays non-vacuous.
- Missing doc comments on the module's unsupported-target fallbacks (`missing_docs` caught
  them on i686, where that arm compiles and the host arm does not).

### Recheck after the `ultra` work: a page freed unwiped, and a test that restored on one path only

Two defects, both found by reading the code back against what it claims rather than by a
tool — which is the same reason the earlier `Page::drop` gap survived the tests that touch
this module.

- **`Page::drop` freed the page without wiping it.** `LockedKey::drop` wipes the bytes, then
  unlocks and drops the page, so the *normal* path was scrubbed. But `LockedKey::new`'s
  failure path — the key bytes and their integrity tag already written, `mlock` just refused
  — drops the `Page` **directly**, and a `?` there returned through live key material that
  the allocator then handed out again. That is the same defect class the entry points were
  fixed for, in the one place a `Drop` impl could be relied on to cover instead. The wipe is
  now in `Page::drop`, where it cannot be forgotten when another early return is added to
  `new`; it is a **volatile** store for the same reason the other wipes are (`CHANGELOG`,
  *Zeroization: two copies the wipes could not reach*). Cost: one page of volatile stores,
  once per key lifetime.
- **`deny_debugging_is_enforced_by_the_kernel_and_reversible` claimed to restore the process's
  dumpable flag on every path, and restored it on one.** The restore was an explicit call at
  the end of the test; the two assertions between `deny_debugging()` and that call could
  panic straight out through `Drop`, leaving the whole test *binary* non-dumpable — which
  costs every later test its core dump and stops `gdb`/`strace` attaching to a run that is
  failing, exactly when someone wants them. The restore is now an RAII guard armed before the
  first assertion, so "every path restores it" is true by construction. Verified non-vacuous
  with a planted panic: with the guard the probe passes, with the guard's body emptied it
  fails with *"the guard did not restore the flag on the panic path"*.

Both are in the `locked`/`ultra` layer and neither is a wire-format change.

### The release job: six defects, including one that shipped the wrong compiled library

The same re-check went over `.github/workflows/ci.yml`, which had grown the three-configuration
release. Six defects, ordered by what they would have cost:

- **Every bundle shipped the `ultra` `.rlib`.** The packaging loop built only the example
  (`cargo build --release $flags --example xsiv_stdin`) and then copied
  `target/release/libxchacha20_blake3_siv*.rlib`. Building an example does not uplift the lib's
  root `rlib`, so the root artifact left on disk still had the feature set of the last plain
  `cargo build` — the `ultra` one, three steps earlier (measured: after an example-only opt-out
  build the root `rlib` was byte-identical to the `ultra` build's). The `opt-out` and `hardened`
  bundles therefore contained the `ultra` library while their manifest said "the compiled library
  for this configuration", and the three `.rlib` digests in the per-bundle tables would have been
  identical. Fixed by adding `--lib`; running the loop locally, the three `.rlib` digests are now
  distinct, and the three KATs are still byte-identical (`sha256 = 6ffe02e3…`).
- **The "matrix still names them" guard could not fail.** It grepped the workflow for
  `profile: release, default features` and two sibling strings — which appear as literals in the
  loop *doing the grepping*, three lines above the `grep`. So the guard passed unconditionally;
  deleting a configuration's test-matrix leg would still have printed "matrix leg present". Fixed
  by anchoring the search to a matrix row (leading `- ` and end-of-line `$`), so the loop's own
  literals no longer match and the longer `… with rng` row no longer matches the shorter leg.
- **`publish` was not gated on the blocking `timing-instrument` job.** Its `needs` list omitted
  it, so a release could be cut from a commit whose timing instrument had rotted, contradicting
  the comment above `needs` ("a failure anywhere blocks this"). Added.
- **The workflow-level `cancel-in-progress: true` reached the `release` job.** A push to `main`
  while a release was uploading assets cancelled it mid-publish, and `gh release create`/`upload`
  is not atomic — the partial release the publish step otherwise works to prevent. Now
  `cancel-in-progress` is `${{ github.event_name == 'pull_request' }}`: PR runs still cancel,
  `main` runs queue and each publishes its own `sha-<commit>` tag.
- **The cross-configuration failure diagnostic was a no-op.** `diff <(cat dist/*/kat.txt)` passes
  a *single* operand to `diff`, which printed "missing operand" and exited 2 behind `|| true`, so
  the one failure path that matters printed nothing useful. Replaced with a loop that prints all
  three outputs.
- **`$deps` was undefined** in the qemu step's "no binaries ran" branch, so `set -u` aborted with
  an unrelated message instead of the intended diagnosis. Reworded.

Also: each bundle now ships `vector.txt` (the input `kat.txt` is the answer for, with its digest
in the manifest), so a consumer can re-derive the KAT rather than take the bundled digest on
faith.

### Documentation: numbers and claims that disagreed across files

The same pass cross-checked the prose against the code and against itself, and found several
places where a claim was stated twice with different values, or stated more strongly than the
code supports:

- **The changelog contradicted the README and the code** on the second comparison shape: the
  entry still said it was "`dual-mac`/`ultra`"-only and cost "+2.7% at 64 B", while the code
  gates it on `hardened` and the later entry (and the README) say every gate-building
  configuration and "+1.4 ns". The stale paragraph now points forward to the entry that
  superseded it. (A later pass sharpened "every configuration" to "every *gate-building*
  configuration", because `--no-default-features` compiles neither the second gate nor the
  fold — see the recheck entry above.)
- **The `dual-mac` round-trip cost** read "+8–25%" in the README and "+6..25%" in `Cargo.toml`
  and the changelog; the README now matches the other two.
- **"`hardened,dual-mac` (everything `ultra` has except the witness)"** was false — it also drops
  `locked` and `rng`. The README now says what the configuration is, and names
  `hardened,dual-mac,locked,rng` for the "`ultra` minus the witness" configuration.
- **§4.10 said "every cryptographic call in the non-test source is one of these five"**, but
  `locked`'s integrity tag calls unkeyed `blake3::hash` — a sixth call. It is now enumerated as
  "the one call outside the construction" (arguments for why it adds no assumption), counted by
  `tests/construction_inventory.rs`, and the "a seventh thing to assume" slip for L3.6 (which is
  the sixth of L3.1–L3.6) is corrected.
- **§8's Rowhammer rows** (three of them, in §8.2, §8.5 and §9) said a "flipped key page" or
  "corrupted page" is detected; the check covers only the 40-byte key-and-tag region, and a flip
  in the unused remainder is deliberately *not* reported (the test asserts that). Corrected in
  all three, and the "AMD-code" framing for what is an unkeyed hash is qualified.
- **§8.2's DFA row** listed `mac_key` as per-message; it is per-*nonce* (Thm 1), as the power row
  two lines up says. Corrected. The Debugger row's "observes `/proc/self/mem` being refused"
  overstated the test, which reads the flag back but does not assert the procfs refusal.
- **§8.2's "Swap / hibernation"** row now says swap only: `mlock` does not keep a page out of a
  suspend-to-disk image.

### Release policy

- **The byte format is frozen at construction revision `v0.3`.** It will not change
  without a revision bump, a `CHANGELOG` entry and the known-answer vectors updated in
  the same commit; `kat_regression_lock` re-asserts the published bytes from a fixture
  no in-crate change can edit, so the promise is mechanical rather than stated. (Two
  version numbers are in play and are kept apart: the **construction revision**
  `v0.3` is the bytes, and the **crate version** `0.1.0` is the Rust API. The
  construction has changed twice: v0.1 -> v0.2, then v0.2 -> v0.3 with the two-level
  tag.)
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
  below +4.5% from 4 KiB up. (**Superseded**: the `v0.3` re-measurement gives +25% at 64 B,
  +24% at 256 B, +23% at 1 KiB, +11% at 4 KiB, within the noise floor from 16 KiB up; the
  figures above were taken before the second comparison shape was added to every build.)
- **Fault-injection check** (`tools/fi_check.sh`) plus its detector
  (`tests/decision.rs`), and a CI step for both.
- **Large-message reference vectors** (`tests/vectors_differential_large.txt`):
  nine sizes from 1999 B to 1 MiB as digests, so the sizes around the tag's
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
