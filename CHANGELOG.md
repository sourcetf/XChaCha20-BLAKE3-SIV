# Changelog

Short, and deliberately about **the wire format** first: this construction is not a
standard, so a consumer needs to know when the bytes move. Versions below refer to
construction revisions; the crate version in `Cargo.toml` is `0.1.0` and no release
tags have been cut yet.

## Unreleased

### Wire format

**Unchanged.** Every ciphertext and tag this revision produces is byte-identical to
the previous one; the KATs, the differential fixture against `tools/ref_impl.py` and
the accelerated-path corpus all still pin the same bytes. Nothing below touches the
construction — it is hardening, correctness in `ultra`, and evidence quality.

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

Under `dual-mac`/`ultra`, the second gate now `AND`s in `ct_eq_independent`, a
differently *written* constant-time comparison (an 8-byte fold into a `u64`, one
comparison at the end). Re-measured against the same fault: **no forgery in 2,000,000
attempts**. One fault can now only disarm one of the two comparisons, so a forgery needs
two faults — which is the boundary the README's table states.

**The default builds are deliberately unchanged here.** `hardened` on its own still
compares both gates through `subtle`, and still accepts that forgery; this is an
`ultra` defence, and the README's fault table says so on the row rather than leaving
the reader to infer that two gates over one comparison are two witnesses. Cost under
`ultra`: one extra 65-byte comparison, about +2.7% at 64 B and +0.1% at 1 MiB.

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

- `locked_key_is_actually_locked` **fails** when the kernel refuses to lock, instead
  of returning early with `ok`; `XSIV_ALLOW_UNLOCKED=1` is the explicit opt-out. It also
  now asserts the lock is on the *live* key's page (unlocking it must move `VmLck`),
  which is the assertion that catches the moved-after-locking bug above.
- `every_layer_is_compiled_in_under_ultra` and
  `without_dual_mac_there_is_no_second_derivation_on_this_target` asserted that
  `src/lib.rs` *contains* `#[cfg(feature = "dual-mac")]` — true in every build, so they
  could not fail. Replaced with `ultra_enables_every_layer_it_bundles` (`cfg!`) and
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
something measurable: the default build's rate is ~9x lower than the opt-out one and ~40x
lower than the reference implementation's.

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
