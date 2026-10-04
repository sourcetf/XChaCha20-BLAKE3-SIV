# Performance

Provenance and method for every performance number this repository quotes, split
out of [`README.md`](README.md) so the README stays about the construction and the
security argument. The figures, the noise floor and the methodology are unchanged;
the configuration and throughput figures that the README's tables cite resolve to a
table here. (Some per-layer *costs* — the fold's 1.4 ns, the integrity tag's 42 ns,
`mlock`'s ~7 µs, `scrub_stack`'s 16 KiB of stack — are stated on the README's layer
rows themselves, because each is a property of one layer rather than a configuration
measurement; those are not repeated here.)

Measured head-to-head against RustCrypto's `chacha20poly1305` — the natural
reference point, since `XChaCha20Poly1305` has the same 24-byte nonce and the same
ChaCha20 core. Reproduce with `cargo bench --bench compare`, which drives both
sides through `aead`'s in-place interface so neither pays for an API shape the
other does not have. Release profile as shipped (`lto`, `codegen-units = 1`), AMD
Ryzen 9 7945HX under WSL2, **15 bytes** of AAD (`b"associated data"`, the benchmark's
single constant), and both sides on their native SIMD backends (BLAKE3's
C/assembly kernels, Poly1305's AVX2 four-block path). The 12-byte-nonce
`ChaCha20Poly1305` is measured too and tracks `XChaCha20Poly1305` closely — re-measured
2026-10-03 over the same three passes and all nine sizes, the median cell differs by **1.6%** and the
worst by 6.1% (1 KiB decryption) — so it is not tabulated.

**All figures in this file were re-measured on 2026-10-03 for revision `v0.3`** (the two-level
tag), by `tools/bench_3pass.sh`, which runs exactly the protocol below and writes the raw
criterion output per configuration per pass; `tools/bench_summarise.py` turns that into the
tables. `v0.3`'s extra keyed-BLAKE3 call and extra ChaCha20 derivation block are a **fixed
per-message cost**, so the change shows at the small sizes and is inside the noise floor from
16 KiB up.

## The three configurations, measured

**Three `cargo bench` runs per configuration**, each pinned to one core (`taskset -c 3`), with
the configuration order rotated between passes (`default, opt-out, ultra` then `ultra, opt-out,
default` then `opt-out, ultra, default`) so no configuration is always measured first or last;
the reported figure per cell is the **median of the three passes**. Criterion's median of 100
samples per pass, `--warm-up-time 2 --measurement-time 4`, sizes 64 B to 1 MiB, shipped release
profile. The benchmark also runs 700 B and 5000 B — the two non-power-of-two sizes that keep the
SIMD tails visible — and they are not tabulated below; the seven sizes in the tables are the
ones the noise floor was computed over.

**Noise floor, measured rather than assumed**: the reference implementation is the *same code*
in all nine runs (three configurations × three passes), so the spread of its own cells is the
floor. Across the 189 reference measurements (63 pass-to-pass cells, three passes each), the median spread is **6.8%**, the 90th
percentile **10%**, the worst cell **15%** (the small sizes and 1 MiB — the first is CPU-boost
sensitive, the second shares LLC and DRAM with whatever else is on the host). **Differences
smaller than that are the same number**, which is why most of the `hardened`-vs-`opt-out` column
pairs below read as ties and why this section does not quote a figure to three digits.

**The `ultra`-cost table below was re-measured after the witness's residue-wipe pass** (the
copies the audit found unwiped: `Output`'s CV and message block, the streaming locals, the
preallocated CV stack), and that campaign ran while the third-party audit was executing its own
suites on this host, so its **own** noise floor is larger: across its 189 reference
measurements the median pass-to-pass spread is **12.7%**, the 90th percentile **105%** and the
worst cell **148%**. That is why only that table was taken from the noisier campaign: the
witness change moved 1 MiB decryption from 10.1x to 12.4x (~23%, above even that floor, and
consistent in all three passes), while the other tables' cells moved by amounts inside it. A
quieter re-run of the whole campaign is the right way to refresh them.

`opt-out` is `--no-default-features` (one comparison), `hardened` is the default (two gates,
the second independently *shaped*, fail-closed, and both constant-time comparison *shapes*), `ultra` adds
the witness cross-check and the `locked`/`rng`/`dual-mac` layers. All three produce **identical
bytes** — the KATs and the differential fixture pin that in every configuration — so what the
table below prices is exactly the defences.

Throughput, ratio against `XChaCha20Poly1305` (> 1 means this crate is faster):

| Message | opt-out enc | opt-out dec | **hardened enc** | **hardened dec** | ultra enc | ultra dec |
| --- | --- | --- | --- | --- | --- | --- |
| 64 B | 1.25x | 1.13x | **1.25x** | 0.89x | 0.81x | 0.36x |
| 256 B | 1.08x | 1.01x | **1.16x** | 0.88x | 0.76x | 0.29x |
| 1 KiB | 0.86x | 0.84x | 0.87x | 0.70x | 0.67x | 0.21x |
| 4 KiB | 1.02x | 1.02x | 1.02x | 0.91x | 0.83x | 0.15x |
| 16 KiB | 1.23x | 1.21x | **1.25x** | **1.21x** | 1.14x | 0.13x |
| 64 KiB | 1.21x | 1.23x | **1.21x** | **1.19x** | 1.19x | 0.12x |
| 1 MiB | 1.34x | 1.30x | **1.35x** | **1.30x** | 1.29x | 0.13x |

Round trip (encrypt then decrypt, in place), same ratio:

| Message | opt-out | hardened | ultra |
| --- | --- | --- | --- |
| 64 B | 1.23x | **1.00x** | 0.47x |
| 256 B | 1.02x | 0.99x | 0.43x |
| 1 KiB | 0.85x | 0.81x | 0.31x |
| 4 KiB | 1.02x | 0.97x | 0.26x |
| 16 KiB | 1.15x | **1.18x** | 0.24x |
| 64 KiB | 1.19x | **1.19x** | 0.22x |
| 1 MiB | 1.34x | **1.35x** | 0.23x |

Latency in microseconds at three sizes, the three configurations and the
reference (median of the three passes, each criterion's median of 100 samples):

| | opt-out | hardened | ultra | XChaCha20Poly1305 |
| --- | --- | --- | --- | --- |
| encrypt 64 B | 0.95 | 0.94 | 1.46 | 1.17 |
| encrypt 16 KiB | 7.32 | 7.25 | 8.54 | 9.07 |
| encrypt 1 MiB | 370 | 386 | 385 | 522 |
| decrypt 64 B | 1.06 | 1.32 | 3.24 | 1.17 |
| decrypt 16 KiB | 7.62 | 7.81 | 70.7 | 9.44 |
| decrypt 1 MiB | 391 | 394 | 3988 | 511 |

Read both tables as: this crate pays more *per message* (three derived keys, a
65-byte tag, and wiping all of it) and less *per byte* (BLAKE3 beats Poly1305 once
there is enough data to batch). Two costs are visible in the configuration
comparison, and both are the price of a defence rather than an accident:

* **`hardened`'s second gate is a fixed per-message cost on decrypt** — two more
  65-byte constant-time comparisons plus an independently written eight-byte fold
  (each gate runs `subtle`'s byte loop both ways round, so the default build makes
  four 65-byte comparison passes and the opt-out build two), the volatile re-reads
  and the fail-closed plumbing — so it shows at the small end (1.06 → 1.32 us at 64 B) and
  its share is inside the noise floor by 1 MiB (391 → 394 us, i.e. a tie inside the
  noise floor). Encryption pays nothing for it: 0.95 → 0.94 us.
* **`ultra`'s witness is a per-byte cost on decrypt**, because it is a scalar
  re-implementation: **2.7x the default at 64 B, 4.0x at 1 KiB, 11.0x at 64 KiB,
  12.4x at 1 MiB** (re-measured after the residue-wipe pass; the small sizes are at
  or inside the campaign's own noise floor, the large ones are not) — which is why the
  round trip above ends near 0.19x. Its in-place *encryption* is untouched (0.92-1.05x
  at every size) because that path carries no witness; the allocating `encrypt`, which
  does, lands at 7.1x the default on the round trip at 1 MiB. If a deployment wants the fault model and not
  the cost, `hardened,dual-mac` — `ultra`'s two fault-model layers, without the witness
  and without the `locked`/`rng` layers — is the configuration to measure against; the
  table's `opt-out` and `hardened` columns bracket it, since `dual-mac` costs one extra
  tag pass. (`ultra` minus *only* the witness is `hardened,dual-mac,locked,rng`, the
  configuration the "what the `ultra` layer costs" table below measures.)

Latency is not throughput divided by size, because the fixed per-message cost
dominates at the small end: at 64 bytes the default build is about as fast as the
reference on encryption (0.94 against 1.17 us) and answers sooner on the round trip,
and it is the slower of the two around 1 KiB, where `Poly1305`'s four-block AVX2 path
is at its best and BLAKE3 has little to batch. **Decryption at 64–256 bytes is within
the noise floor either way** (0.89x, 0.88x), and the small-message decrypt gap is what
the `hardened` decision and the fixed `v0.3` cost add.

**What the `ultra` layer costs, relative to the default configuration** — the same
three passes, so the noise floor above applies: a ratio within ~7% of 1.00 is a tie.
This is the table the layer and fault rows cite, because a ratio against the
*reference* (above) and a ratio against the *default* are different quantities:

| Message | decrypt | encrypt | round trip (in place) | round trip (allocating) |
| --- | --- | --- | --- | --- |
| 64 B | 2.73x | 1.50x | 2.20x | 2.48x |
| 256 B | 3.24x | 1.32x | 2.44x | 2.87x |
| 1 KiB | 3.96x | 1.43x | 2.82x | 3.30x |
| 4 KiB | 6.93x | 1.28x | 4.02x | 4.96x |
| 16 KiB | 10.37x | 1.05x | 5.46x | 6.65x |
| 64 KiB | 11.02x | 1.05x | 6.06x | 6.59x |
| 1 MiB | 12.41x | 0.92x | 6.47x | 7.07x |

The encrypt column is the point made above, in numbers: it is a tie at 64 KiB and
beyond (the witness runs only on the allocating `encrypt`, which is why the
allocating round trip is worse than the in-place one), while decrypt — which always
cross-checks — grows with the message because the witness is byte-serial.

**How far these ratios move between builds.** Every number in this file is one host's, one
compiler's and one harness's. A third-party audit re-measured the layered configurations with
its own probe (process CPU time, five interleaved rounds, its own machine and its own harness)
and got the same *directions* at larger magnitudes: `dual-mac` against the default at 1 KiB came
out at 1.69x on in-place decryption and 1.81x allocating, where the README's layer row states
+30% at 64 B and +40% at 1 KiB on this host; `ultra`'s allocating decryption at 1 KiB at 4.62x,
where the table above says 3.96x; and `dual-mac`'s fixed encrypt-side cost at +43–44% (64 B),
+40–42% (1 KiB) and +3–5% (16 KiB), which is the `scrub_stack` row's ~0.5–1 µs per call seen as
a percentage. The audit does not attribute the difference to either side's figures, and the
*shape* each mechanism predicts is what the layer rows actually claim — a fixed per-call cost is
largest at the small end and gone by 16 KiB, the second tag pass grows with the message, the
witness is per byte — so read the constants here as one build's and the mechanisms as the claim.
Refreshing the constants for a given deployment means re-running `tools/bench_3pass.sh` on that
host; nothing here is a portable constant.

Two structural properties bound what a caller can do with that latency, and both
follow from the construction rather than from this implementation:

* **Encryption cannot produce its first ciphertext byte until the whole message has
  been hashed.** The tag covers the plaintext, the encryption key is derived from
  the tag, and only then does the ChaCha20 pass start: two serialized passes, no
  early output, and a single message's latency does not shrink with more cores.
  It is still faster end to end — 386 us against 522 us at 1 MiB in the default
  configuration — because BLAKE3
  hashes faster than ChaCha20 streams, but a caller cannot overlap the work with
  its own processing the way a one-pass AEAD allows.
* **Decryption starts immediately but decides late.** The encryption key depends
  only on the tag, which the caller supplies, so the ChaCha20 pass runs at once;
  authentication then hashes the recovered plaintext in full. The plaintext
  therefore exists in the buffer before it is verified, which is why the API wipes
  it and never returns it on failure, and why an application must not act on it
  until `decrypt` returns.

The percentiles in the latency table are per *sample*, each averaging hundreds of
calls, so they do not show per-call jitter: this host's clock costs ~35 ns per
`Instant::now()`, which is exactly why each sample averages hundreds of calls -- and
a genuine tail-latency measurement still needs bare metal, where the clock and the
scheduler are far quieter than in this container.

The allocating `encrypt`/`decrypt` API costs more than the in-place one on a round
trip, and by how much depends on the allocator: 4-7% in the criterion harness for the
default build (re-measured 2026-10-03; up to 37% for `ultra` at 16 KiB), but up to
**2.5x at 1 MiB in a standalone probe** (`examples/profile_probe.rs`: 2098 us against
843 us per message). The extra
work is real either way -- two 1 MiB allocations, the copies into them, and the
wipe of the `Plaintext` that `decrypt` returns -- and the in-place path touches
none of it. For large messages, use the in-place API.

**Every number above is the default build.** `ultra` is a different trade and is
measured separately in its own section: its independent second implementation costs
2.7x at 64 bytes and 12.4x at 1 MiB on decryption, because it is scalar and re-runs
the tag pass per byte (the figures are the "what the `ultra` layer costs" table in
"The three configurations, measured"). Nothing above changes if you turn `ultra` on and then off again — the
default build's machine code is untouched by the feature.

**Where the remaining headroom is, and where it is not.** Measured, so that nobody
has to rediscover it:

* The ChaCha20 *tail* and the 64-byte key-material block stay scalar, even though a
  four-lane kernel cuts their instruction count by roughly two thirds. Tried:
  callgrind put the scalar rounds at 28% of the instructions in a 64-byte round
  trip, so routing them through `blocks4` looked like free money -- and it measured
  22% *slower* at 64 bytes and 10% slower at 100, because the four-lane kernel
  writes a 256-byte keystream into a scratch that must then be zeroized (64 bytes
  for the scalar block) and transposes lanes the scalar path does not need. A small
  message is latency- and memory-bound, not issue-bound. The comment in
  `chacha20_apply` carries these numbers.
* Wiping BLAKE3's internal state costs 15% of the instructions in a 64-byte round
  trip -- it wipes the whole CV stack, most of which a one-chunk input never
  touched. It stays: that no copy of the keyed-BLAKE3 key material survives the call is the
  guarantee, and only the dependency can say which of its state that covers.
* Above a few megabytes, intra-message parallelism is real, but it is a policy
  decision rather than an oversight. Hashing 16 MiB with a reused four-thread pool
  measured 3.7x against one thread (8 threads: 4.8x); at 1 MiB the same measurement
  gives 1.02-1.08x, because a single core already runs at ~8.9 GiB/s there and the
  coordination costs what the parallelism buys. (This one is a hand measurement on this
  host, unlike the tables above: no committed script reproduces it, and it is recorded
  because the decision it supports is a design call.) The crate does not do it: it would
  need `std`, a thread pool, and cores the caller may already be using. BLAKE3
  ships threaded hashing (`update_rayon`) as an opt-in feature for the same reason,
  and RustCrypto's ciphers are single-threaded. Parallelise across messages
  instead, and check a workload with `examples/profile_probe.rs` before assuming
  anything here.

Two implementation choices dominate the throughput numbers, both verified to leave
the wire format byte-identical (the KATs, the differential fixture and
`test_all_accelerated_paths_agree_on_a_boundary_corpus` pin every byte, and they
run against both):

* **BLAKE3's native backends, not `pure`.** The `pure` feature selects BLAKE3's
  Rust-intrinsics backends; leaving it off lets BLAKE3 use its C/assembly SIMD
  kernels, which is worth 24–32% from 4 KiB up. See the note in `Cargo.toml` for
  the portability story (it falls back to the Rust backends when the target has
  no compiler) and for the two cases that still pass `--features pure`.
* **One contiguous buffer for the tag, for mid-sized messages.** BLAKE3's
  incremental API only takes its batched path when a call starts on a chunk
  boundary, so feeding it `head`, then `aad`, then `msg` dropped the whole message
  onto the one-block-at-a-time path — 2.1–2.3x slower at 4–16 KiB. Messages from
  2 KiB to 64 KiB are now hashed through one exact-sized, wiped buffer, which
  removed the 4 KiB deficit entirely (it was 1.66x behind XChaCha20-Poly1305
  there; it is now level). Above 64 KiB the copy costs more than the batching
  saves, so the three-part call stays.
