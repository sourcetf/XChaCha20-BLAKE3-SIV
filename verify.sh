#!/usr/bin/env bash
#
# Full verification pipeline for XChaCha20-BLAKE3-SIV.
#
# Runs, in order of increasing cost:
#   1. reference-implementation self-checks (python) and fixture freshness
#   2. cargo fmt / clippy
#   3. the unit + differential test suite
#   4. cross-compilation for aarch64, i686 and riscv64
#   5. Kani bounded model checking  (slow: minutes; the whole-permutation
#      harnesses dominate)
#
# Usage:
#   ./verify.sh              # everything except Kani
#   ./verify.sh --kani       # everything, including Kani
#   ./verify.sh --kani-only  # just Kani (after a code change, to re-prove)
#
set -euo pipefail

cd "$(dirname "$0")"

# rustup's toolchain lives here; the system rustc may be a different (stale)
# toolchain without the cross targets installed.
export PATH="$HOME/.cargo/bin:$PATH"

RUN_KANI=0
KANI_ONLY=0
RUN_CROSS_EXEC=0
RUN_MIRI=0
RUN_CTGRIND=0
RUN_DENY=0
RUN_FUZZ=0
for arg in "$@"; do
  case "$arg" in
    --kani) RUN_KANI=1 ;;
    --kani-only) RUN_KANI=1; KANI_ONLY=1 ;;
    --cross-exec) RUN_CROSS_EXEC=1 ;;
    # Kept as an alias: the stage used to execute aarch64 only.
    --aarch64-exec) RUN_CROSS_EXEC=1 ;;
    --miri) RUN_MIRI=1 ;;
    --ctgrind) RUN_CTGRIND=1 ;;
    --deny) RUN_DENY=1 ;;
    --fuzz) RUN_FUZZ=1 ;;
    --deep) RUN_KANI=1; RUN_CROSS_EXEC=1; RUN_MIRI=1; RUN_CTGRIND=1; RUN_DENY=1; RUN_FUZZ=1 ;;
    --all) RUN_KANI=1; RUN_CROSS_EXEC=1; RUN_MIRI=1 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

step() { echo; echo "=== $* ==="; }

# Locate a qemu-user emulator for a target.  Honours `$QEMU_<ARCH>` (e.g.
# `$QEMU_AARCH64`, `$QEMU_I386`) first, then the usual user-local install, then
# whatever is on $PATH.
find_qemu() {
  local name="$1" arch var
  arch="$(printf '%s' "${name#qemu-}" | tr '[:lower:]-' '[:upper:]_')"
  var="QEMU_${arch}"
  if [ -n "${!var:-}" ] && [ -x "${!var}" ]; then
    echo "${!var}"; return 0
  fi
  for c in "$HOME/.local/bin/$name" "$(command -v "$name" 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then echo "$c"; return 0; fi
  done
  return 1
}

if [ "$KANI_ONLY" -eq 0 ]; then
  step "1. reference implementation self-checks"
  if command -v python3 >/dev/null 2>&1 && python3 -c "import blake3" 2>/dev/null; then
    python3 tools/ref_impl.py >/dev/null
    python3 tools/gen_test_vectors.py --check
  else
    echo "SKIPPED: python3 with the 'blake3' module is required."
    echo "         (pip install blake3)  The commited fixture is still tested"
    echo "         below; only its regeneration check is skipped."
  fi

  step "2. formatting and lints"
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  # The `rng` feature adds a public module and a dependency; lint it too, or a
  # warning there would only surface once someone enabled the feature.
  cargo clippy --all-targets --features rng -- -D warnings

  step "3. test suite"
  cargo test --release
  # `rng` gates the `random` module and its tests.
  cargo test --release --features rng

  # The security tests are in `tests/security.rs` and run with the rest above,
  # but they are called out because two of them can be slow (the timing screen
  # takes ~45 s) and one is skipped by nothing -- if it starts failing, this
  # line says which area to look at.
  step "3b. security tests (property, fuzz, timing screen)"
  cargo test --release --test security

  # `--no-default-features` is how a `no_std` user consumes this crate.
  step "3c. no-default-features build"
  cargo check --no-default-features --all-targets

  step "4. cross-compilation"
  # Type-check against the gnu target (no linker needed), then build the musl
  # target, which is what step 5 executes.  `.cargo/config.toml` selects
  # rust-lld so no cross C toolchain is required.
  if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-gnu; then
    cargo check --target aarch64-unknown-linux-gnu --all-targets
  else
    echo "SKIPPED (gnu): aarch64-unknown-linux-gnu target not installed."
    echo "         (rustup target add aarch64-unknown-linux-gnu)"
  fi
  if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-musl; then
    cargo check --target aarch64-unknown-linux-musl --all-targets
  else
    echo "SKIPPED (musl): aarch64-unknown-linux-musl target not installed."
    echo "         (rustup target add aarch64-unknown-linux-musl)"
  fi
  # riscv64 has no SIMD backend compiled at all, so this type-checks the
  # scalar-only configuration (see `.cargo/config.toml` for why it is not
  # linked/executed).
  if rustup target list --installed 2>/dev/null | grep -q riscv64gc-unknown-linux-musl; then
    cargo check --target riscv64gc-unknown-linux-musl --all-targets
  else
    echo "SKIPPED (riscv64): target not installed."
    echo "         (rustup target add riscv64gc-unknown-linux-musl)"
  fi
fi

if [ "$RUN_CROSS_EXEC" -eq 1 ]; then
  step "5. cross-architecture execution under qemu (aarch64 NEON, i686 32-bit)"
  # Two configurations that cannot be exercised natively here:
  #
  #   * aarch64 -- the only way the NEON kernel is ever *executed*.  On x86 it is
  #     compiled out entirely, so a type-check says nothing about whether it
  #     computes the right keystream; the crate's own docs flag the NEON scalar
  #     transpose as unverifiable without aarch64 hardware.
  #   * i686 -- the only way the 32-bit code paths run.  `usize` is 32 bits
  #     there, so `check_lengths`, the length fields fed to the tag and every
  #     loop bound take a different route through the same source.
  #
  # qemu-user closes both gaps for everything except throughput.
  # `--aarch64-exec` is accepted as an alias of `--cross-exec`.
  pair_list="aarch64-unknown-linux-musl:qemu-aarch64 i686-unknown-linux-musl:qemu-i386"
  total=0
  for pair in $pair_list; do
    target="${pair%%:*}"
    emulator="${pair##*:}"
    if ! QEMU="$(find_qemu "$emulator")"; then
      echo "SKIPPED ($emulator): no $emulator found."
      echo "         Expected \$QEMU_${emulator^^}, \$HOME/.local/bin/$emulator, or"
      echo "         $emulator on \$PATH.  On Debian/Ubuntu this needs no root:"
      echo "           apt-get download qemu-user && dpkg-deb -x qemu-user_*.deb ~/.local"
      continue
    fi
    echo
    echo "--- $target ---"
    echo "using emulator: $QEMU"

    cargo test --target "$target" --release --no-run

    # Run the built test executables directly rather than through
    # `cargo test --target`, so the emulator is used explicitly and the runner
    # config cannot silently fall back to executing the target code natively.
    deps="target/$target/release/deps"
    ran=0
    for bin in "$deps"/xchacha20_blake3_siv-* "$deps"/differential_reference-* "$deps"/security-*; do
      case "$bin" in *.d|*.rlib|*.rmeta) continue ;; esac
      [ -x "$bin" ] || continue
      # The security binary runs too -- its property tests and deterministic fuzz
      # loop are exactly the kind of broad exercise that a new backend or a new
      # word size needs -- but the dudect-style timing screen is skipped there:
      # an emulated clock cannot resolve real timing differences, so it would be
      # measuring the emulator and could fail for reasons that have nothing to
      # do with this code.
      extra=()
      case "$(basename "$bin")" in security-*) extra=(--skip timing) ;; esac
      echo "--- $(basename "$bin") ---"
      "$QEMU" "$bin" --test-threads=1 ${extra[@]+"${extra[@]}"}
      ran=$((ran + 1))
    done
    [ "$ran" -gt 0 ] || { echo "no $target test binaries found in $deps" >&2; exit 1; }
    echo "executed $ran $target test binaries under qemu"
    total=$((total + ran))
  done
  [ "$total" -gt 0 ] || { echo "no cross-architecture emulator available" >&2; exit 1; }
fi

if [ "$RUN_MIRI" -eq 1 ]; then
  step "6b. Miri (UB detection on the unsafe paths)"
  # Miri cannot run `__cpuid_count` (inline asm), so `detect_avx2` returns false
  # under `cfg(miri)` and this exercises the SSE2, transpose and zeroization
  # paths. Slow: minutes, not seconds. Requires `rustup component add miri`.
  if cargo +nightly miri --version >/dev/null 2>&1; then
    MIRI_TESTS=(
      test_zeroize_covers_unaligned_prefix
      test_x86_simd_kernels_match_scalar
      test_simd_xor_matches_scalar_and_raw
      test_empty_inputs
    )
    # `-Zmiri-strict-provenance` is what actually exercises the raw-pointer
    # arithmetic in the zeroization helpers and the tag-buffer wipe; the Tree
    # Borrows pass is a second opinion, because the two aliasing models do not
    # accept the same programs.
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
      cargo +nightly miri test --release --lib -- "${MIRI_TESTS[@]}"
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-tree-borrows" \
      cargo +nightly miri test --release --lib -- "${MIRI_TESTS[@]}"
  else
    echo "SKIPPED: miri component not installed"
    echo "         (rustup component add miri --toolchain nightly)"
  fi
fi

if [ "$RUN_CTGRIND" -eq 1 ]; then
  step "7. ctgrind (constant-time, via valgrind memcheck)"
  # Marks secrets as undefined and lets memcheck report any branch or index that
  # depends on them. The script verifies its own negative control first, so a
  # clean result cannot come from poisoning that never took effect.
  if [ -x tools/ctgrind.sh ]; then
    tools/ctgrind.sh
  else
    echo "SKIPPED: tools/ctgrind.sh missing"
  fi
fi

if [ "$RUN_DENY" -eq 1 ]; then
  step "8. cargo-deny (advisories, licences, bans, sources)"
  if cargo deny --version >/dev/null 2>&1; then
    cargo deny check
  else
    echo "SKIPPED: cargo-deny not installed"
    echo "         (cargo install cargo-deny --locked)"
  fi
fi

if [ "$RUN_FUZZ" -eq 1 ]; then
  step "9. coverage-guided fuzzing (cargo-fuzz + libFuzzer + ASAN)"
  # Bounded by FUZZ_SECONDS so this stays usable in a pipeline; raise it for a
  # soak run. The target asserts round-trip correctness, rejection of every
  # single-bit corruption, and the wipe-on-failure contract, so any failure here
  # is a real defect rather than a smoke test.
  FUZZ_SECONDS="${FUZZ_SECONDS:-120}"
  if cargo fuzz --version >/dev/null 2>&1 && cargo +nightly --version >/dev/null 2>&1; then
    cargo +nightly fuzz run roundtrip -- -max_total_time="$FUZZ_SECONDS"
  else
    echo "SKIPPED: cargo-fuzz and/or nightly toolchain not available"
    echo "         (cargo install cargo-fuzz; rustup toolchain install nightly)"
  fi
fi

if [ "$RUN_KANI" -eq 1 ]; then
  step "6. Kani bounded model checking"
  # `-Z stubbing` is REQUIRED: several harnesses use #[kani::stub] to replace the
  # ChaCha20 permutation, the zeroization helper and the BLAKE3 commitment with
  # cheap stand-ins.  Without the flag Kani rejects the attribute and the suite
  # fails to compile.  See the `proofs` module for the cost model.
  #
  # `--extra-pointer-checks` adds CBMC's pointer-safety checks on top of the
  # harness assertions; it is unstable, hence `-Z unstable-options`.  CI uses the
  # same pair (the Kani version is pinned there so neither can drift).
  cargo kani -Z stubbing -Z unstable-options --extra-pointer-checks
fi

# Each hint is printed only for the step that was actually skipped.
if [ "$RUN_KANI" -eq 0 ] || [ "$RUN_CROSS_EXEC" -eq 0 ] || [ "$RUN_MIRI" -eq 0 ] \
   || [ "$RUN_CTGRIND" -eq 0 ] || [ "$RUN_DENY" -eq 0 ] || [ "$RUN_FUZZ" -eq 0 ]; then
  echo
  if [ "$RUN_KANI" -eq 0 ]; then
    echo "(Kani skipped; pass --kani to include it.)"
  fi
  if [ "$RUN_CROSS_EXEC" -eq 0 ]; then
    echo "(cross-architecture execution skipped; pass --cross-exec to include it.)"
  fi
  if [ "$RUN_MIRI" -eq 0 ]; then
    echo "(Miri skipped; pass --miri to include it.)"
  fi
  if [ "$RUN_CTGRIND" -eq 0 ]; then
    echo "(ctgrind skipped; pass --ctgrind to include it.)"
  fi
  if [ "$RUN_DENY" -eq 0 ]; then
    echo "(cargo-deny skipped; pass --deny to include it.)"
  fi
  if [ "$RUN_FUZZ" -eq 0 ]; then
    echo "(fuzzing skipped; pass --fuzz to include it.)"
  fi
  echo "(Pass --deep for Kani + aarch64 + Miri + ctgrind + deny + fuzz.)"
  echo "(Run ./verify.sh --all for everything.)"
fi

step "all requested checks passed"
