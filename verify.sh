#!/usr/bin/env bash
#
# Full verification pipeline for XChaCha20-Poly1305-SIV.
#
# Runs, in order of increasing cost:
#   1. reference-implementation self-checks (python) and fixture freshness
#   2. cargo fmt / clippy
#   3. the unit + differential test suite
#   4. cross-compilation for aarch64 (the NEON path)
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
RUN_AARCH64_EXEC=0
for arg in "$@"; do
  case "$arg" in
    --kani) RUN_KANI=1 ;;
    --kani-only) RUN_KANI=1; KANI_ONLY=1 ;;
    --aarch64-exec) RUN_AARCH64_EXEC=1 ;;
    --all) RUN_KANI=1; RUN_AARCH64_EXEC=1 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

step() { echo; echo "=== $* ==="; }

# Locate an aarch64 emulator for step 5.  Honour $QEMU_AARCH64 first, then the
# usual user-local install, then whatever is on $PATH.
find_qemu_aarch64() {
  if [ -n "${QEMU_AARCH64:-}" ] && [ -x "${QEMU_AARCH64}" ]; then
    echo "${QEMU_AARCH64}"; return 0
  fi
  for c in "$HOME/.local/bin/qemu-aarch64" "$(command -v qemu-aarch64 2>/dev/null || true)"; do
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

if [ "$RUN_AARCH64_EXEC" -eq 1 ]; then
  step "5. aarch64 execution under qemu (the NEON path)"
  # This is the only way the aarch64 SIMD kernel is ever *executed*.  On x86 the
  # NEON backend is compiled out entirely, so a type-check alone says nothing
  # about whether it computes the right keystream -- and the crate's own docs
  # flag the NEON scalar transpose as unverifiable without aarch64 hardware.
  # qemu-user closes that gap for everything except throughput.
  if ! QEMU="$(find_qemu_aarch64)"; then
    echo "SKIPPED: no aarch64 emulator found."
    echo "         Expected \$QEMU_AARCH64, \$HOME/.local/bin/qemu-aarch64, or"
    echo "         qemu-aarch64 on \$PATH.  On Debian/Ubuntu this needs no root:"
    echo "           apt-get download qemu-user && dpkg-deb -x qemu-user_*.deb ~/.local"
    exit 1
  fi
  echo "using emulator: $QEMU"

  cargo test --target aarch64-unknown-linux-musl --release --no-run

  # Run the built test executables directly rather than through
  # `cargo test --target`, so the emulator is used explicitly and the runner
  # config cannot silently fall back to executing aarch64 code natively.
  deps="target/aarch64-unknown-linux-musl/release/deps"
  ran=0
  for bin in "$deps"/xchacha20_poly1305_siv-* "$deps"/differential_reference-*; do
    case "$bin" in *.d|*.rlib|*.rmeta) continue ;; esac
    [ -x "$bin" ] || continue
    echo "--- $(basename "$bin") ---"
    "$QEMU" "$bin" --test-threads=1
    ran=$((ran + 1))
  done
  [ "$ran" -gt 0 ] || { echo "no aarch64 test binaries found in $deps" >&2; exit 1; }
  echo
  echo "Executed $ran aarch64 test binaries under qemu."
fi

if [ "$RUN_KANI" -eq 1 ]; then
  step "6. Kani bounded model checking"
  # `-Z stubbing` is REQUIRED: several harnesses use #[kani::stub] to replace the
  # ChaCha20 permutation, the zeroization helper and the BLAKE3 commitment with
  # cheap stand-ins.  Without the flag Kani rejects the attribute and the suite
  # fails to compile.  See the `proofs` module for the cost model.
  cargo kani -Z stubbing
fi

# Each hint is printed only for the step that was actually skipped.
if [ "$RUN_KANI" -eq 0 ] || [ "$RUN_AARCH64_EXEC" -eq 0 ]; then
  echo
  if [ "$RUN_KANI" -eq 0 ]; then
    echo "(Kani skipped; pass --kani to include it.)"
  fi
  if [ "$RUN_AARCH64_EXEC" -eq 0 ]; then
    echo "(aarch64 execution skipped; pass --aarch64-exec to include it.)"
  fi
  echo "(Run ./verify.sh --all for everything.)"
fi

step "all requested checks passed"
