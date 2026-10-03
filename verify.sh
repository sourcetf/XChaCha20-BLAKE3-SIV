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
#   ./verify.sh              # stages 1-4: the reference self-checks, fmt/clippy, the
#                            # test suite, and the cross-target type-checks
#   ./verify.sh --kani       # ...plus Kani
#   ./verify.sh --kani-only  # just Kani (after a code change, to re-prove)
#
# Stage switches, all off by default: --cross-exec (aarch64, i686 and
# powerpc64 big-endian, under qemu), --miri, --ctgrind, --deny, --fuzz,
# --tsan, --tools (the tool-level gates: the fault campaign, the instruction
# sweeps, the cache-profile differential, the planted-bug checks, the Kani cfg
# check and the broad differential), --kani.
#
#   ./verify.sh --deep       # all of them
#   ./verify.sh --all        # the same thing; the name says what it means
#
# `--deep`/`--all` are the invocations that claim to leave nothing out, so they
# refuse to finish while any stage was skipped. Until this was fixed, `--all` set
# *fewer* switches than `--deep` (no ctgrind, cargo-deny, fuzzing or TSAN) while
# the README called it "everything", and neither ran the tool-level gates that CI
# runs on every push.

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
RUN_TSAN=0
RUN_TOOLS=0
STRICT=0
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
    --tsan) RUN_TSAN=1 ;;
    --tools) RUN_TOOLS=1 ;;
    # Same trick as `check.sh`: the usage text is this file's own header, so there is
    # only one copy to keep true. `--help` was not handled at all before, which made
    # `./verify.sh --help` an error rather than an answer.
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^#\{1,\}//; s/^ //'
      exit 0 ;;
    --deep|--all)
      # One set of switches with two names: `--all` used to set fewer of them than
      # `--deep` while being documented as "everything", which is the same class of
      # defect as a skip reported as a pass -- a word claiming more than the code does.
      RUN_KANI=1; RUN_CROSS_EXEC=1; RUN_MIRI=1; RUN_CTGRIND=1
      RUN_DENY=1; RUN_FUZZ=1; RUN_TSAN=1; RUN_TOOLS=1; STRICT=1 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

step() { echo; echo "=== $* ==="; }

# Skips are recorded, not just printed: a stage that did not run must not be reported
# as one that passed. `--deep` and `--all` claim to have run everything, so they
# refuse to finish while anything was skipped; a narrow invocation lists what it
# skipped and still exits 0, which is the point of a narrow invocation.
SKIPPED_STAGES=()
skip() {
  local stage="$1"; shift
  SKIPPED_STAGES+=("$stage")
  echo "SKIPPED ($stage): $*"
}

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
    skip "reference implementation self-checks" "python3 with the 'blake3' module is required (pip install blake3). The committed fixture is still replayed by cargo test below; what is skipped is its regeneration against the published vectors, which is the anchor the whole fixture rests on."
  fi

  step "2. formatting and lints"
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  # The `rng` feature adds a public module and a dependency; lint it too, or a
  # warning there would only surface once someone enabled the feature.
  cargo clippy --all-targets --features rng -- -D warnings

  # The tools' contract with this script: a gate that could not run answers exit 3,
  # and this script reports that as a skipped stage. Both halves are checked here
  # (seconds), because "a skip counted as a pass" is the failure this script has
  # twice reported as a green run.
  tools/gate_selftest.sh

  step "3. test suite"
  cargo test --release
  # `rng` gates the `random` module and its tests.
  cargo test --release --features rng

  # The security tests are in `tests/security.rs` and run with the rest above,
  # but they are called out because one of them is a fuzz loop -- if it starts
  # failing, this line says which area to look at.
  step "3b. security tests (property, fuzz)"
  cargo test --release --test security

  # The timing screen is its own target, gated `#![cfg(not(debug_assertions))]`,
  # so a release build is what runs it.
  step "3c. timing screen (release builds only)"
  cargo test --release --test timing

  # `--no-default-features` is how a `no_std` user consumes this crate.
  step "3d. no-default-features build"
  cargo check --no-default-features --all-targets

  step "4. cross-compilation"
  # Type-check against the gnu target (no linker needed), then build the musl
  # target, which is what step 5 executes.  `.cargo/config.toml` selects
  # rust-lld so no cross C toolchain is required.
  # `ultra` is in the feature list alongside `pure` so the witness is type-checked for
  # these targets too; stage 5 below *executes* it on three of them. (`pure` is what makes
  # BLAKE3's C kernels unnecessary here; see stage 5.)
  if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-gnu; then
    cargo check --target aarch64-unknown-linux-gnu --all-targets --features ultra,pure
  else
    skip "aarch64-unknown-linux-gnu type-check" "target not installed"
    echo "         (rustup target add aarch64-unknown-linux-gnu)"
  fi
  if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-musl; then
    cargo check --target aarch64-unknown-linux-musl --all-targets --features ultra,pure
  else
    skip "aarch64-unknown-linux-musl type-check" "target not installed"
    echo "         (rustup target add aarch64-unknown-linux-musl)"
  fi
  # riscv64 has no SIMD backend compiled at all, so this type-checks the
  # scalar-only configuration (see `.cargo/config.toml` for why it is not
  # linked/executed).
  if rustup target list --installed 2>/dev/null | grep -q riscv64gc-unknown-linux-musl; then
    cargo check --target riscv64gc-unknown-linux-musl --all-targets --features ultra,pure
  else
    skip "riscv64gc-unknown-linux-musl type-check" "target not installed"
    echo "         (rustup target add riscv64gc-unknown-linux-musl)"
  fi
fi

if [ "$RUN_CROSS_EXEC" -eq 1 ]; then
  step "5. cross-architecture execution under qemu (aarch64 NEON, i686 32-bit, powerpc64 big-endian)"
  # Two configurations that cannot be exercised natively here:
  #
  #   * aarch64 -- the only way the NEON kernel is ever *executed*.  On x86 it is
  #     compiled out entirely, so a type-check says nothing about whether it
  #     computes the right keystream; the crate's own docs flag the NEON scalar
  #     transpose as unverifiable without aarch64 hardware.
  #   * i686 -- the only way the 32-bit code paths run.  `usize` is 32 bits
  #     there, so `check_lengths`, the length fields fed to the tag and every
  #     loop bound take a different route through the same source.
  #   * powerpc64 -- the only way any of this runs on a **big-endian** machine,
  #     where the 35 `from_le_bytes`/`to_le_bytes` call sites in lib.rs have to do
  #     real work instead of being identity functions, and where a four-byte load
  #     is not the `u32` the code assumes.  Miri's s390x cross-interpretation
  #     covers the same question by interpretation; this executes compiled
  #     big-endian machine code.
  #
  # qemu-user closes both gaps for everything except throughput.
  # `--aarch64-exec` is accepted as an alias of `--cross-exec`.
  pair_list="aarch64-unknown-linux-musl:qemu-aarch64 i686-unknown-linux-musl:qemu-i386 powerpc64-unknown-linux-musl:qemu-ppc64"
  total=0
  for pair in $pair_list; do
    target="${pair%%:*}"
    emulator="${pair##*:}"
    if ! QEMU="$(find_qemu "$emulator")"; then
      skip "$target execution" "no $emulator found"
      echo "         Expected \$QEMU_${emulator^^}, \$HOME/.local/bin/$emulator, or"
      echo "         $emulator on \$PATH.  On Debian/Ubuntu this needs no root:"
      echo "           apt-get download qemu-user && dpkg-deb -x qemu-user_*.deb ~/.local"
      continue
    fi
    echo
    echo "--- $target ---"
    echo "using emulator: $QEMU"

    # `--features pure`: BLAKE3 needs a *target* C toolchain for its C kernels on
    # x86_64/aarch64, and this stage exists to execute *this crate's* SIMD code,
    # not BLAKE3's; the wire format is identical either way. `ultra` is added to the
    # build below, where the reason is written out.
    if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
      skip "$target execution" "the target is not installed (rustup target add $target)"
      echo "           rustup target add $target"
      continue
    fi

    # Big-endian needs no cross toolchain: powerpc64-unknown-linux-musl is tier-2,
    # so `rustup target add` brings prebuilt std, and rust-std ships the
    # self-contained crt objects *and* musl's libc, so rust-lld can link it.  Three
    # details are needed, all of them found by making this work:
    #
    #   * `libgcc_s.a` -- rustc asks for the unwinder under that name, and rust-std
    #     ships the very same library as `libunwind.a`, so this stage makes an
    #     alias instead of demanding a toolchain;
    #   * `-C relocation-model=static` -- the shipped `libc.a` is non-PIC, so a PIE
    #     link dies with "R_PPC64_ADDR64 ... recompile with -fPIC";
    #   * `-L native=` -- a search path for that alias.
    #
    # The flags are target-scoped so host crates (proc macros, build scripts) keep
    # the ordinary host linker.
    unset CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_LINKER CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_RUSTFLAGS
    case "$target" in
      powerpc64-unknown-linux-musl)
        sysroot="$(rustc --print sysroot)"
        host="$(rustc -vV | sed -n 's/^host: //p')"
        alias_dir="$HOME/.local/share/xsiv-cross"
        mkdir -p "$alias_dir"
        ln -sf "$sysroot/lib/rustlib/$target/lib/self-contained/libunwind.a" "$alias_dir/libgcc_s.a"
        export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_LINKER="$sysroot/lib/rustlib/$host/bin/rust-lld"
        export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C linker-flavor=ld.lld -C link-self-contained=yes -C relocation-model=static -L native=$alias_dir"
        ;;
    esac

    # Run the built test executables directly rather than through `cargo test --target`,
    # so the emulator is used explicitly and the runner config cannot silently fall back
    # to executing the target code natively.
    #
    # `--features pure` on the build: BLAKE3 needs a *target* C toolchain for its C kernels
    # on x86_64/aarch64, and this stage exists to execute *this crate's* SIMD code, not
    # BLAKE3's; the wire format is identical either way.
    #
    # Every binary this build produced, parsed from cargo's own report, rather than a
    # hand-listed few or a glob over `$deps`. The hand list left `counter_range` (whose
    # 32-bit assertions exist for this run), `locked` (whose syscall numbers are
    # per-architecture), `decision`, `decision_scope`, `ultra` and `variable_latency` built
    # but never executed; the glob additionally picks up artifacts from *earlier* feature
    # configurations, and running those executes stale code -- measured locally, three such
    # binaries failed with counts from an older revision of their tests, which reads as a
    # broken cross target. Two are excluded because the emulator cannot provide what they
    # need: `timing*` a real clock (and `security`'s timing screen with it), `ctgrind*`
    # valgrind on x86_64.
    # `--features ultra,pure`: `pure` because BLAKE3 needs a *target* C toolchain for its
    # C kernels on x86_64/aarch64, and this stage exists to execute *this crate's* SIMD
    # code, not BLAKE3's; the wire format is identical either way. `ultra` because it is
    # the configuration with the most code in it, and its second implementation is
    # hand-written **byte-order-sensitive** code -- `from_le_bytes`/`to_le_bytes` on every
    # word of a ChaCha20 block and a BLAKE3 state -- which is exactly what a big-endian
    # target is here to exercise, and whose 64-bit length and chunk-counter arithmetic is
    # what the 32-bit target exercises. Building it out on these targets meant the only
    # architecture-dependent code in the crate was the only code never run on another
    # architecture.
    # `CARGO_TERM_COLOR=never` because this output is *parsed* and the workflows set
    # `CARGO_TERM_COLOR=always`, which colours cargo's `Executable` lines even through a
    # pipe; `2>&1` because those lines go to **stderr** -- `ci.yml`'s equivalent step had
    # neither and reported "cargo reported no executables" on every cross target for two
    # commits, while this copy worked because the variable is unset locally and the redirect
    # was already here.
    exes="$(CARGO_TERM_COLOR=never cargo test --target "$target" --release --no-run \
            --features ultra,pure 2>&1 \
            | sed -n 's/^ *Executable .*(\(.*\))$/\1/p')"
    [ -n "$exes" ] || { echo "cargo reported no $target executables" >&2; exit 1; }
    ran=0
    for bin in $exes; do
      case "$(basename "$bin")" in timing-*|ctgrind-*) continue ;; esac
      extra=()
      case "$(basename "$bin")" in security-*) extra=(--skip timing) ;; esac
      echo "--- $(basename "$bin") ---"
      "$QEMU" "$bin" --test-threads=1 ${extra[@]+"${extra[@]}"}
      ran=$((ran + 1))
    done
    [ "$ran" -gt 0 ] || { echo "no $target test binaries were executed under qemu (the built set was empty, or every binary was excluded)" >&2; exit 1; }
    echo "executed $ran $target test binaries under qemu"
    total=$((total + ran))
  done
  [ "$total" -gt 0 ] || { echo "no cross-architecture emulator available" >&2; exit 1; }
fi

if [ "$RUN_MIRI" -eq 1 ]; then
  step "6b. Miri (UB detection on the unsafe paths, both accelerated targets)"
  # Miri cannot run `__cpuid_count` (inline asm), so `detect_avx2` falls back to
  # the *compiled* feature set: a default build takes the SSE2 and scalar paths,
  # and `-C target-feature=+avx2` makes Miri execute the AVX2 kernel too (it
  # refuses a `#[target_feature]` call whose feature is not enabled, which is why
  # this is a separate run rather than always on). The aarch64 run interprets the
  # NEON kernel. Slow: minutes, not seconds. Requires `rustup component add miri`.
  if cargo +nightly miri --version >/dev/null 2>&1; then
    MIRI_TESTS=(
      test_zeroize_covers_unaligned_prefix
      test_x86_simd_kernels_match_scalar
      test_simd_xor_matches_scalar_and_raw
      test_empty_inputs
      test_detached_matches_attached
    )
    # `-Zmiri-strict-provenance` is what actually exercises the raw-pointer
    # arithmetic in the zeroization helpers and the tag-buffer wipe; the Tree
    # Borrows pass is a second opinion, because the two aliasing models do not
    # accept the same programs.
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
      cargo +nightly miri test --release --features pure --lib -- "${MIRI_TESTS[@]}"
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-tree-borrows" \
      cargo +nightly miri test --release --features pure --lib -- "${MIRI_TESTS[@]}"

    echo
    echo "--- Miri, AVX2 kernel (x86_64) ---"
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
      RUSTFLAGS="-C target-feature=+avx2" \
      cargo +nightly miri test --release --features pure --lib -- \
        test_x86_simd_kernels_match_scalar \
        test_simd_xor_matches_scalar_and_raw \
        test_simd_matches_scalar_all_lengths

    echo
    echo "--- Miri, NEON kernel (aarch64, cross-interpreted) ---"
    cargo +nightly miri setup --target aarch64-unknown-linux-gnu >/dev/null
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
      cargo +nightly miri test --release --features pure --target aarch64-unknown-linux-gnu --lib -- \
        test_aarch64_neon_kernel_matches_scalar \
        test_simd_xor_matches_scalar_and_raw \
        test_zeroize_covers_unaligned_prefix
  else
    skip "Miri" "the miri component is not installed (rustup +nightly component add miri)"
    echo "         (rustup component add miri --toolchain nightly)"
  fi
fi

if [ "$RUN_CTGRIND" -eq 1 ]; then
  step "7. ctgrind (constant-time, via valgrind memcheck)"
  # Marks secrets as undefined and lets memcheck report any branch or index that
  # depends on them. Two controls come with it: a deliberate leak in the test
  # binary that valgrind must flag, and a secret-dependent branch planted inside
  # `decrypt`/`decrypt_in_place_detached` in a throwaway copy that must make the
  # check fail -- so neither a poisoning that never took effect nor a suppression
  # wider than the decision can turn into a clean result.
  if [ -x tools/ctgrind.sh ]; then
    # Exit 3 means the tool could not run at all (no valgrind). Until this was
    # handled, `tools/ctgrind.sh` answered "SKIPPED: valgrind not found" with exit 0
    # and this stage was counted as *run and passed* -- the same defect as the skip
    # handling above, one level down, and the reason every tool here now answers 3.
    set +e
    tools/ctgrind.sh
    ctgrind_rc=$?
    set -e
    if [ "$ctgrind_rc" -eq 3 ]; then
      skip "ctgrind" "tools/ctgrind.sh could not run (it needs valgrind; its output above says why)"
    elif [ "$ctgrind_rc" -ne 0 ]; then
      exit "$ctgrind_rc"
    fi
  else
    skip "ctgrind" "tools/ctgrind.sh missing"
  fi
fi

if [ "$RUN_DENY" -eq 1 ]; then
  step "8. cargo-deny (advisories, licences, bans, sources)"
  if cargo deny --version >/dev/null 2>&1; then
    cargo deny check
  else
    skip "cargo-deny" "not installed (cargo install cargo-deny)"
    echo "         (cargo install cargo-deny --locked)"
  fi
fi

if [ "$RUN_TSAN" -eq 1 ]; then
  step "7b. ThreadSanitizer over the concurrency test"
  # `tools/tsan.sh` runs its own negative control first: a deliberately racy test
  # must be *reported* before the crate's own run is allowed to mean anything.
  # It needs nightly and the rust-src component, because std is shipped
  # uninstrumented and mixing it with an instrumented crate is an ABI mismatch
  # ("`-Zsanitizer=thread` in this crate is incompatible with `-Zsanitizer` being
  # unset in dependency `panic_unwind`"), so the run rebuilds std with
  # `-Zbuild-std`.
  if cargo +nightly --version >/dev/null 2>&1 && rustup component list --installed 2>/dev/null | grep -q '^rust-src'; then
    tools/tsan.sh
  else
    skip "ThreadSanitizer" "needs the nightly toolchain and rust-src (rustup component add rust-src)"
    echo "           rustup component add rust-src"
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
    # The same target with `ultra`, which is the only configuration that runs the second
    # implementation over the key: new code on the caller-controlled path, so the
    # "no panic, no out-of-bounds, every corruption rejected" assertions apply to it too.
    # Half the budget, because every input does a second full decryption.
    #
    # `xchacha20-blake3-siv/ultra` is a *dependency* feature; if it were silently dropped
    # this would be a second run of the first configuration. Build first and require the
    # witness symbols to be in the binary, so a dropped flag is a failure rather than a
    # duplicate.
    # `grep -c`, not `nm | grep -q`: this script runs with `set -o pipefail`, and `grep
    # -q` exits at the first match, which kills the writer with SIGPIPE and makes the
    # *pipeline* fail even though the match was found. The first version of this guard
    # did exactly that and reported "the ultra feature did not apply" on a binary that
    # had sixteen witness symbols in it -- the same trap `tools/ctgrind.sh` documents.
    fuzz_target_dir="fuzz/target/$(rustc +nightly -vV | sed -n 's/^host: //p')/release"
    cargo +nightly fuzz build roundtrip --features xchacha20-blake3-siv/ultra
    witness_symbols="$(nm -C "$fuzz_target_dir/roundtrip" 2>/dev/null | grep -c 'witness::' || true)"
    if [ "${witness_symbols:-0}" -gt 0 ]; then
      echo "fuzz binary has $witness_symbols witness symbol(s): the ultra feature is on"
      cargo +nightly fuzz run roundtrip --features xchacha20-blake3-siv/ultra \
        -- -max_total_time="$((FUZZ_SECONDS / 2))"
    else
      echo "FAILED: no witness symbols in $fuzz_target_dir/roundtrip -- the ultra feature" >&2
      echo "        did not apply, so this run would test the default configuration twice" >&2
      exit 1
    fi
  else
    skip "fuzzing" "cargo-fuzz and/or the nightly toolchain not available"
    echo "         (cargo install cargo-fuzz; rustup toolchain install nightly)"
  fi
fi

if [ "$RUN_TOOLS" -eq 1 ]; then
  step "10. tool-level gates (what CI runs on every push)"
  # Each of these answers 3 for "could not run" and non-zero for "found something",
  # and the difference is the whole point of the convention `tools/gate_selftest.sh`
  # checks: a tool that could not run is a *skipped stage* here, never absorbed into a
  # green run. This stage is where that convention is actually exercised, which is why
  # it exists -- the tools were all wired into CI and none of them into this script.
  run_tool() {  # name, tool-path, args...
    local name="$1" tool="$2"; shift 2
    if [ ! -f "$tool" ]; then
      skip "$name" "$tool is missing"
      return 0
    fi
    local rc=0
    set +e
    case "$tool" in
      *.py) python3 "$tool" "$@" ;;
      *)    bash "$tool" "$@" ;;
    esac
    rc=$?
    set -e
    case "$rc" in
      0) : ;;
      # 3 is the documented "could not run"; 127 is the interpreter itself missing,
      # which is the same situation from this script's point of view.
      3|127) skip "$name" "$tool could not run here (its output above says why)" ;;
      *) echo "FAILED: $name (exit $rc)" >&2; exit "$rc" ;;
    esac
  }

  # The fault campaign: thirteen rows, each a source change (or its absence) with an
  # expected effect on a detector. `tools/mutation_check.sh` is the other direction --
  # it plants known bugs and requires the *checks* to fail, because a check that cannot
  # fail is not a check.
  run_tool "planted bugs (mutation check)" tools/mutation_check.sh
  run_tool "fault-injection campaign"      tools/fi_check.sh

  # The instruction-level sweeps, in `--quick` mode: every byte of the decision
  # function, both fault models, three configurations. The full sweep over the whole
  # entry points is the scheduled `wide` job's (and `tools/fi_instruction.sh`'s).
  run_tool "instruction sweep (nop)"  tools/fi_instruction.sh --quick
  run_tool "instruction sweep (bits)" tools/fi_instruction.sh --quick --bits

  # The cache/branch-profile differential, with its planted-leak control, in the two
  # configurations that matter (the default build and `ultra`, which puts a second
  # implementation on the key path).
  run_tool "cache profile"              tools/cache_profile.sh 24
  run_tool "cache profile self-test"    tools/cache_profile.sh --selftest
  XSIV_FEATURES=ultra run_tool "cache profile (ultra)"           tools/cache_profile.sh 24
  XSIV_FEATURES=ultra run_tool "cache profile self-test (ultra)" tools/cache_profile.sh --selftest

  # The mutation campaign over the decision, and the gate that says the committed
  # `mutants.out/` still describes *this* source (tests/README.md calls it evidence that
  # must match HEAD; until `tools/mutation_evidence.py` existed, nothing checked).
  #
  # `cargo mutants` writes `mutants.out/` in place and has no output-directory flag, so
  # the committed directory is kept aside first, the campaign runs, and on success the
  # committed copy is restored -- a verification step that leaves the tree dirty is a
  # step people stop running. On failure the fresh output stays, because that is the file
  # to commit.
  if cargo mutants --version >/dev/null 2>&1; then
    work_mut="$(mktemp -d)"
    if [ -d mutants.out ]; then
      cp -r mutants.out "$work_mut/committed"
      set +e
      cargo mutants --features ultra -f src/lib.rs \
        -F 'decrypt|accept_or_reject' -E 'replace & with \|' \
        -- --test decision --test security > "$work_mut/campaign.log" 2>&1
      mut_rc=$?
      set -e
      tail -2 "$work_mut/campaign.log"
      if [ "$mut_rc" -ne 0 ]; then
        echo "FAILED: the mutation campaign reported an uncaught mutant (exit $mut_rc)" >&2
        grep -E "MISSED" "$work_mut/campaign.log" | head -5 >&2
        rm -rf "$work_mut"
        exit "$mut_rc"
      fi
      # `mutation_evidence.py` distinguishes three outcomes and so must this gate:
      #   0 = the committed evidence describes this run; restore it over the fresh run.
      #   3 = "could not compare" (missing or unparseable directory). That is a skipped
      #       stage, exactly like every other tool's exit 3 -- recorded so `--deep`/`--all`
      #       refuses to call the run complete rather than printing "all requested checks
      #       passed" over a check that never happened.
      #   1 = the committed evidence is stale. That is the finding this gate exists to
      #       report, so it fails the run; a gate that cannot fail is the bug.
      # `|| ev_rc=$?` rather than a bare call: under `set -e` a non-zero exit (1 *or* 3)
      # would abort the script here before the branches below could run.
      ev_rc=0
      python3 tools/mutation_evidence.py "$work_mut/committed" mutants.out || ev_rc=$?
      if [ "$ev_rc" -eq 0 ]; then
        rm -rf mutants.out && cp -r "$work_mut/committed" mutants.out
      elif [ "$ev_rc" -eq 3 ]; then
        skip "mutation evidence" "could not compare the committed evidence with this run (exit 3); mutants.out/ is left as the fresh run rather than pretending it matched"
      else
        echo "FAILED: the committed mutants.out/ does not describe this source (exit $ev_rc)" >&2
        echo "        mutants.out/ now holds the fresh run: commit it, or discard it with" >&2
        echo "        'git checkout -- mutants.out' if this run was not a source change" >&2
        rm -rf "$work_mut"
        exit "$ev_rc"
      fi
    else
      skip "mutation evidence" "mutants.out/ is missing"
    fi
    rm -rf "$work_mut"
  else
    skip "mutation campaign" "cargo-mutants is not installed (cargo install cargo-mutants)"
  fi

  # The Kani harnesses must still fit the crate's internals, and the random differential
  # pushes vectors this crate never committed through the Python reference.
  run_tool "Kani cfg check"     tools/check_kani_cfg.sh
  run_tool "broad differential" tools/broad_differential.py "${BROAD_VECTORS:-4000}"

  # Advisory, and said out loud rather than silently: what this measures is residue in
  # frames the *compiler* chose, so a change in layout reports instead of blocking --
  # CI's `stack-residue` job is `continue-on-error` for the same reason.
  if [ -f tools/stack_residue.sh ]; then
    local_rc=0
    set +e
    bash tools/stack_residue.sh
    local_rc=$?
    set -e
    if [ "$local_rc" -ne 0 ] && [ "$local_rc" -ne 3 ]; then
      echo "ADVISORY: tools/stack_residue.sh reported a change (exit $local_rc) -- see" >&2
      echo "          above. This measures compiler-chosen stack layout, so it does not" >&2
      echo "          fail the run (CI's stack-residue job is continue-on-error)." >&2
    fi
  else
    skip "stack residue" "tools/stack_residue.sh is missing"
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
  # `-j` (the thread pool's default width) is not cosmetic: without it Kani
  # verifies one harness at a time, so the suite spends its life on a single
  # core. With it, the independent harnesses run concurrently.
  cargo kani -j --output-format=terse --features pure -Z stubbing -Z unstable-options \
    --extra-pointer-checks
fi

# Each hint is printed only for the step that was actually skipped.
if [ "$RUN_KANI" -eq 0 ] || [ "$RUN_CROSS_EXEC" -eq 0 ] || [ "$RUN_MIRI" -eq 0 ] \
   || [ "$RUN_CTGRIND" -eq 0 ] || [ "$RUN_DENY" -eq 0 ] || [ "$RUN_FUZZ" -eq 0 ] \
   || [ "$RUN_TOOLS" -eq 0 ]; then
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
  if [ "$RUN_TOOLS" -eq 0 ]; then
    echo "(the tool-level gates skipped; pass --tools to include them.)"
  fi
  echo "(Pass --deep --tools for Kani + qemu execution + Miri + ctgrind + deny + fuzz +"
  echo " ThreadSanitizer + the tool-level gates; --deep and --all are the same set.)"
fi

if [ "${#SKIPPED_STAGES[@]}" -eq 0 ]; then
  step "all requested checks passed"
elif [ "$STRICT" -eq 1 ]; then
  step "FAILED: ${#SKIPPED_STAGES[@]} stage(s) skipped in a run that claims to be complete"
  for stage in "${SKIPPED_STAGES[@]}"; do echo "  skipped: $stage"; done
  echo
  echo "This invocation (--deep or --all) is the one that is supposed to leave nothing"
  echo "out, so a skipped stage is a failure here rather than a note. Install what is"
  echo "missing, or use the narrower invocation that does not claim to run it."
  exit 1
else
  step "all requested checks passed, apart from ${#SKIPPED_STAGES[@]} skipped stage(s)"
  for stage in "${SKIPPED_STAGES[@]}"; do echo "  skipped: $stage"; done
fi
