#!/usr/bin/env bash
#
# One-command build + verification for XChaCha20-BLAKE3-SIV.
#
# Reach for this when you want the whole pipeline to just work: it provisions
# the optional dependencies (cross targets, an aarch64 emulator), builds every
# target, then hands off to `verify.sh` for the verification stages.
#
# The stage logic deliberately lives in `verify.sh` alone so the two scripts
# cannot drift apart.  This one adds: dependency provisioning, an explicit
# build step, timing, and a final summary.  For the narrow "re-prove after a
# small edit" case, `./verify.sh --kani-only` is cheaper and is still the right
# tool.
#
# Usage:
#   ./check.sh                 provision, build, verify (fast stages only)
#   ./check.sh --fast          skip all cross-target work
#   ./check.sh --cross-exec    also execute the aarch64/i686 suites under qemu,
                             plus big-endian powerpc64 via qemu-ppc64
#   ./check.sh --kani          also run Kani bounded model checking (slow)
#   ./check.sh --all           both of the above
#   ./check.sh --no-provision  never touch the network or modify the toolchain
#   ./check.sh --help
#
# Nothing here needs root: package downloads use `apt-get download` (which
# works unprivileged) and the emulator is extracted into ~/.local/bin.

set -euo pipefail

cd "$(dirname "$0")"

# rustup's toolchain lives here, and the emulator in ~/.local/bin.  Without the
# former, a stale system rustc is picked up that has no cross targets and
# cannot see Kani.
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

# ── Options ───────────────────────────────────────────────────────────

VERIFY_ARGS=()
PROVISION=1
FAST=0

usage() {
  cat <<'EOF'
One-command build + verification for XChaCha20-BLAKE3-SIV.

Usage:
  ./check.sh                 provision, build, verify (fast stages only)
  ./check.sh --fast          skip all cross-target work
  ./check.sh --cross-exec    also execute the aarch64/i686 suites under qemu,
                             plus big-endian powerpc64 via qemu-ppc64
  ./check.sh --kani          also run Kani bounded model checking (slow)
  ./check.sh --all           both of the above
  ./check.sh --no-provision  never touch the network or modify the toolchain
  ./check.sh --help

Stages:
  1. provision   rustup targets, an aarch64 emulator, and a Kani check
  2. build       host release (default + rng) and aarch64-unknown-linux-musl
  3. verify      delegated to ./verify.sh (see that file for the stage list)

Exit status is non-zero if any requested stage fails.
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --all)          VERIFY_ARGS+=(--all) ;;
    --kani)         VERIFY_ARGS+=(--kani) ;;
    --cross-exec|--aarch64-exec) VERIFY_ARGS+=(--cross-exec) ;;
    --fast)         FAST=1 ;;
    --no-provision) PROVISION=0 ;;
    -h|--help)      usage ;;
    *) printf 'unknown option: %s\n(run --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

# ── Output helpers ────────────────────────────────────────────────────

# Only colourise an interactive terminal, so a redirected log stays readable.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_OFF=$'\033[0m'
else
  C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_OFF=''
fi

STAGE_NO=0
T0_ALL=$SECONDS
SUMMARY=()

note() { printf '%s\n' "$*"; }
ok()   { printf '%s  ok%s  %s\n'  "$C_GREEN"  "$C_OFF" "$*"; }
skip() { printf '%s  --%s  %s\n'  "$C_YELLOW" "$C_OFF" "$*"; }
fail() { printf '%sFAIL%s  %s\n'  "$C_RED"    "$C_OFF" "$*" >&2; }

on_error() {
  local code=$1 line=$2
  printf '\n%sFAILED%s (exit %s) at %s line %s\n' \
    "$C_RED" "$C_OFF" "$code" "$(basename "$0")" "$line" >&2
  printf 'elapsed: %ss\n' "$((SECONDS - T0_ALL))" >&2
  exit "$code"
}
trap 'on_error $? $LINENO' ERR

stage() {
  STAGE_NO=$((STAGE_NO + 1))
  printf '\n%s[%d] %s%s\n' "$C_BOLD" "$STAGE_NO" "$*" "$C_OFF"
}

record() { SUMMARY+=("$*"); }

# ── Provisioning helpers ──────────────────────────────────────────────

# Add a rustup target if missing.  Non-fatal: a missing cross target only
# means that target's stage is skipped.
ensure_target() {
  local target="$1"
  if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    return 0
  fi
  note "installing rust target: $target"
  rustup target add "$target" >/dev/null 2>&1
}

# `qemu-user` ships every emulator this project uses (qemu-aarch64, qemu-i386),
# so one download covers the whole cross-execution stage; only the lookup is
# per-architecture.  Mirrors verify.sh's find_qemu.
find_qemu() {
  local name="$1" arch var c
  arch="$(printf '%s' "${name#qemu-}" | tr '[:lower:]-' '[:upper:]_')"
  var="QEMU_${arch}"
  for c in "${!var:-}" "$HOME/.local/bin/$name" \
           "$(command -v "$name" 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

# Install the emulators into ~/.local/bin without root.
#
# `qemu-user-static` is only a small metapackage pointing at `qemu-user`, which
# is where the actual (statically linked) binaries live -- so `qemu-user` is
# the package to fetch.  Every step is best-effort: no emulator simply means
# the aarch64 execution stage is skipped, not that the build fails.
provision_qemu() {
  if find_qemu qemu-aarch64 >/dev/null; then
    ok "aarch64 emulator present: $(find_qemu qemu-aarch64)"
    return 0
  fi
  if ! command -v apt-get >/dev/null || ! command -v dpkg-deb >/dev/null; then
    skip "no apt-get/dpkg-deb; cannot fetch an aarch64 emulator"
    return 1
  fi

  note "fetching qemu-user (no root required)"
  local tmp dest em
  tmp="$(mktemp -d)" || { skip "mktemp failed"; return 1; }
  dest="$HOME/.local/bin/qemu-aarch64"

  # All the fallible work happens in one subshell with one exit path, so the
  # temp directory is removed whether it succeeded or failed.  (A `trap ... RETURN`
  # would be shorter but relies on bash's trap-inheritance rules, and its
  # failure mode -- a leaked temp dir, or worse a trap firing in an unrelated
  # caller -- is exactly the kind of thing that is invisible until it matters.)
  if (
       set -e
       cd "$tmp"
       apt-get download qemu-user >/dev/null 2>&1
       deb="$(find . -maxdepth 1 -name 'qemu-user_*.deb' | head -1)"
       [ -n "$deb" ]
       dpkg-deb -x "$deb" ./x
       mkdir -p "$(dirname "$dest")"
       for em in qemu-aarch64 qemu-i386 qemu-ppc64; do
         cp "./x/usr/bin/$em" "$HOME/.local/bin/$em"
         chmod +x "$HOME/.local/bin/$em"
       done
     ); then
    chmod +x "$dest"
    rm -rf "$tmp"
    ok "installed $dest"
    return 0
  fi

  rm -rf "$tmp"
  skip "could not fetch or install an aarch64 emulator"
  skip "  (offline, or no qemu-user package available for this distro)"
  skip "  aarch64 execution will be skipped; see the README for setup"
  return 1
}

# ── Preflight ─────────────────────────────────────────────────────────

stage "preflight"
if ! command -v cargo >/dev/null; then
  fail "cargo not found on PATH"
  exit 1
fi
ok "rustc $(rustc --version 2>/dev/null | awk '{print $2}')"
record "preflight: rustc $(rustc --version 2>/dev/null | awk '{print $2}')"

if [ -f Cargo.lock ]; then
  ok "Cargo.lock present (reproducible dependency set)"
else
  skip "no Cargo.lock; dependency versions are not pinned"
fi

# ── Stage: provision ──────────────────────────────────────────────────

if [ "$PROVISION" -eq 1 ]; then
  stage "provisioning optional dependencies"

  if ! command -v rustup >/dev/null; then
    skip "rustup not found; cross targets cannot be installed"
    record "provision: no rustup (cross targets unavailable)"
  else
    # musl is what gets built and *executed* under qemu (aarch64 for the NEON
    # kernel, i686 for the 32-bit paths); gnu is type-checked only.  All are
    # attempted so `verify.sh` can use whichever is available.
    for t in aarch64-unknown-linux-musl i686-unknown-linux-musl powerpc64-unknown-linux-musl aarch64-unknown-linux-gnu; do
      if ensure_target "$t"; then
        ok "target $t"
      else
        skip "target $t unavailable"
      fi
    done
    if [ "$FAST" -eq 0 ]; then
      if ensure_target riscv64gc-unknown-linux-musl; then
        ok "target riscv64gc-unknown-linux-musl"
      else
        skip "target riscv64gc-unknown-linux-musl unavailable"
      fi
    fi
    record "provision: rust cross targets"
  fi

  if [ "$FAST" -eq 0 ]; then
    if provision_qemu; then
      record "provision: aarch64 emulator"
    else
      record "provision: no aarch64 emulator"
    fi
  else
    skip "aarch64 emulator (--fast)"
  fi

  # Kani is optional: without it only the proof stage is skipped.
  if command -v cargo-kani >/dev/null; then
    ok "cargo-kani $(cargo kani --version 2>/dev/null | head -1 || true)"
    record "provision: Kani available"
  else
    skip "cargo-kani not installed; the Kani stage will be skipped"
    record "provision: no Kani"
  fi
else
  stage "provisioning (skipped: --no-provision)"
  record "provision: skipped by request"
fi

# ── Stage: build ──────────────────────────────────────────────────────

stage "building"

# Deliberately *not* passing `--offline`: on a fresh checkout the registry cache
# is empty and an offline build fails outright.  Cargo's own opt-in mechanism
# (`CARGO_NET_OFFLINE`, or `--offline` in `.cargo/config.toml`) is the right
# place to force offline behaviour, and it is honoured without any flag here.
cargo build --release
cargo build --release --features rng
ok "host release (default + rng)"
record "build: host release x2"

if [ "$FAST" -eq 0 ]; then
  if rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-musl; then
    # The musl target links with the toolchain's own rust-lld against a
    # self-contained libc.a, so no cross C toolchain is needed.
    # `--features pure`: BLAKE3's C kernels would need a cross C toolchain.
    cargo build --target aarch64-unknown-linux-musl --release --features pure
    ok "aarch64-unknown-linux-musl release"
    record "build: aarch64-unknown-linux-musl"
  else
    skip "aarch64-unknown-linux-musl not installed"
    record "build: no aarch64 target"
  fi
else
  skip "cross build (--fast)"
fi

# ── Stage: verify ─────────────────────────────────────────────────────

stage "verifying (delegated to ./verify.sh)"

if [ ! -x ./verify.sh ]; then
  fail "./verify.sh is missing or not executable"
  exit 1
fi

# `--fast` means "no cross-target work", so any cross-execution request has to
# be dropped before delegating.  `--all` implies aarch64 execution, so under
# --fast it degrades to its Kani half rather than being dropped entirely.
if [ "$FAST" -eq 1 ]; then
  FILTERED=()
  saw_all=0
  for a in ${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}; do
    case "$a" in
      --all)          saw_all=1 ;;
      --cross-exec|--aarch64-exec) ;; # dropped: contradicts --fast
      *)              FILTERED+=("$a") ;;
    esac
  done
  if [ "$saw_all" -eq 1 ]; then
    FILTERED+=(--kani)
  fi
  VERIFY_ARGS=(${FILTERED[@]+"${FILTERED[@]}"})
fi

# Explicit if/else rather than `cmd && ok || fail`: the `||` form would run the
# command a second time on failure, and a second run that succeeds would report
# success for a suite that had already failed.  A verifier must not be able to
# pass by accident.
if [ "${#VERIFY_ARGS[@]}" -gt 0 ]; then
  if ./verify.sh "${VERIFY_ARGS[@]}"; then
    record "verify: passed"
  else
    fail "./verify.sh reported a failure"
    exit 1
  fi
else
  if ./verify.sh; then
    record "verify: passed"
  else
    fail "./verify.sh reported a failure"
    exit 1
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────

printf '\n%s==== summary ====%s\n' "$C_BOLD" "$C_OFF"
printf 'total elapsed: %ss\n' "$((SECONDS - T0_ALL))"
if [ "${#SUMMARY[@]}" -gt 0 ]; then
  for line in "${SUMMARY[@]}"; do printf '  - %s\n' "$line"; done
fi

HOST_ARTIFACT=target/release/libxchacha20_blake3_siv.rlib
if [ -f "$HOST_ARTIFACT" ]; then
  printf 'artifact: %s\n' "$HOST_ARTIFACT"
else
  fail "expected host artifact missing: $HOST_ARTIFACT"
  exit 1
fi

printf '\n%sall requested checks passed%s\n' "$C_GREEN" "$C_OFF"
