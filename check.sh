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
#   ./check.sh --fast          skip all cross-target work (no cross targets are
#                              installed; a --cross-exec request is dropped with a note)
#   ./check.sh --cross-exec    also execute the aarch64/i686 suites under qemu,
#                              plus big-endian powerpc64 via qemu-ppc64
#   ./check.sh --kani          also run Kani bounded model checking (slow)
#   ./check.sh --tools         also run the tool-level gates (fault campaign,
#                              instruction sweeps, cache-profile differential,
#                              planted-bug checks) -- the tools CI's per-push job runs
#   ./check.sh --all           every verification stage `verify.sh --all` has, which is
#                              more than cross-exec plus Kani: ctgrind, cargo-deny,
#                              fuzzing, TSAN and the tool-level gates too
#   ./check.sh --no-provision  skip provisioning (rustup targets, emulator); the
#                              builds below may still fetch crates that are not cached
#   ./check.sh --help
#
# Nothing here needs root: package downloads use `apt-get download` (which
# works unprivileged) and the emulator is extracted into ~/.local/bin.

set -euo pipefail

# Resolve this script's own path before changing directory: `--help` prints the header
# back out of this file, and a relative `$0` naming a directory stops resolving after
# the `cd` (same defect and fix as `verify.sh`).
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$SELF")"

# rustup's toolchain lives here, and the emulator in ~/.local/bin.  Without the
# former, a stale system rustc is picked up that has no cross targets and
# cannot see Kani.
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

# ── Options ───────────────────────────────────────────────────────────

VERIFY_ARGS=()
PROVISION=1
FAST=0

# The usage text is the file's own header comment rather than a second copy of it.
# It *was* a second copy, and the two had drifted: `--help` still described `--all` as
# "both of the above" (cross-exec plus Kani) after `--all` had grown into the full
# verify.sh set, and the new `--tools` line was in the header alone. Printing the header
# makes that impossible; the `#` is stripped and the block runs to the first blank line.
usage() {
  sed -n '2,/^$/p' "$SELF" | sed 's/^#\{1,\}//; s/^ //'
  echo
  echo "Stages:"
  echo "  1. provision   rustup targets, an aarch64 emulator, and a Kani check"
  echo "  2. build       host release (default + rng) and aarch64-unknown-linux-musl"
  echo "  3. verify      delegated to ./verify.sh (see that file for the stage list)"
  echo
  echo "Exit status is non-zero if any requested stage fails."
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --all)          VERIFY_ARGS+=(--all) ;;
    --tools)        VERIFY_ARGS+=(--tools) ;;
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

# `qemu-user` ships every emulator this project uses (qemu-aarch64, qemu-i386,
# qemu-ppc64, qemu-riscv64), so one download covers the whole cross-execution
# stage; only the lookup is per-architecture.  Mirrors verify.sh's find_qemu.
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
# that target's execution stage is skipped, not that the build fails.
#
# All four are checked, not just aarch64: this used to return as soon as
# `qemu-aarch64` was found, so a host that had only that one never fetched the
# rest -- and because `verify.sh --cross-exec` now needs `qemu-riscv64` as well,
# `./check.sh --all` (the documented one-command provisioning path) failed on
# exactly the fresh hosts it exists for.
QEMU_EMULATORS=(qemu-aarch64 qemu-i386 qemu-ppc64 qemu-riscv64)
provision_qemu() {
  local missing=() em
  for em in "${QEMU_EMULATORS[@]}"; do
    find_qemu "$em" >/dev/null || missing+=("$em")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    ok "emulators present: ${QEMU_EMULATORS[*]}"
    return 0
  fi
  if ! command -v apt-get >/dev/null || ! command -v dpkg-deb >/dev/null; then
    skip "no apt-get/dpkg-deb; cannot fetch: ${missing[*]}"
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
       for em in "${QEMU_EMULATORS[@]}"; do
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
  elif [ "$FAST" -eq 1 ]; then
    # `--fast` is documented as "skip all cross-target work": installing five
    # targets only for the cross stages (and the cross build below) to be skipped
    # would contradict the flag and touch the network for nothing.
    skip "rust cross targets (--fast)"
    record "provision: cross targets skipped (--fast)"
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
    if ensure_target riscv64gc-unknown-linux-musl; then
      ok "target riscv64gc-unknown-linux-musl"
    else
      skip "target riscv64gc-unknown-linux-musl unavailable"
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

  # Kani is optional: without it the proof stage is skipped. A run that *asked* for
  # it (--kani, or --all's complete set) fails rather than pretending it ran, so this
  # check is a note about the default invocation, not a guarantee for every one.
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

# `--fast` means "no cross-target work", so any cross-execution request has to be
# dropped before delegating -- and nothing else may be.  `--all` is a single token to
# `verify.sh` that sets a dozen switches, so under `--fast` it is expanded into the ones
# that need no cross target (Kani runs natively; so do miri -- x86_64 and an
# interpreted aarch64 target, no qemu -- and ctgrind, cargo-deny, fuzzing, TSAN and the
# tool-level gates) rather than being replaced by `--kani`, which would have silently
# dropped the rest.  miri used to be omitted here, so `--fast --all` quietly ran a
# smaller set than `verify.sh --all` minus cross-exec.  Note what dropping `--all`'s
# strict bookkeeping does **not** change: the names in the expansion are passed to
# `verify.sh` as explicit requests, and a stage that was named and could not run is a
# failure (exit 1), not a skip -- so `--fast --all` on a host without miri, valgrind or
# Kani ends in a FAILED line that says which stage was missing, rather than in a
# quieter success.  A comment here claimed the opposite (that an unavailable miri is a
# skip under `--fast`); it never was, and an audit caught the difference.
if [ "$FAST" -eq 1 ]; then
  FILTERED=()
  saw_all=0
  dropped_cross=0
  for a in ${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}; do
    case "$a" in
      --all)          saw_all=1 ;;
      --cross-exec|--aarch64-exec) dropped_cross=1 ;; # dropped: contradicts --fast
      *)              FILTERED+=("$a") ;;
    esac
  done
  if [ "$saw_all" -eq 1 ]; then
    FILTERED+=(--kani --miri --ctgrind --deny --fuzz --tsan --tools)
  fi
  VERIFY_ARGS=(${FILTERED[@]+"${FILTERED[@]}"})
  # Say it rather than dropping it silently: a request that quietly stops being a
  # request is the same family as a skip reported as a pass.
  if [ "$dropped_cross" -eq 1 ]; then
    skip "--cross-exec dropped: --fast asks for no cross-target work"
  fi
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

# The host rlib this run was supposed to produce. Derived from `CARGO_TARGET_DIR`, because
# the builds above honour it: the hard-coded `target/...` pointed at a directory the build
# may not have written to, where an *older* rlib from a previous run would satisfy the
# assertion.
#
# Freshness is measured against the inputs, not against the start of this run: cargo does
# not touch an output whose unit is already fresh, so a second `check.sh` on unchanged
# sources would fail a "newer than this run started" test even though the rlib is current
# (the build above simply had nothing to do). "No input is newer than the rlib" is the
# property that matters, and a foreign file planted at this path fails it.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
HOST_ARTIFACT="$TARGET_DIR/release/libxchacha20_blake3_siv.rlib"
stale_input=""
if [ -f "$HOST_ARTIFACT" ]; then
  stale_input="$(find src Cargo.toml Cargo.lock -type f -newer "$HOST_ARTIFACT" -print -quit 2>/dev/null || true)"
fi
# ...and it has to *be* an rlib: an existence check alone accepted any file, including the
# 46-byte text file an audit planted at this path.
if [ -f "$HOST_ARTIFACT" ] && [ -z "$stale_input" ] \
   && [ "$(head -c 8 "$HOST_ARTIFACT" 2>/dev/null)" = '!<arch>' ]; then
  printf 'artifact: %s\n' "$HOST_ARTIFACT"
else
  fail "expected host artifact missing, stale, or not an rlib: $HOST_ARTIFACT (target dir: $TARGET_DIR)"
  exit 1
fi

# Not an unconditional "all requested checks passed": a narrow run's verify.sh may exit 0
# after recording skipped stages ("all requested checks passed, apart from N skipped").
# Repeating the skips here would mean capturing verify.sh's output and losing its live
# progress; pointing at that summary is honest and keeps the stream.
printf '\n%sbuild and verification finished%s -- see verify.sh above for any skipped stage(s)\n' "$C_GREEN" "$C_OFF"
