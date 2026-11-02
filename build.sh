#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Same PATH fix-up as verify.sh/check.sh/tools/*: rustup's shims live under
# ~/.cargo/bin, which a non-login shell on this host does not have.
export PATH="$HOME/.cargo/bin:$PATH"

echo "=== XChaCha20-BLAKE3-SIV 构建脚本 ==="

# 默认 release 构建
# 如需 debug 构建：./build.sh debug
MODE="${1:-release}"

echo "构建模式: ${MODE}"
echo

case "${MODE}" in
  release)
    cargo build --locked --release
    ;;
  debug)
    cargo build --locked
    ;;
  *)
    echo "未知模式: ${MODE} (可选: release | debug)" >&2
    exit 1
    ;;
esac

echo
echo "构建完成。"
