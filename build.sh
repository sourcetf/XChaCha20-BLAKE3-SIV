#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Same PATH fix-up as verify.sh/check.sh/tools/*: rustup's shims live under
# ~/.cargo/bin, which a non-login shell on this host does not have.
export PATH="$HOME/.cargo/bin:$PATH"

# 拒绝多余的位置参数，而不是悄悄忽略：`./build.sh release junk` 过去会照常 release
# 构建并以 0 退出，敲错的命令看起来像完成了要求的事。
if [ "$#" -gt 1 ]; then
  echo "用法: $0 [release|debug]" >&2
  echo "多余参数: ${*:2}" >&2
  exit 2
fi

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
