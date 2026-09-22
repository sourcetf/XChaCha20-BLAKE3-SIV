#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== XChaCha20-Poly1305-SIV 构建脚本 ==="

# 默认 release 构建
# 如需 debug 构建：./build.sh debug
MODE="${1:-release}"

echo "构建模式: ${MODE}"
echo

case "${MODE}" in
  release|debug)
    cargo build --"${MODE}"
    ;;
  *)
    echo "未知模式: ${MODE} (可选: release | debug)" >&2
    exit 1
    ;;
esac

echo
echo "构建完成。"
