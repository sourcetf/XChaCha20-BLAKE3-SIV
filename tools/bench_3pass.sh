#!/usr/bin/env bash
# Reproduce performance.md's measurement protocol: three configurations, three passes
# each, configuration order rotated between passes, every run pinned to one core, with
# the documented criterion settings (--warm-up-time 2 --measurement-time 4).
#
# Writes one file per (config, pass) into $OUT. Nothing is summarised here; the
# analysis is separate so the raw criterion output is kept.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${OUT:-bench-out}"
mkdir -p "$OUT"

run_one() { # $1 = config name, $2.. = extra cargo args
  local name="$1"; shift
  local pass="$1"; shift
  local dest="$OUT/$name-pass$pass.txt"
  echo "=== $name pass $pass -> $dest ==="
  taskset -c 3 cargo bench --offline --bench compare "$@" -- \
    --warm-up-time 2 --measurement-time 4 > "$dest" 2>&1
  local times
  times="$(grep -c 'time:' "$dest" || true)"
  if [ "${times:-0}" -eq 0 ]; then
    # An empty criterion run used to finish with "done: 0 time lines" and then an
    # unconditional "ALL BENCH RUNS COMPLETE" -- an empty measurement set that
    # bench_summarise.py would only discover later. Fail here instead.
    echo "FAIL: $dest has no criterion 'time:' lines, so this pass measured nothing" >&2
    tail -20 "$dest" >&2
    exit 1
  fi
  echo "    done: $times time lines"
}

for pass in 1 2 3; do
  case "$pass" in
    1) order=(hardened opt-out ultra) ;;
    2) order=(ultra opt-out hardened) ;;
    3) order=(opt-out ultra hardened) ;;
  esac
  for name in "${order[@]}"; do
    case "$name" in
      hardened) run_one "$name" "$pass" ;;
      opt-out)  run_one "$name" "$pass" --no-default-features ;;
      ultra)    run_one "$name" "$pass" --features ultra ;;
    esac
  done
done
echo "ALL BENCH RUNS COMPLETE"
