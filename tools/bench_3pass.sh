#!/usr/bin/env bash
# Reproduce performance.md's measurement protocol: three configurations, three passes
# each, configuration order rotated between passes, every run pinned to one core, with
# the documented criterion settings (--warm-up-time 2 --measurement-time 4).
#
# Writes one file per (config, pass) into $OUT. Nothing is summarised here; the
# analysis is separate so the raw criterion output is kept.
#
# Every pass first *witnesses* the configuration it is about to measure, because a
# criterion log alone cannot tell one configuration from another: three identical
# builds all print `time:` lines, and a dropped `--features ultra` would be written
# down, then summarised, as a fourth configuration. The pass resolves the `compare`
# bench binary cargo would run (`--no-run` plus its JSON stream), records the resolved
# invocation, the binary's sha256 and its `witness::` symbol count at the top of the
# file it is about to fill, and refuses to run when the witness does not match:
#
#   * `ultra` must carry `witness::` symbols -- the same nm witness `verify.sh` uses
#     for the ultra fuzz build -- and hardened/opt-out must not, so a lost or leaked
#     feature flag is a failure rather than a differently-labelled run;
#   * no two configurations may resolve to the same binary hash, so a lost
#     `--no-default-features` cannot turn opt-out into a rerun of hardened.
#
# `--config profile.bench.strip=false` is passed to the witness build *and* the
# measured run so they share one artefact; `strip` controls only the symbol table, so
# it cannot change a measurement.
set -euo pipefail
cd "$(dirname "$0")/.."

# The witness reads cargo and nm itself; a direct run needs the rustup bin directory
# on PATH the way every sibling tool arranges it.
export PATH="$HOME/.cargo/bin:$PATH"
command -v nm >/dev/null 2>&1 || {
  echo "FAIL: nm (binutils) is not on PATH, so the configuration witness has nothing" >&2
  echo "      to read the bench binary with." >&2
  exit 1
}

OUT="${OUT:-bench-out}"
mkdir -p "$OUT"

declare -A seen_hash=()   # configuration -> sha256 of the bench binary it resolved

# The bench executable cargo would run for these arguments, taken from cargo's own
# JSON stream rather than a glob over the deps directory: that directory holds one
# binary per feature set, and a glob would name whichever came last.
bench_executable() {  # extra cargo args...
  cargo bench --offline --bench compare "$@" --no-run \
    --config 'profile.bench.strip=false' --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
exes = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
       and (m.get("target") or {}).get("name") == "compare":
        exes.append(m["executable"])
print(exes[-1] if exes else "")
'
}

run_one() { # $1 = config name, $2 = pass, $3.. = extra cargo args
  local name="$1"; shift
  local pass="$1"; shift
  local dest="$OUT/$name-pass$pass.txt"

  local bin
  bin="$(bench_executable "$@" || true)"
  [ -n "$bin" ] || {
    echo "FAIL: cargo reported no bench executable for the $name configuration, so" >&2
    echo "      there is no binary to witness and nothing to measure." >&2
    exit 1
  }
  local witness hash
  witness="$(nm -C "$bin" 2>/dev/null | grep -c 'witness::' || true)"
  hash="$(sha256sum "$bin" 2>/dev/null | cut -d' ' -f1 || true)"
  [ -n "$hash" ] || {
    echo "FAIL: could not hash the bench binary $bin, so no two configurations could" >&2
    echo "      be told apart." >&2
    exit 1
  }
  case "$name" in
    ultra)
      [ "${witness:-0}" -gt 0 ] || {
        echo "FAIL: the ultra pass resolved a bench binary with no witness:: symbols" >&2
        echo "      ($bin): --features ultra did not apply, so this pass would measure" >&2
        echo "      the default configuration under the ultra name." >&2
        exit 1
      } ;;
    *)
      [ "${witness:-0}" -eq 0 ] || {
        echo "FAIL: the $name pass resolved a bench binary with $witness witness::" >&2
        echo "      symbol(s) ($bin): the ultra code is in a configuration that must" >&2
        echo "      not contain it." >&2
        exit 1
      } ;;
  esac
  if [ "${#seen_hash[@]}" -gt 0 ]; then
    local other
    for other in "${!seen_hash[@]}"; do
      if [ "$other" != "$name" ] && [ "${seen_hash[$other]}" = "$hash" ]; then
        echo "FAIL: the $name and $other passes resolved the same bench binary" >&2
        echo "      ($bin, sha256 ${hash:0:16}): a feature flag did not apply, so the" >&2
        echo "      campaign would summarise one configuration under two names." >&2
        exit 1
      fi
    done
  fi
  seen_hash[$name]="$hash"

  # The witness goes into the same file as the measurement, so the raw output keeps
  # what was actually built and run rather than only what was intended.
  {
    echo "# configuration: $name (pass $pass)"
    echo "# cargo bench --offline --bench compare $* -- --warm-up-time 2 --measurement-time 4"
    echo "# bench binary: $bin"
    echo "# sha256: $hash"
    echo "# witness:: symbols under nm -C: $witness"
    echo "# (--config profile.bench.strip=false is on the witness build and this run so"
    echo "#  they share one artefact; strip does not affect codegen or timing.)"
  } > "$dest"
  echo "=== $name pass $pass -> $dest (witness:: $witness symbols, sha256 ${hash:0:12}) ==="
  taskset -c 3 cargo bench --offline --bench compare "$@" \
    --config 'profile.bench.strip=false' -- \
    --warm-up-time 2 --measurement-time 4 >> "$dest" 2>&1
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
