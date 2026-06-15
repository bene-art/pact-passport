#!/usr/bin/env bash
# Phase A confirmatory runner — orchestrates the §12 ablation matrix.
#
# Runs the full Stage 2 probe battery across 6 configurations:
#   BASELINE   — no flags (the v0.7.1 reference behavior)
#   ABL-BIND   — holder-proof enforcement disabled
#   ABL-CHAIN  — v1.3 chain re-derivation disabled
#   ABL-RECEIPT — signed receipt writes disabled
#   ABL-NONCE  — visa nonce binding disabled
#   ABL-RATE   — visa rate ceiling disabled
#
# Each probe is invoked in a FRESH PYTHON PROCESS per config — the src-side
# `_ablations.py` reads env at import time, so process isolation is what
# guarantees the flag takes effect. Results land in a single timestamped
# run directory, organized as:
#
#   tests/stage2/results_phase_a_<UTC-ts>/
#     ├── BASELINE/
#     │   ├── R1_v013_replay.json
#     │   ├── A4_refs_forgery.json
#     │   └── ...
#     ├── ABL-BIND/
#     │   └── ...
#     └── ...
#
# Each result JSON carries result["ablation"]["config_id"] matching the
# directory name — redundant by design so per-file inspection doesn't
# require walking up to the parent dir.
#
# Usage:
#   ./scripts/run_phase_a.sh                          # all 6 configs, all probes
#   ./scripts/run_phase_a.sh --config BASELINE        # one config
#   ./scripts/run_phase_a.sh --probe probe_r1_replay  # one probe across all configs
#   ./scripts/run_phase_a.sh --dry-run                # print the invocation matrix
#
# Halts at the first failure; this is a measurement, not a soak test. To
# resume after a fix, pass --skip-existing.

set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '[%s] FATAL: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------

CONFIGS=(BASELINE ABL-BIND ABL-CHAIN ABL-RECEIPT ABL-NONCE ABL-RATE)
ONLY_CONFIG=""
ONLY_PROBE=""
DRY_RUN=0
SKIP_EXISTING=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --config) ONLY_CONFIG="$2"; shift 2 ;;
        --probe)  ONLY_PROBE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --skip-existing) SKIP_EXISTING=1; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "unknown arg: $1" ;;
    esac
done

if [[ -n "$ONLY_CONFIG" ]]; then
    valid=0
    for c in "${CONFIGS[@]}"; do
        if [[ "$c" == "$ONLY_CONFIG" ]]; then valid=1; break; fi
    done
    [[ $valid -eq 1 ]] || die "unknown config '$ONLY_CONFIG'. Valid: ${CONFIGS[*]}"
    CONFIGS=("$ONLY_CONFIG")
fi

# Discover probe modules.
PROBES=()
for f in tests/stage2/probe_*.py; do
    name=$(basename "$f" .py)
    if [[ -n "$ONLY_PROBE" && "$name" != "$ONLY_PROBE" ]]; then
        continue
    fi
    PROBES+=("$name")
done
[[ ${#PROBES[@]} -gt 0 ]] || die "no probes matched"

# ---------------------------------------------------------------------------
# Pre-flight.
# ---------------------------------------------------------------------------

if [[ ! -d .venv ]]; then
    die ".venv missing — run scripts/nuc_bootstrap.sh first (or pip install -e .[dev,cbor,fast])"
fi
# shellcheck disable=SC1091
source .venv/bin/activate

export PYTHONPATH="$REPO_ROOT:$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

# Confirm src-side and harness-side ablation modules import cleanly.
python -c "from pact_passport import _ablations; from tests.stage2 import _ablations as h; print('ablation modules OK:', h.ABLATION_NAMES)" \
    || die "ablation modules failed to import"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_ROOT="tests/stage2/results_phase_a_${TS}"
log "Phase A run starting"
log "  run dir:  $OUT_ROOT"
log "  configs:  ${CONFIGS[*]}"
log "  probes:   ${#PROBES[@]} (${PROBES[*]:0:3}...)"
log "  dry-run:  $DRY_RUN"

if [[ $DRY_RUN -eq 1 ]]; then
    for cfg in "${CONFIGS[@]}"; do
        for p in "${PROBES[@]}"; do
            echo "would run: $cfg / $p"
        done
    done
    log "dry-run done — no probes invoked"
    exit 0
fi

mkdir -p "$OUT_ROOT"

# ---------------------------------------------------------------------------
# Per-config × per-probe matrix.
# ---------------------------------------------------------------------------

run_one() {
    local cfg=$1 probe=$2
    local cfg_dir="$OUT_ROOT/$cfg"
    mkdir -p "$cfg_dir"

    local result_json="$cfg_dir/${probe#probe_}.json"
    if [[ $SKIP_EXISTING -eq 1 && -f "$result_json" ]]; then
        log "  skip (exists): $cfg / $probe"
        return 0
    fi

    # Translate config label to env vars. Exactly one flag per non-BASELINE
    # config; assert_single_ablation_or_baseline() guards against drift.
    local env_args=()
    case $cfg in
        BASELINE)    : ;;  # no flag
        ABL-BIND)    env_args=("PACT_ABLATION_BIND=1") ;;
        ABL-CHAIN)   env_args=("PACT_ABLATION_CHAIN=1") ;;
        ABL-RECEIPT) env_args=("PACT_ABLATION_RECEIPT=1") ;;
        ABL-NONCE)   env_args=("PACT_ABLATION_NONCE=1") ;;
        ABL-RATE)    env_args=("PACT_ABLATION_RATE=1") ;;
        *) die "unhandled config $cfg" ;;
    esac

    log "  run: $cfg / $probe"

    # Probe writes to tests/stage2/results_<ts>/. We capture that path and
    # move the produced JSONs into the config dir. Each invocation is a
    # fresh process so env+module-load are clean.
    local pre_dirs post_dirs new_dir
    pre_dirs=$(ls -d tests/stage2/results_2* 2>/dev/null | sort -u || true)
    env ${env_args[@]+"${env_args[@]}"} python -m "tests.stage2.${probe}" >/dev/null 2>&1
    post_dirs=$(ls -d tests/stage2/results_2* 2>/dev/null | sort -u || true)
    new_dir=$(comm -13 <(echo "$pre_dirs") <(echo "$post_dirs") | tail -1)

    if [[ -z "$new_dir" || ! -d "$new_dir" ]]; then
        die "$cfg / $probe produced no result dir"
    fi

    # Move every JSON the probe wrote into the config dir.
    mv "$new_dir"/*.json "$cfg_dir/" 2>/dev/null || true
    rmdir "$new_dir" 2>/dev/null || true
}

started=$(date +%s)
n_started=0 n_done=0 n_failed=0
n_total=$(( ${#CONFIGS[@]} * ${#PROBES[@]} ))

for cfg in "${CONFIGS[@]}"; do
    log "=== config: $cfg ==="
    for probe in "${PROBES[@]}"; do
        n_started=$((n_started + 1))
        if run_one "$cfg" "$probe"; then
            n_done=$((n_done + 1))
        else
            n_failed=$((n_failed + 1))
            log "FAILED: $cfg / $probe — halting"
            break 2
        fi
    done
done

elapsed=$(( $(date +%s) - started ))

# ---------------------------------------------------------------------------
# Roll-up summary.
# ---------------------------------------------------------------------------

python - <<PY
import glob, json
results = {}
for f in sorted(glob.glob("$OUT_ROOT/*/*.json")):
    parts = f.split("/")
    cfg = parts[-2]
    pid = parts[-1].replace(".json", "")
    try:
        d = json.load(open(f))
    except Exception:
        d = {}
    results.setdefault(cfg, []).append((pid, d.get("outcome", "?")))

print()
print("=== Phase A scoreboard ===")
for cfg in sorted(results):
    pass_n = sum(1 for _, o in results[cfg] if o == "pass")
    new_n = sum(1 for _, o in results[cfg] if o == "new_finding")
    err_n = sum(1 for _, o in results[cfg] if o == "harness_error")
    total = len(results[cfg])
    print(f"  {cfg:<14} pass={pass_n}/{total}  new_finding={new_n}  harness_error={err_n}")
PY

log "Phase A complete in ${elapsed}s — ${n_done}/${n_total} succeeded, ${n_failed} failed"
log "results: $OUT_ROOT"
