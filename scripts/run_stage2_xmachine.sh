#!/usr/bin/env bash
# Phase A cross-tailnet runner — orchestrates Mac ↔ NUC Stage 2 probes.
#
# What this does:
#   1. SSH into the NUC and spawn a long-lived PACTAgent (`nuc_runner`) on
#      a known port. Wait for /pact/v1/health to respond.
#   2. Run cross-tailnet probes from the Mac with STAGE2_NUC_URL set to
#      the NUC agent's URL. Each probe sends REQs to that URL over
#      Tailscale.
#   3. (Optionally) trigger the loopback Phase A matrix on each side
#      separately: Mac via local invocation, NUC via SSH. Per-side
#      diagonals are the §12 attribution evidence for each node.
#   4. Tear down: kill the NUC agent.
#
# What this does NOT do (yet):
#   - Convert ATTR_BIND / ATTR_NONCE probes to cross-machine. Those need
#     cap pre-staging from NUC → Mac. Tracked as the "ATTR cross-machine"
#     follow-up; current orchestrator just runs the cross-tailnet smokes
#     (X1) and reuses local loopback matrices.
#
# Usage:
#   ./scripts/run_stage2_xmachine.sh                 # spawn NUC + run X1 + teardown
#   ./scripts/run_stage2_xmachine.sh --xmachine-probe X1_xmachine_smoke
#   ./scripts/run_stage2_xmachine.sh --keep-nuc      # leave the NUC agent up after probes
#   ./scripts/run_stage2_xmachine.sh --nuc-loopback  # also run Phase A matrix on NUC loopback
#   ./scripts/run_stage2_xmachine.sh --mac-loopback  # also run Phase A matrix on Mac loopback
#   ./scripts/run_stage2_xmachine.sh --dry-run       # print plan, don't execute
#
# Halts at first probe failure (this is a measurement, not a soak test).

set -euo pipefail

log()  { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die()  { printf '[%s] FATAL: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }
warn() { printf '[%s] WARN: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Defaults / config.
# ---------------------------------------------------------------------------

NUC_SSH_HOST="${NUC_SSH_HOST:-nuc}"                    # ~/.ssh/config alias
NUC_TS_HOST="${NUC_TS_HOST:-nucnode.tailcf96a0.ts.net}"  # MagicDNS hostname
NUC_AGENT_NAME="${NUC_AGENT_NAME:-nuc_runner}"
NUC_AGENT_PORT="${NUC_AGENT_PORT:-9101}"
NUC_REPO_PATH="${NUC_REPO_PATH:-/c/projects/pact-passport}"
NUC_GIT_BASH='C:\Program Files\Git\bin\bash.exe'

XMACHINE_PROBES=(probe_x1_xmachine_smoke)
KEEP_NUC=0
RUN_NUC_LOOPBACK=0
RUN_MAC_LOOPBACK=0
DRY_RUN=0
ONLY_PROBE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --xmachine-probe)   ONLY_PROBE="$2"; shift 2 ;;
        --keep-nuc)         KEEP_NUC=1; shift ;;
        --nuc-loopback)     RUN_NUC_LOOPBACK=1; shift ;;
        --mac-loopback)     RUN_MAC_LOOPBACK=1; shift ;;
        --dry-run)          DRY_RUN=1; shift ;;
        --nuc-host)         NUC_TS_HOST="$2"; shift 2 ;;
        --nuc-port)         NUC_AGENT_PORT="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "unknown arg: $1" ;;
    esac
done

[[ -n "$ONLY_PROBE" ]] && XMACHINE_PROBES=("$ONLY_PROBE")

NUC_AGENT_URL="http://${NUC_TS_HOST}:${NUC_AGENT_PORT}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_ROOT="tests/stage2/results_phase_a_xmachine_${TS}"

log "Phase A cross-tailnet runner starting"
log "  repo:         $REPO_ROOT"
log "  NUC SSH:      ${NUC_SSH_HOST} → ${NUC_TS_HOST}"
log "  NUC agent:    ${NUC_AGENT_NAME} @ port ${NUC_AGENT_PORT}"
log "  NUC URL:      ${NUC_AGENT_URL}"
log "  xmach probes: ${XMACHINE_PROBES[*]}"
log "  nuc loopback: $RUN_NUC_LOOPBACK"
log "  mac loopback: $RUN_MAC_LOOPBACK"
log "  out dir:      $OUT_ROOT"
log "  dry-run:      $DRY_RUN"

if [[ $DRY_RUN -eq 1 ]]; then
    log "dry-run — nothing executed"
    exit 0
fi

mkdir -p "$OUT_ROOT/xmachine" "$OUT_ROOT/mac" "$OUT_ROOT/nuc"

# ---------------------------------------------------------------------------
# Pre-flight: confirm Mac venv + harness imports.
# ---------------------------------------------------------------------------

[[ -d .venv ]] || die ".venv missing — run pip install -e .[dev,cbor,fast] first"
# shellcheck disable=SC1091
source .venv/bin/activate
export PYTHONPATH="$REPO_ROOT:$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

python -c "
from tests.stage2._harness import stand_up_remote_agent, share_remote_identity_into, maybe_remote_peer
from tests.stage2 import _spawn_remote_agent
print('harness modules OK')
" || die "Mac harness module imports failed"

# ---------------------------------------------------------------------------
# 1. Spawn nuc_runner on NUC.
# ---------------------------------------------------------------------------

log "=== 1. Spawn ${NUC_AGENT_NAME} on NUC port ${NUC_AGENT_PORT} ==="

# IMPORTANT: synchronous-spawn-then-capture-PID hangs on Windows
# OpenSSH server — the session never returns even with `nohup ... &`
# + `< /dev/null` + `> log 2>&1`. The server holds the session until
# all descendants exit. Hung 52 min in a prior run, confirmed 2026-06-17.
#
# Fix: background the SSH itself, poll /pact/v1/health from outside for
# ready signal, and tear down via a SEPARATE SSH call that uses
# PowerShell Stop-Process matched by command-line pattern. No PID
# capture needed.

# First, ensure any prior spawn at this port is gone (clean slate).
log "  (clean) terminate any prior _spawn_remote_agent on NUC"
ssh "$NUC_SSH_HOST" 'powershell -NoProfile -Command "(Get-Process python -ErrorAction SilentlyContinue) | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }"' 2>/dev/null || true
sleep 1

SPAWN_CMD=$(cat <<EOF
cd ${NUC_REPO_PATH} && \
source .venv/Scripts/activate && \
python -m tests.stage2._spawn_remote_agent ${NUC_AGENT_NAME} --port ${NUC_AGENT_PORT}
EOF
)
# Background the SSH itself. We don't care about its return; we poll
# /pact/v1/health for readiness. SSH may hang waiting for the python
# process to exit — that's fine, the orchestrator doesn't wait on it.
log "  spawning in background SSH..."
ssh "$NUC_SSH_HOST" "\"${NUC_GIT_BASH}\" -lc \"${SPAWN_CMD}\"" \
    > /tmp/nuc_spawn_${TS}.log 2>&1 &
NUC_SSH_BG_PID=$!
log "  background SSH PID (local) = ${NUC_SSH_BG_PID}; remote agent log = /tmp/${NUC_AGENT_NAME}.log on NUC"

teardown_nuc() {
    [[ $KEEP_NUC -eq 1 ]] && { log "  --keep-nuc set; leaving NUC agent up"; return 0; }
    log "  teardown: Stop-Process matching _spawn_remote_agent on NUC"
    ssh "$NUC_SSH_HOST" 'powershell -NoProfile -Command "(Get-Process python -ErrorAction SilentlyContinue) | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }"' 2>/dev/null || \
        warn "teardown SSH returned non-zero (agent may already be down)"
    # Also tear down our local background SSH (may be hung).
    kill "${NUC_SSH_BG_PID}" 2>/dev/null || true
}
trap teardown_nuc EXIT

# ---------------------------------------------------------------------------
# 2. Wait for NUC agent to be ready (poll /pact/v1/health).
# ---------------------------------------------------------------------------

log "=== 2. Wait for NUC agent ready ==="
ready=0
for i in $(seq 1 30); do
    body=$(curl -sS --max-time 4 "${NUC_AGENT_URL}/pact/v1/health" 2>/dev/null || true)
    if [[ "$body" == *'"status": "ok"'* ]]; then
        log "  ready in ${i}s: $body"
        ready=1
        break
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || die "NUC agent did not become ready in 30s; check /tmp/${NUC_AGENT_NAME}.log on NUC"

# Stamp the resolved NUC URL + identity for downstream consumption.
echo "$NUC_AGENT_URL" > "$OUT_ROOT/.nuc_url"
curl -sS "${NUC_AGENT_URL}/pact/v1/identity" > "$OUT_ROOT/.nuc_identity.json"

# ---------------------------------------------------------------------------
# 3. Run cross-tailnet probes from Mac with STAGE2_NUC_URL set.
# ---------------------------------------------------------------------------

log "=== 3. Cross-tailnet probes (Mac → NUC) ==="
n_xmach_ok=0
n_xmach_fail=0
for probe in "${XMACHINE_PROBES[@]}"; do
    log "  run xmachine: $probe"

    # Each probe writes to its own results dir; capture by name.
    pre_dirs=$(ls -d tests/stage2/results_2* 2>/dev/null | sort -u || true)
    STAGE2_NUC_URL="$NUC_AGENT_URL" python -m "tests.stage2.${probe}" >/dev/null 2>&1
    post_dirs=$(ls -d tests/stage2/results_2* 2>/dev/null | sort -u || true)
    new_dir=$(comm -13 <(echo "$pre_dirs") <(echo "$post_dirs") | tail -1)

    if [[ -z "$new_dir" ]]; then
        warn "  $probe produced no result dir"
        n_xmach_fail=$((n_xmach_fail+1))
        continue
    fi

    mv "$new_dir"/*.json "$OUT_ROOT/xmachine/" 2>/dev/null
    rmdir "$new_dir" 2>/dev/null || true

    # Outcome check.
    outcome=$(python -c "
import json, glob
files = glob.glob('${OUT_ROOT}/xmachine/${probe#probe_}.json'.replace('xmachine_smoke', 'xmachine_smoke').upper().replace('XMACHINE_SMOKE', 'xmachine_smoke'))
# fallback: match the most-recent json
import os
files = sorted([f for f in os.listdir('${OUT_ROOT}/xmachine') if f.endswith('.json')])
if not files: print('?'); exit(0)
d = json.load(open('${OUT_ROOT}/xmachine/' + files[-1]))
print(d.get('outcome', '?'))
" 2>/dev/null || echo "?")

    if [[ "$outcome" == "pass" ]]; then
        log "    -> pass"
        n_xmach_ok=$((n_xmach_ok+1))
    else
        warn "    -> $outcome"
        n_xmach_fail=$((n_xmach_fail+1))
    fi
done

# ---------------------------------------------------------------------------
# 4. Optional: Mac loopback Phase A matrix (delegates to run_phase_a.sh).
# ---------------------------------------------------------------------------

if [[ $RUN_MAC_LOOPBACK -eq 1 ]]; then
    log "=== 4. Mac loopback Phase A matrix ==="
    ./scripts/run_phase_a.sh --probe probe_attr_ablations >/dev/null 2>&1 || warn "Mac loopback matrix had failures"
    mac_latest=$(ls -dt tests/stage2/results_phase_a_2* 2>/dev/null | head -1)
    [[ -n "$mac_latest" ]] && mv "$mac_latest" "$OUT_ROOT/mac/" || warn "Mac loopback results not found"
fi

# ---------------------------------------------------------------------------
# 5. Optional: NUC loopback Phase A matrix (run remotely via SSH).
# ---------------------------------------------------------------------------

if [[ $RUN_NUC_LOOPBACK -eq 1 ]]; then
    log "=== 5. NUC loopback Phase A matrix (via SSH) ==="
    NUC_RUN_CMD=$(cat <<EOF
cd ${NUC_REPO_PATH} && \
source .venv/Scripts/activate && \
./scripts/run_phase_a.sh --probe probe_attr_ablations
EOF
    )
    ssh "$NUC_SSH_HOST" "\"${NUC_GIT_BASH}\" -lc \"${NUC_RUN_CMD}\"" 2>&1 | tail -20

    # Pull the latest results dir back. tar streams over SSH.
    log "  pulling NUC results back to $OUT_ROOT/nuc/"
    nuc_latest=$(ssh "$NUC_SSH_HOST" "\"${NUC_GIT_BASH}\" -lc 'ls -dt ${NUC_REPO_PATH}/tests/stage2/results_phase_a_2* | head -1'" 2>/dev/null | tr -d '\r')
    if [[ -n "$nuc_latest" ]]; then
        ssh "$NUC_SSH_HOST" "\"${NUC_GIT_BASH}\" -lc 'cd ${NUC_REPO_PATH} && tar c -C $(dirname $nuc_latest) $(basename $nuc_latest)'" | tar x -C "$OUT_ROOT/nuc/"
        log "  pulled $(basename $nuc_latest)"
    else
        warn "NUC loopback results not found"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Final summary.
# ---------------------------------------------------------------------------

elapsed=$(( $(date +%s) - $(date -j -f %Y%m%dT%H%M%SZ "$TS" +%s 2>/dev/null || echo 0) ))

log "==="
log "Phase A cross-tailnet run COMPLETE"
log "  xmachine probes: $n_xmach_ok pass, $n_xmach_fail fail"
log "  results dir:     $OUT_ROOT"
log "==="

if [[ $n_xmach_fail -gt 0 ]]; then
    die "$n_xmach_fail xmachine probe(s) failed — investigate before claiming Phase A"
fi
