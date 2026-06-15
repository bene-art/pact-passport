#!/usr/bin/env bash
# NUC bootstrap for Stage 2 cross-machine runs.
#
# Brings a fresh (or stale) pact-passport clone on the NUC to a known-good
# state: latest main + editable install + harness smoke + one loopback probe
# end-to-end. Idempotent — re-runs are safe.
#
# Usage:
#   ./scripts/nuc_bootstrap.sh                  # latest origin/main
#   ./scripts/nuc_bootstrap.sh <commit-or-tag>  # pin to a specific commit
#   ./scripts/nuc_bootstrap.sh v0.7.1-pre-registration  # after the freeze tag
#
# Exits non-zero on first failure. Every step is logged with a timestamp.
# Goal: when the bridge comes up on NUC reconnect day, this is the only
# script you need to run before kicking off Phase A confirmatory runs.
#
# What this does NOT do:
#   - Configure Tailscale (assumes `tailscale status` already shows both
#     Mac and NUC reachable; document the auth steps in NUC_READINESS.md).
#   - Run cross-machine probes — those require both ends up; this script
#     proves NUC-side install is sane via a loopback R1 probe.
#   - Pull or build the LLM models — Ollama setup is its own concern.

set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '[%s] FATAL: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

TARGET_REF="${1:-origin/main}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"
log "repo: $REPO_ROOT"
log "target ref: $TARGET_REF"

# ---------------------------------------------------------------------------
# 1. Safety check: no uncommitted local changes.
# ---------------------------------------------------------------------------

if ! git diff --quiet || ! git diff --cached --quiet; then
    git status -sb
    die "uncommitted changes present — refusing to overwrite. Stash or commit first."
fi
log "git working tree clean"

# ---------------------------------------------------------------------------
# 2. Fetch + check out target ref.
# ---------------------------------------------------------------------------

log "git fetch --tags origin"
git fetch --tags origin

# Resolve TARGET_REF (could be a branch, tag, or sha). Refuse if it doesn't exist.
if ! TARGET_SHA=$(git rev-parse --verify "$TARGET_REF" 2>/dev/null); then
    die "ref '$TARGET_REF' did not resolve. Did the tag push? Try a sha or 'origin/main'."
fi
log "resolved $TARGET_REF -> $TARGET_SHA"

log "git checkout $TARGET_SHA"
git checkout --detach "$TARGET_SHA"

# ---------------------------------------------------------------------------
# 3. venv + editable install.
# ---------------------------------------------------------------------------

if [[ ! -d .venv ]]; then
    log "creating .venv"
    # Cross-platform Python: pick first interpreter on PATH whose
    # path is actually readable+executable AND doesn't live under
    # Microsoft Store's WindowsApps (those are App Execution Alias
    # stubs that hard-fail EACCES under non-interactive shells).
    PY=
    for cand in python python3 py; do
        path=$(command -v "$cand" 2>/dev/null || true)
        [[ -z "$path" ]] && continue
        # Skip WindowsApps stubs (the Permission Denied trap).
        if [[ "$path" == *"/WindowsApps/"* ]]; then continue; fi
        if [[ ! -r "$path" ]]; then continue; fi
        # Confirm it can actually run.
        "$cand" -c "import sys" 2>/dev/null && { PY="$cand"; break; } || true
    done
    [[ -n "$PY" ]] || die "no working python interpreter on PATH (skipping any WindowsApps stubs)"
    log "using interpreter: $PY ($($PY --version 2>&1))"
    "$PY" -m venv .venv
else
    log ".venv exists; reusing"
fi

# shellcheck disable=SC1091
# Cross-platform venv layout: POSIX puts activate under bin/, Windows under Scripts/.
if [[ -f .venv/bin/activate ]]; then
    source .venv/bin/activate
elif [[ -f .venv/Scripts/activate ]]; then
    source .venv/Scripts/activate
else
    die "no venv activate script found under .venv/bin or .venv/Scripts"
fi

log "pip install -e \".[dev,cbor,fast]\""
# Skip pip self-upgrade — Windows can't always replace pip.exe while it's
# running and a non-current pip is fine for our deps. Use `python -m pip`
# for the install itself (cross-platform; doesn't rely on pip.exe shim).
python -m pip install -e ".[dev,cbor,fast]" 2>&1 | tail -3

# Confirm pact_passport actually imports.
RESOLVED_VERSION=$(python -c "import pact_passport; print(pact_passport.__version__)")
log "pact_passport import OK, __version__ = $RESOLVED_VERSION"

# ---------------------------------------------------------------------------
# 4. Harness unit-test smoke (fast, no network).
# ---------------------------------------------------------------------------

log "pytest tests/test_stage2_harness.py -q"
pytest tests/test_stage2_harness.py -q 2>&1 | tail -3

# ---------------------------------------------------------------------------
# 5. Loopback R1 probe — proves Stage 2 plumbing works end-to-end on this host.
# ---------------------------------------------------------------------------
#
# R1 is the lowest-stakes DET probe (v0.1.3 baseline replay over loopback);
# success here means: server stand-up, identity registration, capability
# issue/use, holder_proof, and receipt-write all work on this NUC.

export PYTHONPATH="$REPO_ROOT:$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
log "smoke probe: probe_r1_replay (loopback)"

# Wipe any prior results dirs to avoid PRE/POST confusion. The harness
# unit tests can leak files into a results dir on Windows when
# monkeypatch.chdir isn't honored; cleanest is to start fresh and then
# locate R1's output by name afterward.
rm -rf tests/stage2/results_* 2>/dev/null || true

python -m tests.stage2.probe_r1_replay >/dev/null 2>&1
R1_JSON=$(find tests/stage2 -path '*/results_*/R1_v013_replay.json' -print -quit 2>/dev/null)

if [[ -z "$R1_JSON" || ! -f "$R1_JSON" ]]; then
    die "R1 probe did not write a result JSON — check probe output"
fi

# Python on Windows prints \r\n; tr strips CR so trailing whitespace
# doesn't poison the outcome comparison below.
R1_OUTCOME=$(python -c "
import json
d = json.load(open('$R1_JSON'))
print(d.get('outcome', '?'), d.get('elapsed_s', '?'), d.get('provenance', {}).get('git_sha', '?')[:12])
" | tr -d '\r')
read -r r1_outcome r1_elapsed r1_sha <<< "$R1_OUTCOME"
log "R1: outcome=$r1_outcome elapsed=${r1_elapsed}s git_sha=$r1_sha"

if [[ "$r1_outcome" != "pass" ]]; then
    die "R1 loopback FAILED — install is not sane; investigate before cross-machine."
fi

# ---------------------------------------------------------------------------
# 6. Final summary — what to do next.
# ---------------------------------------------------------------------------

log "==="
log "NUC bootstrap COMPLETE"
log "  pact_passport: $RESOLVED_VERSION"
log "  commit:        $TARGET_SHA"
log "  R1 loopback:   pass (${r1_elapsed}s)"
log ""
log "Next:"
log "  1. Confirm Tailscale auth: 'tailscale status' shows Mac reachable"
log "  2. Confirm identity-doc share path Mac <-> NUC"
log "  3. Run all 33 sub-probes loopback-equivalent on NUC alone:"
log "       for p in tests/stage2/probe_*.py; do python -m tests.stage2.\$(basename \$p .py); done"
log "  4. Cross-machine R1 with Mac (see PACT_RESEARCH_PLAN §8)"
log "==="
