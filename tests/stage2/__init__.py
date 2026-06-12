"""Stage 2 cross-machine experiment battery.

Pre-registered probe suite for v0.7.x + spec v1.3.0-draft. Runs against
NUC + Mac mini via Tailscale once the bridge is live; loopback in dev.

Background:
  - Methodology: PACT_RESEARCH_PLAN.md (Phase 0 / 11. probe inventory).
  - Pre-tag prep + reconciliation discipline: STAGE2_CHANGE_PLAN.md.
  - Original experiment plan:
    ~/Desktop/PACT_HotNets_Paper/experiment_plans/experiment_plan_stage2_model_rotation_2026-06-08.md

Each probe self-describes (`@probe` decorator with pairing, prediction,
threshold, classification ∈ {DETERMINISTIC, STOCHASTIC}, n_trials,
citation). Results land in `tests/stage2/results_<UTC-ts>/` (gitignored
because provenance stamps the local hostname into every result).
"""
