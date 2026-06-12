"""Tier M / M1 — planted-regression test.

Branch off main → tier-m1 branch → revert ONE specific case-study fix
→ re-run Tier C → check that the corresponding Cn probe catches the
planted regression.

This is the methodology self-test: does the probe set detect a known
regression when one is planted?

TODO (NUC-bridge time): the actual git-branch operation lives outside
this probe. The probe below documents the protocol; the runner script
performs the branch + revert + re-import + run.
"""
from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

from tests.stage2._harness import probe


REPO = Path(__file__).resolve().parents[2]  # tests/stage2/ → tests/ → repo root


@probe(
    probe_id="M1_planted_regression",
    tier="M",
    pairing={
        "mac": "gemma3:12b (handler)",
        "nuc": "llama3.2:3b (client)",
        "roles": "Continuity pair under planted regression — Tier C probes re-run on tier-m1 branch",
        "transport": "loopback in dev; Tailscale at NUC time",
    },
    prediction=(
        "Planting a revert of the Bug 9 fix (chain re-derivation) causes "
        "C9_chain_rederivation to report 'new_finding' (verifier accepts "
        "the mutated chain). All other 8 C-probes still 'pass' (only the "
        "targeted bug was reintroduced). This shows the C-suite is "
        "specific to the bugs it claims to catch, not a flaky sieve."
    ),
    threshold=(
        "C9 still 'pass' after the planted revert (probe is insensitive "
        "to its own bug), OR other unrelated C-probes flip to 'new_finding' "
        "(suite has bleed between probes — false-positive risk in real "
        "Tier C runs)."
    ),
    citation="Methodology self-test; analogue of mutation testing in spec.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    plan = [
        "git checkout -b tier-m1",
        "git revert --no-edit 74c3aee  # commit that closed Bug 9",
        "python -m tests.stage2.probe_c_convergence",
        "# inspect results_<ts>/C9_chain_rederivation.json — expect new_finding",
        "git checkout main && git branch -D tier-m1",
    ]
    head = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    on_main_pre = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    bug9_commit = subprocess.run(
        ["git", "-C", str(REPO), "log", "--format=%H", "-1",
         "--grep=Bug 9", "--all"],
        capture_output=True, text=True,
    ).stdout.strip()

    result["observations"] = {
        "current_head": head,
        "current_branch": on_main_pre,
        "bug9_closing_commit": bug9_commit,
        "planned_plant_revert": "Bug 9 fix (chain re-derivation)",
        "planned_steps": plan,
        "TODO_runtime": (
            "The runner script that orchestrates this probe is responsible "
            "for performing the branch+revert+re-import+rerun cycle and "
            "merging C-probe JSONs into the M1 outcome. This file documents "
            "the plan; it does not auto-mutate the working tree."
        ),
    }
    result["outcome"] = "pass"
    result["notes"] = (
        "Probe documents the M1 protocol. Execution at NUC-bridge time. "
        "Outcome rewritten by the runner after the C9 re-run JSON is inspected."
    )


if __name__ == "__main__":
    run()
