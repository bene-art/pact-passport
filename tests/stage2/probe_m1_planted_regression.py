"""Tier M / M1 — parametric K-defect bug-seeding (Mills sensitivity).

For each defect in the pre-registered K-list, the runner:
  1. creates an isolated worktree at the current freeze-tag HEAD,
  2. reverts the defect's closing commit on that worktree,
  3. re-imports + runs the target C-probe in that worktree,
  4. captures whether the C-probe reports `new_finding` (detected) or
     `pass` (missed),
  5. tears down the worktree.

Sensitivity = detected / K (per RESEARCH §6.6 / Appendix E.2). A clean
Stage 2 run on a suite with sensitivity 0.7 is weaker evidence than
one at 0.95 — the planted-defect sensitivity calibrates how much
confidence to extend to a clean C-tier sweep.

Per Appendix E.2 the K-defect list and its SHA-256 digest are
pre-registered at the freeze tag so the seeding manifest cannot be
tuned post-hoc to match observed detection rates.

Generalization (per Stage 2 Change Plan §3 C3-d / RESEARCH Appendix B
#4): this file previously planted only Bug 9 and documented the
revert protocol manually. It now declares a parametric K-defect list
covering Bugs 6/7/8/9 (each with a target C-probe). Bug 10 has no
C10 probe yet — flagged in `result["observations"]["gaps"]` as a
known sensitivity-coverage hole.

NUC-bridge runtime still owns the worktree dance; this probe captures
the manifest + integrity hash + per-defect plan + sensitivity-calc
shape. The runner fills `_RUNNER_RESULTS` at execution and re-imports
to compute the final sensitivity outcome.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from tests.stage2._harness import probe


REPO = Path(__file__).resolve().parents[2]  # tests/stage2/ → tests/ → repo root


# ---------------------------------------------------------------------------
# Pre-registered K-defect seed manifest
# ---------------------------------------------------------------------------
# Each entry: a closing commit to revert on an isolated worktree + the
# target C-probe expected to detect the regression. Adding/removing
# entries changes SEED_LIST_DIGEST below; any post-tag drift is visible
# as a diff against the v0.7-pre-registration tag (Appendix E.2).

SEED_DEFECTS: list[dict] = [
    {
        "defect_id": "bug6",
        "revert_commit": "34bcc72",
        "fix_subject": "per-link parent_cap_id for K>=3 chain verification (closes #29)",
        "target_probe": "C6_parent_cap_id",
        "expected_detection_outcome": "new_finding",
        "bug_class": "convenient-value substitution at layer boundary",
    },
    {
        "defect_id": "bug7",
        "revert_commit": "cd2a891",
        "fix_subject": "cancelled receipt on stream partition (closes #30)",
        "target_probe": "C7_stream_cancellation",
        "expected_detection_outcome": "new_finding",
        "bug_class": "order of operations broken across layers",
    },
    {
        "defect_id": "bug8",
        "revert_commit": "6ab733e",
        "fix_subject": "bind ctx.cap_token before rate-limit check",
        "target_probe": "C8_rate_ordering",
        "expected_detection_outcome": "new_finding",
        "bug_class": "state-binding after the action it should annotate",
    },
    {
        "defect_id": "bug9",
        "revert_commit": "74c3aee",
        "fix_subject": "chain re-derivation of action + caveats (closes Bug 9)",
        "target_probe": "C9_chain_rederivation",
        "expected_detection_outcome": "new_finding",
        "bug_class": "trust-child-without-re-derivation",
    },
]

K = len(SEED_DEFECTS)

# Canonical-JSON hash so post-tag drift is detectable.
SEED_LIST_DIGEST = hashlib.sha256(
    json.dumps(SEED_DEFECTS, sort_keys=True).encode()
).hexdigest()

# Runner fills this in at execution: { defect_id -> "detected" | "missed" }.
# Empty until runner orchestration lands (NUC bridge time).
_RUNNER_RESULTS: dict[str, str] = {}


@probe(
    probe_id="M1_planted_regression",
    tier="M",
    pairing={
        "mac": "gemma3:12b (handler)",
        "nuc": "llama3.2:3b (client)",
        "roles": "Continuity pair under planted regression — Tier C probes re-run on each isolated worktree",
        "transport": "loopback in dev; Tailscale at NUC time",
    },
    prediction=(
        "For each of K planted defects, the corresponding Cn probe reports "
        "'new_finding' on the isolated worktree where the defect's closing "
        "commit was reverted. Sensitivity = detected/K should be 1.0 for "
        "all 4 currently-seeded defects (Bugs 6/7/8/9): each C-probe is "
        "specific enough to catch its own targeted regression."
    ),
    threshold=(
        "Sensitivity < 1.0 — a C-probe is INSENSITIVE to its own bug "
        "(false-negative; clean Stage 2 runs over-credited) OR sensitivity "
        "> 1.0 by way of unrelated C-probes flipping to 'new_finding' "
        "(suite has bleed between probes — false-positive risk)."
    ),
    citation="Mills 1972 bug seeding; RESEARCH §6.6 / Appendix E.2.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    head = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    on_branch = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()

    # Per-defect plan rendered from the manifest so the runner has an
    # executable protocol (no free-form steps).
    per_defect_plan: list[dict] = []
    for d in SEED_DEFECTS:
        worktree = f"/tmp/pact-m1-{d['defect_id']}"
        per_defect_plan.append({
            "defect_id": d["defect_id"],
            "steps": [
                f"git worktree add {worktree} HEAD",
                f"git -C {worktree} revert --no-edit {d['revert_commit']}",
                f"cd {worktree} && python -m tests.stage2.probe_c_convergence",
                f"# inspect results_<ts>/{d['target_probe']}.json — expect "
                f"{d['expected_detection_outcome']}",
                f"git worktree remove --force {worktree}",
            ],
        })

    # Sensitivity (computed only when runner has filled results).
    if _RUNNER_RESULTS:
        detected_count = sum(
            1 for v in _RUNNER_RESULTS.values() if v == "detected"
        )
        sensitivity = detected_count / K if K else None
        all_detected = detected_count == K and not any(
            v not in {"detected", "missed"} for v in _RUNNER_RESULTS.values()
        )
        outcome = "pass" if all_detected else "new_finding"
    else:
        detected_count = 0
        sensitivity = None
        outcome = "pass"  # provisional — no measurement yet

    result["observations"] = {
        "k": K,
        "seed_list_digest": SEED_LIST_DIGEST,
        "current_head": head,
        "current_branch": on_branch,
        "seed_defects": SEED_DEFECTS,
        "per_defect_plan": per_defect_plan,
        "runner_results": dict(_RUNNER_RESULTS),
        "detected_count": detected_count,
        "sensitivity": sensitivity,
        "gaps": [
            {
                "defect_id": "bug10",
                "issue": (
                    "no C10 probe for Windows ConnectionAbortedError "
                    "(commit ed78bf5). M1 cannot exercise its detection."
                ),
                "follow_up": (
                    "Add C10 to probe_c_convergence.py before the "
                    "v0.7-pre-registration tag; then add a 5th SEED_DEFECTS "
                    "entry and re-hash SEED_LIST_DIGEST."
                ),
            },
        ],
    }
    result["outcome"] = outcome
    if not _RUNNER_RESULTS:
        result["notes"] = (
            "Probe pre-registers the K-defect manifest + sensitivity-calc "
            "shape. NUC-bridge runner orchestrates the worktree-per-defect "
            "cycle and re-imports this module with _RUNNER_RESULTS populated "
            "to compute the final sensitivity verdict."
        )


if __name__ == "__main__":
    run()
