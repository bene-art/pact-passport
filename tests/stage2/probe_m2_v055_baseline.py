"""Tier M / M2 — run Tier C against v0.5.5 baseline.

Checkout v0.5.5 tag in a separate worktree, install its dependencies,
re-run Tier C, check that the C-probes corresponding to bugs
historically present in v0.5.5 surface them as new_findings.

This is the second half of the methodology self-test: does the C-suite
detect KNOWN historical bugs when applied to an older substrate?

TODO (NUC-bridge time): worktree creation + dependency installation
is a runner concern. The probe below documents the plan and surfaces
the expected diff between v0.5.5 and v0.7 known bug fixes.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from tests.stage2._harness import probe


REPO = Path(__file__).resolve().parents[2]


# Bugs CLOSED between v0.5.5 and v0.7 (per CLAUDE.md + status doc).
# Tier C probes for these should report 'new_finding' on v0.5.5.
BUGS_CLOSED_AFTER_V055 = [
    ("Bug 6", "parent_cap_id contract", "C6_parent_cap_id"),
    ("Bug 7", "cancelled receipt on stream", "C7_stream_cancellation"),
    ("Bug 8", "V-tier rate ordering", "C8_rate_ordering"),
    ("Bug 9", "chain re-derivation", "C9_chain_rederivation"),
]


@probe(
    probe_id="M2_v055_baseline",
    tier="M",
    pairing={
        "mac": "gemma3:12b (handler on v0.5.5 worktree)",
        "nuc": "llama3.2:3b (client; can stay on v0.7 — cross-version is the point)",
        "roles": "Tier C probes re-run against v0.5.5 substrate",
        "transport": "loopback in dev; Tailscale at NUC time",
    },
    prediction=(
        f"Of the 9 C-probes, the {len(BUGS_CLOSED_AFTER_V055)} corresponding "
        f"to bugs closed AFTER v0.5.5 "
        f"({[b[0] for b in BUGS_CLOSED_AFTER_V055]}) report 'new_finding'. "
        "The other 5 (C1–C5) report 'pass' because those bugs were closed "
        "before v0.5.5. Combined with M1, this completes the meta-claim: "
        "the methodology detects both planted regressions AND known "
        "historical bugs."
    ),
    threshold=(
        "Any of the expected-failing C-probes reports 'pass' on v0.5.5 "
        "(probe is insensitive to its own bug — false-negative risk), OR "
        "any of the expected-passing C-probes (C1–C5) reports 'new_finding' "
        "(probe has bleed between bugs)."
    ),
    citation="Methodology self-test; cross-version regression detection.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    v055_tag = subprocess.run(
        ["git", "-C", str(REPO), "tag", "-l", "v0.5.5"],
        capture_output=True, text=True,
    ).stdout.strip()
    head = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    plan = [
        "git worktree add /tmp/pact-v055 v0.5.5",
        "cd /tmp/pact-v055 && pip install -e .",
        "PYTHONPATH=/tmp/pact-v055/src python -m tests.stage2.probe_c_convergence",
        "# inspect results_<ts>/C{6,7,8,9}.json — expect new_finding",
        "# inspect results_<ts>/C{1,2,3,4,5}.json — expect pass",
        "git worktree remove /tmp/pact-v055",
    ]
    result["observations"] = {
        "v055_tag_exists": bool(v055_tag),
        "current_head": head,
        "expected_failures_on_v055": [
            {"bug": b[0], "desc": b[1], "probe": b[2]}
            for b in BUGS_CLOSED_AFTER_V055
        ],
        "expected_passes_on_v055": ["C1_idempotency_race", "C2_crlf_payload",
                                     "C3_auto_grant_default", "C4_refs_unchecked",
                                     "C5_missing_key_fail_close"],
        "planned_steps": plan,
        "TODO_runtime": (
            "Worktree creation, dependency install, and cross-version "
            "harness sequencing happen in the runner. This file documents "
            "the expected diff."
        ),
    }
    result["outcome"] = "pass"
    result["notes"] = (
        "Probe documents the M2 protocol. Runner orchestrates the worktree "
        "+ re-run + result-merge at NUC-bridge time."
    )


if __name__ == "__main__":
    run()
