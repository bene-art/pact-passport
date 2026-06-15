"""Stage 2 harness-side ablation helpers.

The src-side `_ablations.py` reads `PACT_ABLATION_*` env vars at import
time. Phase A spawns a fresh process per (config × probe) pair via
`scripts/run_phase_a.sh`; this module is what each probe consults to
label its result JSON with the active ablation config.

The naming convention follows §12 of `PACT_RESEARCH_PLAN.md`:

  BASELINE    — no flags set; the v0.7.1 reference behavior.
  ABL-BIND    — PACT_ABLATION_BIND=1
  ABL-CHAIN   — PACT_ABLATION_CHAIN=1
  ABL-RECEIPT — PACT_ABLATION_RECEIPT=1
  ABL-NONCE   — PACT_ABLATION_NONCE=1
  ABL-RATE    — PACT_ABLATION_RATE=1
  ABL-MULTI:* — more than one flag set (named with the sorted list)

`ABL-MULTI` is a hazard label: §12 explicitly says "ship one ablation
at a time" for causal attribution. If the runner accidentally sets
two flags, every result picks it up and the analysis layer can refuse
to attribute defenses. The runner sanity-checks via
`assert_single_ablation_or_baseline()` before kicking off a probe.
"""

from __future__ import annotations

import os
from typing import Any

# Order matches src/pact_passport/_ablations.py.
ABLATION_NAMES: tuple[str, ...] = ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE")


def current_ablations() -> list[str]:
    """Return ablation flag names currently set in the environment.

    Independent of src-side import state — reads env directly each call.
    Used by probe wrappers to stamp result["ablation"] without depending
    on `pact_passport._ablations` having been imported first.
    """
    return [
        name for name in ABLATION_NAMES
        if os.environ.get(f"PACT_ABLATION_{name}", "") == "1"
    ]


def config_id_from_env() -> str:
    """Compute the §12 config label for the current process.

    Returns:
        "BASELINE"          when no ablation flags are set.
        "ABL-<NAME>"        when exactly one is set (the Phase A norm).
        "ABL-MULTI:<list>"  when multiple are set (a hazard — §12 forbids
                            this for causal attribution. The runner sanity
                            check catches it before probe invocation; this
                            return is the fallback if the check is skipped).
    """
    active = current_ablations()
    if not active:
        return "BASELINE"
    if len(active) == 1:
        return f"ABL-{active[0]}"
    return f"ABL-MULTI:{','.join(sorted(active))}"


def tag_result_with_ablations(result: dict[str, Any]) -> None:
    """Stamp `result["ablation"]` with the active config for provenance.

    Idempotent — safe to call multiple times in a probe body. The schema
    matches what the §12 attribution table consumes:
        result["ablation"] = {"active": [...], "config_id": "ABL-BIND"}
    """
    active = current_ablations()
    result["ablation"] = {
        "active": active,
        "config_id": config_id_from_env(),
    }


def assert_single_ablation_or_baseline() -> None:
    """Pre-flight check for the Phase A runner.

    Raises RuntimeError if more than one PACT_ABLATION_* flag is set.
    §12 attribution requires exactly one disabled mechanism per run;
    multi-flag configs invalidate the "this mechanism prevents this
    attack" claim.
    """
    active = current_ablations()
    if len(active) > 1:
        raise RuntimeError(
            f"§12 violation: multiple ablation flags active ({active}). "
            "Set at most one PACT_ABLATION_* per probe invocation."
        )
