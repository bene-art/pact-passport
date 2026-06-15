"""PACT ablation hooks — §12 experimental harness, NOT production surface.

This module exposes module-level boolean constants that gate "remove one
mechanism" guards across the codebase. Each guard is announced via a
WARNING log the first time it fires; every active ablation is also
embedded in the result JSON via `active_ablations()` for provenance.

**Default behavior: all flags are False.** PACT runs exactly as
documented in `spec/PACT_v1.md` when no `PACT_ABLATION_*` env vars are
set. This invariant is asserted by `tests/test_ablations.py::
test_no_ablations_active_by_default` — any commit that flips a default
ON will break that test by design.

**Production deployments MUST verify no `PACT_ABLATION_*` env vars are
set before serving real peers.** The paper §6 limitation already names
this implementation as "a research artifact, not a production-grade
library"; the env-gated flags are part of that posture. They exist
solely to support the §12.2 ablation experiments that causally
attribute defenses to mechanisms.

§12.2 ablation matrix:

  ABL_BIND     — disable holder-proof verification.
                 Predicted newly-passing attack: stolen-token (B2) —
                 attacker presents a cap they don't hold.

  ABL_CHAIN    — disable v1.3 chain re-derivation.
                 Predicted newly-passing attack: rogue-delegator (A5),
                 deep-chain forgery (B3).

  ABL_RECEIPT  — disable signed receipt writes.
                 Predicted consequence: A4/S5 lose post-hoc orphan
                 detectability; H3 audit-detectability claim falsified
                 for the ablated config.

  ABL_NONCE    — disable visa nonce binding.
                 Predicted newly-passing attack: visa replay (V5) —
                 the same visa+holder_proof pair authorizes two
                 distinct request-pairs.

  ABL_RATE     — disable visa rate ceiling.
                 Predicted newly-passing attack: amplification (A6) —
                 visa issuance is uncapped per peer.

Each guard site in `src/pact_passport/` has an `# §12.2 ablation`
comment so a reviewer can grep `ABL_` and inventory every effect.
"""

from __future__ import annotations

import logging
import os

_LOG = logging.getLogger(__name__)


def _read(name: str) -> bool:
    return os.environ.get(f"PACT_ABLATION_{name}", "") == "1"


ABL_BIND: bool = _read("BIND")
ABL_CHAIN: bool = _read("CHAIN")
ABL_RECEIPT: bool = _read("RECEIPT")
ABL_NONCE: bool = _read("NONCE")
ABL_RATE: bool = _read("RATE")


def active_ablations() -> list[str]:
    """Return active ablation flag names — used for result-JSON provenance.

    Returns an empty list in the default (production-safe) configuration.
    A non-empty list MUST appear in every result emitted by a probe run
    under that ablation config; the §12 ablation attribution table is
    derived from these per-trial labels.
    """
    return [
        name
        for name, on in (
            ("BIND", ABL_BIND),
            ("CHAIN", ABL_CHAIN),
            ("RECEIPT", ABL_RECEIPT),
            ("NONCE", ABL_NONCE),
            ("RATE", ABL_RATE),
        )
        if on
    ]


# Module-load WARNING — fires once per process if any flag is on.
# If you see this in a production log, something is wrong; investigate
# before responding to any peer with a non-default verification path.
if active_ablations():
    _LOG.warning(
        "PACT ABLATIONS ACTIVE: %s — research-only mode, NOT production-safe. "
        "If this appears in a non-experimental deployment, halt and audit.",
        active_ablations(),
    )
