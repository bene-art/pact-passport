"""Unilateral audit receipts.

Each agent signs their own view. No cooperation required.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, UTC

from pact import crypto
from pact._canonical import canonical_json


def create_receipt(
    private_key: bytes,
    agent_id: str,
    task_ref: str,
    refs: list[str],
    outcome: str,
    extra: dict | None = None,
) -> dict:
    """Create a unilateral signed receipt.

    Args:
        private_key: The signing agent's private key.
        agent_id: The signing agent's ID.
        task_ref: The message ID of the original REQ.
        refs: All message IDs involved in this interaction.
        outcome: "completed", "failed", or "timeout".
        extra: Optional dict of additional audit fields (e.g. V-tier visa
            metadata) merged into the receipt before signing. Reserved
            keys (``type``, ``agent``, ``task_ref``, ``refs``, ``outcome``,
            ``timestamp``, ``alg``, ``signature``) cannot be overridden.

    Returns:
        A receipt dict with signature.
    """
    receipt = {
        "type": "receipt",
        "agent": agent_id,
        "task_ref": task_ref,
        "refs": refs,
        "outcome": outcome,
        "timestamp": datetime.now(UTC).isoformat(),
        "alg": crypto.ALG,
    }
    if extra:
        for k, v in extra.items():
            if k not in receipt:
                receipt[k] = v
    sig = crypto.sign(canonical_json(receipt), private_key)
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


def verify_receipt(receipt: dict, public_key: bytes) -> bool:
    """Verify a receipt's signature.

    Returns False on missing/malformed signature rather than raising.
    See v0.5.3 honesty patch — fail-closed on malformed input.
    """
    sig = receipt.get("signature")
    if not sig:
        return False
    try:
        sig_bytes = base64.b64decode(sig)
    except (binascii.Error, ValueError, TypeError):
        return False
    signable = {k: v for k, v in receipt.items() if k != "signature"}
    return crypto.verify(canonical_json(signable), sig_bytes, public_key)
