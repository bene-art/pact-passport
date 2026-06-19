"""Audit + hygiene checks for v1.4 / v0.8 messages and receipts.

This module provides three classes of audit:

1. **REQ hygiene** (``audit_req``) — pre-dispatch checks that a REQ message is
   well-formed per spec v1.4 (§18.2 ``audit_context`` shape; §18.3 fault-code
   classification of any issues; §18.4 caveat-profile assessment).

2. **Receipt hygiene** (``audit_receipt``) — post-exchange checks that a
   receipt is *bilateral* per spec §18.6: both the receiver's signature
   over the RES envelope AND the initiator's acknowledgment signature over
   the RES are present and verify against valid keys.

3. **Attack-scenario conformance** (``run_attack_scenario``) — given a
   scenario record from ``spec/attacks/attacks.json``, returns whether the
   implementation produces the predicted ``fault.code``.

The hygiene checks return ``AuditResult`` objects rather than raising —
they are intended to be embedded in receipts (§18.6) or returned to
clients as wire metadata (analogous to AIP's ``X-AIP-Audit`` header, but
PACT's variant is bilaterally signed when embedded in a receipt).

AIP parallel: ``aip_mcp/audit.py`` provides ``audit_compact`` and
``audit_chained``. PACT's design subordinates these into the bilateral
receipt model — the audit verdict becomes part of the signed record,
not a sidecar response header.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any

from pact_passport import crypto
from pact_passport._canonical import canonical_json
from pact_passport.errors import (
    PACT_AUDIENCE_MISMATCH,
    PACT_HOLDER_PROOF_INVALID,
    PACT_RECEIPT_NOT_BILATERAL,
    PACT_SIGNATURE_INVALID,
    PACT_TOKEN_EXPIRED,
    PACT_TOKEN_MALFORMED,
    PACT_TOKEN_MISSING,
)
from pact_passport.message import PACTMessage, verify_holder_proof, verify_message


# =============================================================================
# Result shape
# =============================================================================

@dataclass
class AuditResult:
    """Outcome of a hygiene audit.

    Fields:
        passed: True if no errors. Warnings may still be present.
        errors: List of ``(code, detail)`` tuples for fault-class issues.
            ``code`` is a wire-level fault code from ``pact_passport.errors``.
        warnings: List of ``(label, detail)`` strings for non-fatal issues.
        metadata: Optional structured observations (e.g., the inferred
            policy profile, the timestamp of the audit).
    """

    passed: bool = True
    errors: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def add_error(self, code: str, detail: str) -> None:
        self.errors.append((code, detail))
        self.passed = False

    def add_warning(self, label: str, detail: str) -> None:
        self.warnings.append((label, detail))

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "errors": [{"code": c, "detail": d} for c, d in self.errors],
            "warnings": [{"label": l, "detail": d} for l, d in self.warnings],
            "metadata": dict(self.metadata),
        }


# =============================================================================
# REQ hygiene (spec §18.2, §18.3)
# =============================================================================

REQUIRED_AUDIT_CONTEXT_KEYS = frozenset({
    "purpose", "request_id", "audience_hint", "expires_at",
})
"""Keys required on every v1.4 REQ ``audit_context`` (spec §18.2)."""

RECOMMENDED_AUDIT_PURPOSES = frozenset({
    "task", "delegation-step", "tool-call", "audit-export",
    "revocation-broadcast", "research-subtask", "system",
})
"""Purpose tags spec §18.2 SHOULD use. Implementations MAY accept others."""


def audit_req(
    msg: PACTMessage,
    sender_public_key: bytes | None = None,
    holder_public_key: bytes | None = None,
) -> AuditResult:
    """Audit a REQ message for spec v1.4 hygiene.

    Args:
        msg: The REQ to audit.
        sender_public_key: If provided, verify the outer envelope signature.
        holder_public_key: If provided, verify the v1.4 holder_proof
            (uses ``message.verify_holder_proof`` with the legacy-v0.7
            fallback enabled per spec §18.7 migration window).

    Returns ``AuditResult`` with errors / warnings populated. Errors map
    to wire-level fault codes (spec §18.3) that the receiver SHOULD emit
    if rejecting the REQ.
    """
    result = AuditResult()
    result.metadata["audit_kind"] = "req"
    result.metadata["msg_id"] = msg.id
    result.metadata["msg_type"] = msg.type

    if msg.type != "REQ":
        result.add_warning(
            "non_req",
            f"audit_req called on type={msg.type!r}; expected REQ",
        )

    # --- audit_context structural check (spec §18.2) ---
    ctx = msg.audit_context
    if ctx is None:
        result.add_error(
            PACT_TOKEN_MALFORMED,
            "REQ is missing required audit_context field (spec §18.2)",
        )
    else:
        if not isinstance(ctx, dict):
            result.add_error(
                PACT_TOKEN_MALFORMED,
                f"audit_context must be a JSON object, got {type(ctx).__name__}",
            )
        else:
            missing = REQUIRED_AUDIT_CONTEXT_KEYS - set(ctx)
            if missing:
                result.add_error(
                    PACT_TOKEN_MALFORMED,
                    f"audit_context missing required keys: {sorted(missing)}",
                )
            for key in REQUIRED_AUDIT_CONTEXT_KEYS & set(ctx):
                value = ctx[key]
                if not isinstance(value, str):
                    result.add_error(
                        PACT_TOKEN_MALFORMED,
                        f"audit_context.{key} must be a string",
                    )
                    continue
                # audience_hint MAY be empty (visa-request broadcast form,
                # where sender doesn't know the gatekeeper's agent_id pre-visa).
                # Other keys MUST be non-empty.
                if key != "audience_hint" and not value.strip():
                    result.add_error(
                        PACT_TOKEN_MALFORMED,
                        f"audit_context.{key} must be a non-empty string",
                    )

            # Purpose tag check (warning only — spec SHOULD)
            purpose = ctx.get("purpose")
            if isinstance(purpose, str) and purpose not in RECOMMENDED_AUDIT_PURPOSES:
                result.add_warning(
                    "uncommon_purpose",
                    f"audit_context.purpose={purpose!r} is not in the SHOULD list "
                    f"(spec §18.2). Recommended values: {sorted(RECOMMENDED_AUDIT_PURPOSES)}",
                )

            # Audience binding (spec §18.2): audience_hint MUST equal to_agent
            if ctx.get("audience_hint") != msg.to_agent:
                result.add_error(
                    PACT_AUDIENCE_MISMATCH,
                    f"audit_context.audience_hint={ctx.get('audience_hint')!r} "
                    f"does not equal REQ.to_agent={msg.to_agent!r} (spec §18.2)",
                )

            # Expiry check
            expires_at = ctx.get("expires_at")
            if isinstance(expires_at, str):
                try:
                    expires = datetime.fromisoformat(expires_at)
                    if expires < datetime.now(UTC):
                        result.add_error(
                            PACT_TOKEN_EXPIRED,
                            f"audit_context.expires_at={expires_at} is in the past",
                        )
                except (ValueError, TypeError):
                    result.add_error(
                        PACT_TOKEN_MALFORMED,
                        f"audit_context.expires_at={expires_at!r} is not valid ISO 8601",
                    )

    # --- outer envelope signature (spec §6.2, unchanged from v0.7) ---
    if sender_public_key is not None:
        if not msg.signature:
            result.add_error(
                PACT_TOKEN_MISSING,
                "REQ has no signature field",
            )
        elif not verify_message(msg, sender_public_key):
            result.add_error(
                PACT_SIGNATURE_INVALID,
                "REQ envelope signature does not verify under sender's public key",
            )

    # --- holder_proof (spec §18.1) ---
    if holder_public_key is not None and msg.holder_proof:
        if not verify_holder_proof(msg, holder_public_key):
            result.add_error(
                PACT_HOLDER_PROOF_INVALID,
                "REQ holder_proof signature does not verify against the v1.4 "
                "structured payload nor against the v0.7 legacy bare-msg.id form",
            )

    return result


# =============================================================================
# Bilateral receipt audit (spec §18.6)
# =============================================================================

def audit_receipt(
    receipt: dict,
    receiver_public_key: bytes,
    initiator_public_key: bytes | None = None,
) -> AuditResult:
    """Audit a receipt for bilateral-signature property (spec §18.6).

    A bilateral receipt under v1.4 carries BOTH:

    1. The receiver's signature over the canonical-JSON RES payload
       (the existing receipt structure).
    2. The initiator's acknowledgment signature over the canonical-JSON
       receipt minus the ``initiator_ack_signature`` field
       (the new v1.4 ``initiator_ack_signature`` field).

    A receipt missing either signature is non-bilateral; this function
    flags such receipts with ``pact_receipt_not_bilateral`` (spec §18.3).

    Args:
        receipt: The receipt dict (see ``pact_passport.receipt``).
        receiver_public_key: Used to verify the receiver-side signature.
        initiator_public_key: If provided, also verify the
            ``initiator_ack_signature``. If None, the initiator-ack
            check is skipped (use this when you only have the receiver's
            key but want to confirm receiver-side validity).

    Returns ``AuditResult``. ``passed`` is True only if both signatures
    verify (when both public keys are provided).
    """
    result = AuditResult()
    result.metadata["audit_kind"] = "receipt"
    result.metadata["receipt_id"] = receipt.get("receipt_id") or receipt.get("id")

    # --- Receiver signature ---
    receiver_sig_b64 = receipt.get("signature")
    if not receiver_sig_b64:
        result.add_error(
            PACT_TOKEN_MISSING,
            "Receipt is missing 'signature' field (the receiver's signature)",
        )
    else:
        signable = {k: v for k, v in receipt.items()
                    if k not in {"signature", "initiator_ack_signature"}}
        try:
            sig_bytes = base64.b64decode(receiver_sig_b64)
        except (binascii.Error, ValueError, TypeError):
            result.add_error(
                PACT_SIGNATURE_INVALID,
                "Receipt receiver signature is malformed base64",
            )
        else:
            if not crypto.verify(canonical_json(signable), sig_bytes, receiver_public_key):
                result.add_error(
                    PACT_SIGNATURE_INVALID,
                    "Receipt receiver signature does not verify against receiver_public_key",
                )

    # --- Initiator-ack signature (bilateral marker — spec §18.6) ---
    ack_sig_b64 = receipt.get("initiator_ack_signature")
    if ack_sig_b64 is None:
        # Missing the ack is what makes a receipt non-bilateral.
        result.add_error(
            PACT_RECEIPT_NOT_BILATERAL,
            "Receipt has no initiator_ack_signature; receipt is not bilateral (spec §18.6)",
        )
    elif initiator_public_key is not None:
        # Initiator signs over the canonical-JSON of the receipt
        # MINUS the initiator_ack_signature field itself.
        ack_signable = {k: v for k, v in receipt.items() if k != "initiator_ack_signature"}
        try:
            ack_bytes = base64.b64decode(ack_sig_b64)
        except (binascii.Error, ValueError, TypeError):
            result.add_error(
                PACT_SIGNATURE_INVALID,
                "Receipt initiator_ack_signature is malformed base64",
            )
        else:
            if not crypto.verify(canonical_json(ack_signable), ack_bytes, initiator_public_key):
                result.add_error(
                    PACT_SIGNATURE_INVALID,
                    "Receipt initiator_ack_signature does not verify against initiator_public_key",
                )

    if result.passed:
        result.metadata["bilateral_signature_status"] = "verified"
    return result


def sign_initiator_ack(receipt: dict, initiator_private_key: bytes) -> str:
    """Compute the initiator-acknowledgment signature for a receipt (spec §18.6).

    Returns the base64-encoded Ed25519 signature over the canonical-JSON of
    the receipt MINUS the ``initiator_ack_signature`` field. Callers
    typically place the returned string into the receipt's
    ``initiator_ack_signature`` field to make the receipt bilateral.
    """
    ack_signable = {k: v for k, v in receipt.items() if k != "initiator_ack_signature"}
    sig = crypto.sign(canonical_json(ack_signable), initiator_private_key)
    return base64.b64encode(sig).decode("ascii")


def make_bilateral_receipt(
    receipt: dict,
    initiator_private_key: bytes,
) -> dict:
    """Return ``receipt`` with the v1.4 ``initiator_ack_signature`` added.

    The original receipt is not mutated; a new dict is returned.
    """
    bilateral = dict(receipt)
    bilateral["initiator_ack_signature"] = sign_initiator_ack(receipt, initiator_private_key)
    return bilateral


# =============================================================================
# Attack scenario conformance (spec §18.8 + spec/attacks/attacks.json)
# =============================================================================

@dataclass
class ScenarioOutcome:
    """Result of running one attack-scenario test against an impl."""

    scenario_id: str
    predicted_error: str
    predicted_status: int
    observed_error: str | None
    observed_status: int | None
    matched: bool
    notes: str = ""


def scenario_predicts_match(
    scenario: dict,
    observed_error: str | None,
    observed_status: int | None,
) -> ScenarioOutcome:
    """Compare an observed substrate outcome against a scenario's prediction.

    Args:
        scenario: A scenario record from ``spec/attacks/attacks.json``.
        observed_error: The fault.code (or "pact_ok") the substrate emitted.
        observed_status: The HTTP status (or 200) the substrate returned.

    Returns ``ScenarioOutcome`` with ``matched=True`` if both observed
    values equal the scenario's predicted values.
    """
    predicted_error = scenario.get("predicted_error", "")
    predicted_status = int(scenario.get("predicted_status", 0))
    matched = (
        observed_error == predicted_error
        and observed_status == predicted_status
    )
    return ScenarioOutcome(
        scenario_id=scenario.get("id", ""),
        predicted_error=predicted_error,
        predicted_status=predicted_status,
        observed_error=observed_error,
        observed_status=observed_status,
        matched=matched,
        notes=scenario.get("notes", ""),
    )


__all__ = [
    "AuditResult",
    "REQUIRED_AUDIT_CONTEXT_KEYS",
    "RECOMMENDED_AUDIT_PURPOSES",
    "audit_req",
    "audit_receipt",
    "sign_initiator_ack",
    "make_bilateral_receipt",
    "ScenarioOutcome",
    "scenario_predicts_match",
]
