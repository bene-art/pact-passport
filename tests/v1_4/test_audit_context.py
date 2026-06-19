"""Tests for v1.4 / v0.8 structured audit_context field (spec §18.2)."""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

import pytest

from pact_passport import crypto
from pact_passport.message import PACTMessage, build_req
from pact_passport.audit import (
    audit_req,
    REQUIRED_AUDIT_CONTEXT_KEYS,
    RECOMMENDED_AUDIT_PURPOSES,
)
from pact_passport.errors import (
    PACT_AUDIENCE_MISMATCH,
    PACT_TOKEN_EXPIRED,
    PACT_TOKEN_MALFORMED,
)


@pytest.fixture
def keypair():
    return crypto.generate_keypair()


def test_build_req_auto_synthesizes_audit_context(keypair):
    """spec §18.2 — every v1.4 REQ MUST carry audit_context.

    build_req synthesizes one when caller doesn't provide it.
    """
    priv, _ = keypair
    msg = build_req(
        from_private_key=priv,
        from_id="sha256:sender",
        to_id="sha256:receiver",
        intent="task",
    )
    assert msg.audit_context is not None
    assert set(msg.audit_context) == REQUIRED_AUDIT_CONTEXT_KEYS
    assert msg.audit_context["audience_hint"] == "sha256:receiver"
    assert msg.audit_context["request_id"] == msg.id
    assert msg.audit_context["purpose"] == "task"


def test_build_req_respects_custom_purpose(keypair):
    """audit_purpose argument propagates to audit_context.purpose."""
    priv, _ = keypair
    msg = build_req(
        from_private_key=priv,
        from_id="sha256:s",
        to_id="sha256:r",
        intent="task",
        audit_purpose="delegation-step",
    )
    assert msg.audit_context["purpose"] == "delegation-step"


def test_build_req_accepts_explicit_audit_context(keypair):
    """Caller-supplied audit_context is preserved verbatim."""
    priv, _ = keypair
    custom_ctx = {
        "purpose": "audit-export",
        "request_id": "explicit-uuid-1234",
        "audience_hint": "sha256:r",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    msg = build_req(
        from_private_key=priv,
        from_id="sha256:s",
        to_id="sha256:r",
        intent="task",
        audit_context=custom_ctx,
    )
    assert msg.audit_context == custom_ctx


def test_build_req_rejects_audit_context_missing_keys(keypair):
    """spec §18.2 — all 4 required keys MUST be present."""
    priv, _ = keypair
    incomplete = {
        "purpose": "task",
        "audience_hint": "sha256:r",
        # missing request_id, expires_at
    }
    with pytest.raises(ValueError, match="missing required keys"):
        build_req(
            from_private_key=priv,
            from_id="sha256:s",
            to_id="sha256:r",
            intent="task",
            audit_context=incomplete,
        )


def test_build_req_rejects_audience_hint_mismatch(keypair):
    """spec §18.2 — audience_hint MUST equal to_id."""
    priv, _ = keypair
    mismatched = {
        "purpose": "task",
        "request_id": "uuid-x",
        "audience_hint": "sha256:WRONG_RECEIVER",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    with pytest.raises(ValueError, match="audience_hint"):
        build_req(
            from_private_key=priv,
            from_id="sha256:s",
            to_id="sha256:r",
            intent="task",
            audit_context=mismatched,
        )


# ---------------------------------------------------------------------------
# audit_req(): receiver-side validation
# ---------------------------------------------------------------------------

def test_audit_req_passes_on_well_formed_message(keypair):
    """A correctly-built REQ produces a clean AuditResult."""
    priv, _ = keypair
    msg = build_req(
        from_private_key=priv,
        from_id="sha256:s",
        to_id="sha256:r",
        intent="task",
    )
    result = audit_req(msg)
    assert result.passed, f"expected pass, got errors: {result.errors}"


def test_audit_req_flags_missing_audit_context():
    """Missing audit_context → pact_token_malformed."""
    msg = PACTMessage(
        id="x", type="REQ", from_agent="sha256:s", to_agent="sha256:r",
    )
    # audit_context not set
    result = audit_req(msg)
    assert not result.passed
    codes = [c for c, _ in result.errors]
    assert PACT_TOKEN_MALFORMED in codes


def test_audit_req_flags_audience_mismatch():
    """audience_hint != to_agent → pact_audience_mismatch."""
    msg = PACTMessage(
        id="x", type="REQ", from_agent="sha256:s", to_agent="sha256:r",
        audit_context={
            "purpose": "task",
            "request_id": "x",
            "audience_hint": "sha256:WRONG",  # mismatch
            "expires_at": "2030-01-01T00:00:00+00:00",
        },
    )
    result = audit_req(msg)
    assert not result.passed
    codes = [c for c, _ in result.errors]
    assert PACT_AUDIENCE_MISMATCH in codes


def test_audit_req_flags_expired_context():
    """expires_at in the past → pact_token_expired."""
    past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    msg = PACTMessage(
        id="x", type="REQ", from_agent="sha256:s", to_agent="sha256:r",
        audit_context={
            "purpose": "task",
            "request_id": "x",
            "audience_hint": "sha256:r",
            "expires_at": past,
        },
    )
    result = audit_req(msg)
    assert not result.passed
    codes = [c for c, _ in result.errors]
    assert PACT_TOKEN_EXPIRED in codes


def test_audit_req_warns_on_unusual_purpose():
    """purpose outside RECOMMENDED set is a warning, not an error."""
    msg = PACTMessage(
        id="x", type="REQ", from_agent="sha256:s", to_agent="sha256:r",
        audit_context={
            "purpose": "evil-mojo",  # not in recommended set
            "request_id": "x",
            "audience_hint": "sha256:r",
            "expires_at": "2030-01-01T00:00:00+00:00",
        },
    )
    result = audit_req(msg)
    assert result.passed  # purpose tag mismatch is a warning, not error
    labels = [l for l, _ in result.warnings]
    assert "uncommon_purpose" in labels
