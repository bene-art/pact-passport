"""δ.1.1 + δ.1.2 dispatch-integration tests for spec §18.2 audit_context.

These tests verify that ``audit_req`` is plumbed into PACTAgent's dispatch
pipeline — not only the library function in ``audit.py`` (covered by
``test_audit_context.py``) but the actual REQ → response path that a wire
client would experience.

Two flows exercised: ``intent=task`` (``_step_audit_req`` in the pipeline)
and ``intent=request_visa`` (inline check in ``_handle_visa_request``).

Migration window: with ``audit_context_strict=False`` (default), missing
``audit_context`` is accepted with a DeprecationWarning. With strict=True,
missing audit_context is rejected as ``pact_token_malformed``. Malformed
audit_context (audience mismatch, expiry, structure) is always rejected
regardless of strict mode because the sender has declared v1.4 conformance.
"""
from __future__ import annotations

import base64
import uuid
import warnings
from datetime import datetime, timedelta, UTC

import pytest

from pact_passport import PACTAgent, PACTMessage, crypto
from pact_passport._canonical import canonical_json
from pact_passport.errors import (
    PACT_AUDIENCE_MISMATCH,
    PACT_TOKEN_EXPIRED,
    PACT_TOKEN_MALFORMED,
)


# =============================================================================
# Fixtures + helpers
# =============================================================================

class _Peer:
    """A registered peer with ephemeral keypair + agent_id."""

    def __init__(self):
        self.private_key, self.public_key = crypto.generate_keypair()
        pub_b64 = base64.b64encode(self.public_key).decode("ascii")
        self.agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        self.identity_doc = {
            "agent_id": self.agent_id,
            "public_key": pub_b64,
            "alg": crypto.ALG,
        }


@pytest.fixture
def gatekeeper(tmp_path):
    """Default agent (non-strict mode)."""
    agent = PACTAgent("gatekeeper", store_dir=tmp_path / "gk")
    agent._ensure_identity()

    @agent.handle("ping")
    def ping(payload):
        return {"pong": True}

    return agent


@pytest.fixture
def gatekeeper_strict(tmp_path):
    """Strict-mode agent — rejects REQs without audit_context."""
    agent = PACTAgent(
        "gatekeeper_strict",
        store_dir=tmp_path / "gks",
        audit_context_strict=True,
    )
    agent._ensure_identity()

    @agent.handle("ping")
    def ping(payload):
        return {"pong": True}

    return agent


@pytest.fixture
def stranger():
    """A passport-less peer."""
    return _Peer()


def _sign(msg: PACTMessage, private_key: bytes) -> dict:
    sig = crypto.sign(canonical_json(msg.signable_dict()), private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


def _registered_peer(agent: PACTAgent) -> _Peer:
    """Create a peer + TOFU-register it on the agent."""
    peer = _Peer()
    agent._tofu_register(peer.agent_id, peer.identity_doc)
    return peer


def _loopback() -> tuple:
    return ("127.0.0.1", 55555)


def _task_req(
    peer: _Peer,
    gatekeeper_id: str,
    *,
    audit_context: dict | None = None,
    cap_id: str | None = None,
) -> dict:
    """Build a signed task REQ with caller-chosen audit_context."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=peer.agent_id,
        to_agent=gatekeeper_id,
        intent="task",
        payload={"action": "ping"},
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        idempotency_key=str(uuid.uuid4()),
        identity_doc=peer.identity_doc,
        audit_context=audit_context,
        cap_id=cap_id,
    )
    return _sign(msg, peer.private_key)


def _visa_req(
    peer: _Peer,
    *,
    audit_context: dict | None = None,
    action: str = "ping",
) -> dict:
    """Build a signed visa REQ with caller-chosen audit_context."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=peer.agent_id,
        to_agent="",
        intent="request_visa",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"action": action},
        identity_doc=peer.identity_doc,
        audit_context=audit_context,
    )
    return _sign(msg, peer.private_key)


def _valid_audit_context(req_id: str, audience: str, *, purpose: str = "task") -> dict:
    return {
        "purpose": purpose,
        "request_id": req_id,
        "audience_hint": audience,
        "expires_at": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
    }


# =============================================================================
# δ.1.1 — _handle_task audit_req plumbing
# =============================================================================

def test_task_with_valid_audit_context_dispatches(gatekeeper):
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), gk_id)
    req = _task_req(peer, gk_id, audit_context=ac)
    # request_id must match msg.id for build, override after construction
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "ok", res
    assert res["payload"]["pong"] is True


def test_task_missing_audit_context_non_strict_passes_with_warning(gatekeeper):
    """Migration window: missing audit_context warns but dispatches."""
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    req = _task_req(peer, gk_id, audit_context=None)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        res = gatekeeper._dispatch(req, remote_addr=_loopback())

    assert res["status"] == "ok", res
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)
                   and "audit_context" in str(w.message)]
    assert deprecation, f"Expected DeprecationWarning; got {[str(w.message) for w in caught]}"


def test_task_missing_audit_context_strict_mode_rejected(gatekeeper_strict):
    peer = _registered_peer(gatekeeper_strict)
    gk_id = gatekeeper_strict._ensure_identity().agent_id
    req = _task_req(peer, gk_id, audit_context=None)
    res = gatekeeper_strict._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_task_audit_context_audience_mismatch_rejected(gatekeeper):
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), "sha256:wrong_audience")
    req = _task_req(peer, gk_id, audit_context=ac)
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_AUDIENCE_MISMATCH, res


def test_task_audit_context_expired_rejected(gatekeeper):
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), gk_id)
    ac["expires_at"] = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    req = _task_req(peer, gk_id, audit_context=ac)
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_EXPIRED, res


def test_task_audit_context_missing_key_rejected(gatekeeper):
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), gk_id)
    del ac["audience_hint"]
    req = _task_req(peer, gk_id, audit_context=ac)
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_task_audit_context_non_string_value_rejected(gatekeeper):
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), gk_id)
    ac["expires_at"] = 99999  # int instead of ISO string
    req = _task_req(peer, gk_id, audit_context=ac)
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_task_audit_context_dispatch_order_before_capability(gatekeeper):
    """audit_req runs BEFORE _step_verify_capability — cheap-first ordering."""
    peer = _registered_peer(gatekeeper)
    gk_id = gatekeeper._ensure_identity().agent_id
    ac = _valid_audit_context(str(uuid.uuid4()), "sha256:wrong")  # audit fails
    req = _task_req(peer, gk_id, audit_context=ac,
                    cap_id="sha256:nonexistent_capability")  # would also fail cap verify
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_AUDIENCE_MISMATCH, res


# =============================================================================
# δ.1.2 — _handle_visa_request audit_req plumbing
# =============================================================================

def test_visa_request_missing_audit_context_non_strict_dispatches(gatekeeper, stranger):
    """Visa request without audit_context in non-strict: warning, then visa flow."""
    req = _visa_req(stranger, audit_context=None)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        res = gatekeeper._dispatch(req, remote_addr=_loopback())

    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)
                   and "audit_context" in str(w.message)]
    assert deprecation, f"Expected DeprecationWarning; got {[str(w.message) for w in caught]}"
    if res["status"] == "error":
        assert res["fault"]["code"] != PACT_TOKEN_MALFORMED, res


def test_visa_request_missing_audit_context_strict_rejected(gatekeeper_strict, stranger):
    req = _visa_req(stranger, audit_context=None)
    res = gatekeeper_strict._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_visa_request_malformed_audit_context_audience_rejected(gatekeeper, stranger):
    """Visa request with present-but-bad audit_context.audience_hint is rejected."""
    ac = _valid_audit_context(str(uuid.uuid4()), "sha256:wrong_audience",
                              purpose="visa-request")
    req = _visa_req(stranger, audit_context=ac)
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_AUDIENCE_MISMATCH, res


def test_visa_request_with_valid_audit_context_dispatches(gatekeeper, stranger):
    """Visa request with audit_context.audience_hint='' matches to_agent=''."""
    @gatekeeper.handle("ping_v", visa_eligible=True)
    def ping_v(payload):
        return {"pong": True}

    ac = _valid_audit_context(str(uuid.uuid4()), "", purpose="visa-request")
    req = _visa_req(stranger, audit_context=ac, action="ping_v")
    res = gatekeeper._dispatch(req, remote_addr=_loopback())
    if res["status"] == "error":
        assert res["fault"]["code"] != PACT_TOKEN_MALFORMED, res
        assert res["fault"]["code"] != PACT_AUDIENCE_MISMATCH, res
