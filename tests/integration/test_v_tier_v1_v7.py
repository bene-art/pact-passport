"""V-tier (v0.6): seven adversarial probes against the visa machinery.

Pre-registered thresholds match ``g4 revision visa tiered trust.md`` §7.
All seven are *independent* of each other and probe distinct layers:

* V1, V2, V4 — the caveat layer (action scope, expiry, non-delegation)
* V3       — the *receipt* layer (compromise-window enumeration)
* V5       — nonce binding (per-request-pair)
* V6       — the default-policy rate ceiling (race-safe under load)
* V7       — issuer binding (cross-issuer rejection)

Convention: every test that involves a visa goes through the full
``intent="request_visa"`` issuance path so the policy + receipt + nonce
machinery is exercised end-to-end, not mocked.
"""

from __future__ import annotations

import base64
import threading
import time
import uuid
from datetime import datetime, timedelta, UTC

import pytest

from pact_passport import (
    HandlerCost,
    PACTAgent,
    PACTMessage,
    crypto,
)
from pact_passport._canonical import canonical_json
from pact_passport.capability import CapabilityToken, Caveat, attenuate
from pact_passport.errors import AttenuationViolation


# ---------------------------------------------------------------------------
# Helpers — a passport-less "stranger" with only an ephemeral keypair.
# ---------------------------------------------------------------------------

class Stranger:
    """A passport-less peer: ephemeral keypair + derived agent_id."""

    def __init__(self):
        self.private_key, self.public_key = crypto.generate_keypair()
        pub_b64 = base64.b64encode(self.public_key).decode("ascii")
        # PACT agent_id derivation: sha256(ALG || pub_b64). Matches
        # PACTAgent._tofu_register so the gatekeeper TOFU-binds us.
        self.agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        self.identity_doc = {
            "agent_id": self.agent_id,
            "public_key": pub_b64,
            "alg": crypto.ALG,
        }


def _sign_and_finalize(msg: PACTMessage, private_key: bytes) -> dict:
    sig = crypto.sign(canonical_json(msg.signable_dict()), private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


def _build_request_visa(stranger: Stranger, action: str) -> dict:
    """Build a signed ``intent="request_visa"`` REQ from the stranger."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=stranger.agent_id,
        to_agent="",  # gatekeeper agent_id is unknown to stranger pre-visa
        intent="request_visa",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"action": action},
        identity_doc=stranger.identity_doc,
    )
    return _sign_and_finalize(msg, stranger.private_key)


def _build_task_with_visa(
    stranger: Stranger,
    gatekeeper_agent_id: str,
    visa_dict: dict,
    nonce_to_sign: str,
    payload_extra: dict | None = None,
) -> dict:
    """Build a signed task REQ presenting the visa. ``holder_proof``
    signs ``nonce_to_sign`` (visa nonce) rather than ``msg.id``.
    """
    msg_id = str(uuid.uuid4())
    deadline = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
    msg = PACTMessage(
        id=msg_id,
        type="REQ",
        from_agent=stranger.agent_id,
        to_agent=gatekeeper_agent_id,
        intent="task",
        cap_id=visa_dict["cap_id"],
        cap_envelope=visa_dict,
        deadline=deadline,
        idempotency_key=str(uuid.uuid4()),
        payload=payload_extra or {},
        identity_doc=stranger.identity_doc,
        audit_context={
            "purpose": "task",
            "request_id": msg_id,
            "audience_hint": gatekeeper_agent_id,
            "expires_at": deadline,
        },
    )
    # Holder proof signs the visa's server-issued nonce (V-tier).
    proof_sig = crypto.sign(nonce_to_sign.encode(), stranger.private_key)
    msg.holder_proof = base64.b64encode(proof_sig).decode("ascii")
    return _sign_and_finalize(msg, stranger.private_key)


def _gatekeeper(tmp_path, name: str = "alice") -> tuple[PACTAgent, dict]:
    """Build a gatekeeper with a visa-eligible ``ping`` handler whose
    cost matches the default-policy ceiling and a non-visa-eligible
    ``private`` handler that should refuse visa issuance.

    Returns (agent, call_counts) where call_counts tracks per-action
    handler invocations for V1's "private handler must never run" check.
    """
    agent = PACTAgent(name, store_dir=tmp_path / name)
    agent._ensure_identity()
    calls: dict[str, int] = {"ping": 0, "private": 0}

    @agent.handle("ping", visa_eligible=True, cost=HandlerCost(payload_bytes=64, compute_ms=10))
    def ping(payload):
        calls["ping"] += 1
        return {"pong": True, "echo": payload.get("echo")}

    @agent.handle("private")
    def private(payload):
        calls["private"] += 1  # V1 threshold: this must NEVER reach > 0 via visa
        return {"secret": "leaked"}

    return agent, calls


def _loopback_addr() -> tuple:
    return ("127.0.0.1", 55555)


# ---------------------------------------------------------------------------
# V1: Over-broad visa — visa for ``ping`` cannot reach ``private``.
# ---------------------------------------------------------------------------

def test_v1_overbroad_visa_cannot_reach_other_action(tmp_path):
    """V1 threshold: any dispatch under an action-X visa must NOT
    invoke the action-Y handler. Probed two ways:

    (a) Payload-only escalation: peer sets ``payload.action="private"``
        while presenting a ``ping`` visa. Dispatch routes on cap.action,
        so the request silently lands on ``ping`` and ``private`` is
        never reached.
    (b) Envelope tampering: peer mutates ``cap_envelope.action`` to
        ``"private"``. The gatekeeper-side store still holds the
        original cap; the tampered envelope is ignored (cap is loaded
        from store, not envelope) and dispatch again lands on ``ping``.
    """
    agent, calls = _gatekeeper(tmp_path)
    stranger = Stranger()

    visa_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    assert visa_res["status"] == "ok", visa_res
    visa = visa_res["payload"]["visa"]

    # (a) Payload-only escalation under the ping visa.
    task = _build_task_with_visa(
        stranger, agent._ensure_identity().agent_id, visa,
        nonce_to_sign=visa["nonce"],
        payload_extra={"action": "private", "echo": "escalate"},
    )
    agent._dispatch(task, remote_addr=_loopback_addr())

    # Pre-registered V1 threshold: action-Y handler must never run
    # under an action-X visa. We do NOT assert on the response code —
    # the substrate is allowed to silently route to action-X and ignore
    # the payload-action hint; what it MUST NOT do is invoke ``private``.
    assert calls["private"] == 0, (
        f"V1 BREACH: private handler invoked under ping visa "
        f"(ping={calls['ping']}, private={calls['private']})"
    )


# ---------------------------------------------------------------------------
# V2: Expired visa.
# ---------------------------------------------------------------------------

def test_v2_expired_visa_rejected(tmp_path, monkeypatch):
    agent, calls = _gatekeeper(tmp_path)
    stranger = Stranger()

    # Issue a visa with a 1-second expiry by injecting a custom policy.
    from pact_passport.visa import VisaContext, VisaGrant, Caveat as VisaCaveat
    short_expiry = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    agent._custom_visa_policy = lambda ctx: VisaGrant(caveats=[
        VisaCaveat(restrict="expires", value=short_expiry),
        VisaCaveat(restrict="max_invocations", value=1),
        VisaCaveat(restrict="no_further_delegation", value=True, terminal=True),
    ])

    visa_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    visa = visa_res["payload"]["visa"]

    # Wait past expiry.
    time.sleep(1.2)

    task = _build_task_with_visa(
        stranger, agent._ensure_identity().agent_id, visa,
        nonce_to_sign=visa["nonce"],
        payload_extra={"echo": "hi"},
    )
    res = agent._dispatch(task, remote_addr=_loopback_addr())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == "capability_invalid", res
    assert "expired" in res["fault"]["detail"].lower(), res


# ---------------------------------------------------------------------------
# V3: Compromised-holder receipt fidelity.
# ---------------------------------------------------------------------------

def test_v3_receipt_fidelity_under_compromise(tmp_path):
    agent, calls = _gatekeeper(tmp_path)
    stranger = Stranger()

    # 1. Get a visa.
    visa_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    visa = visa_res["payload"]["visa"]
    visa_cap_id = visa["cap_id"]
    nonce = visa["nonce"]
    fingerprint = visa["ephemeral_key_fingerprint"]

    # 2. Adversary (with compromised ephemeral key) uses it once → succeeds.
    task1 = _build_task_with_visa(
        stranger, agent._ensure_identity().agent_id, visa,
        nonce_to_sign=nonce, payload_extra={"echo": "first"},
    )
    res1 = agent._dispatch(task1, remote_addr=_loopback_addr())
    assert res1["status"] == "ok", res1

    # 3. Adversary tries again → max_invocations=1 fail.
    task2 = _build_task_with_visa(
        stranger, agent._ensure_identity().agent_id, visa,
        nonce_to_sign=nonce, payload_extra={"echo": "second"},
    )
    res2 = agent._dispatch(task2, remote_addr=_loopback_addr())
    assert res2["status"] == "error", res2
    assert res2["fault"]["code"] == "rate_limited", res2

    # Pre-registered V3 threshold: post-hoc enumeration of compromise
    # window from receipts ALONE — no out-of-band reconciliation.
    receipts = agent._store.list_receipts(agent.name)
    visa_events = [r for r in receipts if r.get("event_type", "").startswith("visa")]
    assert len(visa_events) >= 3, f"expected ≥3 visa events, got {visa_events}"

    required = {
        "visa_cap_id", "ephemeral_key_fingerprint", "action",
        "visa_nonce", "timestamp", "agent",
    }
    for r in visa_events:
        if r["event_type"] == "visa_grant":
            # Issuance receipt — same required field set.
            missing = required - r.keys()
            assert not missing, f"visa_grant missing fields {missing}: {r}"
        elif r["event_type"] == "visa_use":
            missing = required - r.keys()
            assert not missing, f"visa_use missing fields {missing}: {r}"
            assert r["visa_cap_id"] == visa_cap_id
            assert r["ephemeral_key_fingerprint"] == fingerprint
            assert r["action"] == "ping"
            assert r["visa_nonce"] == nonce

    # All three events must reference the same cap and fingerprint —
    # this is what lets the auditor enumerate the window.
    cap_ids = {r.get("visa_cap_id") for r in visa_events}
    fps = {r.get("ephemeral_key_fingerprint") for r in visa_events}
    assert cap_ids == {visa_cap_id}, cap_ids
    assert fps == {fingerprint}, fps


# ---------------------------------------------------------------------------
# V4: Escalation attempt — non-delegation is structurally enforced.
# ---------------------------------------------------------------------------

def test_v4_visa_cannot_be_delegated(tmp_path):
    agent, calls = _gatekeeper(tmp_path)
    stranger = Stranger()

    visa_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    visa = CapabilityToken.from_dict(visa_res["payload"]["visa"])

    # Attempt: stranger tries to attenuate the visa to a fresh victim.
    victim = Stranger()
    with pytest.raises(AttenuationViolation):
        attenuate(
            parent=visa,
            delegator_private_key=stranger.private_key,
            delegator_id=stranger.agent_id,
            new_holder_id=victim.agent_id,
            additional_caveats=[Caveat(restrict="max_invocations", value=1)],
        )


# ---------------------------------------------------------------------------
# V5: Nonce replay across request-pair.
# ---------------------------------------------------------------------------

def test_v5_nonce_replay_across_request_pair_rejected(tmp_path):
    agent, calls = _gatekeeper(tmp_path)
    stranger = Stranger()

    # Adversary captures fresh visa_A + holder_proof over nonce_A.
    visa_a_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    visa_a = visa_a_res["payload"]["visa"]
    nonce_a = visa_a["nonce"]
    captured_holder_proof_b64 = base64.b64encode(
        crypto.sign(nonce_a.encode(), stranger.private_key)
    ).decode("ascii")

    # Separately, gatekeeper issues visa_B with a fresh nonce_B.
    visa_b_res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_loopback_addr())
    visa_b = visa_b_res["payload"]["visa"]
    nonce_b = visa_b["nonce"]
    assert nonce_a != nonce_b, "nonces must be unique per visa"

    # Adversary presents visa_B but holder_proof from REQ_A (signing nonce_A).
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=stranger.agent_id,
        to_agent=agent._ensure_identity().agent_id,
        intent="task",
        cap_id=visa_b["cap_id"],
        cap_envelope=visa_b,
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        idempotency_key=str(uuid.uuid4()),
        payload={"echo": "replay"},
        identity_doc=stranger.identity_doc,
        holder_proof=captured_holder_proof_b64,  # signed nonce_A, NOT nonce_B
    )
    body = _sign_and_finalize(msg, stranger.private_key)

    res = agent._dispatch(body, remote_addr=_loopback_addr())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == "holder_proof_invalid", res


# ---------------------------------------------------------------------------
# V6: Parallel-issuance amplification — default cross-visa rate ceiling.
# ---------------------------------------------------------------------------

def test_v6_serial_issuance_respects_rate_ceiling(tmp_path):
    """Serial: 5 visas succeed, the 6th refuses with rate ceiling."""
    agent, calls = _gatekeeper(tmp_path)
    grants = 0
    refusals = 0
    for _ in range(6):
        stranger = Stranger()  # different ephemeral key each request
        res = agent._dispatch(
            _build_request_visa(stranger, "ping"),
            remote_addr=_loopback_addr(),  # SAME peer_network_id
        )
        if res["status"] == "ok":
            grants += 1
        else:
            refusals += 1
            assert res["fault"]["code"] == "denied", res
    assert grants == 5 and refusals == 1, (grants, refusals)


def test_v6_concurrent_issuance_serialized_per_peer(tmp_path):
    """Concurrent: 12 threads, same peer_network_id — exactly 5 grants.

    Closes the read-modify-write race on the rate counter. Without the
    per-peer issuance lock, two threads could each observe count=4 and
    both grant, blowing past the ceiling.
    """
    agent, calls = _gatekeeper(tmp_path)
    results = []
    lock = threading.Lock()

    def attempt():
        stranger = Stranger()
        res = agent._dispatch(
            _build_request_visa(stranger, "ping"),
            remote_addr=_loopback_addr(),
        )
        with lock:
            results.append(res["status"])

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    grants = sum(1 for s in results if s == "ok")
    refusals = sum(1 for s in results if s == "error")
    assert grants == 5, (grants, refusals, results)
    assert grants + refusals == 12, (grants, refusals)


# ---------------------------------------------------------------------------
# V7: Cross-issuer confusion — visa from Bob rejected at Alice.
# ---------------------------------------------------------------------------

def test_v7_cross_issuer_visa_rejected(tmp_path):
    alice, alice_calls = _gatekeeper(tmp_path, "alice")
    bob, bob_calls = _gatekeeper(tmp_path, "bob")
    stranger = Stranger()

    # Bob mints a visa for the stranger.
    bob_visa_res = bob._dispatch(
        _build_request_visa(stranger, "ping"), remote_addr=_loopback_addr(),
    )
    assert bob_visa_res["status"] == "ok"
    bob_visa = bob_visa_res["payload"]["visa"]

    # Stranger presents Bob's visa to Alice.
    task = _build_task_with_visa(
        stranger, alice._ensure_identity().agent_id, bob_visa,
        nonce_to_sign=bob_visa["nonce"],
        payload_extra={"echo": "cross"},
    )
    res = alice._dispatch(task, remote_addr=_loopback_addr())
    assert res["status"] == "error", res
    assert res["fault"]["code"] == "capability_invalid", res
    # Specifically the issuer check — see _step_verify_capability.
    assert (
        "issuer" in res["fault"]["detail"].lower()
        or "not this agent" in res["fault"]["detail"].lower()
    ), res
