"""Phase B adversary loop — LLM-driven exploratory red-team against PACT.

Per `PACT_RESEARCH_PLAN.md` §9 (post-Phase-A, explicitly non-confirmatory):
adversary LLM proposes attacks against a (role × property) target cell, harness
dispatches against a fresh PACT setup, observer classifies outcome and feeds
NL feedback back to the adversary. Memory: last 5 attempts in context.

Smoke target: KEY-COMP × P-AUTH (D1 Gap class B item — no current coverage
of fully compromised holder key). Single primitive `forge_message_with_stolen_key`.
After smoke validates the loop, factor primitives into `_adversary_primitives.py`
and targets into `_adversary_targets.py`, add the other 4 Gap-B targets.

Result schema:
  tests/stage2/adversary_runs/<UTC-ts>/<target>_<model>.jsonl   (one line per iter)
  tests/stage2/adversary_runs/<UTC-ts>/<target>_<model>_summary.json

Usage:
  PYTHONPATH=. python -m tests.stage2.adversary_loop \\
      --target "KEY-COMP × P-AUTH" \\
      --adversary gemma4:e4b \\
      --max-iters 30
"""
from __future__ import annotations

import argparse
import json
import platform
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    cross_share_identities,
    ollama_chat,
    record_llm_call,
    resolve_model_digest,
    stand_up_agent,
    teardown,
)


# ---------------------------------------------------------------------------
# DeepInfra adversary path (Phase B-2 — frontier-tier LLM via API).
# Borrows DEEPINFRA_API_KEY from ~/.local/env or process environment.
# ---------------------------------------------------------------------------

DEEPINFRA_ENDPOINT = "https://api.deepinfra.com/v1/openai/chat/completions"


def _load_deepinfra_key() -> str | None:
    """Read DEEPINFRA_API_KEY from process env or ~/.local/.env."""
    import os
    key = os.environ.get("DEEPINFRA_API_KEY")
    if key:
        return key
    env_path = Path.home() / ".local" / ".env"
    if not env_path.exists():
        return None
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("DEEPINFRA_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def deepinfra_chat(
    model: str,
    prompt: str,
    *,
    seed: int = 0,
    temperature: float = 0.7,
    max_tokens: int = 512,
    system: str | None = None,
    api_key: str | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """OpenAI-compatible chat completion via DeepInfra. Returns {text, raw, sampling}.

    Mirrors `ollama_chat()` shape so caller code can dispatch by flag without
    rewriting. Stdlib urllib only.
    """
    import urllib.request
    if api_key is None:
        api_key = _load_deepinfra_key()
    if not api_key:
        raise RuntimeError("DEEPINFRA_API_KEY not set in env or ~/.local/.env")

    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
    }
    req = urllib.request.Request(
        DEEPINFRA_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = json.loads(resp.read())
    text = raw.get("choices", [{}])[0].get("message", {}).get("content", "")
    return {
        "text": text,
        "raw": raw,
        "sampling": {"seed": seed, "temperature": temperature, "max_tokens": max_tokens},
    }


# ---------------------------------------------------------------------------
# Targets — Gap-B cells from D1_threat_coverage_matrix.md
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    name: str
    property: str
    adversary_role: str
    description: str
    primitives: tuple[str, ...]
    expected_outcome: str


TARGETS: tuple[Target, ...] = (
    Target(
        name="KEY-COMP × P-AUTH",
        property="P-AUTH",
        adversary_role="KEY-COMP",
        description=(
            "Adversary holds a compromised holder private key. Attempts to "
            "impersonate the legitimate holder in interactions with a target "
            "agent. The gap question: with a valid signature (because the key "
            "is real), is there any other defense that catches the impersonation?"
        ),
        primitives=("forge_message_with_stolen_key",),
        expected_outcome=(
            "PACT verifies messages via Ed25519 signature. With a stolen but "
            "valid key, the substrate cannot distinguish legitimate holder "
            "from impersonator. Forged messages predicted to be ACCEPTED. "
            "A REJECTION would indicate a hidden secondary defense."
        ),
    ),
    Target(
        name="KEY-COMP × P-BIND",
        property="P-BIND",
        adversary_role="KEY-COMP",
        description=(
            "Adversary has stolen Carol's private key. Carol is a legitimate "
            "cap holder. Adversary (Mallory) sends a REQ claiming to be Carol "
            "and carrying Carol's cap with a stolen-key-signed holder_proof. "
            "Tests whether holder-binding is enforced beyond signature check."
        ),
        primitives=("forge_holder_proof_with_stolen_key",),
        expected_outcome=(
            "With Carol's stolen key, the holder_proof signature verifies. "
            "The receiver cannot distinguish stolen-key use from legitimate "
            "Carol activity. Predicted: ACCEPTED. A REJECTION would indicate "
            "a defense beyond signature (e.g., transport-bound peer identity)."
        ),
    ),
    Target(
        name="DELEG-MAL × P-AUDIT",
        property="P-AUDIT",
        adversary_role="DELEG-MAL",
        description=(
            "A malicious intermediate party tampers with a signed receipt "
            "(e.g., modifies the payload bytes) before forwarding for audit. "
            "Tests whether downstream tamper of receipts is detectable via "
            "signature verification."
        ),
        primitives=("delegator_tamper_with_receipt",),
        expected_outcome=(
            "Receipts are signed via Ed25519 over canonicalized JSON. Any "
            "tamper of payload bytes breaks the signature. Predicted: tampered "
            "receipt FAILS verification. An ACCEPTANCE would indicate a "
            "signature-coverage gap (e.g., payload not covered by signature)."
        ),
    ),
    Target(
        name="MITM × P-BIND",
        property="P-BIND",
        adversary_role="MITM",
        description=(
            "A MITM attacker intercepts a REQ and reorders fields inside "
            "the cap_envelope (e.g., swaps key order in the envelope dict, "
            "reorders caveats array) before delivery to the receiver."
        ),
        primitives=("mitm_cap_envelope_reorder",),
        expected_outcome=(
            "PACT canonicalizes JSON (sorted keys, lexically-ordered fields) "
            "before signing. Reordering payload doesn't affect canonicalized "
            "bytes; signature still verifies. Predicted: ACCEPTED (canonical "
            "form unchanged) OR REJECTED (signature breaks). Either outcome "
            "is informative."
        ),
    ),
    Target(
        name="SYBIL × P-AUTH",
        property="P-AUTH",
        adversary_role="SYBIL",
        description=(
            "Adversary brute-forces a fresh keypair until finding one whose "
            "agent_id has a matching N-byte prefix with Alice's. Submits a "
            "REQ as the lookalike, carrying Alice's cap. Tests whether the "
            "receiver compares full agent_id or just a prefix."
        ),
        primitives=("sybil_lookalike_identity",),
        expected_outcome=(
            "agent_id is sha256(public_key); PACT compares full identifiers. "
            "Prefix-collision lookalike has a DIFFERENT full id and submits "
            "a holder_proof with their OWN key (which doesn't match Alice's "
            "cap holder_id). Predicted: REJECTED with holder_proof_invalid "
            "or capability_invalid. An ACCEPTANCE would indicate prefix-based "
            "comparison (P-AUTH defect)."
        ),
    ),
)
TARGETS_BY_NAME = {t.name: t for t in TARGETS}


# ---------------------------------------------------------------------------
# Primitives — concrete attacks dispatched by the harness
# ---------------------------------------------------------------------------

@dataclass
class SubstrateOutcome:
    primitive_name: str
    substrate_status: str | None
    substrate_fault_code: str | None
    substrate_payload: dict | None
    harness_error: str | None
    raw_response: dict | None


def forge_message_with_stolen_key(
    *,
    intent: str = "task",
    action: str = "ask",
    payload_extras: dict | None = None,
    **_unused,
) -> SubstrateOutcome:
    """KEY-COMP × P-AUTH primitive.

    Setup:
      - Alice (legitimate holder), Bob (target receiver). Bob has a pre-existing
        relationship with Alice — Bob has issued Alice a cap for `action`.
        Bob has a registered handler for `action` returning {"ok": true}.
      - Adversary has STOLEN Alice's private key.

    Action: Adversary uses Alice's stolen key to send a fresh REQ to Bob,
      authenticated as Alice, carrying the cap Bob already gave Alice +
      a valid-looking holder_proof signed with the stolen key.

    Test: with all signatures valid (because adversary has the key), is there
    any defense that catches the impersonation?

    Cap-direction rule (v0.6+): cap.issuer must equal req.to_id. So Bob (target)
    is cap issuer; Alice (compromised holder) is cap holder.
    """
    payload = {"action": action}
    if payload_extras:
        payload.update(payload_extras)

    with tempfile.TemporaryDirectory() as tmp:
        alice = stand_up_agent("alice-keycomp", Path(tmp) / "alice", host="127.0.0.1")
        bob = stand_up_agent("bob-keycomp", Path(tmp) / "bob", host="127.0.0.1")
        cross_share_identities(alice, bob)
        try:
            # Bob registers a handler so the action is dispatchable
            @bob["agent"].handle(action)
            def _handler(_p):
                return {"ok": True}

            stolen_priv = alice["private_key"]
            # Bob → Alice cap (correct direction per single-issuer rule)
            cap = issue_capability(
                issuer_private_key=bob["private_key"],
                issuer_id=bob["agent_id"],
                holder_id=alice["agent_id"],
                action=action,
            )
            # Adversary signs REQ with stolen Alice key
            req = build_req(
                from_private_key=stolen_priv,
                from_id=alice["agent_id"],
                to_id=bob["agent_id"],
                intent=intent,
                payload=payload,
                cap_envelope=cap.to_dict(),
                holder_proof_key=stolen_priv,
            )
            try:
                res = send_message(bob["url"], req)
                fault = (res or {}).get("fault") or {}
                return SubstrateOutcome(
                    primitive_name="forge_message_with_stolen_key",
                    substrate_status=res.get("status"),
                    substrate_fault_code=fault.get("code"),
                    substrate_payload=res.get("payload"),
                    harness_error=None,
                    raw_response=res,
                )
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="forge_message_with_stolen_key",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"dispatch error: {type(e).__name__}: {e}",
                    raw_response=None,
                )
        finally:
            teardown(alice, bob)


def forge_holder_proof_with_stolen_key(
    *,
    intent: str = "task",
    action: str = "ask",
    payload_extras: dict | None = None,
    **_unused,
) -> SubstrateOutcome:
    """KEY-COMP × P-BIND primitive.

    Carol (legitimate cap holder), Bob (cap issuer + receiver), Mallory (adversary).
    Mallory has stolen Carol's private key. Mallory sends REQ to Bob claiming
    to be Carol, carrying Carol's cap and a stolen-key-signed holder_proof.

    Mechanically identical to forge_message_with_stolen_key, but framed for the
    P-BIND target — the relevant question is whether holder-binding is enforced
    beyond signature.
    """
    payload = {"action": action}
    if payload_extras:
        payload.update(payload_extras)

    with tempfile.TemporaryDirectory() as tmp:
        carol = stand_up_agent("carol-pbind", Path(tmp) / "carol", host="127.0.0.1")
        bob = stand_up_agent("bob-pbind", Path(tmp) / "bob", host="127.0.0.1")
        cross_share_identities(carol, bob)
        try:
            @bob["agent"].handle(action)
            def _handler(_p):
                return {"ok": True}

            stolen_carol_priv = carol["private_key"]
            cap = issue_capability(
                issuer_private_key=bob["private_key"],
                issuer_id=bob["agent_id"],
                holder_id=carol["agent_id"],
                action=action,
            )
            req = build_req(
                from_private_key=stolen_carol_priv,
                from_id=carol["agent_id"],
                to_id=bob["agent_id"],
                intent=intent,
                payload=payload,
                cap_envelope=cap.to_dict(),
                holder_proof_key=stolen_carol_priv,
            )
            try:
                res = send_message(bob["url"], req)
                fault = (res or {}).get("fault") or {}
                return SubstrateOutcome(
                    primitive_name="forge_holder_proof_with_stolen_key",
                    substrate_status=res.get("status"),
                    substrate_fault_code=fault.get("code"),
                    substrate_payload=res.get("payload"),
                    harness_error=None,
                    raw_response=res,
                )
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="forge_holder_proof_with_stolen_key",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"dispatch error: {type(e).__name__}: {e}",
                    raw_response=None,
                )
        finally:
            teardown(carol, bob)


def delegator_tamper_with_receipt(
    *,
    tamper_field: str = "text",
    tamper_value: str = "MALICIOUS",
    intent: str = "task",
    action: str = "ask",
    **_unused,
) -> SubstrateOutcome:
    """DELEG-MAL × P-AUDIT primitive.

    Alice issues a request to Bob and receives a signed receipt. A malicious
    intermediate (Carol) modifies the receipt payload bytes (the named field)
    before re-signing or forwarding. We measure whether signature verification
    (on the tampered receipt against Bob's identity) catches the change.

    Adversary params: `tamper_field` (key in payload dict to overwrite),
    `tamper_value` (string to insert).
    """
    payload = {"action": action}

    with tempfile.TemporaryDirectory() as tmp:
        alice = stand_up_agent("alice-paudit", Path(tmp) / "alice", host="127.0.0.1")
        bob = stand_up_agent("bob-paudit", Path(tmp) / "bob", host="127.0.0.1")
        cross_share_identities(alice, bob)
        try:
            @bob["agent"].handle(action)
            def _handler(_p):
                return {"text": "legitimate response", "ok": True}

            cap = issue_capability(
                issuer_private_key=bob["private_key"],
                issuer_id=bob["agent_id"],
                holder_id=alice["agent_id"],
                action=action,
            )
            req = build_req(
                from_private_key=alice["private_key"],
                from_id=alice["agent_id"],
                to_id=bob["agent_id"],
                intent=intent,
                payload=payload,
                cap_envelope=cap.to_dict(),
                holder_proof_key=alice["private_key"],
            )
            try:
                res = send_message(bob["url"], req)
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="delegator_tamper_with_receipt",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"initial dispatch: {type(e).__name__}: {e}",
                    raw_response=None,
                )

            # Carol (DELEG-MAL) intercepts the receipt and tampers
            tampered = json.loads(json.dumps(res))  # deep copy
            if isinstance(tampered.get("payload"), dict):
                tampered["payload"][tamper_field] = tamper_value

            # Use PACT's actual PACTMessage.signable_dict() for verification.
            # The tamper is on the payload field; if that field is in signable_dict,
            # canonical bytes change → signature breaks. If unchanged, tamper IS
            # OUTSIDE signed scope → real signature-coverage finding.
            try:
                from pact_passport import crypto
                from pact_passport._canonical import canonical_json
                from pact_passport.message import PACTMessage
                import base64

                if "signature" not in tampered:
                    return SubstrateOutcome(
                        primitive_name="delegator_tamper_with_receipt",
                        substrate_status=None,
                        substrate_fault_code="no_signature_in_res",
                        substrate_payload={"verify_status": "no_signature"},
                        harness_error=None,
                        raw_response=tampered,
                    )

                # Reconstruct the original (untampered) message → bytes that were signed
                clean_msg = PACTMessage.from_dict(res)
                clean_bytes = canonical_json(clean_msg.signable_dict())
                tampered_msg = PACTMessage.from_dict(tampered)
                tampered_bytes = canonical_json(tampered_msg.signable_dict())
                bytes_changed = clean_bytes != tampered_bytes

                sig = base64.b64decode(tampered["signature"])
                bob_pub_bytes = bob["public_key"]
                # crypto.verify returns True/False, never raises
                ok = crypto.verify(tampered_bytes, sig, bob_pub_bytes)
                verify_status = "passed" if ok else "failed"
                verify_error = None if ok else "signature_invalid_on_tampered_bytes"

                return SubstrateOutcome(
                    primitive_name="delegator_tamper_with_receipt",
                    substrate_status=("ok" if verify_status == "passed" else "error"),
                    substrate_fault_code=(
                        None if verify_status == "passed" else f"verify_{verify_status}"
                    ),
                    substrate_payload={
                        "tampered_field": tamper_field,
                        "verify_status": verify_status,
                        "verify_error": verify_error,
                        "bytes_changed_by_tamper": bytes_changed,
                    },
                    harness_error=None,
                    raw_response=tampered,
                )
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="delegator_tamper_with_receipt",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"verify path: {type(e).__name__}: {e}",
                    raw_response=tampered,
                )
        finally:
            teardown(alice, bob)


def mitm_cap_envelope_reorder(
    *,
    reorder_strategy: str = "swap_keys",
    intent: str = "task",
    action: str = "ask",
    **_unused,
) -> SubstrateOutcome:
    """MITM × P-BIND primitive.

    Alice → Bob with a valid cap. MITM modifies the cap_envelope before sending:
    reorders the dict keys, reorders caveats, or appends junk keys.

    Strategies (adversary picks via `reorder_strategy` param):
      - "swap_keys"     : reverse dict key order in cap_envelope
      - "extra_field"   : add an unsigned extra field
      - "duplicate_key" : (limited — Python dicts dedupe) appends another caveat
    """
    import base64
    from pact_passport import crypto
    from pact_passport._canonical import canonical_json
    from pact_passport.message import PACTMessage
    from datetime import timedelta
    import uuid

    payload = {"action": action}

    with tempfile.TemporaryDirectory() as tmp:
        alice = stand_up_agent("alice-mitm", Path(tmp) / "alice", host="127.0.0.1")
        bob = stand_up_agent("bob-mitm", Path(tmp) / "bob", host="127.0.0.1")
        cross_share_identities(alice, bob)
        try:
            @bob["agent"].handle(action)
            def _handler(_p):
                return {"ok": True}

            cap = issue_capability(
                issuer_private_key=bob["private_key"],
                issuer_id=bob["agent_id"],
                holder_id=alice["agent_id"],
                action=action,
            )
            cap_dict = cap.to_dict()

            # Apply MITM mutation
            if reorder_strategy == "swap_keys":
                cap_dict = dict(reversed(list(cap_dict.items())))
            elif reorder_strategy == "extra_field":
                cap_dict["_mitm_injected"] = "MITM_PAYLOAD"
            elif reorder_strategy == "duplicate_key":
                if isinstance(cap_dict.get("caveats"), list):
                    cap_dict["caveats"] = cap_dict["caveats"] + cap_dict["caveats"]

            req = build_req(
                from_private_key=alice["private_key"],
                from_id=alice["agent_id"],
                to_id=bob["agent_id"],
                intent=intent,
                payload=payload,
                cap_envelope=cap_dict,
                holder_proof_key=alice["private_key"],
            )
            try:
                res = send_message(bob["url"], req)
                fault = (res or {}).get("fault") or {}
                return SubstrateOutcome(
                    primitive_name="mitm_cap_envelope_reorder",
                    substrate_status=res.get("status"),
                    substrate_fault_code=fault.get("code"),
                    substrate_payload=res.get("payload"),
                    harness_error=None,
                    raw_response=res,
                )
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="mitm_cap_envelope_reorder",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"dispatch error: {type(e).__name__}: {e}",
                    raw_response=None,
                )
        finally:
            teardown(alice, bob)


def sybil_lookalike_identity(
    *,
    prefix_bytes: int = 2,
    intent: str = "task",
    action: str = "ask",
    **_unused,
) -> SubstrateOutcome:
    """SYBIL × P-AUTH primitive.

    Brute-forces a fresh keypair until its agent_id matches Alice's first
    `prefix_bytes` bytes (capped at 3 to keep wall clock bounded). The
    lookalike then submits a REQ to Bob carrying Alice's cap and signing
    with the lookalike's own key.

    Tests: does the receiver compare full agent_id, or fall for the prefix
    match? Predicted: full-id comparison → REJECTED.
    """
    import base64
    from pact_passport import crypto

    payload = {"action": action}
    prefix_bytes = min(int(prefix_bytes), 3)  # cap for wall clock

    with tempfile.TemporaryDirectory() as tmp:
        alice = stand_up_agent("alice-sybil", Path(tmp) / "alice", host="127.0.0.1")
        bob = stand_up_agent("bob-sybil", Path(tmp) / "bob", host="127.0.0.1")
        cross_share_identities(alice, bob)
        try:
            @bob["agent"].handle(action)
            def _handler(_p):
                return {"ok": True}

            target_prefix = alice["agent_id"][: 7 + prefix_bytes * 2]
            lookalike_priv = lookalike_pub_b64 = lookalike_id = None
            max_attempts = 200_000
            attempts = 0
            while attempts < max_attempts:
                priv, pub = crypto.generate_keypair()
                pub_b64 = base64.b64encode(pub).decode("ascii")
                candidate_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
                if candidate_id.startswith(target_prefix):
                    lookalike_priv = priv
                    lookalike_pub_b64 = pub_b64
                    lookalike_id = candidate_id
                    break
                attempts += 1

            if lookalike_id is None:
                return SubstrateOutcome(
                    primitive_name="sybil_lookalike_identity",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=(
                        f"no prefix collision after {max_attempts} attempts "
                        f"(prefix_bytes={prefix_bytes})"
                    ),
                    raw_response=None,
                )

            cap = issue_capability(
                issuer_private_key=bob["private_key"],
                issuer_id=bob["agent_id"],
                holder_id=alice["agent_id"],
                action=action,
            )
            req = build_req(
                from_private_key=lookalike_priv,
                from_id=lookalike_id,
                to_id=bob["agent_id"],
                intent=intent,
                payload=payload,
                cap_envelope=cap.to_dict(),
                holder_proof_key=lookalike_priv,
            )
            try:
                res = send_message(bob["url"], req)
                fault = (res or {}).get("fault") or {}
                pl = res.get("payload") or {}
                pl_summary = {
                    "lookalike_id_prefix": lookalike_id[:7 + prefix_bytes * 2],
                    "alice_id_prefix": alice["agent_id"][:7 + prefix_bytes * 2],
                    "n_attempts": attempts,
                }
                return SubstrateOutcome(
                    primitive_name="sybil_lookalike_identity",
                    substrate_status=res.get("status"),
                    substrate_fault_code=fault.get("code"),
                    substrate_payload=pl_summary,
                    harness_error=None,
                    raw_response=res,
                )
            except Exception as e:
                return SubstrateOutcome(
                    primitive_name="sybil_lookalike_identity",
                    substrate_status=None,
                    substrate_fault_code=None,
                    substrate_payload=None,
                    harness_error=f"dispatch error: {type(e).__name__}: {e}",
                    raw_response=None,
                )
        finally:
            teardown(alice, bob)


PRIMITIVES: dict[str, Callable[..., SubstrateOutcome]] = {
    "forge_message_with_stolen_key": forge_message_with_stolen_key,
    "forge_holder_proof_with_stolen_key": forge_holder_proof_with_stolen_key,
    "delegator_tamper_with_receipt": delegator_tamper_with_receipt,
    "mitm_cap_envelope_reorder": mitm_cap_envelope_reorder,
    "sybil_lookalike_identity": sybil_lookalike_identity,
}


# ---------------------------------------------------------------------------
# Observer — classify substrate outcome vs target prediction + NL feedback
# ---------------------------------------------------------------------------

OutcomeClass = Literal["finding", "noise", "harness_error"]


@dataclass
class ObservedOutcome:
    classification: OutcomeClass
    nl_feedback: str
    summary: str


def observe(outcome: SubstrateOutcome, target: Target) -> ObservedOutcome:
    if outcome.harness_error:
        return ObservedOutcome(
            classification="harness_error",
            nl_feedback=(
                f"The harness failed to dispatch your attack: "
                f"{outcome.harness_error}. Try a different primitive or params."
            ),
            summary=f"harness_error: {outcome.harness_error[:80]}",
        )

    # KEY-COMP × * : substrate is EXPECTED to accept (no defense beyond signature).
    # A rejection = unexpected hidden defense = FINDING.
    if target.adversary_role == "KEY-COMP":
        if outcome.substrate_status == "ok":
            return ObservedOutcome(
                classification="noise",
                nl_feedback=(
                    f"Receiver ACCEPTED (status=ok). Matches expected outcome — "
                    f"with stolen but valid key, the substrate cannot distinguish "
                    f"impersonation at the {target.property} layer. To find a defect, "
                    f"vary intent strings, action names, or payload shapes to look "
                    f"for an UNEXPECTED rejection."
                ),
                summary=f"accepted (status=ok) — expected behavior at {target.property}",
            )
        if outcome.substrate_status == "error":
            return ObservedOutcome(
                classification="finding",
                nl_feedback=(
                    f"Receiver REJECTED with fault_code={outcome.substrate_fault_code}. "
                    f"UNEXPECTED — {target.property} should accept any valid signature. "
                    f"A hidden defense fired. Probe variations to characterize."
                ),
                summary=(
                    f"FINDING: unexpected rejection at {target.property} "
                    f"(fault={outcome.substrate_fault_code})"
                ),
            )

    # DELEG-MAL × P-AUDIT : tampered receipt should FAIL verify. ACCEPTANCE = finding.
    if target.name == "DELEG-MAL × P-AUDIT":
        pl = outcome.substrate_payload or {}
        verify_status = pl.get("verify_status")
        if verify_status == "failed":
            return ObservedOutcome(
                classification="noise",
                nl_feedback=(
                    "Receipt signature verification FAILED on the tampered receipt. "
                    "This is the expected outcome — signature covers the canonical "
                    "payload, tamper is detected. Vary the tamper_field and "
                    "tamper_value params to probe whether any field is NOT covered."
                ),
                summary=f"tamper detected (verify_failed) — expected",
            )
        if verify_status == "passed":
            return ObservedOutcome(
                classification="finding",
                nl_feedback=(
                    "Receipt signature verification PASSED on the tampered receipt. "
                    "UNEXPECTED — payload was modified but signature still verifies. "
                    "Likely a signature-coverage gap. Capture this and try variations."
                ),
                summary=f"FINDING: tampered receipt passed verification",
            )
        # no_signature or other
        return ObservedOutcome(
            classification="noise",
            nl_feedback=f"verify_status={verify_status}; not a finding.",
            summary=f"verify_status={verify_status}",
        )

    # MITM × P-BIND: both outcomes are expected depending on strategy.
    # - swap_keys: accept (canonical form unchanged) — expected
    # - extra_field: reject (signature breaks on new key) OR accept = defect
    # - duplicate_key: reject (canonical form changes) — expected
    # Classification: report substrate behavior; treat as noise unless extra_field
    # specifically slips through (which would be a real signature-coverage gap).
    if target.name == "MITM × P-BIND":
        if outcome.substrate_status == "ok":
            return ObservedOutcome(
                classification="noise",
                nl_feedback=(
                    f"Receiver ACCEPTED. For swap_keys this is expected — "
                    f"canonical_json sorts keys before signing, so reorder yields "
                    f"identical canonical form. For extra_field or duplicate_key, "
                    f"an acceptance WOULD be a finding — try those strategies."
                ),
                summary=(
                    f"tampered envelope accepted "
                    f"(likely canonical-form-equivalent reorder)"
                ),
            )
        if outcome.substrate_status == "error":
            return ObservedOutcome(
                classification="noise",
                nl_feedback=(
                    f"Receiver REJECTED with fault_code={outcome.substrate_fault_code}. "
                    f"Canonicalization or signature check caught the tamper. "
                    f"Try other reorder strategies (swap_keys, extra_field, duplicate_key)."
                ),
                summary=(
                    f"tamper rejected (fault={outcome.substrate_fault_code})"
                ),
            )

    # SYBIL × P-AUTH : lookalike submission should be REJECTED (full-id check).
    # ACCEPTANCE = finding (prefix-based comparison defect).
    if target.name == "SYBIL × P-AUTH":
        if outcome.substrate_status == "error":
            return ObservedOutcome(
                classification="noise",
                nl_feedback=(
                    f"Lookalike REJECTED with fault_code={outcome.substrate_fault_code}. "
                    f"This is expected — agent_id comparison uses the full hash. "
                    f"Try larger prefix_bytes (max 3) or different intent/action."
                ),
                summary=f"lookalike rejected (fault={outcome.substrate_fault_code}) — expected",
            )
        if outcome.substrate_status == "ok":
            return ObservedOutcome(
                classification="finding",
                nl_feedback=(
                    f"Lookalike ACCEPTED (status=ok). UNEXPECTED — full-id "
                    f"comparison should reject. Possible prefix-based comparison "
                    f"defect at P-AUTH. Vary params to characterize."
                ),
                summary=f"FINDING: lookalike accepted at P-AUTH",
            )

    return ObservedOutcome(
        classification="noise",
        nl_feedback=f"Outcome status={outcome.substrate_status}, no classification rule.",
        summary=f"unclassified (status={outcome.substrate_status})",
    )


# ---------------------------------------------------------------------------
# Adversary LLM — propose next attack from target context + prior attempts
# ---------------------------------------------------------------------------

ADVERSARY_SYSTEM = """You are a security researcher attempting to find protocol-level
defects in the PACT agent-trust substrate. Your job: PROPOSE concrete attacks against
a (role × property) target.

You will see TARGET, DESCRIPTION, EXPECTED_OUTCOME, available PRIMITIVES, and your
PRIOR ATTEMPTS. Respond with JSON only — no prose outside the JSON object:

{
  "rationale": "<one sentence — why might this variant find a defect>",
  "primitive": "<exactly one name from PRIMITIVES>",
  "params": { <primitive-specific knobs> }
}

If prior attempts all yielded expected behavior, vary edge cases: unusual intent
strings, unusual action names, payload shapes, near-collision parameter values.
"""


@dataclass
class AdversaryProposal:
    rationale: str
    primitive: str
    params: dict


def propose_attack(
    *,
    model: str,
    seed: int,
    target: Target,
    prior_attempts: list[dict],
    call_record_sink: dict,
    use_deepinfra: bool = False,
) -> AdversaryProposal | None:
    history_str = "\n".join(
        f"  iter {a['iteration']}: primitive={a['proposal']['primitive']}, "
        f"params={a['proposal']['params']} → {a['observed_summary']}"
        for a in prior_attempts[-5:]
    ) or "  (none yet)"

    user = (
        f"TARGET: {target.name}\n"
        f"DESCRIPTION: {target.description}\n"
        f"EXPECTED_OUTCOME: {target.expected_outcome}\n\n"
        f"PRIMITIVES: {list(target.primitives)}\n\n"
        f"PRIOR ATTEMPTS:\n{history_str}\n\n"
        f"Propose your next attack as JSON only."
    )

    if use_deepinfra:
        out = deepinfra_chat(
            model, user,
            seed=seed, temperature=0.8, max_tokens=512,
            system=ADVERSARY_SYSTEM,
        )
        record_llm_call(
            call_record_sink, model=model,
            seed=seed, temperature=0.8, num_predict=512,
            api="deepinfra",
        )
    else:
        out = ollama_chat(
            model, user,
            seed=seed, temperature=0.8, num_predict=512, think=False,
            system=ADVERSARY_SYSTEM,
        )
        record_llm_call(
            call_record_sink, model=model,
            seed=seed, temperature=0.8, num_predict=512,
        )

    text = out["text"].strip()
    # Strip prose around JSON object
    if "{" in text and "}" in text:
        start = text.index("{")
        end = text.rindex("}") + 1
        text = text[start:end]

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    primitive = parsed.get("primitive")
    if primitive not in target.primitives:
        return None
    return AdversaryProposal(
        rationale=str(parsed.get("rationale", ""))[:200],
        primitive=str(primitive),
        params=dict(parsed.get("params") or {}),
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _provenance() -> dict[str, Any]:
    try:
        git_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=2,
        ).stdout.strip()
    except Exception:
        git_sha = "unknown"
    return {
        "git_sha": git_sha,
        "host": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, choices=list(TARGETS_BY_NAME))
    p.add_argument("--adversary", required=True, help="Ollama model name or DeepInfra model id")
    p.add_argument("--use-deepinfra", action="store_true",
                   help="Route adversary calls through DeepInfra OpenAI-compatible API instead of local Ollama")
    p.add_argument("--max-iters", type=int, default=30)
    p.add_argument("--consec-no-finding", type=int, default=8)
    p.add_argument("--wall-clock-sec", type=int, default=1800)
    p.add_argument("--seed-base", type=int, default=0)
    args = p.parse_args()

    target = TARGETS_BY_NAME[args.target]
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(__file__).parent / "adversary_runs" / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_target = args.target.replace(" ", "_").replace("×", "x").replace("/", "_")
    safe_model = args.adversary.replace(":", "_").replace("/", "_").replace(".", "_")
    jsonl_path = out_dir / f"{safe_target}_{safe_model}.jsonl"
    summary_path = out_dir / f"{safe_target}_{safe_model}_summary.json"

    provenance = _provenance()
    if args.use_deepinfra:
        # API model digest is just the model id — no local manifest
        model_digest = f"deepinfra:{args.adversary}"
        # Pre-flight: ensure API key is loadable
        if not _load_deepinfra_key():
            print("FATAL: DEEPINFRA_API_KEY not in env or ~/.local/.env", file=sys.stderr)
            return 2
    else:
        model_digest = resolve_model_digest(args.adversary)

    print(f"=== Phase B adversary loop ===")
    print(f"  target       : {target.name}")
    print(f"  adversary    : {args.adversary}")
    print(f"  model_digest : {model_digest}")
    print(f"  out_dir      : {out_dir}")
    print(f"  max_iters    : {args.max_iters}")
    print()

    prior: list[dict] = []
    findings: list[dict] = []
    consec_no_finding = 0
    start_t = time.time()
    stop_reason = "max_iters"
    last_iter = -1

    for i in range(args.max_iters):
        last_iter = i
        elapsed = time.time() - start_t
        if elapsed > args.wall_clock_sec:
            stop_reason = "wall_clock"
            break

        seed = args.seed_base + i

        call_sink = {"llm_runtime": []}
        proposal = propose_attack(
            model=args.adversary, seed=seed, target=target,
            prior_attempts=prior, call_record_sink=call_sink,
            use_deepinfra=args.use_deepinfra,
        )

        iter_record: dict[str, Any] = {
            "ts_utc": datetime.now(UTC).isoformat(),
            "iteration": i,
            "target": target.name,
            "adversary": args.adversary,
            "model_digest": model_digest,
            "seed": seed,
            "llm_runtime": call_sink["llm_runtime"],
            "provenance": provenance,
        }

        if proposal is None:
            iter_record.update({
                "proposal": None,
                "outcome_classification": "harness_error",
                "observed_summary": "adversary emitted malformed JSON",
                "nl_feedback": None,
                "substrate_result": None,
            })
        else:
            try:
                outcome = PRIMITIVES[proposal.primitive](**proposal.params)
                observed = observe(outcome, target)
                substrate_result = {
                    "status": outcome.substrate_status,
                    "fault_code": outcome.substrate_fault_code,
                    "payload_keys": (
                        sorted(outcome.substrate_payload.keys())
                        if outcome.substrate_payload else None
                    ),
                    "harness_error": outcome.harness_error,
                }
            except Exception as e:
                outcome = None
                observed = ObservedOutcome(
                    classification="harness_error",
                    nl_feedback=f"primitive raised: {type(e).__name__}: {e}",
                    summary=f"primitive_exception: {type(e).__name__}: {e}",
                )
                substrate_result = None

            iter_record.update({
                "proposal": {
                    "rationale": proposal.rationale,
                    "primitive": proposal.primitive,
                    "params": proposal.params,
                },
                "substrate_result": substrate_result,
                "outcome_classification": observed.classification,
                "observed_summary": observed.summary,
                "nl_feedback": observed.nl_feedback,
            })

            prior.append({
                "iteration": i,
                "proposal": iter_record["proposal"],
                "observed_summary": observed.summary,
            })

            if observed.classification == "finding":
                findings.append(iter_record)
                consec_no_finding = 0
            else:
                consec_no_finding += 1

        with jsonl_path.open("a") as f:
            f.write(json.dumps(iter_record) + "\n")

        cls = iter_record["outcome_classification"]
        summary_line = (iter_record.get("observed_summary") or "")[:80]
        print(f"  iter {i:3d}  {cls:14s}  {summary_line}")

        if consec_no_finding >= args.consec_no_finding:
            stop_reason = "consecutive_no_finding"
            break

    elapsed_total = round(time.time() - start_t, 2)

    n_total = last_iter + 1
    n_findings = len(findings)
    n_noise = sum(
        1 for line in jsonl_path.read_text().splitlines()
        if '"outcome_classification": "noise"' in line
    )
    n_harness_error = sum(
        1 for line in jsonl_path.read_text().splitlines()
        if '"outcome_classification": "harness_error"' in line
    )

    summary = {
        "target": target.name,
        "adversary": args.adversary,
        "model_digest": model_digest,
        "started_at_utc": (
            datetime.fromtimestamp(start_t, UTC).isoformat()
        ),
        "finished_at_utc": datetime.now(UTC).isoformat(),
        "elapsed_s": elapsed_total,
        "iterations": n_total,
        "stopped_reason": stop_reason,
        "n_findings": n_findings,
        "n_noise": n_noise,
        "n_harness_error": n_harness_error,
        "findings_iterations": [f["iteration"] for f in findings],
        "provenance": provenance,
        "args": vars(args),
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    print()
    print(f"=== summary ===")
    print(f"  iterations    : {n_total}")
    print(f"  stopped       : {stop_reason}")
    print(f"  findings      : {n_findings}")
    print(f"  noise         : {n_noise}")
    print(f"  harness_error : {n_harness_error}")
    print(f"  elapsed       : {elapsed_total}s")
    print(f"  jsonl         : {jsonl_path}")
    print(f"  summary       : {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
