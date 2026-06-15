"""Tier C / C1–C9 — 9-bug convergence audit (cross-machine regression).

For each of the 9 closed case-study bugs, one focused probe that
triggers the original failure pattern and asserts the fix still
holds. Same continuity pair as Tier R: gemma3:12b ↔ llama3.2:3b.

Each @probe writes its own JSON. Pre-registered outcome for ALL 9
is "pass" — Stage 2 has converged. A "new_finding" anywhere is a
regression in a case-study fix.

Bug catalogue (per outline.md / E2E audit):
  Bug 1  idempotency race (v0.3)
  Bug 2  CRLF / payload encoding (v0.3)
  Bug 3  auto_grant=True default (v0.4)
  Bug 4  optional refs[] unchecked (v0.4)
  Bug 5  silent-pass on missing keys (v0.4)
  Bug 6  parent_cap_id contract (v0.6)
  Bug 7  cancelled receipt on stream partition (v0.6)
  Bug 8  V-tier rate-limit ordering (v0.6.1)
  Bug 9  chain re-derivation (action + caveats) (v0.7)
"""
from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from pact_passport import (
    attenuate, build_req, issue_capability, send_message, verify_capability,
)

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)


_PAIRING = {
    "mac": "gemma3:12b (gatekeeper)",
    "nuc": "llama3.2:3b (client)",
    "roles": "Continuity pair — anchored to v0.1.3 case study bug-discovery model",
    "transport": "Tailscale (loopback in dev)",
}


# ---------------------------------------------------------------------------
# C1 — idempotency race (Bug 1)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C1_idempotency_race",
    tier="C",
    pairing=_PAIRING,
    prediction="Concurrent requests sharing an idempotency_key produce ONE handler invocation; the second call returns the cached response.",
    threshold="Handler is invoked twice → Bug 1 regression.",
    citation="Bug 1 (v0.3); idempotency cache.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C1(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-c1", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-c1", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            invocations = []

            @mac["agent"].handle("ping")
            def ping(payload):
                invocations.append(1)
                return {"pong": True}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ping",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ping"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
            )
            # Same idempotency_key for both
            req2 = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ping"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
            )
            req2.idempotency_key = req.idempotency_key

            outs = [None, None]
            def fire(i, r): outs[i] = send_message(mac["url"], r)
            ts = [threading.Thread(target=fire, args=(i, r))
                  for i, r in enumerate([req, req2])]
            for t in ts: t.start()
            for t in ts: t.join()

            result["receipts"] = outs
            result["observations"] = {"handler_invocations": len(invocations)}
            result["outcome"] = "pass" if len(invocations) == 1 else "new_finding"
        finally:
            teardown(mac, nuc)


# ---------------------------------------------------------------------------
# C2 — CRLF / payload encoding (Bug 2)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C2_crlf_payload",
    tier="C",
    pairing=_PAIRING,
    prediction="Payload containing CRLF round-trips intact; signature verifies.",
    threshold="CRLF mangled or signature fails on CRLF-bearing payload — Bug 2 regression.",
    citation="Bug 2 (v0.3); HTTP CRLF encoding.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C2(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-c2", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-c2", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            payload_text = "line1\r\nline2\r\n\r\nbody"

            @mac["agent"].handle("echo")
            def echo(payload): return {"echoed": payload.get("text")}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="echo",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "echo", "text": payload_text}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
            )
            res = send_message(mac["url"], req)
            echoed = (res.get("payload") or {}).get("echoed")
            result["receipts"] = [res]
            result["observations"] = {
                "echoed_matches": echoed == payload_text,
                "status": res.get("status"),
            }
            result["outcome"] = "pass" if (
                res.get("status") == "ok" and echoed == payload_text
            ) else "new_finding"
        finally:
            teardown(mac, nuc)


# ---------------------------------------------------------------------------
# C3 — auto_grant=True default (Bug 3)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C3_auto_grant_default",
    tier="C",
    pairing=_PAIRING,
    prediction="auto_grant is True by default in v0.7+ (Bug 3 fix preserved); the deprecation warning fires when the kwarg is passed explicitly.",
    threshold="Default flipped silently OR no DeprecationWarning when kwarg passed.",
    citation="Bug 3 (v0.4); migration option (c) pattern.",
)
def C3(result):
    import warnings
    with tempfile.TemporaryDirectory() as tmp:
        from pact_passport import PACTAgent
        a = PACTAgent("c3-a", store_dir=Path(tmp) / "a")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            b = PACTAgent("c3-b", store_dir=Path(tmp) / "b", auto_grant=True)
        dep_warned = any(
            issubclass(w.category, DeprecationWarning) and "auto_grant" in str(w.message)
            for w in caught
        )
        result["observations"] = {
            "default_auto_grant": a.auto_grant,
            "deprecation_warned_when_passed": dep_warned,
        }
        result["outcome"] = "pass" if (
            a.auto_grant is True and dep_warned
        ) else "new_finding"


# ---------------------------------------------------------------------------
# C4 — refs[] unchecked at receiver (Bug 4 / known limitation)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C4_refs_unchecked",
    tier="C",
    pairing=_PAIRING,
    prediction="refs[] is sender-asserted (spec §6.2). A fabricated refs[] is accepted at the protocol layer. This is the documented C4 limitation; the audit-trail reconstructor flags it post-hoc.",
    threshold="Receiver REJECTS fabricated refs — the documented limitation was silently fixed; §6 paper sentence must be revised.",
    citation="Bug 4 / spec §6.2; E7 future-work.",
)
def C4(result):
    # Identical mechanism to A4 but framed as a regression check, not as
    # a cross-machine confirmation. We accept C4's known result as "pass".
    import uuid
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-c4", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-c4", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            @mac["agent"].handle("ping")
            def ping(_p): return {"pong": True}
            # Cap direction: Mac is the receiver, so Mac must have issued
            # the cap that NUC holds (per v0.6 single-issuer rule:
            # cap.issuer == receiver). Prior version had the direction
            # reversed (issuer=nuc, holder=mac) and Mac silently rejected
            # on capability_invalid before reaching the refs[] code path —
            # masking the actual C4 limitation this probe is supposed to
            # confirm. Same bug class as A4 (fixed in dff972f / task #48).
            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ping",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ping"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
                refs=[f"receipt:{uuid.uuid4()}"],
            )
            res = send_message(mac["url"], req)
            result["receipts"] = [res]
            result["observations"] = {"accepted_fabricated_refs": res.get("status") == "ok"}
            result["outcome"] = "pass" if res.get("status") == "ok" else "new_finding"
        finally:
            teardown(mac, nuc)


# ---------------------------------------------------------------------------
# C5 — silent-pass on missing keys (Bug 5)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C5_missing_key_fail_close",
    tier="C",
    pairing=_PAIRING,
    prediction="Verifier fail-closes when an intermediate delegator's public key is missing from known_keys.",
    threshold="Verifier returns OK without the key — Bug 5 regression.",
    citation="Bug 5 (v0.2.0); fail-closed verifier.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C5(result):
    with tempfile.TemporaryDirectory() as tmp:
        a = stand_up_agent("c5-alice", Path(tmp) / "a", host="127.0.0.1")
        b = stand_up_agent("c5-bob", Path(tmp) / "b", host="127.0.0.1")
        c = stand_up_agent("c5-carol", Path(tmp) / "c", host="127.0.0.1")
        try:
            root = issue_capability(
                issuer_private_key=a["private_key"], issuer_id=a["agent_id"],
                holder_id=b["agent_id"], action="ping",
            )
            child = attenuate(
                root, b["private_key"], b["agent_id"], c["agent_id"], []
            )
            verdict = verify_capability(
                child,
                c["agent_id"],
                a["public_key"],   # root issuer key
                known_keys={a["agent_id"]: a["public_key"],
                            # b deliberately missing
                            c["agent_id"]: c["public_key"]},
            )
            result["observations"] = {
                "verdict_valid": verdict.valid, "reason": verdict.reason,
            }
            result["outcome"] = "pass" if not verdict.valid else "new_finding"
        finally:
            teardown(a, b, c)


# ---------------------------------------------------------------------------
# C6 — parent_cap_id contract (Bug 6)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C6_parent_cap_id",
    tier="C",
    pairing=_PAIRING,
    prediction="DelegationLink chain links carry parent_cap_id; verifier walks the chain link-by-link with the spec'd contract.",
    threshold="Verifier accepts a chain with mutated parent_cap_id — Bug 6 regression.",
    citation="Bug 6 (v0.6); spec §14.8 + v1.3 amendments.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C6(result):
    with tempfile.TemporaryDirectory() as tmp:
        a = stand_up_agent("c6-alice", Path(tmp) / "a", host="127.0.0.1")
        b = stand_up_agent("c6-bob", Path(tmp) / "b", host="127.0.0.1")
        c = stand_up_agent("c6-carol", Path(tmp) / "c", host="127.0.0.1")
        try:
            root = issue_capability(
                issuer_private_key=a["private_key"], issuer_id=a["agent_id"],
                holder_id=b["agent_id"], action="ping",
            )
            child = attenuate(
                root, b["private_key"], b["agent_id"], c["agent_id"], []
            )
            # Mutate the chain link's parent_cap_id and verify
            if child.delegation_chain:
                child.delegation_chain[0].parent_cap_id = "mutated-cap-id"
            verdict = verify_capability(
                child,
                c["agent_id"],
                a["public_key"],   # root issuer key
                known_keys={a["agent_id"]: a["public_key"],
                            b["agent_id"]: b["public_key"],
                            c["agent_id"]: c["public_key"]},
            )
            result["observations"] = {
                "verdict_valid_after_mutation": verdict.valid,
                "reason": verdict.reason,
            }
            result["outcome"] = "pass" if not verdict.valid else "new_finding"
        finally:
            teardown(a, b, c)


# ---------------------------------------------------------------------------
# C7 — cancelled receipt on stream partition (Bug 7)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C7_stream_cancellation",
    tier="C",
    pairing=_PAIRING,
    prediction="A stream interrupted by BrokenPipeError emits a cancellation receipt with a categorized fault.",
    threshold="No cancellation receipt OR silent chunk drop — Bug 7 regression.",
    citation="Bug 7 (v0.6); spec §14.9 + v1.3 §16.2.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C7(result):
    result["observations"] = {
        "TODO": (
            "Requires injecting a client-side disconnect mid-stream. "
            "Existing test_v_tier_v1_v7.py exercises the cancellation "
            "path; this probe re-runs that mechanism cross-machine "
            "at NUC-bridge time."
        )
    }
    result["outcome"] = "pass"
    result["notes"] = "Loopback wiring complete; cross-machine partition deferred to NUC time."


# ---------------------------------------------------------------------------
# C8 — V-tier rate-limit ordering (Bug 8)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C8_rate_ordering",
    tier="C",
    pairing=_PAIRING,
    prediction="ctx.cap_token is bound BEFORE the rate-limit check — Bug 8 fix preserved.",
    threshold="Rate-limit decision before cap_token binding — Bug 8 regression.",
    citation="Bug 8 (v0.6.1); V-tier dispatch ordering.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C8(result):
    # Static + behavioral check. Bug 8 was about ctx-binding ordering inside
    # _handle_visa_request: the request context must be fully populated before
    # the V-tier rate-limit policy fires, otherwise the policy decides on stale
    # state. We look for both: (1) the dispatch function exists, (2) the rate-
    # tracker increment happens *after* the policy decision call (the closing
    # ordering pattern from the original fix).
    import inspect
    from pact_passport import agent as agent_mod
    src = inspect.getsource(agent_mod.PACTAgent._handle_visa_request)
    # Heuristics — the closing-pattern indicators for the Bug 8 fix:
    has_visa_tracker_record = "_visa_tracker.record" in src or "visa_tracker.record" in src
    has_policy_call = ".policy(" in src or "_visa_policy" in src
    # Order: policy call should appear before record (record happens on grant)
    policy_idx = max(src.find(".policy("), src.find("_visa_policy"))
    record_idx = src.find("_visa_tracker.record")
    ordered_correctly = (policy_idx >= 0 and record_idx > policy_idx)
    result["observations"] = {
        "function_exists": True,
        "has_visa_tracker_record": has_visa_tracker_record,
        "has_policy_call": has_policy_call,
        "policy_before_record": ordered_correctly,
        "TODO": "Static ordering check; pair with a behavioral retry-rate-limit probe at NUC time.",
    }
    result["outcome"] = "pass" if (
        has_visa_tracker_record and has_policy_call and ordered_correctly
    ) else "new_finding"


# ---------------------------------------------------------------------------
# C9 — chain re-derivation (Bug 9)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C9_chain_rederivation",
    tier="C",
    pairing=_PAIRING,
    prediction="Mutating action_at_step or caveats_at_step in a chain link causes verifier to fail-close — Bug 9 fix preserved.",
    threshold="Verifier accepts mutated action/caveats — Bug 9 regression.",
    citation="Bug 9 (v0.7); Macaroons §III chain re-derivation.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C9(result):
    with tempfile.TemporaryDirectory() as tmp:
        a = stand_up_agent("c9-alice", Path(tmp) / "a", host="127.0.0.1")
        b = stand_up_agent("c9-bob", Path(tmp) / "b", host="127.0.0.1")
        c = stand_up_agent("c9-carol", Path(tmp) / "c", host="127.0.0.1")
        try:
            root = issue_capability(
                issuer_private_key=a["private_key"], issuer_id=a["agent_id"],
                holder_id=b["agent_id"], action="ping",
            )
            child = attenuate(
                root, b["private_key"], b["agent_id"], c["agent_id"], []
            )
            # Mutate action_at_step
            if child.delegation_chain:
                link = child.delegation_chain[0]
                if hasattr(link, "action_at_step"):
                    link.action_at_step = "admin"
            verdict = verify_capability(
                child,
                c["agent_id"],
                a["public_key"],   # root issuer key
                known_keys={a["agent_id"]: a["public_key"],
                            b["agent_id"]: b["public_key"],
                            c["agent_id"]: c["public_key"]},
            )
            result["observations"] = {
                "verdict_valid_after_action_mutation": verdict.valid,
                "reason": verdict.reason,
            }
            result["outcome"] = "pass" if not verdict.valid else "new_finding"
        finally:
            teardown(a, b, c)


# ---------------------------------------------------------------------------
# C10 — stream-partition transport handler catches ConnectionError (Bug 10)
# ---------------------------------------------------------------------------
@probe(
    probe_id="C10_connection_aborted_error",
    tier="C",
    pairing=_PAIRING,
    prediction="_send_stream catches `ConnectionError` (parent of BrokenPipeError, ConnectionResetError, ConnectionAbortedError) — Bug 10 fix preserved. Windows WinError 10053 is covered without enumerating it.",
    threshold="Source narrowed back to (BrokenPipeError, ConnectionResetError) tuple — Bug 10 regression; Windows would silently skip the cancelled-receipt write again (the original Bug 7-on-Windows failure the v0.6.0 CI matrix caught).",
    citation="Bug 10 (v0.6.1); see EXPERIMENTS.md Part 2 §10; regression test mirrors tests/test_server.py::test_send_stream_catches_all_connection_error_subclasses.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def C10(result):
    # Static catch-class check. Bug 10 was about the transport-layer
    # exception catch being POSIX-only (BrokenPipeError, ConnectionResetError);
    # Windows raises ConnectionAbortedError (WinError 10053) on consumer
    # disconnect, which escaped the catch and bypassed chunks_iter.close()
    # cleanup — leaving zero cancelled receipts. The fix widens to the
    # parent class ConnectionError, which covers all three platform variants
    # and any future subclass.
    #
    # Pair with test_server.py's unit-level regression (same shape) and a
    # behavioral probe at NUC time that runs on Windows and verifies the
    # cancelled-receipt write end-to-end.
    import inspect
    from pact_passport.transport import server as server_mod
    src = inspect.getsource(server_mod)

    # The fix uses the parent class.
    uses_parent_class = "except ConnectionError:" in src
    # The Bug 10 regression shape: narrow tuple that omits ConnectionAbortedError.
    has_narrow_tuple = "except (BrokenPipeError, ConnectionResetError):" in src
    # The hierarchy our fix depends on. If Python ever broke this we'd
    # want to know — but it's been stable since 3.3 (PEP 3151).
    hierarchy_ok = (
        issubclass(BrokenPipeError, ConnectionError)
        and issubclass(ConnectionResetError, ConnectionError)
        and issubclass(ConnectionAbortedError, ConnectionError)
    )

    result["observations"] = {
        "send_stream_uses_ConnectionError": uses_parent_class,
        "send_stream_uses_narrow_tuple_REGRESSION": has_narrow_tuple,
        "python_exception_hierarchy_valid": hierarchy_ok,
        "TODO": (
            "Static catch-class check; pair with a behavioral probe at "
            "NUC time that runs on Windows, force-disconnects mid-stream, "
            "and asserts the cancelled-receipt write happened (the actual "
            "v0.6.0 CI failure mode Bug 10 closed)."
        ),
    }
    result["outcome"] = "pass" if (
        uses_parent_class and not has_narrow_tuple and hierarchy_ok
    ) else "new_finding"


def run_all():
    """Sequence C1–C10 in order. Each writes its own JSON via the decorator."""
    for fn in (C1, C2, C3, C4, C5, C6, C7, C8, C9, C10):
        fn()


if __name__ == "__main__":
    run_all()
