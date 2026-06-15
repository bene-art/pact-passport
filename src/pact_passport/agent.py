"""PACTAgent: high-level API wiring identity, capabilities, transport, and discovery."""

from __future__ import annotations

import base64
import binascii
import inspect
import logging
import signal
import sys
import threading
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterator

from zeroconf import Zeroconf

from pact_passport import _ablations, crypto
from pact_passport._canonical import canonical_json
from pact_passport._chaos import chaos_sleep
from pact_passport.identity import Identity
from pact_passport.capability import CapabilityToken, Caveat, issue_capability, verify_capability
from pact_passport.message import (
    PACTMessage, build_req, build_res, build_res_chunk, verify_message,
    verify_holder_proof, is_deadline_exceeded,
)
from pact_passport.errors import HandlerFailure
from pact_passport.receipt import create_receipt
from pact_passport.store import PACTStore
from pact_passport.transport.server import PACTServer
from pact_passport.transport.client import send_message, fetch_identity
from pact_passport.transport.discovery import (
    register_agent, unregister_agent, discover_agents, resolve_agent,
)
from pact_passport.visa import (
    HandlerCost,
    ProtocolAdvertisement,
    VisaContext,
    VisaGrant,
    VisaIssuanceTracker,
    VisaPolicy,
    VisaRefuse,
    derive_peer_network_id,
    issue_visa,
    make_default_visa_policy,
    verify_visa_holder_proof,
)

logger = logging.getLogger(__name__)

# Sentinel for deprecated `auto_grant` constructor argument. Distinguishes
# "caller passed nothing" from "caller passed True/False explicitly" so the
# deprecation warning only fires when the deprecated surface is actually used.
_AUTO_GRANT_UNSET = object()


@dataclass
class _DispatchCtx:
    """State shared across pipeline steps in PACTAgent._handle_task."""
    msg: PACTMessage
    identity: Identity
    sender_pub: bytes | None = None
    cap_token: CapabilityToken | None = None
    action: str = ""
    remote_addr: tuple | None = None


class PACTAgent:
    """A PACT protocol agent.

    Usage:
        agent = PACTAgent("alice", capabilities=["get_weather"])

        @agent.handle("get_weather")
        def weather(payload):
            return {"temp": 72}

        agent.serve()
    """

    def __init__(
        self,
        name: str,
        capabilities: list[str] | None = None,
        store_dir: Path | None = None,
        host: str = "0.0.0.0",
        port: int = 0,
        auto_grant: Any = _AUTO_GRANT_UNSET,
        idempotency_cache_max: int = 10_000,
        max_deadline_seconds: int = 3600,
        visa_policy: VisaPolicy | None = None,
        advertise_protocol: ProtocolAdvertisement | None = None,
    ):
        self.name = name
        self.capabilities = capabilities or []
        self.host = host
        self.port = port
        if auto_grant is not _AUTO_GRANT_UNSET:
            warnings.warn(
                "PACTAgent(auto_grant=...) is deprecated and has no effect "
                "since v0.5.1. Remove the argument; it will be removed in v1.0.",
                DeprecationWarning,
                stacklevel=2,
            )
            self.auto_grant = bool(auto_grant)
        else:
            self.auto_grant = True
        # Upper bound on REQ deadlines, server-side. A request whose
        # deadline lies further than this in the future is rejected at
        # message validation. Without this, an unbounded deadline +
        # a hung handler can hold the per-agent task lock indefinitely.
        # 3600s (1h) is a reasonable default for synchronous workloads;
        # bump it for very-long-running streaming intents.
        self.max_deadline_seconds = max_deadline_seconds
        self._handlers: dict[str, Callable] = {}
        self._store = PACTStore(store_dir)
        self._identity: Identity | None = None
        self._server: PACTServer | None = None
        self._zc: Zeroconf | None = None
        self._mdns_info = None
        # Idempotency cache + invocation counts are persisted per-agent
        # to disk (issue #5). Loaded lazily on first dispatch via
        # _ensure_state_loaded(). The lock below serializes both reads
        # and writes inside a single process.
        self._idempotency_cache: dict[str, tuple[dict, datetime]] = {}  # key → (response, expires)
        self._invocation_counts: dict[str, int] = {}  # cap_id → count
        self._state_loaded = False
        # LRU bound on the cache (issue #5 follow-up). Tunable via
        # idempotency_cache_max constructor arg.
        self._idempotency_cache_max = idempotency_cache_max
        self._task_lock = threading.Lock()
        # V-tier (v0.6). visa_eligible is opt-in at handler registration
        # via @agent.handle("...", visa_eligible=True); default is False
        # (refusal). Pass a custom visa_policy to override the locked
        # default — useful for tests that exercise specific failure modes.
        self._visa_eligible_actions: set[str] = set()
        self._handler_costs: dict[str, HandlerCost] = {}
        self._visa_tracker = VisaIssuanceTracker()
        self._custom_visa_policy = visa_policy
        # v1.3 / spec §16.5 — passive protocol advertisement. Default
        # None (absent on the wire); when set, the agent emits the
        # advertisement on visa-grant and structured-refusal
        # responses. The field is normatively inert on receive
        # (MUST-NOT consumed); no code path acts on a received value.
        self.advertise_protocol = advertise_protocol

    def _ensure_identity(self) -> Identity:
        """Load or create the agent's identity."""
        if self._identity:
            return self._identity
        if self._store.has_agent(self.name):
            self._identity = Identity.load(self.name, self._store)
        else:
            self._identity = Identity.create(self.name, self._store)
        return self._identity

    def _ensure_state_loaded(self) -> None:
        """Load idempotency cache + invocation counts from disk (issue #5).

        Called lazily on first dispatch; safe to call repeatedly. The
        on-disk format is JSON: cache values are [response, expires_iso].
        Expired entries are dropped on load.
        """
        if self._state_loaded:
            return
        raw = self._store.load_idempotency_cache(self.name)
        now = datetime.now(UTC)
        cache: dict[str, tuple[dict, datetime]] = {}
        for k, v in raw.items():
            try:
                response, expires_iso = v
                expires = datetime.fromisoformat(expires_iso)
                if expires > now:
                    cache[k] = (response, expires)
            except (ValueError, TypeError):
                continue  # corrupt entry, drop
        self._idempotency_cache = cache
        self._invocation_counts = self._store.load_invocation_counts(self.name)
        self._state_loaded = True

    def _persist_idempotency(self) -> None:
        """Write the idempotency cache to disk in JSON-serializable form."""
        serializable = {
            k: [resp, expires.isoformat()]
            for k, (resp, expires) in self._idempotency_cache.items()
        }
        self._store.save_idempotency_cache(self.name, serializable)

    def _persist_invocation_counts(self) -> None:
        self._store.save_invocation_counts(self.name, self._invocation_counts)

    def _persist_receipt(self, receipt: dict) -> None:
        """Save a receipt to the store, respecting §12.2 ABL_RECEIPT.

        When ABL_RECEIPT is active, the write is suppressed entirely.
        Predicted consequence: A4 / S5 lose post-hoc orphan
        detectability — the H3 audit-detectability claim is falsified
        for the ablated config (no receipts to reconstruct against).
        """
        if _ablations.ABL_RECEIPT:
            logger.warning(
                "ABL_RECEIPT active: receipt write suppressed (receipt_id=%s)",
                receipt.get("id") or receipt.get("receipt_id", "?")
                if isinstance(receipt, dict) else "?",
            )
            return
        self._store.save_receipt(self.name, receipt)

    def handle(
        self,
        action: str,
        visa_eligible: bool = False,
        cost: HandlerCost | None = None,
    ) -> Callable:
        """Decorator to register a handler for a capability action.

        Args:
            action: The capability action name.
            visa_eligible: V-tier opt-in. When True, the default visa
                policy will consider issuing visas for this action to
                passport-less peers. Default False (fail-closed).
            cost: Author-honest cost declaration for the default policy's
                ceiling checks (payload bytes, compute ms, idempotency).
                Only meaningful when visa_eligible=True.
        """
        def decorator(fn: Callable) -> Callable:
            self._handlers[action] = fn
            if visa_eligible:
                self._visa_eligible_actions.add(action)
                if cost is not None:
                    self._handler_costs[action] = cost
            return fn
        return decorator

    @property
    def _visa_policy(self) -> VisaPolicy:
        """The active visa policy. Built lazily so handler registration
        (which mutates _visa_eligible_actions and _handler_costs) is
        captured at first use, not at construction time.
        """
        if self._custom_visa_policy is not None:
            return self._custom_visa_policy
        return make_default_visa_policy(self._visa_eligible_actions, self._handler_costs)

    def _dispatch(self, body: dict, remote_addr: tuple | None = None) -> dict:
        """Handle an incoming PACT message.

        ``remote_addr`` is the transport-boundary client address
        ``(host, port)``. The V-tier visa policy derives
        ``peer_network_id`` from it (v0.6); legacy callers that don't
        pass it get ``None`` and the default policy refuses with
        ``peer_network_id unobservable``.
        """
        identity = self._ensure_identity()

        msg = PACTMessage.from_dict(body)

        # Intent: identity
        if msg.intent == "identity":
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                payload=identity.to_identity_document(),
            )
            return res.to_dict()

        # Intent: discover
        if msg.intent == "discover":
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                payload={"capabilities": self.capabilities},
            )
            return res.to_dict()

        # Intent: request_visa (V-tier, v0.6).
        if msg.intent == "request_visa":
            return self._handle_visa_request(msg, identity, remote_addr)

        # Intent: task
        if msg.intent == "task":
            return self._handle_task(msg, identity, remote_addr)

        # Unknown intent
        res = build_res(
            identity._private_key, identity.agent_id, msg,
            status="error",
            fault={"code": "unknown_intent", "detail": f"Unknown intent: {msg.intent}"},
        )
        return res.to_dict()

    def _handle_task(self, msg: PACTMessage, identity: Identity, remote_addr: tuple | None = None):
        """Process a task REQ via a pipeline of validators.

        Returns either a single dict (one-shot RES) or an iterator of
        dicts (streaming RES_CHUNKs). The HTTP layer routes on type.
        """
        ctx = _DispatchCtx(msg=msg, identity=identity, remote_addr=remote_addr)
        with self._task_lock:
            self._ensure_state_loaded()
            for step in (
                self._step_check_deadline,
                self._step_idempotency_lookup,
                self._step_verify_sender,
                self._step_verify_capability,
                self._step_resolve_action,
            ):
                result = step(ctx)
                if result is not None:
                    return result
            return self._step_run_handler(ctx)

    def _handle_visa_request(
        self,
        msg: PACTMessage,
        identity: Identity,
        remote_addr: tuple | None,
    ) -> dict:
        """Process a ``request_visa`` REQ from a passport-less peer.

        The peer presents an ephemeral identity_doc inline (TOFU). We
        verify it binds to their claimed agent_id, then run the visa
        policy with a gatekeeper-derived ``peer_network_id``. Grant →
        mint and return a visa cap with a server-issued nonce. Refuse →
        opaque ``denied`` to the peer, full rationale recorded only in
        our receipt. The issuance path is serialized per
        ``peer_network_id`` so the rate ceiling closes V6 race-free.
        """
        ctx = _DispatchCtx(msg=msg, identity=identity, remote_addr=remote_addr)

        # Stranger must present an ephemeral identity_doc inline. The
        # TOFU path binds it to a fresh agent_id derived from the key.
        if not msg.identity_doc:
            return self._dispatch_err(
                ctx, "visa_no_identity",
                "request_visa requires an inline identity_doc",
            )
        sender_pub = self._resolve_sender_key(msg.from_agent)
        if sender_pub is None:
            sender_pub = self._tofu_register(msg.from_agent, msg.identity_doc)
        if sender_pub is None:
            return self._dispatch_err(
                ctx, "visa_invalid_identity",
                "ephemeral identity_doc does not bind to claimed agent_id",
            )
        if not verify_message(msg, sender_pub):
            return self._dispatch_err(
                ctx, "visa_invalid_signature",
                "request_visa signature did not verify under presented identity",
            )
        ctx.sender_pub = sender_pub

        requested_action = msg.payload.get("action") if msg.payload else None
        if not isinstance(requested_action, str) or not requested_action:
            return self._dispatch_err(
                ctx, "visa_no_action",
                "request_visa payload must include {action: <str>}",
            )

        peer_network_id = derive_peer_network_id(remote_addr)
        payload_hash = crypto.sha256_digest(canonical_json(msg.payload or {}))
        ephemeral_fp = crypto.sha256_digest(sender_pub)

        # §4 concurrency note: serialize per peer_network_id so the
        # rate-ceiling read-modify-write cannot race across threads.
        peer_lock = self._visa_tracker.lock_for(peer_network_id)
        with peer_lock:
            recent_count = self._visa_tracker.recent_count(peer_network_id)
            # §12.2 ABL_RATE: hide accumulated count from the policy
            # so the rate ceiling is never tripped. Predicted newly-
            # passing attack: amplification (A6) — visa issuance per
            # peer becomes uncapped.
            if _ablations.ABL_RATE:
                logger.warning(
                    "ABL_RATE active: visa rate ceiling bypassed for peer %s (true count was %d)",
                    peer_network_id, recent_count,
                )
                recent_count = 0
            vctx = VisaContext(
                action=requested_action,
                payload_hash=payload_hash,
                peer_network_id=peer_network_id,
                recent_visa_count_window=recent_count,
                resource_headroom=1.0,
            )
            policy_result = self._visa_policy(vctx)

            if isinstance(policy_result, VisaRefuse):
                return self._build_visa_refusal(
                    msg, identity, policy_result.reason,
                    peer_network_id, ephemeral_fp, requested_action,
                    advertisement_override=policy_result.protocol_advertisement,
                )

            visa = issue_visa(
                issuer_private_key=identity._private_key,
                issuer_id=identity.agent_id,
                holder_id=msg.from_agent,
                action=requested_action,
                caveats=policy_result.caveats,
                ephemeral_key_fingerprint=ephemeral_fp,
            )
            self._store.save_capability(self.name, visa.to_dict())
            self._visa_tracker.record(peer_network_id)

        # Return the visa to the peer. The visa cap dict carries
        # visa=true + nonce + fingerprint — the peer presents the whole
        # thing as cap_envelope on the follow-up task REQ.
        grant_payload: dict = {
            "visa": visa.to_dict(),
            "nonce": visa.nonce,
        }
        # v1.3 / spec §16.5 — emit passive protocol advertisement when
        # configured. Per-decision override (policy_result.protocol_advertisement)
        # takes precedence over the agent default (self.advertise_protocol).
        # The field is signed by build_res (MITM tampering breaks
        # verification) and normatively inert on receive.
        advertisement = policy_result.protocol_advertisement or self.advertise_protocol
        if advertisement is not None:
            grant_payload["protocol_advertisement"] = advertisement.to_dict()
        res = build_res(
            identity._private_key, identity.agent_id, msg,
            payload=grant_payload,
        )
        self._store.save_message(self.name, msg.to_dict())
        self._store.save_message(self.name, res.to_dict())
        self._persist_receipt(create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id, refs=[msg.id, res.id], outcome="completed",
            extra={
                "event_type": "visa_grant",
                "visa_cap_id": visa.cap_id,
                "ephemeral_key_fingerprint": ephemeral_fp,
                "action": requested_action,
                "peer_network_id": peer_network_id,
                "visa_nonce": visa.nonce,
                "policy_id": "default_v0_6"
                             if self._custom_visa_policy is None
                             else "custom",
            },
        ))
        return res.to_dict()

    def _build_visa_refusal(
        self,
        msg: PACTMessage,
        identity: Identity,
        reason: str,
        peer_network_id: str,
        ephemeral_fp: str,
        action: str,
        advertisement_override: ProtocolAdvertisement | None = None,
    ) -> dict:
        """Refused-path: opaque ``denied`` to peer, full rationale only
        in our receipt (§3 *Refusal posture*).

        Optionally carries a passive ``protocol_advertisement`` (v1.3 /
        spec §16.5) in the refusal payload. The fault itself stays
        opaque (``denied``); the advertisement leaks one thing — that
        the gatekeeper speaks PACT — which is orthogonal to the policy
        rationale that the refusal continues to hide.
        """
        # v1.3 / spec §16.5 — per-decision override (from VisaRefuse)
        # takes precedence over the agent default.
        advertisement = advertisement_override or self.advertise_protocol
        refusal_payload: dict | None = None
        if advertisement is not None:
            refusal_payload = {"protocol_advertisement": advertisement.to_dict()}
        res = build_res(
            identity._private_key, identity.agent_id, msg,
            payload=refusal_payload,
            status="error",
            fault={"code": "denied", "detail": "denied"},
        )
        self._store.save_message(self.name, msg.to_dict())
        self._store.save_message(self.name, res.to_dict())
        self._persist_receipt(create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id, refs=[msg.id, res.id], outcome="failed",
            extra={
                "event_type": "visa_refused",
                "ephemeral_key_fingerprint": ephemeral_fp,
                "action": action,
                "peer_network_id": peer_network_id,
                "rationale": reason,
                "policy_id": "default_v0_6"
                             if self._custom_visa_policy is None
                             else "custom",
            },
        ))
        return res.to_dict()

    def _visa_receipt_extra(self, ctx: _DispatchCtx) -> dict:
        """V3 fidelity: when a visa is in play, every receipt records
        the audit fields needed to enumerate the compromise window from
        receipts alone — issuer, visa_cap_id, ephemeral_key_fingerprint,
        action, signed nonce, timestamp (timestamp is on every receipt
        already).
        """
        if not ctx.cap_token or not ctx.cap_token.visa:
            return {}
        return {
            "event_type": "visa_use",
            "visa_cap_id": ctx.cap_token.cap_id,
            "ephemeral_key_fingerprint": ctx.cap_token.ephemeral_key_fingerprint,
            "action": ctx.cap_token.action,
            "visa_nonce": ctx.cap_token.nonce,
        }

    # --- Dispatch pipeline steps ---

    def _step_check_deadline(self, ctx: _DispatchCtx) -> dict | None:
        if is_deadline_exceeded(ctx.msg):
            return self._dispatch_err(ctx, "deadline_exceeded", "Request deadline has passed")
        # Reject deadlines further in the future than max_deadline_seconds.
        # Prevents a malicious or buggy peer from pinning the task lock
        # with a year-2099 deadline.
        if ctx.msg.deadline:
            try:
                deadline_dt = datetime.fromisoformat(ctx.msg.deadline)
                horizon_s = (deadline_dt - datetime.now(UTC)).total_seconds()
                if horizon_s > self.max_deadline_seconds:
                    return self._dispatch_err(
                        ctx, "deadline_too_far",
                        f"Deadline {int(horizon_s)}s exceeds max {self.max_deadline_seconds}s",
                    )
            except (ValueError, TypeError):
                # Malformed deadline — let other validation steps handle.
                pass
        return None

    def _step_idempotency_lookup(self, ctx: _DispatchCtx) -> dict | Iterator[dict] | None:
        # Chaos hook: widens the cache-check + handler-execute window
        # under PACT_CHAOS=1. No effect in normal runs.
        chaos_sleep()
        msg = ctx.msg
        if msg.idempotency_key and msg.idempotency_key in self._idempotency_cache:
            cached_res, expires_at = self._idempotency_cache[msg.idempotency_key]
            if datetime.now(UTC) < expires_at:
                # Streaming replay: cached value is a list of chunk dicts.
                # Yield them back as a fresh iterator so the HTTP layer
                # streams them just like a fresh response (#11).
                if isinstance(cached_res, list):
                    return iter(cached_res)
                return cached_res  # one-shot replay
            del self._idempotency_cache[msg.idempotency_key]
        return None

    def _step_verify_sender(self, ctx: _DispatchCtx) -> dict | None:
        msg = ctx.msg
        sender_pub = self._resolve_sender_key(msg.from_agent)
        # Trust-on-first-use: an unknown peer providing an inline
        # identity_doc that derives correctly to its claimed agent_id
        # is auto-cached and accepted (issue #2).
        if sender_pub is None and msg.identity_doc:
            sender_pub = self._tofu_register(msg.from_agent, msg.identity_doc)
        if sender_pub is None:
            return self._dispatch_err(
                ctx, "unknown_peer",
                f"sender {msg.from_agent[:24]}... is not in peer cache "
                f"and no identity_doc was provided",
            )
        if not verify_message(msg, sender_pub):
            # Rotation refresh path (issue #4). The cached pubkey may be
            # stale because the sender rotated their keys. If they include
            # a fresh identity_doc, attempt a KERI-style continuity check:
            # the new pubkey's hash must match the cached doc's
            # next_key_digest. If it does, update the cache and retry.
            refreshed_pub = self._maybe_refresh_peer_after_rotation(msg)
            if refreshed_pub is not None and verify_message(msg, refreshed_pub):
                sender_pub = refreshed_pub
            else:
                return self._dispatch_err(ctx, "invalid_signature",
                                          "Message signature verification failed")
        ctx.sender_pub = sender_pub
        return None

    def _step_verify_capability(self, ctx: _DispatchCtx) -> dict | None:
        msg = ctx.msg
        if not msg.cap_id:
            return None  # falls through to payload-action lookup

        cap_dict = self._store.load_capability(self.name, msg.cap_id)
        from_envelope = False

        if not cap_dict and msg.cap_envelope:
            # Cap not in our store but provided inline — verify the chain
            # and cache it. This is what makes A→B→C delegation work
            # over the wire (issue #10).
            cap_dict = msg.cap_envelope
            if cap_dict.get("cap_id") != msg.cap_id:
                return self._dispatch_err(
                    ctx, "capability_invalid",
                    "cap_envelope.cap_id does not match msg.cap_id",
                )
            from_envelope = True
        elif not cap_dict:
            # cap_id claimed but neither local nor provided inline.
            # v0.4.0: reject explicitly instead of silently falling
            # through to action-name dispatch.
            return self._dispatch_err(
                ctx, "cap_unknown",
                f"cap_id {msg.cap_id[:24]}... not in local store and no cap_envelope provided",
            )

        token = CapabilityToken.from_dict(cap_dict)

        # The cap must have been issued by us (root issuer).
        if token.issuer != ctx.identity.agent_id:
            return self._dispatch_err(
                ctx, "capability_invalid",
                f"cap issuer {token.issuer[:24]}... is not this agent",
            )

        # For chain verification, gather pubkeys from peer cache.
        known_keys = self._build_known_keys_for_chain(ctx.identity, cap_dict)
        result = verify_capability(token, msg.from_agent, ctx.identity.public_key, known_keys)
        if not result.valid:
            return self._dispatch_err(ctx, "capability_invalid", result.reason)

        # If verified from envelope, cache it locally for future use.
        if from_envelope:
            self._store.save_capability(self.name, cap_dict)

        # Holder proof is mandatory when cap_id is present (issue #3).
        # §12.2 ABL_BIND: when active, bypass every holder-proof check
        # below (presence + signature + visa-nonce). The dispatch is
        # honored regardless. See src/pact_passport/_ablations.py.
        if _ablations.ABL_BIND:
            logger.warning(
                "ABL_BIND active: holder-proof bypassed for msg id=%s cap_id=%s",
                msg.id, getattr(token, "cap_id", "?"),
            )
        elif not msg.holder_proof:
            return self._dispatch_err(ctx, "holder_proof_required",
                                      "holder_proof is mandatory when cap_id is present")
        elif token.visa:
            # V-tier (v0.6). On a visa, holder_proof signs the visa's
            # server-issued nonce instead of msg.id. Closes V5 (nonce
            # replay across the request-pair).
            if not token.nonce:
                return self._dispatch_err(ctx, "visa_invalid", "visa carries no nonce")
            # §12.2 ABL_NONCE: bypass nonce-binding check on visa holder-proof.
            # Predicted newly-passing attack: visa replay (V5) — same
            # (visa, holder_proof) pair authorizes two distinct request-pairs.
            if _ablations.ABL_NONCE:
                logger.warning(
                    "ABL_NONCE active: visa nonce-binding bypassed for visa %s",
                    token.cap_id,
                )
            elif not verify_visa_holder_proof(msg.holder_proof, token.nonce, ctx.sender_pub):
                return self._dispatch_err(ctx, "holder_proof_invalid",
                                          "Visa holder-proof did not sign visa nonce")
        else:
            if not verify_holder_proof(msg, ctx.sender_pub):
                return self._dispatch_err(ctx, "holder_proof_invalid",
                                          "Holder proof verification failed")

        # V3 fidelity: bind the verified visa to ctx BEFORE the
        # rate-limit check so a rate-limited refusal still attributes
        # the attempt to the compromised visa in receipts. (Without
        # this, the second visa-use after compromise leaves no
        # ephemeral_key_fingerprint trail.)
        ctx.cap_token = token

        # Rate limit (max_invocations caveat). Read-then-increment is
        # serialized by the outer _task_lock.
        max_inv = self._get_max_invocations(token)
        if max_inv is not None:
            chaos_sleep()
            count = self._invocation_counts.get(token.cap_id, 0)
            if count >= max_inv:
                return self._dispatch_err(
                    ctx, "rate_limited",
                    f"max_invocations ({max_inv}) exceeded for cap {token.cap_id}",
                )
            self._invocation_counts[token.cap_id] = count + 1
            self._persist_invocation_counts()

        return None

    def _step_resolve_action(self, ctx: _DispatchCtx) -> dict | None:
        if ctx.cap_token:
            ctx.action = ctx.cap_token.action
        else:
            ctx.action = ctx.msg.payload.get("action", "")
        if ctx.action not in self._handlers:
            return self._dispatch_err(ctx, "no_handler",
                                      f"No handler for action: {ctx.action}")
        return None

    def _step_run_handler(self, ctx: _DispatchCtx) -> dict | Iterator[dict]:
        msg, identity = ctx.msg, ctx.identity
        handler = self._handlers[ctx.action]
        try:
            result = handler(msg.payload)
        except HandlerFailure as e:
            # Handler explicitly signalled failure with a custom fault.
            # Use the handler's fault code, not a generic handler_error.
            return self._dispatch_err(ctx, e.code, e.detail or str(e))
        except Exception as e:
            return self._dispatch_err(ctx, "handler_error", str(e))

        # Streaming path: handler returned a generator. We detect
        # specifically via inspect.isgenerator — NOT __iter__, which
        # would match lists, tuples, strings, dicts, etc. and stream
        # them incorrectly. Returning a generator is the contract.
        if inspect.isgenerator(result):
            return self._run_streaming_handler(ctx, result)

        # One-shot path (existing).
        res = build_res(
            identity._private_key, identity.agent_id, msg,
            payload=result if isinstance(result, dict) else {"result": result},
        )
        self._store.save_message(self.name, msg.to_dict())
        self._store.save_message(self.name, res.to_dict())
        self._persist_receipt(create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id, refs=[msg.id, res.id], outcome="completed",
            extra=self._visa_receipt_extra(ctx),
        ))

        result_dict = res.to_dict()
        self._cache_idempotent_response(msg, result_dict)
        return result_dict

    def _run_streaming_handler(self, ctx: _DispatchCtx, source) -> Iterator[dict]:
        """Wrap a generator handler: sign each yielded payload as a
        RES_CHUNK and collect for caching. Issue #11.

        Three exit paths, all of which produce a signed receipt:

        - **Normal completion**: outcome=``completed``; chunk_dicts has
          all chunks; idempotency cache populated for replay.
        - **Handler raised**: outcome=``failed``; last chunk is a
          signed error chunk; idempotency cache NOT populated (so a
          retry re-executes the handler).
        - **Consumer disconnect**: outcome=``cancelled``; chunk_dicts
          has whatever chunks were emitted before disconnect; cache
          NOT populated. Triggered by ``GeneratorExit`` raised at the
          suspended ``yield`` when the transport's
          ``_send_stream`` calls ``chunks_iter.close()`` after a
          ``BrokenPipeError``. The cancelled receipt closes Bug 7
          (GH #30) — see ``bug7_fix_design.md``.

        The receipt-write block lives in a ``finally`` so it runs on
        all three exit paths. ``outcome`` is a state variable
        initialized to ``cancelled``; completion and failure paths
        overwrite it explicitly. ``GeneratorExit`` (which is a
        ``BaseException``, not an ``Exception``) bypasses both
        explicit assignments, the default sticks, and the cancelled
        receipt records the partial chunk set.
        """
        msg, identity = ctx.msg, ctx.identity
        chunk_dicts: list[dict] = []
        outcome = "cancelled"   # default; overwritten on completed or failed
        seq = 0
        last_payload = None

        def _build_and_sign(payload, final):
            nonlocal seq
            chunk = build_res_chunk(
                identity._private_key, identity.agent_id, msg,
                chunk_seq=seq, chunk_final=final, payload=payload,
            )
            seq += 1
            return chunk.to_dict()

        try:
            try:
                for payload in source:
                    if last_payload is not None:
                        # Emit the previously held chunk as non-final
                        out = _build_and_sign(last_payload, final=False)
                        chunk_dicts.append(out)
                        yield out
                    last_payload = payload if isinstance(payload, dict) else {"result": payload}
                # Emit the final chunk
                if last_payload is None:
                    last_payload = {}  # empty stream
                out = _build_and_sign(last_payload, final=True)
                chunk_dicts.append(out)
                yield out
                outcome = "completed"
            except Exception as e:
                # Handler raised mid-stream; emit an error chunk as the terminal
                err_chunk = build_res_chunk(
                    identity._private_key, identity.agent_id, msg,
                    chunk_seq=seq, chunk_final=True,
                    payload={}, status="error",
                    fault={"code": "handler_error", "detail": str(e)},
                ).to_dict()
                chunk_dicts.append(err_chunk)
                yield err_chunk
                outcome = "failed"
            # GeneratorExit (consumer disconnect) is a BaseException —
            # not caught here; falls through to finally with outcome
            # still set to "cancelled".
        finally:
            # Persist + receipt on every exit path. Order matters:
            # idempotency cache MUST be written before the receipt and
            # ONLY on completed outcome. Cancelled streams don't
            # populate the cache — a retry with the same
            # idempotency_key should re-execute, not replay a partial.
            # Failed streams also don't cache — the error is a real
            # handler outcome, not something to replay (#11).
            self._store.save_message(self.name, msg.to_dict())
            for chunk in chunk_dicts:
                self._store.save_message(self.name, chunk)
            if msg.idempotency_key and outcome == "completed":
                self._cache_idempotent_response(msg, chunk_dicts)
            self._persist_receipt(create_receipt(
                identity._private_key, identity.agent_id,
                task_ref=msg.id,
                refs=[msg.id] + [c["id"] for c in chunk_dicts],
                outcome=outcome,
                extra=self._visa_receipt_extra(ctx),
            ))

    def _cache_idempotent_response(self, msg: PACTMessage, response) -> None:
        """Cache a one-shot dict OR a streaming chunk list under the
        idempotency_key. The value distinguishes shape on replay:
        list → re-stream; dict → one-shot."""
        if not msg.idempotency_key:
            return
        ttl = timedelta(seconds=60)
        if msg.deadline:
            try:
                deadline_dt = datetime.fromisoformat(msg.deadline)
                ttl = max(deadline_dt - datetime.now(UTC),
                          timedelta(seconds=10))
            except ValueError:
                pass
        self._idempotency_cache[msg.idempotency_key] = (
            response, datetime.now(UTC) + ttl,
        )
        self._evict_expired_cache()
        self._enforce_lru_cap()
        self._persist_idempotency()

    def _dispatch_err(self, ctx: _DispatchCtx, code: str, detail: str) -> dict:
        """Build a signed error response for any dispatch step.

        Also writes a signed `outcome=failed` receipt so the failure is
        part of the audit trail. Without this, timeouts and rejections
        leave no record on the receiver side, breaking the bilateral-
        receipt promise on failure paths.
        """
        res = build_res(
            ctx.identity._private_key, ctx.identity.agent_id, ctx.msg,
            status="error",
            fault={"code": code, "detail": detail},
        )
        # Persist the inbound REQ + signed error RES + a failed receipt.
        # save_message is idempotent on id, so writing both here is safe
        # even when an earlier dispatch step already wrote the inbound msg.
        self._store.save_message(self.name, ctx.msg.to_dict())
        self._store.save_message(self.name, res.to_dict())
        extra = self._visa_receipt_extra(ctx)
        if extra:
            extra["fault_code"] = code
        self._persist_receipt(create_receipt(
            ctx.identity._private_key, ctx.identity.agent_id,
            task_ref=ctx.msg.id, refs=[ctx.msg.id, res.id],
            outcome="failed",
            extra=extra,
        ))
        return res.to_dict()

    def _resolve_sender_key(self, agent_id: str) -> bytes | None:
        """Look up a sender's public key from peers cache.

        Returns None on a malformed cache entry (corrupt base64) instead
        of raising — caller treats it as "no key" and may trigger TOFU.
        """
        peer = self._store.load_peer(agent_id)
        if not peer or "public_key" not in peer:
            return None
        try:
            return base64.b64decode(peer["public_key"])
        except (binascii.Error, ValueError, TypeError):
            return None

    def _build_known_keys_for_chain(self, identity: Identity, cap_dict: dict) -> dict:
        """Collect pubkeys needed to verify a delegation chain (issue #10).

        Includes:
          - our own identity (root issuer if cap was minted here)
          - every delegator in the chain (from peer cache)
          - the holder (from peer cache)

        Missing keys cause verify_capability to fail closed (issue #8).
        """
        known: dict[str, bytes] = {identity.agent_id: identity.public_key}

        for link in cap_dict.get("delegation_chain", []):
            agent_id = link.get("from")
            if agent_id and agent_id not in known:
                pub = self._resolve_sender_key(agent_id)
                if pub is not None:
                    known[agent_id] = pub

        holder_id = cap_dict.get("holder")
        if holder_id and holder_id not in known:
            pub = self._resolve_sender_key(holder_id)
            if pub is not None:
                known[holder_id] = pub

        return known

    def _maybe_refresh_peer_after_rotation(self, msg: PACTMessage) -> bytes | None:
        """Try to refresh a stale peer pubkey using the REQ's inline doc.

        Issue #4 — when a peer rotates their keys, our cached pubkey is
        stale and verify_message fails. If the sender includes their new
        identity_doc, we can verify rotation continuity (KERI-style):

          hash(new_doc.public_key) == old_doc.next_key_digest

        Note: agent_id does NOT derive from the *current* public_key —
        it's anchored at inception. The continuity proof itself is what
        cryptographically binds the new key to the existing identity.

        Returns the verified new public_key bytes, or None if the
        continuity proof fails (treat as attack or unrecoverable stale).
        """
        if not msg.identity_doc:
            return None

        new_doc = msg.identity_doc
        new_pub_b64 = new_doc.get("public_key")
        if not new_pub_b64:
            return None

        # Sanity: doc must claim the same agent_id as the message sender.
        if new_doc.get("agent_id") != msg.from_agent:
            return None

        # Continuity check: the new pubkey's hash must match the prior
        # doc's pre-rotation commitment. This is the KERI binding —
        # without the original private key, the attacker can't have
        # known what next_key_digest the cached doc committed to.
        old_doc = self._store.load_peer(msg.from_agent)
        if not old_doc:
            return None
        old_next = old_doc.get("next_key_digest")
        if not old_next:
            return None
        try:
            new_pub = base64.b64decode(new_pub_b64)
        except (binascii.Error, ValueError, TypeError):
            return None
        if crypto.sha256_digest(new_pub) != old_next:
            return None

        # Continuity verified — update cache.
        self._store.save_peer(msg.from_agent, new_doc)
        return new_pub

    def _tofu_register(self, claimed_agent_id: str, identity_doc: dict) -> bytes | None:
        """Trust-on-first-use registration of an inline identity_doc.

        The sender claims `from_agent = claimed_agent_id` and includes a
        full identity_doc inline. We accept it ONLY IF the claimed agent_id
        derives cryptographically from the doc's public_key. After the
        check, we cache the doc as a peer.

        Returns the verified public_key bytes if the doc binds to the
        claimed agent_id, None otherwise.

        Note: this is genuinely "trust on first use" — an attacker can
        present any fresh identity, but they cannot impersonate an
        existing agent_id without that agent's private key. Combined with
        capability-scoped authorization (auto_grant=False), unknown peers
        cannot do anything they haven't been explicitly granted.
        """
        pub_b64 = identity_doc.get("public_key")
        if not pub_b64:
            return None
        # agent_id = sha256(alg || public_key_b64)
        derived = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        if derived != claimed_agent_id:
            return None
        if identity_doc.get("agent_id") != claimed_agent_id:
            return None
        # Decode pubkey defensively. If it's malformed base64, we reject
        # the TOFU registration without caching anything — treating it
        # the same as a failed agent_id derivation check.
        try:
            pub_bytes = base64.b64decode(pub_b64)
        except (binascii.Error, ValueError, TypeError):
            return None
        # Bind: cache the doc and return the pubkey
        self._store.save_peer(claimed_agent_id, identity_doc)
        return pub_bytes

    def ask(
        self,
        target: str,
        action: str,
        payload: dict | None = None,
        deadline_seconds: int = 30,
    ) -> dict:
        """Send a task REQ to another agent. Auto-handshake on first contact."""
        identity = self._ensure_identity()

        # Resolve target
        agent_info = resolve_agent(target)
        if not agent_info:
            return {"status": "error", "fault": {"code": "not_found", "detail": f"Agent '{target}' not found"}}

        base_url = f"http://{agent_info['host']}:{agent_info['port']}"

        # Auto-handshake: fetch identity if we don't have it
        peer = self._store.load_peer(agent_info["agent_id"])
        if not peer:
            peer = fetch_identity(base_url)
            if peer:
                self._store.save_peer(agent_info["agent_id"], peer)

        # Find a locally-stored capability for this issuer+action, if any.
        # Pre-v0.5.1 this had an `auto_grant` fallback path that called
        # an empty stub; the stub returned None unconditionally, so the
        # parameter was dead code. Removed in v0.5.1. To grant a peer
        # the right to call you, use `self.grant(holder_id, action, ...)`
        # explicitly before the peer sends its REQ.
        cap = self._find_capability_for(agent_info["agent_id"], action)

        # Build and send task REQ
        msg = build_req(
            from_private_key=identity._private_key,
            from_id=identity.agent_id,
            to_id=agent_info["agent_id"],
            intent="task",
            payload={**(payload or {}), "action": action},
            cap_id=cap.cap_id if cap else None,
            holder_proof_key=identity._private_key if cap else None,
            deadline_seconds=deadline_seconds,
        )

        result = send_message(base_url, msg, timeout=deadline_seconds)

        # Store message and receipt
        self._store.save_message(self.name, msg.to_dict())
        if "id" in result:
            self._store.save_message(self.name, result)

        outcome = "completed" if result.get("status") == "ok" else "failed"
        receipt = create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id,
            refs=[msg.id] + ([result["id"]] if "id" in result else []),
            outcome=outcome,
        )
        self._persist_receipt(receipt)

        return result

    def _find_capability_for(self, issuer_id: str, action: str) -> CapabilityToken | None:
        """Find a stored capability for this issuer+action."""
        for cap_dict in self._store.list_capabilities(self.name):
            cap = CapabilityToken.from_dict(cap_dict)
            if cap.issuer == issuer_id and cap.action == action:
                return cap
        return None


    @staticmethod
    def _get_max_invocations(token: CapabilityToken) -> int | None:
        """Get the effective max_invocations from a token's caveats (minimum of all)."""
        vals = [c.value for c in token.caveats if c.restrict == "max_invocations"]
        return min(vals) if vals else None

    def _evict_expired_cache(self) -> None:
        """Remove expired entries from the idempotency cache."""
        now = datetime.now(UTC)
        expired = [k for k, (_, exp) in self._idempotency_cache.items() if now >= exp]
        for k in expired:
            del self._idempotency_cache[k]

    def _enforce_lru_cap(self) -> None:
        """Bound the idempotency cache by oldest-expiry-first eviction.

        v0.3.0 LRU is approximate — we evict entries with earliest
        expires_at when the cap is exceeded. Real LRU would track
        access order, but for an idempotency cache "soonest to expire
        anyway" is a good-enough heuristic and avoids extra bookkeeping.
        """
        n = len(self._idempotency_cache)
        if n <= self._idempotency_cache_max:
            return
        excess = n - self._idempotency_cache_max
        # Sort by expires_at ascending; remove the earliest-expiring excess
        ordered = sorted(self._idempotency_cache.items(), key=lambda kv: kv[1][1])
        for key, _ in ordered[:excess]:
            del self._idempotency_cache[key]

    def grant(
        self,
        holder_id: str,
        action: str,
        caveats: list[Caveat] | None = None,
    ) -> CapabilityToken:
        """Issue a capability token to another agent."""
        identity = self._ensure_identity()
        token = issue_capability(
            identity._private_key, identity.agent_id, holder_id, action,
            caveats=caveats,
        )
        self._store.save_capability(self.name, token.to_dict())
        return token

    def revoke(self, cap_id: str) -> bool:
        """Revoke a previously issued capability."""
        cap_dict = self._store.load_capability(self.name, cap_id)
        if not cap_dict:
            return False
        cap_dict["revoked"] = True
        self._store.save_capability(self.name, cap_dict)
        return True

    def list_receipts(self) -> list[dict]:
        """Read-only access to this agent's authentic receipt store.

        Returns the list of signed receipts this agent itself wrote
        (one per dispatch, sorted by timestamp). Used by Stage 2 probes
        (A4 refs forgery, S5 receipt mimicry) to assert orphan-absent:
        a fabricated receipt-id or refs[] entry that was *accepted at
        the protocol layer* still does not appear as an authentic
        receipt in this store. Closes the construct-validity gap noted
        in `tests/stage2/probe_s5_receipt_mimicry.py`:94 ("we don't
        currently have a clean introspection of the store").

        No dispatch behavior change; pure read-only accessor wrapping
        ``self._store.list_receipts(self.name)``.
        """
        return self._store.list_receipts(self.name)

    def get_causal_chain(self, msg_id: str) -> list[dict]:
        """Walk the message DAG backwards from msg_id to reconstruct causal history."""
        chain = []
        visited = set()
        queue = [msg_id]
        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            msg = self._store.load_message(self.name, current_id)
            if msg:
                chain.append(msg)
                for ref in msg.get("refs", []):
                    if ref not in visited:
                        queue.append(ref)
        return chain

    def discover(self, timeout: float = 3.0) -> list[dict]:
        """Discover PACT agents on the local network."""
        return discover_agents(timeout)

    def serve(self, blocking: bool = True) -> int:
        """Start serving. Returns the port number.

        If blocking=True, blocks until Ctrl-C.
        """
        identity = self._ensure_identity()

        self._server = PACTServer(
            host=self.host,
            port=self.port,
            dispatch=self._dispatch,
            identity_doc=identity.to_identity_document(),
        )
        actual_port = self._server.start()
        self.port = actual_port

        # Register on mDNS
        self._zc = Zeroconf()
        self._mdns_info = register_agent(
            self._zc, self.name, identity.agent_id,
            actual_port, self.capabilities,
        )

        ip = self._mdns_info.parsed_addresses()[0] if self._mdns_info.addresses else "0.0.0.0"
        print(f"Serving {self.name} on http://{ip}:{actual_port} (agent_id: {identity.agent_id})")
        print(f"Capabilities: {self.capabilities}")
        print("Registered on local network via mDNS")
        print("Press Ctrl-C to stop")

        if blocking:
            try:
                signal.signal(signal.SIGINT, lambda *_: self.stop() or sys.exit(0))
                signal.signal(signal.SIGTERM, lambda *_: self.stop() or sys.exit(0))
                self._server._thread.join()
            except (KeyboardInterrupt, SystemExit):
                self.stop()

        return actual_port

    def stop(self) -> None:
        """Stop serving and unregister from mDNS."""
        if self._mdns_info and self._zc:
            try:
                unregister_agent(self._zc, self._mdns_info)
                self._zc.close()
            except Exception:
                pass
            self._zc = None
            self._mdns_info = None

        if self._server:
            self._server.stop()
            self._server = None

        print(f"\n{self.name} stopped.")
