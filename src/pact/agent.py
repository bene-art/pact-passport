"""PACTAgent: high-level API wiring identity, capabilities, transport, and discovery."""

from __future__ import annotations

import base64
import inspect
import logging
import signal
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Any, Iterator

from zeroconf import Zeroconf

from pact import crypto
from pact._chaos import chaos_sleep
from pact.identity import Identity
from pact.capability import CapabilityToken, Caveat, issue_capability, verify_capability, attenuate
from pact.message import (
    PACTMessage, build_req, build_res, build_res_chunk, verify_message,
    verify_holder_proof, is_deadline_exceeded,
)
from pact.receipt import create_receipt
from pact.store import PACTStore
from pact.transport.server import PACTServer
from pact.transport.client import send_message, fetch_identity
from pact.transport.discovery import (
    register_agent, unregister_agent, discover_agents, resolve_agent,
)

logger = logging.getLogger(__name__)


@dataclass
class _DispatchCtx:
    """State shared across pipeline steps in PACTAgent._handle_task."""
    msg: PACTMessage
    identity: Identity
    sender_pub: bytes | None = None
    cap_token: CapabilityToken | None = None
    action: str = ""


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
        auto_grant: bool = True,  # deprecated v0.5.1 — has no effect
        idempotency_cache_max: int = 10_000,
    ):
        self.name = name
        self.capabilities = capabilities or []
        self.host = host
        self.port = port
        self.auto_grant = auto_grant
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
        now = datetime.now(timezone.utc)
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

    def handle(self, action: str) -> Callable:
        """Decorator to register a handler for a capability action."""
        def decorator(fn: Callable) -> Callable:
            self._handlers[action] = fn
            return fn
        return decorator

    def _dispatch(self, body: dict) -> dict:
        """Handle an incoming PACT message."""
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

        # Intent: task
        if msg.intent == "task":
            return self._handle_task(msg, identity)

        # Unknown intent
        res = build_res(
            identity._private_key, identity.agent_id, msg,
            status="error",
            fault={"code": "unknown_intent", "detail": f"Unknown intent: {msg.intent}"},
        )
        return res.to_dict()

    def _handle_task(self, msg: PACTMessage, identity: Identity):
        """Process a task REQ via a pipeline of validators.

        Returns either a single dict (one-shot RES) or an iterator of
        dicts (streaming RES_CHUNKs). The HTTP layer routes on type.
        """
        ctx = _DispatchCtx(msg=msg, identity=identity)
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

    # --- Dispatch pipeline steps ---

    def _step_check_deadline(self, ctx: "_DispatchCtx") -> dict | None:
        if is_deadline_exceeded(ctx.msg):
            return self._dispatch_err(ctx, "deadline_exceeded", "Request deadline has passed")
        return None

    def _step_idempotency_lookup(self, ctx: "_DispatchCtx") -> dict | Iterator[dict] | None:
        # Chaos hook: widens the cache-check + handler-execute window
        # under PACT_CHAOS=1. No effect in normal runs.
        chaos_sleep()
        msg = ctx.msg
        if msg.idempotency_key and msg.idempotency_key in self._idempotency_cache:
            cached_res, expires_at = self._idempotency_cache[msg.idempotency_key]
            if datetime.now(timezone.utc) < expires_at:
                # Streaming replay: cached value is a list of chunk dicts.
                # Yield them back as a fresh iterator so the HTTP layer
                # streams them just like a fresh response (#11).
                if isinstance(cached_res, list):
                    return iter(cached_res)
                return cached_res  # one-shot replay
            del self._idempotency_cache[msg.idempotency_key]
        return None

    def _step_verify_sender(self, ctx: "_DispatchCtx") -> dict | None:
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

    def _step_verify_capability(self, ctx: "_DispatchCtx") -> dict | None:
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
        if not msg.holder_proof:
            return self._dispatch_err(ctx, "holder_proof_required",
                                      "holder_proof is mandatory when cap_id is present")
        if not verify_holder_proof(msg, ctx.sender_pub):
            return self._dispatch_err(ctx, "holder_proof_invalid",
                                      "Holder proof verification failed")

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

        ctx.cap_token = token
        return None

    def _step_resolve_action(self, ctx: "_DispatchCtx") -> dict | None:
        if ctx.cap_token:
            ctx.action = ctx.cap_token.action
        else:
            ctx.action = ctx.msg.payload.get("action", "")
        if ctx.action not in self._handlers:
            return self._dispatch_err(ctx, "no_handler",
                                      f"No handler for action: {ctx.action}")
        return None

    def _step_run_handler(self, ctx: "_DispatchCtx") -> dict | Iterator[dict]:
        msg, identity = ctx.msg, ctx.identity
        handler = self._handlers[ctx.action]
        try:
            result = handler(msg.payload)
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
        self._store.save_receipt(self.name, create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id, refs=[msg.id, res.id], outcome="completed",
        ))

        result_dict = res.to_dict()
        self._cache_idempotent_response(msg, result_dict)
        return result_dict

    def _run_streaming_handler(self, ctx: "_DispatchCtx", source) -> Iterator[dict]:
        """Wrap a generator handler: sign each yielded payload as a
        RES_CHUNK and collect for caching. Issue #11.

        On normal completion: writes a single receipt referencing all
        chunks, caches the chunk list under idempotency_key.
        On generator failure (handler raised): emits an error chunk
        with chunk_final=true and writes a 'failed' receipt.
        On consumer disconnect: cancellation is detected at the HTTP
        layer; the receipt is written with outcome='cancelled' there.
        """
        msg, identity = ctx.msg, ctx.identity
        chunk_dicts: list[dict] = []
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

        # Persist + receipt after the stream completes.
        self._store.save_message(self.name, msg.to_dict())
        for chunk in chunk_dicts:
            self._store.save_message(self.name, chunk)
        outcome = "completed" if chunk_dicts and chunk_dicts[-1].get("status") != "error" else "failed"
        self._store.save_receipt(self.name, create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id,
            refs=[msg.id] + [c["id"] for c in chunk_dicts],
            outcome=outcome,
        ))

        # Cache full chunk list for idempotent replay (#11).
        if msg.idempotency_key and outcome == "completed":
            self._cache_idempotent_response(msg, chunk_dicts)

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
                ttl = max(deadline_dt - datetime.now(timezone.utc),
                          timedelta(seconds=10))
            except ValueError:
                pass
        self._idempotency_cache[msg.idempotency_key] = (
            response, datetime.now(timezone.utc) + ttl,
        )
        self._evict_expired_cache()
        self._enforce_lru_cap()
        self._persist_idempotency()

    def _dispatch_err(self, ctx: "_DispatchCtx", code: str, detail: str) -> dict:
        """Build a signed error response for any dispatch step."""
        res = build_res(
            ctx.identity._private_key, ctx.identity.agent_id, ctx.msg,
            status="error",
            fault={"code": code, "detail": detail},
        )
        return res.to_dict()

    def _resolve_sender_key(self, agent_id: str) -> bytes | None:
        """Look up a sender's public key from peers cache."""
        peer = self._store.load_peer(agent_id)
        if peer and "public_key" in peer:
            return base64.b64decode(peer["public_key"])
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
        new_pub = base64.b64decode(new_pub_b64)
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
        # Bind: cache the doc and return the pubkey
        self._store.save_peer(claimed_agent_id, identity_doc)
        return base64.b64decode(pub_b64)

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
        self._store.save_receipt(self.name, receipt)

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
        now = datetime.now(timezone.utc)
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
        print(f"Registered on local network via mDNS")
        print(f"Press Ctrl-C to stop")

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
