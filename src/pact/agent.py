"""PACTAgent: high-level API wiring identity, capabilities, transport, and discovery."""

from __future__ import annotations

import base64
import logging
import signal
import sys
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Any

from zeroconf import Zeroconf

from pact import crypto
from pact._chaos import chaos_sleep
from pact.identity import Identity
from pact.capability import CapabilityToken, Caveat, issue_capability, verify_capability, attenuate
from pact.message import (
    PACTMessage, build_req, build_res, verify_message,
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
        auto_grant: bool = True,
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
        self._idempotency_cache: dict[str, tuple[dict, datetime]] = {}  # key → (response, expires)
        self._invocation_counts: dict[str, int] = {}  # cap_id → count
        # Serializes _handle_task to keep idempotency cache + invocation counter
        # consistent under ThreadingHTTPServer concurrent dispatch.
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

    def _handle_task(self, msg: PACTMessage, identity: Identity) -> dict:
        """Process a task REQ."""
        with self._task_lock:
            return self._handle_task_locked(msg, identity)

    def _handle_task_locked(self, msg: PACTMessage, identity: Identity) -> dict:
        # Check deadline
        if is_deadline_exceeded(msg):
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                status="error",
                fault={"code": "deadline_exceeded", "detail": "Request deadline has passed"},
            )
            return res.to_dict()

        # Chaos hook: widens the idempotency-check + handler-execute window
        # under PACT_CHAOS=1. Has no effect in normal runs.
        chaos_sleep()

        # Idempotency check with TTL
        if msg.idempotency_key and msg.idempotency_key in self._idempotency_cache:
            cached_res, expires_at = self._idempotency_cache[msg.idempotency_key]
            if datetime.now(timezone.utc) < expires_at:
                return cached_res
            else:
                del self._idempotency_cache[msg.idempotency_key]

        # Verify sender identity (fetch from peers cache or via identity exchange)
        sender_pub = self._resolve_sender_key(msg.from_agent)
        if sender_pub and not verify_message(msg, sender_pub):
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                status="error",
                fault={"code": "invalid_signature", "detail": "Message signature verification failed"},
            )
            return res.to_dict()

        # Verify capability token
        if msg.cap_id:
            cap_dict = self._store.load_capability(self.name, msg.cap_id)
            if cap_dict:
                token = CapabilityToken.from_dict(cap_dict)
                issuer_pub = identity.public_key  # we issued it
                result = verify_capability(token, msg.from_agent, issuer_pub)
                if not result.valid:
                    res = build_res(
                        identity._private_key, identity.agent_id, msg,
                        status="error",
                        fault={"code": "capability_invalid", "detail": result.reason},
                    )
                    return res.to_dict()

                # Verify holder proof
                if sender_pub and msg.holder_proof:
                    if not verify_holder_proof(msg, sender_pub):
                        res = build_res(
                            identity._private_key, identity.agent_id, msg,
                            status="error",
                            fault={"code": "holder_proof_invalid", "detail": "Holder proof verification failed"},
                        )
                        return res.to_dict()

                # Check max_invocations rate limit
                max_inv = self._get_max_invocations(token)
                if max_inv is not None:
                    chaos_sleep()  # widens the read-then-increment window
                    count = self._invocation_counts.get(token.cap_id, 0)
                    if count >= max_inv:
                        res = build_res(
                            identity._private_key, identity.agent_id, msg,
                            status="error",
                            fault={"code": "rate_limited", "detail": f"max_invocations ({max_inv}) exceeded for cap {token.cap_id}"},
                        )
                        return res.to_dict()
                    self._invocation_counts[token.cap_id] = count + 1

                action = token.action
            else:
                # Auto-grant: look up action from payload
                action = msg.payload.get("action", "")
        else:
            action = msg.payload.get("action", "")

        # Dispatch to handler
        handler = self._handlers.get(action)
        if not handler:
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                status="error",
                fault={"code": "no_handler", "detail": f"No handler for action: {action}"},
            )
            return res.to_dict()

        try:
            result_payload = handler(msg.payload)
        except Exception as e:
            res = build_res(
                identity._private_key, identity.agent_id, msg,
                status="error",
                fault={"code": "handler_error", "detail": str(e)},
            )
            return res.to_dict()

        res = build_res(
            identity._private_key, identity.agent_id, msg,
            payload=result_payload if isinstance(result_payload, dict) else {"result": result_payload},
        )

        # Store message and receipt
        self._store.save_message(self.name, msg.to_dict())
        self._store.save_message(self.name, res.to_dict())
        receipt = create_receipt(
            identity._private_key, identity.agent_id,
            task_ref=msg.id, refs=[msg.id, res.id], outcome="completed",
        )
        self._store.save_receipt(self.name, receipt)

        # Cache for idempotency with TTL based on deadline
        result_dict = res.to_dict()
        if msg.idempotency_key:
            ttl = timedelta(seconds=60)  # default 60s TTL
            if msg.deadline:
                try:
                    deadline_dt = datetime.fromisoformat(msg.deadline)
                    ttl = max(deadline_dt - datetime.now(timezone.utc), timedelta(seconds=10))
                except ValueError:
                    pass
            self._idempotency_cache[msg.idempotency_key] = (result_dict, datetime.now(timezone.utc) + ttl)
            self._evict_expired_cache()

        return result_dict

    def _resolve_sender_key(self, agent_id: str) -> bytes | None:
        """Look up a sender's public key from peers cache."""
        peer = self._store.load_peer(agent_id)
        if peer and "public_key" in peer:
            return base64.b64decode(peer["public_key"])
        return None

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

        # Auto-handshake: get or create capability
        cap = self._find_capability_for(agent_info["agent_id"], action)
        if not cap and self.auto_grant:
            # Request a capability via the discover flow
            cap = self._request_auto_grant(base_url, identity, agent_info, action)

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

    def _request_auto_grant(
        self, base_url: str, identity: Identity, agent_info: dict, action: str
    ) -> CapabilityToken | None:
        """Request an auto-granted capability from the target agent.

        In Phase 1, the target auto-issues capabilities. We send an identity
        exchange + discover, and the target issues a cap in the response.
        For now, we create a self-issued stub that the target will honor
        via auto-grant mode.
        """
        # In auto-grant mode (Phase 1), the server accepts requests without
        # a capability token if it has a handler for the action.
        # We return None here and the server will dispatch based on payload.action.
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
