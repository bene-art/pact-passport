"""V-tier visa: session-scoped, attenuated, non-delegable capability for
passport-less peers.

Spec: see ``g4 revision visa tiered trust.md`` §3 (trust gradient) and §4
(locked spec details). The visa is a ``CapabilityToken`` with ``visa=True``,
holder-bound to the requester's ephemeral key, carrying a server-issued
``nonce`` that the requester signs as ``holder_proof`` on use.

No new wire shape: visa flows through the existing ``cap_envelope`` and
``holder_proof`` fields with different semantics when ``visa=True``.

Threat-model boundaries (v0.6):

* ``peer_network_id`` is a *naive* aggregation key (source IPv4 /24 or
  IPv6 /48 observed at the transport boundary). Trivially rotatable on
  any cloud provider — chosen because the limitation is honest. Stronger
  keys (TLS-session-bound, post-handshake) are v0.7 work.
* Cost declarations are author-honest. Runtime measurement and post-hoc
  enforcement are post-v0.6.
* ``ephemeral_key_fingerprint`` is gatekeeper-internal. Receipts record
  it for the issuer's own audit; it is not surfaced to other parties.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Callable

from pact import crypto
from pact._canonical import canonical_json
from pact.capability import CapabilityToken, Caveat


# §4 default-policy ceilings — see ``g4 revision visa tiered trust.md``.
DEFAULT_MAX_PAYLOAD_BYTES = 4096
DEFAULT_MAX_COMPUTE_MS = 100
DEFAULT_VISA_RATE_LIMIT = 5         # per peer_network_id
DEFAULT_VISA_RATE_WINDOW = 60       # seconds
DEFAULT_VISA_EXPIRY_SECONDS = 30


@dataclass
class VisaContext:
    """Input to the visa-issuance policy hook (§4 *Spec details*).

    All five fields are gatekeeper-derived. The requester does not
    contribute to ``peer_network_id`` or ``recent_visa_count_window``;
    those are observed at the transport boundary.
    """
    action: str
    payload_hash: str
    peer_network_id: str
    recent_visa_count_window: int
    resource_headroom: float = 1.0


@dataclass(frozen=True)
class ProtocolAdvertisement:
    """Passive, signed protocol-advertisement metadata (v1.3 / spec §16.5).

    Emit-only. PACT MUST NOT take automated action on a received
    ``protocol_advertisement`` field. See spec §16.5 and
    ``visa_protocol_advertisement_design.md``. The field is the
    smallest possible substrate-discovery primitive: it identifies
    the protocol and points to its spec, with the decision to act on
    that information left entirely out-of-band (to a developer
    reading the spec and writing code).

    Two strings. Flat. No nested structures, no lists. The flatness
    is deliberate — it removes any temptation toward parsing logic.
    """
    protocol: str
    spec_uri: str

    def to_dict(self) -> dict:
        return {"protocol": self.protocol, "spec_uri": self.spec_uri}

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolAdvertisement":
        return cls(protocol=d["protocol"], spec_uri=d["spec_uri"])


@dataclass
class VisaGrant:
    """Policy result: issue a visa with these caveats.

    Optionally carries a passive ``protocol_advertisement`` (v1.3 /
    spec §16.5). When set, the wire response payload includes the
    advertisement under the outer signature so MITM tampering breaks
    verification. The field is normatively inert on receive (MUST-NOT
    consumed); see the design doc.
    """
    caveats: list[Caveat] = field(default_factory=list)
    protocol_advertisement: ProtocolAdvertisement | None = None


@dataclass
class VisaRefuse:
    """Policy result: refuse. ``reason`` is audit-internal, not returned to peer.

    Optionally carries a passive ``protocol_advertisement`` (v1.3 /
    spec §16.5). When set, the refusal response payload includes the
    advertisement under the outer signature. The refusal itself
    remains opaque (``denied``); the advertisement leaks one thing —
    that the gatekeeper speaks PACT — orthogonal to the policy
    rationale that the refusal continues to hide.
    """
    reason: str
    protocol_advertisement: ProtocolAdvertisement | None = None


VisaPolicy = Callable[[VisaContext], "VisaGrant | VisaRefuse"]


def derive_peer_network_id(remote_addr: tuple | None) -> str:
    """Derive a peer aggregation key from a transport-boundary address.

    IPv4 → ``v4:<network>/24``; IPv6 → ``v6:<network>/48``;
    loopback → ``loopback:<host>`` (kept distinct so tests aggregate);
    unknown → ``unknown`` (default-policy refuses on this).
    """
    if remote_addr is None:
        return "unknown"
    try:
        host = remote_addr[0]
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return f"loopback:{host}"
        if isinstance(ip, ipaddress.IPv4Address):
            network = ipaddress.ip_network(f"{host}/24", strict=False)
            return f"v4:{network.network_address}/24"
        network = ipaddress.ip_network(f"{host}/48", strict=False)
        return f"v6:{network.network_address}/48"
    except (ValueError, IndexError, TypeError):
        return "unknown"


class VisaIssuanceTracker:
    """Per-``peer_network_id`` rate window + issuance-path serialization.

    §4 concurrency note: ``recent_visa_count_window`` is read at issuance
    time and the issuance path is serialized per ``peer_network_id`` so
    the rate ceiling is race-free (closes V6).
    """

    def __init__(self, window_seconds: int = DEFAULT_VISA_RATE_WINDOW):
        self._window_seconds = window_seconds
        self._registry_lock = threading.Lock()
        self._per_peer_locks: dict[str, threading.Lock] = {}
        self._issuance_times: dict[str, deque] = defaultdict(deque)

    def lock_for(self, peer_network_id: str) -> threading.Lock:
        with self._registry_lock:
            lock = self._per_peer_locks.get(peer_network_id)
            if lock is None:
                lock = threading.Lock()
                self._per_peer_locks[peer_network_id] = lock
            return lock

    def recent_count(self, peer_network_id: str) -> int:
        """Drop expired entries; return count in the prior window."""
        cutoff = time.monotonic() - self._window_seconds
        q = self._issuance_times[peer_network_id]
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def record(self, peer_network_id: str) -> None:
        self._issuance_times[peer_network_id].append(time.monotonic())


@dataclass
class HandlerCost:
    """Author-honest cost declaration for a visa-eligible handler.

    The defaults assume the handler honors the §4 ceiling. Runtime
    measurement is post-v0.6 — declarations are trusted at issuance
    and the under-declaration surface is flagged in the spec.
    """
    payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    compute_ms: int = DEFAULT_MAX_COMPUTE_MS
    idempotent: bool = True


def make_default_visa_policy(
    visa_eligible_actions: set[str],
    handler_costs: dict[str, HandlerCost] | None = None,
) -> VisaPolicy:
    """Build the §4 default policy bound to a registry of visa-eligible
    handlers and their cost declarations.

    Fail-closed: ``visa_eligible`` is opt-in at handler registration;
    unannotated handlers default to refusal. Cost ceilings hard-coded
    per the spec. Cross-visa rate ceiling closes V6 inside the default.
    """
    costs = handler_costs or {}

    def policy(ctx: VisaContext) -> VisaGrant | VisaRefuse:
        if ctx.peer_network_id == "unknown":
            return VisaRefuse(reason="peer_network_id unobservable")
        if ctx.action not in visa_eligible_actions:
            return VisaRefuse(reason=f"action {ctx.action!r} not visa_eligible")

        cost = costs.get(ctx.action, HandlerCost())
        if not cost.idempotent:
            return VisaRefuse(reason="action declared non-idempotent")
        if cost.payload_bytes > DEFAULT_MAX_PAYLOAD_BYTES:
            return VisaRefuse(
                reason=f"declared payload {cost.payload_bytes}B > {DEFAULT_MAX_PAYLOAD_BYTES}B ceiling"
            )
        if cost.compute_ms > DEFAULT_MAX_COMPUTE_MS:
            return VisaRefuse(
                reason=f"declared compute {cost.compute_ms}ms > {DEFAULT_MAX_COMPUTE_MS}ms ceiling"
            )

        if ctx.recent_visa_count_window >= DEFAULT_VISA_RATE_LIMIT:
            return VisaRefuse(
                reason=(
                    f"rate ceiling: {ctx.recent_visa_count_window} visas already issued to "
                    f"{ctx.peer_network_id} in last {DEFAULT_VISA_RATE_WINDOW}s "
                    f"(limit {DEFAULT_VISA_RATE_LIMIT})"
                )
            )

        expires = (datetime.now(UTC) + timedelta(seconds=DEFAULT_VISA_EXPIRY_SECONDS)).isoformat()
        return VisaGrant(caveats=[
            Caveat(restrict="expires", value=expires),
            Caveat(restrict="max_invocations", value=1),
            Caveat(restrict="no_further_delegation", value=True, terminal=True),
        ])

    return policy


def _generate_nonce() -> str:
    """Server-issued nonce — 16 random bytes, url-safe base64."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def issue_visa(
    issuer_private_key: bytes,
    issuer_id: str,
    holder_id: str,
    action: str,
    caveats: list[Caveat],
    ephemeral_key_fingerprint: str | None = None,
) -> CapabilityToken:
    """Mint a visa: a signed ``CapabilityToken`` with ``visa=True`` and
    a fresh server-issued nonce.

    The visa is signed by the gatekeeper (issuer). Holder is the derived
    ephemeral agent_id of the passport-less requester. On use, the
    requester signs ``nonce`` (not ``msg.id``) as ``holder_proof``.
    """
    token = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=issuer_id,
        holder=holder_id,
        action=action,
        caveats=list(caveats),
        visa=True,
        nonce=_generate_nonce(),
        ephemeral_key_fingerprint=ephemeral_key_fingerprint,
    )
    sig = crypto.sign(canonical_json(token.signable_dict()), issuer_private_key)
    token.signature = base64.b64encode(sig).decode("ascii")
    return token


def verify_visa_holder_proof(
    holder_proof_b64: str,
    visa_nonce: str,
    holder_public_key: bytes,
) -> bool:
    """For a visa cap, ``holder_proof`` signs the visa's server-issued
    nonce — not ``msg.id``. Closes V5 (replay across request-pair).
    """
    if not holder_proof_b64 or not visa_nonce:
        return False
    try:
        sig_bytes = base64.b64decode(holder_proof_b64)
    except (binascii.Error, ValueError, TypeError):
        return False
    return crypto.verify(visa_nonce.encode(), sig_bytes, holder_public_key)
