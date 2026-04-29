"""Capability tokens: issue, holder-bind, verify.

A capability is a signed, holder-bound proof of authority.
Possession of the token IS the authorization.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field

from pact import crypto
from pact._canonical import canonical_json


@dataclass
class Caveat:
    """A restriction on a capability token."""
    restrict: str
    value: object
    terminal: bool = False

    def to_dict(self) -> dict:
        d: dict = {"restrict": self.restrict, "value": self.value}
        if self.terminal:
            d["terminal"] = True
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Caveat:
        return cls(
            restrict=d["restrict"],
            value=d["value"],
            terminal=d.get("terminal", False),
        )


@dataclass
class CapabilityToken:
    """A signed, holder-bound capability token."""
    cap_id: str
    issuer: str  # agent_id
    holder: str  # agent_id
    action: str
    caveats: list[Caveat] = field(default_factory=list)
    alg: str = crypto.ALG
    signature: str = ""  # base64-encoded

    def to_dict(self) -> dict:
        return {
            "cap_id": self.cap_id,
            "issuer": self.issuer,
            "holder": self.holder,
            "action": self.action,
            "caveats": [c.to_dict() for c in self.caveats],
            "alg": self.alg,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CapabilityToken:
        return cls(
            cap_id=d["cap_id"],
            issuer=d["issuer"],
            holder=d["holder"],
            action=d["action"],
            caveats=[Caveat.from_dict(c) for c in d.get("caveats", [])],
            alg=d.get("alg", crypto.ALG),
            signature=d.get("signature", ""),
        )

    def signable_dict(self) -> dict:
        """The dict that gets signed (everything except signature)."""
        d = self.to_dict()
        d.pop("signature", None)
        return d


def issue_capability(
    issuer_private_key: bytes,
    issuer_id: str,
    holder_id: str,
    action: str,
    caveats: list[Caveat] | None = None,
) -> CapabilityToken:
    """Issue a new capability token from issuer to holder."""
    token = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=issuer_id,
        holder=holder_id,
        action=action,
        caveats=caveats or [],
    )
    sig = crypto.sign(canonical_json(token.signable_dict()), issuer_private_key)
    token.signature = base64.b64encode(sig).decode("ascii")
    return token


@dataclass
class CapabilityResult:
    """Result of capability verification."""
    valid: bool
    reason: str | None = None


def verify_capability(
    token: CapabilityToken,
    expected_holder: str,
    issuer_public_key: bytes,
) -> CapabilityResult:
    """Verify a capability token.

    Checks: signature, holder match, and caveats (expiry).
    """
    # Check holder
    if token.holder != expected_holder:
        return CapabilityResult(False, f"Holder mismatch: expected {expected_holder}, got {token.holder}")

    # Check signature
    sig_bytes = base64.b64decode(token.signature)
    signable = canonical_json(token.signable_dict())
    if not crypto.verify(signable, sig_bytes, issuer_public_key):
        return CapabilityResult(False, "Invalid signature on capability token")

    # Check caveats
    now = datetime.now(timezone.utc)
    for caveat in token.caveats:
        if caveat.restrict == "expires":
            expires = datetime.fromisoformat(caveat.value)
            if now > expires:
                return CapabilityResult(False, f"Capability expired at {caveat.value}")

    return CapabilityResult(True)
