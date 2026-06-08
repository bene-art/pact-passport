"""Capability tokens: issue, attenuate, verify.

A capability is a signed, holder-bound proof of authority.
Possession of the token IS the authorization.
Caveats can only be appended (attenuation) — never removed or widened.
"""

from __future__ import annotations

import base64
import binascii
import uuid
import warnings
from datetime import datetime, UTC
from dataclasses import dataclass, field

from pact import crypto
from pact._canonical import canonical_json
from pact.errors import AttenuationViolation


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
class DelegationLink:
    """One link in a delegation chain.

    Each link cryptographically signs the parent cap_id at the moment
    the link is created. ``parent_cap_id`` (v0.6+) records what the link
    actually signed at its own attenuation step. Pre-v0.6 chains may
    omit this field; the verifier falls back to ``token.parent`` for
    those links (correct only at K=2) with a DeprecationWarning. The
    fallback is scheduled for removal in v0.7.
    """
    from_agent: str
    sig: str  # base64-encoded
    parent_cap_id: str | None = None

    def to_dict(self) -> dict:
        d: dict = {"from": self.from_agent, "sig": self.sig}
        if self.parent_cap_id is not None:
            d["parent_cap_id"] = self.parent_cap_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> DelegationLink:
        return cls(
            from_agent=d["from"],
            sig=d["sig"],
            parent_cap_id=d.get("parent_cap_id"),
        )


@dataclass
class CapabilityToken:
    """A signed, holder-bound capability token."""
    cap_id: str
    issuer: str  # agent_id of the original issuer
    holder: str  # agent_id of the current holder
    action: str
    caveats: list[Caveat] = field(default_factory=list)
    parent: str | None = None  # cap_id of parent token (for attenuated tokens)
    delegation_chain: list[DelegationLink] = field(default_factory=list)
    revoked: bool = False
    # V-tier (v0.6). When visa=True, this token is a gatekeeper-issued
    # transit credential for a passport-less peer. holder_proof on use
    # must sign `nonce` rather than msg.id. ephemeral_key_fingerprint is
    # recorded for audit; not surfaced on the wire to other parties.
    visa: bool = False
    nonce: str | None = None
    ephemeral_key_fingerprint: str | None = None
    alg: str = crypto.ALG
    signature: str = ""  # base64-encoded

    def to_dict(self) -> dict:
        d: dict = {
            "cap_id": self.cap_id,
            "issuer": self.issuer,
            "holder": self.holder,
            "action": self.action,
            "caveats": [c.to_dict() for c in self.caveats],
            "alg": self.alg,
            "signature": self.signature,
        }
        if self.parent:
            d["parent"] = self.parent
        if self.delegation_chain:
            d["delegation_chain"] = [dl.to_dict() for dl in self.delegation_chain]
        if self.revoked:
            d["revoked"] = True
        if self.visa:
            d["visa"] = True
        if self.nonce is not None:
            d["nonce"] = self.nonce
        if self.ephemeral_key_fingerprint is not None:
            d["ephemeral_key_fingerprint"] = self.ephemeral_key_fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CapabilityToken:
        return cls(
            cap_id=d["cap_id"],
            issuer=d["issuer"],
            holder=d["holder"],
            action=d["action"],
            caveats=[Caveat.from_dict(c) for c in d.get("caveats", [])],
            parent=d.get("parent"),
            delegation_chain=[DelegationLink.from_dict(dl) for dl in d.get("delegation_chain", [])],
            revoked=d.get("revoked", False),
            visa=d.get("visa", False),
            nonce=d.get("nonce"),
            ephemeral_key_fingerprint=d.get("ephemeral_key_fingerprint"),
            alg=d.get("alg", crypto.ALG),
            signature=d.get("signature", ""),
        )

    def signable_dict(self) -> dict:
        """The dict that gets signed (everything except signature)."""
        d = self.to_dict()
        d.pop("signature", None)
        return d

    def is_terminal(self) -> bool:
        """Check if any caveat prevents further delegation."""
        return any(c.restrict == "no_further_delegation" and c.terminal for c in self.caveats)


def _validate_caveats(caveats: list[Caveat]) -> None:
    """Sanity-check caveat values at issue/attenuate time.

    Catches the foot-guns that produce silently-broken caps:
    - max_invocations must be a positive int (negative or zero values
      issue a cap that's effectively dead-on-arrival because the
      enforcement check `count >= max` is true on first use)
    - expires must be a parseable ISO 8601 timestamp (so the verifier
      doesn't crash on the comparison later)
    """
    for c in caveats:
        if c.restrict == "max_invocations":
            if not isinstance(c.value, int) or isinstance(c.value, bool) or c.value < 1:
                raise ValueError(
                    f"max_invocations must be a positive int (>= 1), got {c.value!r}"
                )
        elif c.restrict == "expires":
            try:
                datetime.fromisoformat(c.value)
            except (TypeError, ValueError) as e:
                raise ValueError(
                    f"expires caveat must be a parseable ISO 8601 timestamp, got {c.value!r}: {e}"
                ) from e


def issue_capability(
    issuer_private_key: bytes,
    issuer_id: str,
    holder_id: str,
    action: str,
    caveats: list[Caveat] | None = None,
) -> CapabilityToken:
    """Issue a new root capability token from issuer to holder.

    Raises ValueError if any caveat value is malformed (negative
    max_invocations, unparseable ISO timestamp, etc.).
    """
    _validate_caveats(caveats or [])
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


def attenuate(
    parent: CapabilityToken,
    delegator_private_key: bytes,
    delegator_id: str,
    new_holder_id: str,
    additional_caveats: list[Caveat],
) -> CapabilityToken:
    """Create an attenuated (narrowed) capability from a parent token.

    Rules:
    - The parent must not be terminal (no_further_delegation).
    - The delegator must be the current holder of the parent.
    - Additional caveats can only restrict, never widen.
    - For numeric caveats (max_invocations), new value must be <= parent value.
    - For time caveats (expires), new value must be <= parent value.
    - The action must remain the same.

    Raises AttenuationViolation on any rule violation. Raises ValueError
    on a malformed caveat value (negative max_invocations, unparseable
    expires timestamp).
    """
    _validate_caveats(additional_caveats)
    # Check terminal
    if parent.is_terminal():
        raise AttenuationViolation("Parent capability has no_further_delegation caveat")

    # Check delegator is the holder
    if parent.holder != delegator_id:
        raise AttenuationViolation(
            f"Delegator {delegator_id} is not the holder of parent capability (holder: {parent.holder})"
        )

    # Validate additional caveats don't widen
    parent_caveats_by_restrict = {}
    for c in parent.caveats:
        parent_caveats_by_restrict.setdefault(c.restrict, []).append(c)

    for new_caveat in additional_caveats:
        existing = parent_caveats_by_restrict.get(new_caveat.restrict, [])
        if existing and new_caveat.restrict == "max_invocations":
            parent_val = min(c.value for c in existing)
            if new_caveat.value > parent_val:
                raise AttenuationViolation(
                    f"Cannot widen max_invocations from {parent_val} to {new_caveat.value}"
                )
        elif existing and new_caveat.restrict == "expires":
            parent_exp = min(c.value for c in existing)
            if new_caveat.value > parent_exp:
                raise AttenuationViolation(
                    f"Cannot extend expiry from {parent_exp} to {new_caveat.value}"
                )

    # Build delegation chain: inherit parent's chain + add delegator's link
    chain = list(parent.delegation_chain)
    # Sign the parent cap_id to prove delegator held the parent.
    # parent_cap_id is recorded on the link so the verifier can check
    # each link against its own contemporaneous parent (closes Bug 6 /
    # GH #29 — multi-hop chain verification fails at K >= 3 without
    # this because the verifier otherwise reaches for token.parent,
    # the parent of the FINAL token, which only coincides with this
    # link's signed value at K=2).
    chain_sig = crypto.sign(parent.cap_id.encode(), delegator_private_key)
    chain.append(DelegationLink(
        from_agent=delegator_id,
        sig=base64.b64encode(chain_sig).decode("ascii"),
        parent_cap_id=parent.cap_id,
    ))

    # Combine caveats: parent's + additional (append-only)
    all_caveats = list(parent.caveats) + list(additional_caveats)

    child = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=parent.issuer,  # root issuer stays the same
        holder=new_holder_id,
        action=parent.action,
        caveats=all_caveats,
        parent=parent.cap_id,
        delegation_chain=chain,
    )

    sig = crypto.sign(canonical_json(child.signable_dict()), delegator_private_key)
    child.signature = base64.b64encode(sig).decode("ascii")

    return child


@dataclass
class CapabilityResult:
    """Result of capability verification."""
    valid: bool
    reason: str | None = None


def verify_capability(
    token: CapabilityToken,
    expected_holder: str,
    issuer_public_key: bytes,
    known_keys: dict[str, bytes] | None = None,
) -> CapabilityResult:
    """Verify a capability token.

    Checks: signature, holder match, caveats (expiry), revocation,
    and delegation chain (if present).

    Returns a CapabilityResult; never raises on malformed input.
    Malformed signatures, malformed base64, or malformed ISO timestamps
    are reported as verification failures, not propagated as exceptions.

    Args:
        token: The capability token to verify.
        expected_holder: The agent_id that should be the holder.
        issuer_public_key: Public key of the root issuer.
        known_keys: Optional dict of agent_id → public_key for chain verification.
    """
    try:
        return _verify_capability_inner(token, expected_holder, issuer_public_key, known_keys)
    except (binascii.Error, ValueError) as e:
        # Malformed base64 in token.signature, link.sig, or malformed
        # ISO timestamp in expires caveat. Pre-v0.5.3 these crashed the
        # verifier. Now they fail-closed as a structured result.
        return CapabilityResult(False, f"Malformed token field: {e}")


def _verify_capability_inner(
    token: CapabilityToken,
    expected_holder: str,
    issuer_public_key: bytes,
    known_keys: dict[str, bytes] | None,
) -> CapabilityResult:
    # Check revoked
    if token.revoked:
        return CapabilityResult(False, "Capability has been revoked")

    # Check holder
    if token.holder != expected_holder:
        return CapabilityResult(False, f"Holder mismatch: expected {expected_holder}, got {token.holder}")

    # Verify signature
    sig_bytes = base64.b64decode(token.signature)
    signable = canonical_json(token.signable_dict())

    if token.delegation_chain:
        # For attenuated tokens, the signature is from the last delegator.
        # Fail closed: if we don't have the delegator's pubkey, we cannot
        # verify the cap. Silently skipping the check (pre-v0.2 behavior)
        # let forged chains pass — see issue #8.
        last_delegator = token.delegation_chain[-1].from_agent
        if not known_keys or last_delegator not in known_keys:
            return CapabilityResult(
                False,
                f"Cannot verify: missing key for delegator {last_delegator[:24]}...",
            )
        delegator_key = known_keys[last_delegator]
        if not crypto.verify(signable, sig_bytes, delegator_key):
            return CapabilityResult(False, "Invalid signature from delegator")
    else:
        # Root token: verify against issuer key
        if not crypto.verify(signable, sig_bytes, issuer_public_key):
            return CapabilityResult(False, "Invalid signature on capability token")

    # Verify every delegation chain link. Same fail-closed rule applies:
    # any link whose key is unknown invalidates the cap. The verifier
    # cannot trust links it cannot check.
    if token.delegation_chain and token.parent:
        if not known_keys:
            return CapabilityResult(False, "Cannot verify chain: known_keys not provided")
        for link in token.delegation_chain:
            if link.from_agent not in known_keys:
                return CapabilityResult(
                    False,
                    f"Cannot verify chain link: missing key for {link.from_agent[:24]}...",
                )
            link_sig = base64.b64decode(link.sig)
            link_key = known_keys[link.from_agent]
            # Each link signs the parent cap_id at its own attenuation
            # step. v0.6+ records that value as link.parent_cap_id; the
            # verifier checks each link against its own contemporaneous
            # parent. Pre-v0.6 chains lack the field; we fall back to
            # token.parent for backwards compatibility (correct only at
            # K=2; K>=3 chains in pre-v0.6 format will still be rejected,
            # which is the existing buggy behavior). Fallback removed
            # in v0.7. See bug6_fix_design.md.
            if link.parent_cap_id is not None:
                signed_value = link.parent_cap_id
            else:
                warnings.warn(
                    "Capability chain link lacks parent_cap_id; "
                    "pre-v0.6 format, deprecated for removal in v0.7",
                    DeprecationWarning,
                    stacklevel=2,
                )
                signed_value = token.parent
            if not crypto.verify(signed_value.encode(), link_sig, link_key):
                return CapabilityResult(False, f"Invalid delegation chain link from {link.from_agent}")

    # Check caveats
    now = datetime.now(UTC)
    for caveat in token.caveats:
        if caveat.restrict == "expires":
            expires = datetime.fromisoformat(caveat.value)
            if now > expires:
                return CapabilityResult(False, f"Capability expired at {caveat.value}")

    return CapabilityResult(True)
