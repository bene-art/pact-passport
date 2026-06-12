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

from pact_passport import crypto
from pact_passport._canonical import canonical_json
from pact_passport.errors import AttenuationViolation


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

    Each link cryptographically signs a canonical payload at the moment
    the link is created. v0.6 (spec v1.2) added ``parent_cap_id`` so
    the link signs the parent's cap_id and the verifier checks it
    against each link's own contemporaneous parent (closes Bug 6).
    v0.7 (spec v1.3) adds ``action_at_step`` and ``caveats_at_step`` so
    the link's signed payload also binds the *content* of the cap
    being created — closing Bug 9 (rogue-delegator forgery: a
    compromised intermediate delegator could otherwise mint children
    with mutated action or stripped caveats and the v1.2 verifier
    accepted them). The verifier walks the chain re-deriving the
    expected (action, caveats) at each hop and rejecting any
    divergence; mechanism follows Macaroons §III (Birgisson et al.
    NDSS 2014) ported to PACT's Ed25519 chain.

    Migration: v1.3 verifier accepts pre-v1.3 links (no ``action_at_step``
    / ``caveats_at_step``) at K=2 with a DeprecationWarning, falling
    back to v1.2 parent_cap_id-only behavior. v1.4 will reject any
    chain link lacking the new fields.
    """
    from_agent: str
    sig: str  # base64-encoded
    parent_cap_id: str | None = None
    action_at_step: str | None = None
    caveats_at_step: list[Caveat] | None = None

    def to_dict(self) -> dict:
        d: dict = {"from": self.from_agent, "sig": self.sig}
        if self.parent_cap_id is not None:
            d["parent_cap_id"] = self.parent_cap_id
        if self.action_at_step is not None:
            d["action_at_step"] = self.action_at_step
        if self.caveats_at_step is not None:
            d["caveats_at_step"] = [c.to_dict() for c in self.caveats_at_step]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> DelegationLink:
        caveats_at_step = None
        if "caveats_at_step" in d:
            caveats_at_step = [Caveat.from_dict(c) for c in d["caveats_at_step"]]
        return cls(
            from_agent=d["from"],
            sig=d["sig"],
            parent_cap_id=d.get("parent_cap_id"),
            action_at_step=d.get("action_at_step"),
            caveats_at_step=caveats_at_step,
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


def _canonical_caveat_value(value: object) -> object:
    """Convert a caveat value into a hashable canonical form for set
    comparison in the v1.3 chain-walk (Bug 9 closure).

    Caveats with structured values (e.g. list / dict payloads) can't be
    placed into a ``frozenset`` as-is. This helper normalizes lists to
    tuples and dicts to sorted tuples-of-items so two equivalent caveat
    values hash the same. Scalar values pass through unchanged.
    """
    if isinstance(value, list):
        return tuple(_canonical_caveat_value(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _canonical_caveat_value(v)) for k, v in value.items()))
    return value


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

    # Combine caveats: parent's + additional (append-only)
    all_caveats = list(parent.caveats) + list(additional_caveats)

    # Build delegation chain: inherit parent's chain + add delegator's link.
    chain = list(parent.delegation_chain)

    # v1.3 link payload binds the child's action and caveats into the
    # signature so a rogue delegator can't mutate them post-attenuate()
    # without invalidating the chain (closes Bug 9 — see
    # bug9_fix_design.md). The link records its own (action, caveats)
    # snapshot so the verifier can walk the chain re-deriving expected
    # values at each hop. parent_cap_id (v1.2, closes Bug 6) is still
    # part of the signed payload.
    link_payload = canonical_json({
        "parent_cap_id": parent.cap_id,
        "action_at_step": parent.action,
        "caveats_at_step": [c.to_dict() for c in all_caveats],
    })
    chain_sig = crypto.sign(link_payload, delegator_private_key)
    chain.append(DelegationLink(
        from_agent=delegator_id,
        sig=base64.b64encode(chain_sig).decode("ascii"),
        parent_cap_id=parent.cap_id,
        action_at_step=parent.action,
        caveats_at_step=all_caveats,
    ))

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

        # v1.3 (Bug 9 closure): walk the chain re-deriving expected
        # (action, caveats) at each hop. Track the running state from
        # the root forward; any divergence is a rogue-delegator
        # forgery. v1.2 chains (parent_cap_id only) and pre-v1.2
        # chains (neither) take the legacy verification paths with
        # DeprecationWarnings.
        running_action: str | None = None
        running_caveats: frozenset = frozenset()
        chain_has_v13_link = False
        chain_has_pre_v13_link = False
        chain_has_pre_v12_link = False

        for i, link in enumerate(token.delegation_chain):
            if link.from_agent not in known_keys:
                return CapabilityResult(
                    False,
                    f"Cannot verify chain link: missing key for {link.from_agent[:24]}...",
                )
            link_sig = base64.b64decode(link.sig)
            link_key = known_keys[link.from_agent]

            if (
                link.parent_cap_id is not None
                and link.action_at_step is not None
                and link.caveats_at_step is not None
            ):
                # v1.3+ link: signature is over the full canonical
                # payload binding parent_cap_id + action + caveats.
                chain_has_v13_link = True
                link_payload = canonical_json({
                    "parent_cap_id": link.parent_cap_id,
                    "action_at_step": link.action_at_step,
                    "caveats_at_step": [c.to_dict() for c in link.caveats_at_step],
                })
                if not crypto.verify(link_payload, link_sig, link_key):
                    return CapabilityResult(False, f"Invalid delegation chain link from {link.from_agent}")

                # Action preservation: every link records the same action
                if running_action is None:
                    running_action = link.action_at_step
                elif link.action_at_step != running_action:
                    return CapabilityResult(
                        False,
                        f"Action mutated at chain step {i}: "
                        f"{running_action!r} -> {link.action_at_step!r}",
                    )

                # Caveat append-only: cumulative caveat set at this
                # step MUST be a superset of the previous step's
                cur_set = frozenset(
                    (c.restrict, _canonical_caveat_value(c.value))
                    for c in link.caveats_at_step
                )
                if not cur_set >= running_caveats:
                    missing = running_caveats - cur_set
                    return CapabilityResult(
                        False,
                        f"Caveats stripped at chain step {i}: missing {missing}",
                    )
                running_caveats = cur_set
            elif link.parent_cap_id is not None:
                # v1.2 link: signature is over parent_cap_id only.
                # Verifier cannot re-derive action / caveats from
                # this link. v1.3 fallback with DeprecationWarning.
                chain_has_pre_v13_link = True
                if not crypto.verify(link.parent_cap_id.encode(), link_sig, link_key):
                    return CapabilityResult(False, f"Invalid delegation chain link from {link.from_agent}")
            else:
                # Pre-v1.2 link: no parent_cap_id. Fall back to
                # token.parent (correct only at K=2). v1.2's existing
                # legacy path.
                chain_has_pre_v12_link = True
                if not crypto.verify(token.parent.encode(), link_sig, link_key):
                    return CapabilityResult(False, f"Invalid delegation chain link from {link.from_agent}")

        if chain_has_pre_v12_link:
            warnings.warn(
                "Capability chain link lacks parent_cap_id; "
                "pre-v1.2 format, deprecated for removal in v1.4",
                DeprecationWarning,
                stacklevel=2,
            )
        if chain_has_pre_v13_link:
            warnings.warn(
                "Capability chain link lacks action_at_step / "
                "caveats_at_step; pre-v1.3 format, deprecated for "
                "removal in v1.4. Action and caveat re-derivation "
                "cannot be enforced for this chain.",
                DeprecationWarning,
                stacklevel=2,
            )

        # v1.3 final-token consistency: if any link in the chain
        # carries the new fields, the leaf token's (action, caveats)
        # MUST match the last v1.3 link's recorded values. This is
        # the check that catches a rogue delegator mutating the
        # final cap dict after attenuate(): the chain remembers the
        # legitimate values; the final cap has to match.
        if chain_has_v13_link and not chain_has_pre_v13_link:
            if running_action is not None and token.action != running_action:
                return CapabilityResult(
                    False,
                    f"Final cap action mismatches chain: "
                    f"{token.action!r} != {running_action!r}",
                )
            final_caveats = frozenset(
                (c.restrict, _canonical_caveat_value(c.value))
                for c in token.caveats
            )
            if final_caveats != running_caveats:
                difference = final_caveats ^ running_caveats
                return CapabilityResult(
                    False,
                    f"Final cap caveats mismatch chain: difference={difference}",
                )

    # Check caveats
    now = datetime.now(UTC)
    for caveat in token.caveats:
        if caveat.restrict == "expires":
            expires = datetime.fromisoformat(caveat.value)
            if now > expires:
                return CapabilityResult(False, f"Capability expired at {caveat.value}")

    return CapabilityResult(True)
