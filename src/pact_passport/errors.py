"""PACT error hierarchy + wire-level fault code taxonomy.

Two distinct concerns coexist in this module:

1. **Python exception classes** (existing) — raised internally by the substrate
   for control flow inside the implementation.

2. **Wire-level fault codes** (added v1.4 / v0.8 — see spec §18.3) — the
   normative string codes implementations MUST emit in the ``fault.code``
   field of RES messages when rejecting a REQ. These are returned over the
   wire, not raised as Python exceptions.

The two stay separate by design. An ``InvalidSignature`` exception raised
internally is translated to the wire fault ``pact_signature_invalid`` by
the transport layer; the wire client sees only the latter.
"""

from __future__ import annotations


class PACTError(Exception):
    """Base error for all PACT operations."""


class IdentityNotFound(PACTError):
    """Agent identity not found in store."""


class InvalidSignature(PACTError):
    """Cryptographic signature verification failed."""


class CapabilityExpired(PACTError):
    """Capability token has expired."""


class CapabilityInvalid(PACTError):
    """Capability token failed verification."""


class DeadlineExceeded(PACTError):
    """Request deadline has passed."""


class DuplicateIdempotencyKey(PACTError):
    """Idempotency key already seen for this agent."""


class PeerUnreachable(PACTError):
    """Could not reach the target agent."""


class AttenuationViolation(PACTError):
    """Attempted to widen a capability during attenuation."""


class HandlerFailure(PACTError):
    """Handler explicitly signalled failure with a custom fault.

    Apps that wrap remote calls (e.g. peer delegation) should raise this
    rather than returning an error dict, so the failure produces a signed
    error response and a `outcome=failed` receipt instead of a misleading
    `outcome=completed` one.

    Example:
        if peer_res.get("status") != "ok":
            raise HandlerFailure("peer_rejected", str(peer_res.get("fault")))
    """

    def __init__(self, code: str = "handler_failure", detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Wire-level fault codes (spec §18.3) — added v1.4 / reference impl v0.8.
#
# Implementations MUST emit one of these string codes in the ``fault.code``
# field of RES messages when rejecting a REQ. The HTTP status mapping applies
# when PACT is carried over HTTP (spec §8.1).
#
# Implementations MAY define additional application-layer fault codes for
# their own purposes. Such codes MUST NOT use the ``pact_`` prefix.
# ---------------------------------------------------------------------------

# Authentication-class faults (HTTP 401)
PACT_TOKEN_MISSING = "pact_token_missing"
PACT_TOKEN_MALFORMED = "pact_token_malformed"
PACT_SIGNATURE_INVALID = "pact_signature_invalid"
PACT_HOLDER_PROOF_INVALID = "pact_holder_proof_invalid"  # PACT-specific
PACT_IDENTITY_UNRESOLVABLE = "pact_identity_unresolvable"
PACT_TOKEN_EXPIRED = "pact_token_expired"
PACT_KEY_REVOKED = "pact_key_revoked"

# Authorization-class faults (HTTP 403)
PACT_SCOPE_INSUFFICIENT = "pact_scope_insufficient"
PACT_BUDGET_EXCEEDED = "pact_budget_exceeded"
PACT_DEPTH_EXCEEDED = "pact_depth_exceeded"
PACT_AUDIENCE_MISMATCH = "pact_audience_mismatch"  # PACT-specific
PACT_RECEIPT_NOT_BILATERAL = "pact_receipt_not_bilateral"  # PACT-specific

# Operational signals (HTTP 410)
PACT_REVOCATION_OBSERVED = "pact_revocation_observed"  # PACT-specific


# Code → HTTP status mapping (spec §18.3).
# When PACT is carried over HTTP (spec §8.1), implementations SHOULD use
# these statuses on response envelopes with the corresponding fault.code.
FAULT_HTTP_STATUS: dict[str, int] = {
    # 401 — Authentication failures
    PACT_TOKEN_MISSING:        401,
    PACT_TOKEN_MALFORMED:      401,
    PACT_SIGNATURE_INVALID:    401,
    PACT_HOLDER_PROOF_INVALID: 401,
    PACT_IDENTITY_UNRESOLVABLE: 401,
    PACT_TOKEN_EXPIRED:        401,
    PACT_KEY_REVOKED:          401,
    # 403 — Authorization failures
    PACT_SCOPE_INSUFFICIENT:   403,
    PACT_BUDGET_EXCEEDED:      403,
    PACT_DEPTH_EXCEEDED:       403,
    PACT_AUDIENCE_MISMATCH:    403,
    PACT_RECEIPT_NOT_BILATERAL: 403,
    # 410 — Operational signals
    PACT_REVOCATION_OBSERVED:  410,
}


# Frozen set of all normative codes — useful for conformance tests and
# the attack-scenario catalogue (spec/attacks/attacks.json).
ALL_FAULT_CODES = frozenset(FAULT_HTTP_STATUS)


def http_status_for_fault(code: str) -> int:
    """Return the HTTP status (per spec §18.3) for a given fault code.

    Returns 500 if the code is not in the normative taxonomy — caller
    should treat that as a substrate-internal bug, not a wire-protocol
    rejection.
    """
    return FAULT_HTTP_STATUS.get(code, 500)
