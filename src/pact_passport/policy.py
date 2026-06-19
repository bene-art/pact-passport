"""Three-tier policy profile validators (v1.4 / spec §18.4).

Defines the **Simple**, **Standard**, and **Advanced** policy profiles for
PACT capability caveats. Profiles graduate complexity additively:

* **Simple** — four templated caveat types with byte-normative canonical-JSON
  forms. Implementations MUST generate the exact byte patterns specified.
  This normativity enables cross-implementation conformance testing.

* **Standard** — adds custom predicates registered by implementations.
  Predicates MUST terminate in ≤100 evaluation steps per REQ.

* **Advanced** — opt-in third-party caveats (external verifier endpoint).
  Implementations MAY refuse Advanced.

The profiles use Macaroons-style caveats — sets of predicates that intersect
to narrow the cap. They are **not** Datalog. The byte-level normativity
matches what AIP v0.3.0 achieves with Datalog templates (see
``aip-tokens.md`` §7) but without taking a Datalog runtime dependency.

Caveats represented as plain dicts with the fields ``restrict``, ``value``,
and (Advanced only) ``third_party``, ``verifier_endpoint``, ``verifier_pubkey``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import Enum
from typing import Any, Callable

from pact_passport._canonical import canonical_json


# =============================================================================
# Profile identifiers (spec §18.4)
# =============================================================================

class PolicyProfile(str, Enum):
    """The three v1.4 policy profiles."""

    SIMPLE = "simple"
    STANDARD = "standard"
    ADVANCED = "advanced"


# =============================================================================
# Simple profile (spec §18.4.1) — four templated caveat types
# =============================================================================
#
# Per spec §18.4.1, implementations MUST generate the exact canonical-JSON
# byte patterns below. The factory functions in this module produce dicts
# whose canonical_json output matches the spec verbatim.

SIMPLE_CAVEAT_RESTRICTS = frozenset({
    "action",        # action allowlist
    "budget_cents",  # budget ceiling, USD cents
    "depth",         # delegation chain depth ceiling
    "expires_at",    # absolute time expiry
})


def make_action_caveat(allowed_actions: list[str]) -> dict:
    """Build a Simple-profile action-allowlist caveat (spec §18.4.1).

    Canonical-JSON form: ``{"restrict":"action","value":["<a1>","<a2>",...]}``

    The action list MUST be non-empty and is normalized to a sorted list
    for canonicalization stability across implementations.
    """
    if not allowed_actions:
        raise ValueError("action caveat requires at least one allowed action")
    return {
        "restrict": "action",
        "value": sorted(set(allowed_actions)),
    }


def make_budget_caveat(budget_cents: int) -> dict:
    """Build a Simple-profile budget-ceiling caveat (spec §18.4.1).

    Canonical-JSON form: ``{"restrict":"budget_cents","value":<int>}``

    budget_cents MUST be a non-negative integer.
    """
    if not isinstance(budget_cents, int) or budget_cents < 0:
        raise ValueError(
            f"budget_cents must be a non-negative int, got {budget_cents!r}"
        )
    return {
        "restrict": "budget_cents",
        "value": budget_cents,
    }


def make_depth_caveat(max_depth: int) -> dict:
    """Build a Simple-profile depth-ceiling caveat (spec §18.4.1).

    Canonical-JSON form: ``{"restrict":"depth","value":<int>}``

    max_depth MUST be ≥1 (a chain of length 0 is the root cap, which is
    not delegated). Depth includes the leaf token: ``depth=1`` allows
    only the root cap, ``depth=2`` allows root + one delegation, etc.
    """
    if not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError(
            f"depth must be an int ≥1, got {max_depth!r}"
        )
    return {
        "restrict": "depth",
        "value": max_depth,
    }


def make_expiry_caveat(expires_at: str | datetime) -> dict:
    """Build a Simple-profile expiry caveat (spec §18.4.1).

    Canonical-JSON form: ``{"restrict":"expires_at","value":"<ISO 8601>"}``

    expires_at may be a ``datetime`` (will be normalized to ISO 8601 with
    timezone) or a string (passed through as-is — must already be valid
    ISO 8601 per spec §2).
    """
    if isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:
            raise ValueError(
                "expires_at datetime must carry a timezone (spec §2)"
            )
        value = expires_at.isoformat()
    elif isinstance(expires_at, str):
        # Validate that it parses as ISO 8601 (raises ValueError if not).
        datetime.fromisoformat(expires_at)
        value = expires_at
    else:
        raise TypeError(
            f"expires_at must be datetime or ISO 8601 string, got {type(expires_at).__name__}"
        )
    return {
        "restrict": "expires_at",
        "value": value,
    }


# Simple-profile caveat satisfaction checks. Each takes the caveat dict
# and a context dict describing the REQ being authorized.

def satisfies_action(caveat: dict, ctx: dict) -> bool:
    """spec §18.4.1: intent.action MUST be in the caveat value array."""
    return ctx.get("action") in caveat["value"]


def satisfies_budget(caveat: dict, ctx: dict) -> bool:
    """spec §18.4.1: cumulative cost-of-operation MUST be ≤ value.

    Minimal interpretation: ``ctx["cost_cents"]`` is the cumulative cost
    observed so far on this cap. Implementations MAY refine.
    """
    return ctx.get("cost_cents", 0) <= caveat["value"]


def satisfies_depth(caveat: dict, ctx: dict) -> bool:
    """spec §18.4.1: chain length to the leaf token MUST be ≤ value."""
    return ctx.get("chain_depth", 0) <= caveat["value"]


def satisfies_expiry(caveat: dict, ctx: dict) -> bool:
    """spec §18.4.1: current time MUST be < value.

    ``ctx["now"]`` may be a datetime; defaults to ``datetime.now(UTC)``.
    """
    now = ctx.get("now") or datetime.now(UTC)
    if isinstance(now, str):
        now = datetime.fromisoformat(now)
    expires = datetime.fromisoformat(caveat["value"])
    return now < expires


_SIMPLE_DISPATCH: dict[str, Callable[[dict, dict], bool]] = {
    "action":       satisfies_action,
    "budget_cents": satisfies_budget,
    "depth":        satisfies_depth,
    "expires_at":   satisfies_expiry,
}


# =============================================================================
# Standard profile (spec §18.4.2) — custom predicates with bounded eval
# =============================================================================

STANDARD_EVAL_STEP_LIMIT = 100
"""Per spec §18.4.2, Standard predicates MUST terminate in ≤100 steps."""


@dataclass
class StandardPredicateHandler:
    """A registered Standard-profile predicate.

    Implementations register handlers via ``register_standard_predicate``.
    The ``func`` is invoked with the caveat dict and the request context;
    it returns True if the caveat is satisfied, False otherwise. ``func``
    MUST NOT exceed ``STANDARD_EVAL_STEP_LIMIT`` steps (enforced by the
    implementation, not by this module).
    """

    name: str
    func: Callable[[dict, dict], bool]


_standard_handlers: dict[str, StandardPredicateHandler] = {}


def register_standard_predicate(name: str, func: Callable[[dict, dict], bool]) -> None:
    """Register a Standard-profile predicate handler.

    Args:
        name: The ``restrict`` field value this handler serves.
        func: A callable ``(caveat: dict, ctx: dict) -> bool``.

    If ``name`` is already registered, raises ValueError (registration is
    one-shot; replacement requires explicit unregister).
    """
    if name in SIMPLE_CAVEAT_RESTRICTS:
        raise ValueError(
            f"Cannot register Standard predicate {name!r} — it shadows a Simple-profile restrict"
        )
    if name in _standard_handlers:
        raise ValueError(f"Standard predicate {name!r} is already registered")
    _standard_handlers[name] = StandardPredicateHandler(name=name, func=func)


def unregister_standard_predicate(name: str) -> None:
    """Remove a previously-registered Standard predicate handler."""
    _standard_handlers.pop(name, None)


def standard_predicate_registered(name: str) -> bool:
    """Return True if a Standard predicate handler is registered for ``name``."""
    return name in _standard_handlers


# =============================================================================
# Advanced profile (spec §18.4.3) — third-party caveats
# =============================================================================

def is_third_party_caveat(caveat: dict) -> bool:
    """Return True if ``caveat`` is a third-party (Advanced) caveat."""
    return bool(caveat.get("third_party"))


@dataclass
class AdvancedProfileSupport:
    """Whether the host implementation supports Advanced caveats.

    Per spec §18.4.3, implementations MAY refuse Advanced. A receiver that
    does not support Advanced SHOULD return ``pact_scope_insufficient`` on
    a REQ whose cap carries any third-party caveat.
    """

    enabled: bool = False
    third_party_handler: Callable[[dict, dict], bool] | None = None


# Module-level default: Advanced support is OFF unless an implementation
# explicitly enables it. This matches spec §18.4.3's MAY-refuse default.
_advanced_support = AdvancedProfileSupport()


def enable_advanced_profile(handler: Callable[[dict, dict], bool]) -> None:
    """Opt into Advanced-profile third-party caveat support.

    ``handler`` is invoked for each third-party caveat. It MUST contact
    the verifier endpoint listed in the caveat and return the boolean
    result of that verifier's assertion.
    """
    _advanced_support.enabled = True
    _advanced_support.third_party_handler = handler


def disable_advanced_profile() -> None:
    """Opt out of Advanced-profile support (reverts to default-deny)."""
    _advanced_support.enabled = False
    _advanced_support.third_party_handler = None


# =============================================================================
# Profile classification + evaluation
# =============================================================================

class PolicyProfileError(Exception):
    """A caveat could not be satisfied; carries a wire-level fault code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def classify_caveat_profile(caveat: dict) -> PolicyProfile:
    """Determine which profile a caveat belongs to.

    Returns the most-restrictive profile that recognizes the caveat:
    SIMPLE if the ``restrict`` field is one of the four Simple types,
    ADVANCED if ``third_party`` is True, STANDARD otherwise.
    """
    if is_third_party_caveat(caveat):
        return PolicyProfile.ADVANCED
    restrict = caveat.get("restrict")
    if restrict in SIMPLE_CAVEAT_RESTRICTS:
        return PolicyProfile.SIMPLE
    return PolicyProfile.STANDARD


def classify_cap_profile(caveats: list[dict]) -> PolicyProfile:
    """Determine the maximum profile required by a cap's caveat list.

    Returns ADVANCED if any caveat is third-party, STANDARD if any is
    a custom predicate, SIMPLE if all are templated.
    """
    levels = {classify_caveat_profile(c) for c in caveats}
    if PolicyProfile.ADVANCED in levels:
        return PolicyProfile.ADVANCED
    if PolicyProfile.STANDARD in levels:
        return PolicyProfile.STANDARD
    return PolicyProfile.SIMPLE


def evaluate_caveats(caveats: list[dict], ctx: dict) -> None:
    """Evaluate a cap's caveat list against a request context.

    Raises ``PolicyProfileError`` with the appropriate wire-level fault
    code (spec §18.3) on the first caveat that is not satisfied.

    Caveat-type-specific failure codes:

    * action: ``pact_scope_insufficient``
    * budget_cents: ``pact_budget_exceeded``
    * depth: ``pact_depth_exceeded``
    * expires_at: ``pact_token_expired``
    * unknown Standard predicate: ``pact_scope_insufficient`` (fail-closed)
    * third-party caveat when Advanced disabled: ``pact_scope_insufficient``
    """
    # Import the fault codes here to avoid a top-level cycle through errors.
    from pact_passport.errors import (
        PACT_BUDGET_EXCEEDED,
        PACT_DEPTH_EXCEEDED,
        PACT_SCOPE_INSUFFICIENT,
        PACT_TOKEN_EXPIRED,
    )

    fault_map = {
        "action":       PACT_SCOPE_INSUFFICIENT,
        "budget_cents": PACT_BUDGET_EXCEEDED,
        "depth":        PACT_DEPTH_EXCEEDED,
        "expires_at":   PACT_TOKEN_EXPIRED,
    }

    for caveat in caveats:
        profile = classify_caveat_profile(caveat)

        if profile == PolicyProfile.SIMPLE:
            check = _SIMPLE_DISPATCH[caveat["restrict"]]
            if not check(caveat, ctx):
                raise PolicyProfileError(
                    code=fault_map[caveat["restrict"]],
                    detail=f"Simple-profile caveat {caveat['restrict']!r} not satisfied",
                )

        elif profile == PolicyProfile.STANDARD:
            handler = _standard_handlers.get(caveat["restrict"])
            if handler is None:
                # Fail-closed per spec §18.4.2: missing handler = reject.
                raise PolicyProfileError(
                    code=PACT_SCOPE_INSUFFICIENT,
                    detail=f"No Standard predicate handler for {caveat.get('restrict')!r}",
                )
            if not handler.func(caveat, ctx):
                raise PolicyProfileError(
                    code=PACT_SCOPE_INSUFFICIENT,
                    detail=f"Standard predicate {caveat['restrict']!r} not satisfied",
                )

        else:  # ADVANCED
            if not _advanced_support.enabled or _advanced_support.third_party_handler is None:
                raise PolicyProfileError(
                    code=PACT_SCOPE_INSUFFICIENT,
                    detail="Third-party (Advanced) caveat encountered but Advanced profile not enabled",
                )
            if not _advanced_support.third_party_handler(caveat, ctx):
                raise PolicyProfileError(
                    code=PACT_SCOPE_INSUFFICIENT,
                    detail=f"Third-party caveat at {caveat.get('verifier_endpoint')!r} did not assert",
                )


# =============================================================================
# Conformance helpers
# =============================================================================

def canonical_simple_caveat_bytes(caveat: dict) -> bytes:
    """Return the canonical-JSON bytes for a Simple-profile caveat.

    Useful for conformance tests that need to verify implementations
    produce the exact byte patterns required by spec §18.4.1.
    """
    profile = classify_caveat_profile(caveat)
    if profile != PolicyProfile.SIMPLE:
        raise ValueError(
            f"canonical_simple_caveat_bytes only applies to SIMPLE caveats, "
            f"got {profile.value}"
        )
    return canonical_json(caveat)


__all__ = [
    # Profile enum
    "PolicyProfile",
    "PolicyProfileError",
    # Simple-profile factories (spec §18.4.1)
    "SIMPLE_CAVEAT_RESTRICTS",
    "make_action_caveat",
    "make_budget_caveat",
    "make_depth_caveat",
    "make_expiry_caveat",
    # Satisfaction checks
    "satisfies_action",
    "satisfies_budget",
    "satisfies_depth",
    "satisfies_expiry",
    # Standard-profile registry (spec §18.4.2)
    "STANDARD_EVAL_STEP_LIMIT",
    "StandardPredicateHandler",
    "register_standard_predicate",
    "unregister_standard_predicate",
    "standard_predicate_registered",
    # Advanced-profile (spec §18.4.3)
    "AdvancedProfileSupport",
    "enable_advanced_profile",
    "disable_advanced_profile",
    "is_third_party_caveat",
    # Classification + evaluation
    "classify_caveat_profile",
    "classify_cap_profile",
    "evaluate_caveats",
    "canonical_simple_caveat_bytes",
]
