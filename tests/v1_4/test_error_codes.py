"""Tests for v1.4 / v0.8 fault-code taxonomy (spec §18.3)."""
from __future__ import annotations

import pytest

from pact_passport.errors import (
    ALL_FAULT_CODES,
    FAULT_HTTP_STATUS,
    # Authentication-class (401)
    PACT_TOKEN_MISSING,
    PACT_TOKEN_MALFORMED,
    PACT_SIGNATURE_INVALID,
    PACT_HOLDER_PROOF_INVALID,
    PACT_IDENTITY_UNRESOLVABLE,
    PACT_TOKEN_EXPIRED,
    PACT_KEY_REVOKED,
    # Authorization-class (403)
    PACT_SCOPE_INSUFFICIENT,
    PACT_BUDGET_EXCEEDED,
    PACT_DEPTH_EXCEEDED,
    PACT_AUDIENCE_MISMATCH,
    PACT_RECEIPT_NOT_BILATERAL,
    # Operational (410)
    PACT_REVOCATION_OBSERVED,
    http_status_for_fault,
)


def test_taxonomy_total_count():
    """spec §18.3 — exactly 13 normative codes (7 + 5 + 1)."""
    assert len(ALL_FAULT_CODES) == 13


def test_all_codes_have_pact_prefix():
    """spec §18.3 — implementations MUST NOT use pact_ for non-normative codes."""
    for code in ALL_FAULT_CODES:
        assert code.startswith("pact_"), f"normative code {code!r} lacks pact_ prefix"


def test_authentication_class_maps_to_401():
    """spec §18.3 authentication faults → HTTP 401."""
    auth_codes = {
        PACT_TOKEN_MISSING, PACT_TOKEN_MALFORMED, PACT_SIGNATURE_INVALID,
        PACT_HOLDER_PROOF_INVALID, PACT_IDENTITY_UNRESOLVABLE,
        PACT_TOKEN_EXPIRED, PACT_KEY_REVOKED,
    }
    assert len(auth_codes) == 7
    for code in auth_codes:
        assert http_status_for_fault(code) == 401, f"{code} should be 401"


def test_authorization_class_maps_to_403():
    """spec §18.3 authorization faults → HTTP 403."""
    authz_codes = {
        PACT_SCOPE_INSUFFICIENT, PACT_BUDGET_EXCEEDED, PACT_DEPTH_EXCEEDED,
        PACT_AUDIENCE_MISMATCH, PACT_RECEIPT_NOT_BILATERAL,
    }
    assert len(authz_codes) == 5
    for code in authz_codes:
        assert http_status_for_fault(code) == 403, f"{code} should be 403"


def test_operational_signal_maps_to_410():
    """spec §18.3 operational signals → HTTP 410."""
    assert http_status_for_fault(PACT_REVOCATION_OBSERVED) == 410


def test_pact_specific_codes_are_present():
    """spec §18.3 — 3 PACT-specific codes beyond AIP-shaped taxonomy."""
    pact_specific = {
        PACT_HOLDER_PROOF_INVALID,
        PACT_AUDIENCE_MISMATCH,  # also distinct in AIP, included in PACT
        PACT_RECEIPT_NOT_BILATERAL,
        PACT_REVOCATION_OBSERVED,
    }
    for code in pact_specific:
        assert code in ALL_FAULT_CODES


def test_unknown_code_maps_to_500():
    """Non-taxonomy code → HTTP 500 (substrate-internal bug)."""
    assert http_status_for_fault("application_bad_input") == 500
    assert http_status_for_fault("pact_made_up") == 500


def test_fault_status_dict_completeness():
    """Every code in ALL_FAULT_CODES has an entry in FAULT_HTTP_STATUS."""
    assert set(FAULT_HTTP_STATUS) == set(ALL_FAULT_CODES)
