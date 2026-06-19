"""δ.1.3 — HTTP status mapping for v1.4 pact_* fault codes (spec §18.3).

These tests verify that the transport layer maps wire-level ``pact_*``
fault codes to the spec §18.3 HTTP status codes (401 / 403 / 410), via
``_status_for_response`` in ``transport/server.py``.

Legacy fault codes (non-``pact_*``) keep the v0.7 behavior of HTTP 200
with fault in the body — until v0.8.2 completes the taxonomy roll-out.
"""
from __future__ import annotations

import pytest

from pact_passport.errors import (
    ALL_FAULT_CODES,
    FAULT_HTTP_STATUS,
    PACT_AUDIENCE_MISMATCH,
    PACT_HOLDER_PROOF_INVALID,
    PACT_REVOCATION_OBSERVED,
    PACT_SCOPE_INSUFFICIENT,
    PACT_TOKEN_EXPIRED,
    PACT_TOKEN_MALFORMED,
    PACT_TOKEN_MISSING,
    http_status_for_fault,
)
from pact_passport.transport.server import _status_for_response


# =============================================================================
# Library-level taxonomy invariants
# =============================================================================

def test_taxonomy_has_exactly_13_codes():
    """v0.8 ships 13 wire-level fault codes (spec §18.3)."""
    assert len(ALL_FAULT_CODES) == 13


def test_every_taxonomy_code_has_http_mapping():
    """Every pact_* fault code MUST have an HTTP status mapping."""
    for code in ALL_FAULT_CODES:
        assert code in FAULT_HTTP_STATUS, f"{code} missing from FAULT_HTTP_STATUS"
        assert FAULT_HTTP_STATUS[code] in (401, 403, 410, 429, 500)


def test_authn_codes_map_to_401():
    """Authentication failures → HTTP 401."""
    for code in (PACT_TOKEN_MISSING, PACT_TOKEN_MALFORMED,
                 PACT_TOKEN_EXPIRED, PACT_HOLDER_PROOF_INVALID):
        assert http_status_for_fault(code) == 401, code


def test_authz_codes_map_to_403():
    """Authorization failures → HTTP 403."""
    for code in (PACT_SCOPE_INSUFFICIENT, PACT_AUDIENCE_MISMATCH):
        assert http_status_for_fault(code) == 403, code


def test_revocation_code_maps_to_410():
    """Operational signal (revocation) → HTTP 410."""
    assert http_status_for_fault(PACT_REVOCATION_OBSERVED) == 410


def test_unknown_code_maps_to_500():
    """An out-of-taxonomy code is a substrate-internal bug → 500."""
    assert http_status_for_fault("not_a_real_fault") == 500
    assert http_status_for_fault("") == 500


# =============================================================================
# Transport-layer _status_for_response — dispatch integration
# =============================================================================

def test_ok_response_returns_200():
    """status='ok' → HTTP 200 regardless of payload."""
    assert _status_for_response({"status": "ok", "payload": {}}) == 200


def test_error_with_pact_token_malformed_returns_401():
    res = {"status": "error", "fault": {"code": "pact_token_malformed", "detail": "..."}}
    assert _status_for_response(res) == 401


def test_error_with_pact_audience_mismatch_returns_403():
    res = {"status": "error", "fault": {"code": "pact_audience_mismatch", "detail": "..."}}
    assert _status_for_response(res) == 403


def test_error_with_pact_token_expired_returns_401():
    res = {"status": "error", "fault": {"code": "pact_token_expired", "detail": "..."}}
    assert _status_for_response(res) == 401


def test_error_with_pact_revocation_returns_410():
    res = {"status": "error", "fault": {"code": "pact_revocation_observed", "detail": "..."}}
    assert _status_for_response(res) == 410


def test_legacy_fault_code_returns_200():
    """Non-pact_* fault codes keep v0.7 behavior (200 with fault in body)
    until v0.8.2 completes the wire-level taxonomy roll-out."""
    res = {"status": "error", "fault": {"code": "capability_invalid", "detail": "..."}}
    assert _status_for_response(res) == 200
    res = {"status": "error", "fault": {"code": "unknown_intent", "detail": "..."}}
    assert _status_for_response(res) == 200


def test_malformed_response_dict_returns_200():
    """Edge cases — non-dict, missing fault, malformed fault — all 200."""
    assert _status_for_response(None) == 200
    assert _status_for_response("not a dict") == 200
    assert _status_for_response({"status": "error"}) == 200  # missing fault
    assert _status_for_response({"status": "error", "fault": "string"}) == 200
    assert _status_for_response({"status": "error", "fault": {"code": None}}) == 200
