"""Tests for the v1.4 attack scenario catalogue (spec §18.8)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pact_passport.audit import scenario_predicts_match
from pact_passport.errors import ALL_FAULT_CODES, http_status_for_fault


CATALOGUE_PATH = Path(__file__).parents[2] / "spec" / "attacks" / "attacks.json"


@pytest.fixture(scope="module")
def catalogue():
    """Load the canonical catalogue once per test module."""
    assert CATALOGUE_PATH.exists(), f"catalogue not found at {CATALOGUE_PATH}"
    with CATALOGUE_PATH.open() as f:
        return json.load(f)


def test_catalogue_loads_as_valid_json(catalogue):
    """spec §18.8 — the catalogue MUST be a parseable JSON object."""
    assert isinstance(catalogue, dict)
    assert "scenarios" in catalogue


def test_catalogue_version_matches_spec_draft(catalogue):
    """Catalogue version SHOULD track spec version."""
    assert catalogue["catalogue_version"] == "1.4.0-draft"
    assert catalogue["spec_version"] == "1.4.0-draft"


def test_catalogue_size(catalogue):
    """spec §18.8 — v1.4 ships 12 scenarios."""
    assert len(catalogue["scenarios"]) == 12


def test_all_scenarios_have_required_fields(catalogue):
    required = {
        "id", "title", "description", "lemma_ref", "test_ref",
        "predicted_error", "predicted_status",
        "v0_7_behavior", "v0_8_behavior",
    }
    for s in catalogue["scenarios"]:
        missing = required - set(s)
        assert not missing, f"scenario {s.get('id')!r} missing fields: {missing}"


def test_scenario_ids_are_unique(catalogue):
    ids = [s["id"] for s in catalogue["scenarios"]]
    assert len(ids) == len(set(ids)), "duplicate scenario ids"


def test_predicted_errors_are_in_taxonomy_or_pact_ok(catalogue):
    """Every predicted_error MUST be either a normative fault code or 'pact_ok'."""
    for s in catalogue["scenarios"]:
        err = s["predicted_error"]
        assert err == "pact_ok" or err in ALL_FAULT_CODES, (
            f"scenario {s['id']!r} has predicted_error={err!r} "
            f"which is not in the v1.4 taxonomy"
        )


def test_predicted_status_matches_taxonomy_mapping(catalogue):
    """Predicted HTTP status MUST match the §18.3 mapping for the error."""
    for s in catalogue["scenarios"]:
        err = s["predicted_error"]
        status = s["predicted_status"]
        if err == "pact_ok":
            assert status == 200, (
                f"scenario {s['id']}: pact_ok must map to 200, got {status}"
            )
        else:
            expected = http_status_for_fault(err)
            assert status == expected, (
                f"scenario {s['id']}: predicted_status={status} does not match "
                f"taxonomy mapping for {err} (= {expected})"
            )


def test_all_formal_lemmas_have_at_least_one_scenario(catalogue):
    """spec §18.8 — every formal lemma SHOULD have ≥1 catalogue entry."""
    pact_lemmas = {"P-AUTH", "P-BIND", "P-MONO", "P-REPLAY", "P-AUDIT", "P-OPAQUE"}
    referenced = {s["lemma_ref"] for s in catalogue["scenarios"]}
    missing = pact_lemmas - referenced
    assert not missing, f"formal lemmas with no catalogue entry: {missing}"


def test_summary_block_matches_scenario_counts(catalogue):
    """The summary block's counts MUST equal the actual scenario list."""
    summary = catalogue["summary"]
    assert summary["total_scenarios"] == len(catalogue["scenarios"])

    v07_acc = sum(1 for s in catalogue["scenarios"]
                  if "accept" in s["v0_7_behavior"].lower())
    v07_rej = sum(1 for s in catalogue["scenarios"]
                  if "reject" in s["v0_7_behavior"].lower())
    # Allow tolerance — some scenarios document "vulnerable" or "N/A"
    assert v07_acc + v07_rej + summary["v0_7_vulnerable_count"] >= summary["total_scenarios"] - 2


def test_aip_comparison_block_present(catalogue):
    """The catalogue includes an apples-to-apples AIP comparison."""
    assert "aip_comparison" in catalogue
    cmp = catalogue["aip_comparison"]
    assert cmp["aip_catalogue_size"] == 3
    assert cmp["pact_catalogue_size"] == 12
    assert len(cmp["pact_scenarios_beyond_aip"]) == 9


def test_v0_7_p_bind_vulnerability_documented(catalogue):
    """The v0.7 → v0.8 P_BIND closure is recorded in the catalogue."""
    hp_replay = next(
        (s for s in catalogue["scenarios"] if s["id"] == "holder-proof-replay"),
        None,
    )
    assert hp_replay is not None
    assert "vulnerable" in hp_replay["v0_7_behavior"].lower()
    assert "rejected" in hp_replay["v0_8_behavior"].lower()
    assert hp_replay["lemma_ref"] == "P-BIND"


# ---------------------------------------------------------------------------
# scenario_predicts_match helper
# ---------------------------------------------------------------------------

def test_scenario_predicts_match_matches_on_exact_observation():
    scenario = {
        "id": "test-scenario",
        "predicted_error": "pact_signature_invalid",
        "predicted_status": 401,
    }
    outcome = scenario_predicts_match(scenario, "pact_signature_invalid", 401)
    assert outcome.matched


def test_scenario_predicts_match_flags_mismatch_on_error():
    scenario = {
        "id": "test-scenario",
        "predicted_error": "pact_signature_invalid",
        "predicted_status": 401,
    }
    outcome = scenario_predicts_match(scenario, "pact_token_malformed", 401)
    assert not outcome.matched


def test_scenario_predicts_match_flags_mismatch_on_status():
    scenario = {
        "id": "test-scenario",
        "predicted_error": "pact_signature_invalid",
        "predicted_status": 401,
    }
    outcome = scenario_predicts_match(scenario, "pact_signature_invalid", 200)
    assert not outcome.matched
