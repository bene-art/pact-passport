"""Unit tests for the Stage 2 probe harness — DET path, multi-trial STOCH
path, Wilson CI math, and provenance stamping. No artifact behavior is
exercised; harness only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.stage2._harness import (
    _new_result,
    probe,
    record_llm_call,
    wilson_ci,
)


# ---------------------------------------------------------------------------
# Wilson 95% CI — known values + edge cases
# ---------------------------------------------------------------------------

def test_wilson_zero_in_n_gives_zero_lower_bound():
    """Zero observed violations in N trials: lower=0, upper>0 (rule-of-3 ish)."""
    low, high = wilson_ci(0, 30)
    assert low == 0.0
    # Upper bound is non-trivial — Wilson at 0/30 ≈ 0.1135.
    assert 0.10 < high < 0.12


def test_wilson_all_violations_pinpoints_upper_at_one():
    """All trials violated: upper≈1.0 (FP-rounded), lower>0."""
    low, high = wilson_ci(30, 30)
    assert high == pytest.approx(1.0)
    assert 0.88 < low < 0.89


def test_wilson_midrange_is_symmetric_ish():
    """2/30 should give a plausible asymmetric CI bracketing the rate."""
    low, high = wilson_ci(2, 30)
    p_hat = 2 / 30
    # CI should bracket the point estimate.
    assert low < p_hat < high
    # Reference: Wilson 95% for 2/30 ≈ (0.0185, 0.2132).
    assert 0.015 < low < 0.025
    assert 0.20 < high < 0.225


def test_wilson_zero_trials_returns_no_info_sentinel():
    """With n=0, return (0, 0) as the no-information sentinel."""
    assert wilson_ci(0, 0) == (0.0, 0.0)
    assert wilson_ci(0, -1) == (0.0, 0.0)


def test_wilson_bounded_to_unit_interval():
    """Even at extreme inputs the result stays in [0, 1]."""
    for v, n in [(0, 1), (1, 1), (1, 2), (50, 100), (99, 100), (100, 100)]:
        low, high = wilson_ci(v, n)
        assert 0.0 <= low <= 1.0
        assert 0.0 <= high <= 1.0
        assert low <= high


# ---------------------------------------------------------------------------
# DET path — single trial, no aggregate field, file at <probe_id>.json
# ---------------------------------------------------------------------------

def test_det_probe_runs_single_trial_no_aggregate(tmp_path, monkeypatch):
    """A DETERMINISTIC probe with n_trials=1 takes the single-trial path."""
    # Redirect RUN_DIR to a tmp area for inspection.
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    @probe(
        probe_id="unit_det_smoke",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="trivially passes",
        threshold="never",
        citation="this test",
        classification="DETERMINISTIC",
        n_trials=1,
    )
    def body(result):
        result["outcome"] = "pass"
        result["observations"] = {"hello": "world"}

    out = body()
    assert out["outcome"] == "pass"
    assert "aggregate" not in out
    assert out["n_trials"] == 1
    assert out["trial_index"] == 0
    # File written to <probe_id>.json (not _trial_NNN).
    written = tmp_path / "results" / "unit_det_smoke.json"
    assert written.exists()
    loaded = json.loads(written.read_text())
    assert loaded["outcome"] == "pass"
    assert "aggregate" not in loaded


# ---------------------------------------------------------------------------
# Multi-trial STOCH path — N trial files + aggregate
# ---------------------------------------------------------------------------

def test_stoch_probe_loops_n_trials_writes_per_trial_and_aggregate(tmp_path, monkeypatch):
    """STOCHASTIC + n_trials>1 runs N trials, writes N per-trial JSONs + 1 aggregate."""
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    # A toy body whose outcome alternates: trial 0,2,4 -> pass; 1,3 -> new_finding.
    # We use a closure counter to make trial behavior deterministic-but-varied.
    counter = {"n": 0}

    @probe(
        probe_id="unit_stoch_loop",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="alternating pass / new_finding by design",
        threshold="never",
        citation="this test",
        classification="STOCHASTIC",
        n_trials=5,
    )
    def body(result):
        i = counter["n"]
        counter["n"] += 1
        if i % 2 == 1:
            result["outcome"] = "new_finding"
            result["observations"] = {"trial_local_i": i}
        else:
            result["outcome"] = "pass"
            result["observations"] = {"trial_local_i": i}

    out = body()

    # Aggregate shape:
    assert "aggregate" in out
    agg = out["aggregate"]
    assert agg["n"] == 5
    assert agg["violations"] == 2  # i=1 and i=3
    assert agg["rate"] == pytest.approx(0.4)
    assert agg["wilson_low"] < agg["rate"] < agg["wilson_high"]
    assert agg["harness_errors"] == 0
    assert agg["outcomes"] == {"pass": 3, "new_finding": 2}
    # Aggregate outcome: at least one violation -> new_finding
    assert out["outcome"] == "new_finding"
    # Per-trial files written:
    for i in range(5):
        f = tmp_path / "results" / f"unit_stoch_loop_trial_{i:03d}.json"
        assert f.exists(), f"missing per-trial file for trial {i}"
        loaded = json.loads(f.read_text())
        assert loaded["trial_index"] == i
        assert loaded["observations"]["trial_local_i"] == i
    # Aggregate file at canonical <probe_id>.json:
    agg_file = tmp_path / "results" / "unit_stoch_loop.json"
    assert agg_file.exists()
    loaded_agg = json.loads(agg_file.read_text())
    assert loaded_agg["aggregate"]["violations"] == 2


def test_stoch_probe_all_pass_aggregate_outcome_pass(tmp_path, monkeypatch):
    """If every trial passes, aggregate outcome is 'pass' and Wilson upper
    bound is the residual-risk number the paper quotes."""
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    @probe(
        probe_id="unit_stoch_all_pass",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="every trial passes",
        threshold="any violation",
        citation="this test",
        classification="STOCHASTIC",
        n_trials=10,
    )
    def body(result):
        result["outcome"] = "pass"

    out = body()
    assert out["outcome"] == "pass"
    assert out["aggregate"]["violations"] == 0
    assert out["aggregate"]["rate"] == 0.0
    # Wilson upper bound at 0/10 ≈ 0.278 — the residual-risk number.
    assert 0.27 < out["aggregate"]["wilson_high"] < 0.30


def test_stoch_probe_harness_errors_excluded_from_rate(tmp_path, monkeypatch):
    """Trials that hit harness_error are excluded from n; rate uses
    countable trials only."""
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    counter = {"n": 0}

    @probe(
        probe_id="unit_stoch_with_errors",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="mix of pass / new_finding / harness_error",
        threshold="never",
        citation="this test",
        classification="STOCHASTIC",
        n_trials=6,
    )
    def body(result):
        i = counter["n"]
        counter["n"] += 1
        if i < 2:
            raise RuntimeError("simulated harness error")
        if i < 4:
            result["outcome"] = "new_finding"
        else:
            result["outcome"] = "pass"

    out = body()
    agg = out["aggregate"]
    assert agg["harness_errors"] == 2
    assert agg["n"] == 4              # 6 - 2 excluded
    assert agg["violations"] == 2     # i=2,3
    assert agg["rate"] == 0.5         # 2/4
    assert agg["outcomes"]["harness_error"] == 2


def test_stoch_probe_all_harness_error_aggregate_outcome_harness_error(tmp_path, monkeypatch):
    """If every trial errors, aggregate outcome is harness_error (no data)."""
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    @probe(
        probe_id="unit_stoch_all_error",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="every trial raises",
        threshold="never",
        citation="this test",
        classification="STOCHASTIC",
        n_trials=3,
    )
    def body(result):
        raise RuntimeError("always")

    out = body()
    assert out["outcome"] == "harness_error"
    assert out["aggregate"]["n"] == 0
    assert out["aggregate"]["rate"] is None
    assert out["aggregate"]["wilson_low"] is None
    assert out["aggregate"]["wilson_high"] is None


# ---------------------------------------------------------------------------
# Decorator validation
# ---------------------------------------------------------------------------

def test_probe_rejects_invalid_classification():
    with pytest.raises(ValueError, match="classification"):
        probe(
            probe_id="x", tier="t", pairing={}, prediction="", threshold="",
            classification="MAYBE",
        )(lambda r: None)


def test_probe_rejects_n_trials_below_one():
    with pytest.raises(ValueError, match="n_trials"):
        probe(
            probe_id="x", tier="t", pairing={}, prediction="", threshold="",
            classification="STOCHASTIC", n_trials=0,
        )(lambda r: None)


# ---------------------------------------------------------------------------
# Provenance — present + has the expected shape
# ---------------------------------------------------------------------------

def test_provenance_fields_present(tmp_path, monkeypatch):
    import tests.stage2._harness as h
    monkeypatch.setattr(h, "RUN_DIR", tmp_path / "results")

    @probe(
        probe_id="unit_provenance",
        tier="unit",
        pairing={"role": "unit-test"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        result["outcome"] = "pass"

    out = body()
    prov = out["provenance"]
    assert "git_sha" in prov
    assert "host" in prov
    assert "os" in prov
    assert "python" in prov


# ---------------------------------------------------------------------------
# record_llm_call — STOCH replay-reproducibility hook
# ---------------------------------------------------------------------------

def test_result_skeleton_has_empty_llm_runtime_slot(tmp_path, monkeypatch):
    """Every probe result starts with an empty llm_runtime list ready for append."""
    monkeypatch.chdir(tmp_path)

    @probe(
        probe_id="X1_empty_llm_runtime",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        result["outcome"] = "pass"

    out = body()
    assert out["llm_runtime"] == []
    assert isinstance(out["model_digests"], dict)


def test_record_llm_call_captures_all_sampling_params(tmp_path, monkeypatch):
    """A single LLM call gets a full record — replay-sufficient with model_digest."""
    monkeypatch.chdir(tmp_path)

    @probe(
        probe_id="X2_record_llm",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        record_llm_call(
            result,
            model="gemma4:e4b",
            seed=42,
            temperature=0.7,
            top_p=0.9,
            top_k=40,
            num_predict=256,
            repeat_penalty=1.1,  # extra kwarg
        )
        result["outcome"] = "pass"

    out = body()
    assert len(out["llm_runtime"]) == 1
    rec = out["llm_runtime"][0]
    assert rec["model"] == "gemma4:e4b"
    assert rec["seed"] == 42
    assert rec["temperature"] == 0.7
    assert rec["top_p"] == 0.9
    assert rec["top_k"] == 40
    assert rec["num_predict"] == 256
    assert rec["extra"] == {"repeat_penalty": 1.1}


def test_record_llm_call_multiple_calls_append_in_order(tmp_path, monkeypatch):
    """Multiple LLM invocations in one trial each get their own record."""
    monkeypatch.chdir(tmp_path)

    @probe(
        probe_id="X3_multi_call",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        record_llm_call(result, model="gemma4:e4b", seed=1, temperature=0.0)
        record_llm_call(result, model="gemma3:12b", seed=2, temperature=0.8)
        result["outcome"] = "pass"

    out = body()
    assert [r["model"] for r in out["llm_runtime"]] == ["gemma4:e4b", "gemma3:12b"]
    assert [r["seed"] for r in out["llm_runtime"]] == [1, 2]


def test_record_llm_call_omitted_params_default_to_none(tmp_path, monkeypatch):
    """Probes that don't pin a knob leave it as None — explicit, not absent."""
    monkeypatch.chdir(tmp_path)

    @probe(
        probe_id="X4_partial_params",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        record_llm_call(result, model="gemma4:e4b", temperature=0.3)
        result["outcome"] = "pass"

    out = body()
    rec = out["llm_runtime"][0]
    assert rec["model"] == "gemma4:e4b"
    assert rec["temperature"] == 0.3
    assert rec["seed"] is None
    assert rec["top_p"] is None
    assert "extra" not in rec  # no extras provided
