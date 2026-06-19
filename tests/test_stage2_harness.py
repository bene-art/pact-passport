"""Unit tests for the Stage 2 probe harness — DET path, multi-trial STOCH
path, Wilson CI math, and provenance stamping. No artifact behavior is
exercised; harness only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.stage2._harness import (
    _MODEL_DIGEST_CACHE,
    _new_result,
    ollama_chat,
    probe,
    record_llm_call,
    resolve_model_digest,
    wilson_ci,
)
from tests.stage2._ablations import (
    assert_single_ablation_or_baseline,
    config_id_from_env,
    current_ablations,
    tag_result_with_ablations,
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


# ---------------------------------------------------------------------------
# §12 ablation tagging — result["ablation"] field
# ---------------------------------------------------------------------------

def test_current_ablations_empty_by_default(monkeypatch):
    """No PACT_ABLATION_* env vars set => empty list."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    assert current_ablations() == []


def test_current_ablations_reads_each_flag(monkeypatch):
    """Each PACT_ABLATION_<NAME>=1 surfaces in the list."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    monkeypatch.setenv("PACT_ABLATION_RATE", "1")
    assert sorted(current_ablations()) == ["BIND", "RATE"]


def test_config_id_baseline(monkeypatch):
    """No flags => 'BASELINE' — the Phase A confirmatory label."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    assert config_id_from_env() == "BASELINE"


def test_config_id_single_ablation(monkeypatch):
    """One flag => 'ABL-<NAME>' — the §12 attribution config shape."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_CHAIN", "1")
    assert config_id_from_env() == "ABL-CHAIN"


def test_config_id_multi_ablation_labels_as_hazard(monkeypatch):
    """Multiple flags => 'ABL-MULTI:<sorted-list>' — flagged for analysis."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    monkeypatch.setenv("PACT_ABLATION_CHAIN", "1")
    assert config_id_from_env() == "ABL-MULTI:BIND,CHAIN"


def test_assert_single_or_baseline_raises_on_multi(monkeypatch):
    """The runner pre-flight check halts on multi-ablation configs."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    monkeypatch.setenv("PACT_ABLATION_NONCE", "1")
    with pytest.raises(RuntimeError, match="§12 violation"):
        assert_single_ablation_or_baseline()


def test_assert_single_or_baseline_silent_on_baseline_and_single(monkeypatch):
    """Baseline and exactly-one configurations pass through quietly."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    assert_single_ablation_or_baseline()  # baseline — no raise

    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    assert_single_ablation_or_baseline()  # single — no raise


def test_result_skeleton_has_baseline_ablation_label(tmp_path, monkeypatch):
    """Every probe result starts with ablation = BASELINE when no env set."""
    monkeypatch.chdir(tmp_path)
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)

    @probe(
        probe_id="X5_baseline_label",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        result["outcome"] = "pass"

    out = body()
    assert out["ablation"] == {"active": [], "config_id": "BASELINE"}


def test_result_skeleton_picks_up_ablation_env(tmp_path, monkeypatch):
    """With PACT_ABLATION_CHAIN=1, every result is stamped ABL-CHAIN."""
    monkeypatch.chdir(tmp_path)
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_CHAIN", "1")

    @probe(
        probe_id="X6_ablation_label",
        tier="X",
        pairing={"role": "smoke"},
        prediction="pass",
        threshold="never",
        citation="this test",
    )
    def body(result):
        result["outcome"] = "pass"

    out = body()
    assert out["ablation"]["active"] == ["CHAIN"]
    assert out["ablation"]["config_id"] == "ABL-CHAIN"


def test_tag_result_with_ablations_is_idempotent(monkeypatch):
    """Multiple calls are safe — provenance state doesn't drift."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.delenv(f"PACT_ABLATION_{name}", raising=False)
    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    result = {}
    tag_result_with_ablations(result)
    first = dict(result["ablation"])
    tag_result_with_ablations(result)
    assert result["ablation"] == first


# ---------------------------------------------------------------------------
# ollama_chat + resolve_model_digest — STOCH-probe HTTP shim
# ---------------------------------------------------------------------------

class _FakeHTTPResp:
    """Minimal urlopen-compatible context manager returning a fixed body."""
    def __init__(self, body: bytes):
        self._body = body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self):
        return self._body


def test_ollama_chat_serializes_options_correctly(monkeypatch):
    """Body sent to /api/chat carries model, prompt, and every sampling knob set."""
    captured: dict = {}

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data)
        return _FakeHTTPResp(json.dumps({"message": {"content": "fake response"}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    result = ollama_chat(
        "gemma4:e4b", "the prompt",
        seed=7, temperature=0.7, top_p=0.95, top_k=40,
        num_predict=64, system="sys", think=False,
    )

    assert result["text"] == "fake response"
    assert captured["url"].endswith("/api/chat")
    body = captured["body"]
    assert body["model"] == "gemma4:e4b"
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "the prompt"},
    ]
    assert body["stream"] is False
    assert body["think"] is False
    opts = body["options"]
    assert opts["seed"] == 7
    assert opts["temperature"] == 0.7
    assert opts["top_p"] == 0.95
    assert opts["top_k"] == 40
    assert opts["num_predict"] == 64


def test_ollama_chat_omits_unset_options(monkeypatch):
    """Only seed + temperature are always sent; the rest opt-in."""
    captured: dict = {}

    def _fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data)
        return _FakeHTTPResp(json.dumps({"message": {"content": "ok"}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    ollama_chat("m", "p", seed=0, temperature=0.0)

    opts = captured["body"]["options"]
    assert set(opts.keys()) == {"seed", "temperature"}
    assert "think" not in captured["body"]


def test_resolve_model_digest_caches_per_process(monkeypatch):
    """Two calls for the same model hit /api/show once."""
    _MODEL_DIGEST_CACHE.clear()
    calls = {"n": 0}

    def _fake_urlopen(req, timeout=None):
        calls["n"] += 1
        return _FakeHTTPResp(json.dumps({"digest": "sha256:deadbeef", "size": 4_000_000_000}).encode())

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    first = resolve_model_digest("gemma4:e4b")
    second = resolve_model_digest("gemma4:e4b")

    assert first == second == "gemma4:e4b@sha256:deadbeef"
    assert calls["n"] == 1


def test_resolve_model_digest_falls_back_to_size_when_digest_missing(monkeypatch):
    """If /api/show omits digest, identity falls back to model#<size> — never empty."""
    _MODEL_DIGEST_CACHE.clear()

    def _fake_urlopen(req, timeout=None):
        return _FakeHTTPResp(json.dumps({"size": 4_000_000_000}).encode())

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    identity = resolve_model_digest("m_with_no_digest")
    assert identity == "m_with_no_digest#4000000000"
