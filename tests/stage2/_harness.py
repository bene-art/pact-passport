"""Stage 2 probe harness — every probe imports from this.

Each probe is a single Python file that:
  1. imports `probe` from `_harness`
  2. imports its locked adversarial string(s) from `_prompts`
  3. defines a body function that mutates `result`
  4. decorates that body with `@probe(...)` declaring pairing + prediction

The decorator captures pre-registration metadata, runs the body,
records receipts + outcome + elapsed time, and writes a single JSON
file to a timestamped `results_<ts>/` directory under this package.

Cross-machine specifics (Tailscale hostnames, model names, transport)
are passed in the `pairing` dict, not hard-coded — every probe is
self-describing.
"""
from __future__ import annotations

import json
import platform
import socket
import subprocess
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from pact_passport.agent import PACTAgent
from pact_passport.identity import Identity
from pact_passport.transport.server import PACTServer

# ---------------------------------------------------------------------------
# Results directory — one timestamped folder per harness import
# ---------------------------------------------------------------------------

RESULTS_ROOT = Path(__file__).parent
_RUN_TS = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
RUN_DIR = RESULTS_ROOT / f"results_{_RUN_TS}"


def _ensure_run_dir() -> Path:
    """Create RUN_DIR lazily — only when the first probe fires.

    Importing the harness alone (e.g., for testing) MUST NOT create
    an empty results directory.
    """
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return RUN_DIR


# ---------------------------------------------------------------------------
# Provenance — C3-c per Stage 2 Change Plan §3 / RESEARCH Appendix C.
# Stamped into every result JSON so a Stage 2 run is reproducible: same
# git SHA + same Python on the same OS + same model digests reproduces
# the same observations.
# ---------------------------------------------------------------------------

def _collect_provenance() -> dict[str, Any]:
    """Capture the host's stable identity at harness-load time.

    Per-probe runtime info (model_digests, trial_index, n_trials) is
    layered on top by the probe wrapper / probe body.
    """
    try:
        git_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            check=True,
            timeout=2.0,
        ).stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        git_sha = "unknown"
    return {
        "git_sha": git_sha,
        "host": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
    }


_PROVENANCE = _collect_provenance()


# ---------------------------------------------------------------------------
# Statistics — Wilson score interval for binomial proportions.
# RESEARCH §6.2: "Report Wilson score intervals for binomial violation
# rates (better than normal approx near 0/1, which is exactly where
# protocol-layer rates will live)." Rolled by hand so the harness has
# zero extra dependencies (scipy not installed in the v0.7.x line).
# ---------------------------------------------------------------------------

WILSON_Z_95 = 1.959963984540054  # two-sided 95% CI


def wilson_ci(violations: int, n: int, z: float = WILSON_Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Args:
        violations: number of "violation" outcomes observed.
        n: number of trials (excluding harness_error trials).
        z: standard-normal quantile for the desired two-sided CI level
           (default 1.96 ≈ 95%).

    Returns:
        (low, high) tuple, both in [0, 1]. Both are 0.0 when n == 0
        (no information; the caller should treat the CI as undefined).
    """
    if n <= 0:
        return (0.0, 0.0)
    p_hat = violations / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denom
    margin = z * ((p_hat * (1 - p_hat) / n + z2 / (4 * n * n)) ** 0.5) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


# ---------------------------------------------------------------------------
# Probe decorator
# ---------------------------------------------------------------------------

# Outcomes counted as "violations" for STOCH probe rate computation.
# `harness_error` is excluded (instrumentation issue, not a protocol obs).
_VIOLATION_OUTCOMES = ("new_finding", "regression")


def record_llm_call(
    result: dict,
    *,
    model: str,
    seed: int | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    num_predict: int | None = None,
    **extra: Any,
) -> None:
    """Append a single LLM-call record to `result["llm_runtime"]`.

    Call this immediately before / after every ollama.chat() or other
    model invocation inside a STOCH probe. The record captures every
    parameter that could affect output sampling so a (model_digest,
    llm_runtime[i]) pair is sufficient for replay.

    Probes also populate `result["model_digests"][model]` with the
    resolved digest the *first* time they call `model`; that's the
    long-lived identity, while llm_runtime[i] is the per-call params.

    `extra` carries any model-specific knobs (e.g. `repeat_penalty`,
    `mirostat`, format-mode flags) without forcing a kwargs explosion
    on this signature.
    """
    record = {
        "model": model,
        "seed": seed,
        "temperature": temperature,
        "top_p": top_p,
        "top_k": top_k,
        "num_predict": num_predict,
    }
    if extra:
        record["extra"] = dict(extra)
    result["llm_runtime"].append(record)


def _new_result(probe_id, tier, pairing, prediction, threshold, citation,
                classification, n_trials, trial_index) -> dict[str, Any]:
    """Fresh per-trial result skeleton with all pre-registration fields."""
    from tests.stage2 import _ablations as _ablation_harness
    result = {
        "probe_id": probe_id,
        "tier": tier,
        "started_at_utc": datetime.now(UTC).isoformat(),
        "pairing": pairing,
        "pre_registered_prediction": prediction,
        "failure_threshold": threshold,
        "citation": citation,
        "classification": classification,
        "provenance": dict(_PROVENANCE),
        # Per-probe LLM model digests — probes that call into an
        # adversary or handler LLM populate this with the resolved
        # digest(s) (e.g. "gemma3:e4b@sha256:..."). Empty dict for
        # purely-deterministic probes.
        "model_digests": {},
        # Per-probe LLM call parameters captured at call time. Each
        # entry is one record: {model, seed, temperature, top_p,
        # top_k, num_predict, ...}. Use record_llm_call() to append.
        # Empty list for purely-deterministic probes; STOCH probes
        # that issue ollama.chat() / API calls MUST record params
        # here so that a given (model_digest, llm_runtime[i]) pair
        # is sufficient for replay. RESEARCH §6.2 reproducibility.
        "llm_runtime": [],
        "trial_index": trial_index,
        "n_trials": n_trials,
        "receipts": [],
        "observations": {},
        "outcome": None,
        "elapsed_s": None,
        "notes": "",
    }
    # §12 ablation config — empty {"active": [], "config_id": "BASELINE"}
    # for normal Phase A confirmatory runs; populated when the probe is
    # invoked under an ABL-* config by scripts/run_phase_a.sh.
    _ablation_harness.tag_result_with_ablations(result)
    return result


def _run_one_trial(fn, result, args, kwargs) -> None:
    """Execute the probe body once, mutating `result` in place."""
    t0 = time.time()
    try:
        fn(result, *args, **kwargs)
        if result["outcome"] is None:
            result["outcome"] = "harness_error"
            result["notes"] = "probe body did not set result['outcome']"
    except Exception as e:
        result["outcome"] = "harness_error"
        result["notes"] = (
            f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
        )
    result["elapsed_s"] = round(time.time() - t0, 3)


def probe(
    probe_id: str,
    tier: str,
    pairing: dict,
    prediction: str,
    threshold: str,
    citation: str = "",
    classification: str = "DETERMINISTIC",
    n_trials: int = 1,
) -> Callable:
    """Wrap a probe body. Captures pre-registration + outcome + receipts.

    The wrapped function must accept a single `result` dict and mutate it.
    By contract the probe body MUST set `result["outcome"]` to one of:
      "pass", "new_finding", "regression", "harness_error".

    Per RESEARCH plan §6 / §5.3, every probe is explicitly classified:

      - "DETERMINISTIC"  — a signature verifies or it does not. N=1 is a
        proof-by-execution counterexample test; single run suffices.
        Examples: protocol-mechanics probes (A4, A5, B*, C-convergence,
        R1, S2/S3/S5 structural). Writes one `<probe_id>.json`.

      - "STOCHASTIC" with n_trials > 1 — LLM adversary or LLM handler
        in the loop; single runs are scientifically invalid. Loops N
        times, writes one `<probe_id>_trial_<i>.json` per trial, plus
        an aggregate `<probe_id>.json` with violation rate + Wilson 95%
        CI (RESEARCH §6.2). Outcomes `new_finding` and `regression`
        count as violations; `harness_error` is excluded from the rate
        (instrumentation issue, not a protocol observation). N=30 by
        default; raise to N=100 for cells where the observed rate
        falls in (0, 0.1) — that's exactly where the normal approx
        breaks down and Wilson earns its keep.

    The aggregate JSON additionally records:
      - `aggregate.n` — trials excluding harness_errors
      - `aggregate.violations` — count of new_finding + regression
      - `aggregate.rate` — violations / n
      - `aggregate.wilson_low`, `wilson_high` — 95% CI bounds
      - `aggregate.harness_errors` — excluded trial count
      - `aggregate.outcomes` — full per-trial outcome tally
      - `aggregate.elapsed_s_total` — wall-clock for the loop

    STOCH with n_trials == 1 (unusual but allowed) takes the
    single-trial path so the aggregate machinery doesn't add noise to
    a one-shot run.
    """
    if classification not in ("DETERMINISTIC", "STOCHASTIC"):
        raise ValueError(
            f"probe '{probe_id}': classification must be "
            f"'DETERMINISTIC' or 'STOCHASTIC', got {classification!r}"
        )
    if n_trials < 1:
        raise ValueError(
            f"probe '{probe_id}': n_trials must be >= 1, got {n_trials}"
        )

    multi_trial = classification == "STOCHASTIC" and n_trials > 1

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs) -> dict:
            run_dir = _ensure_run_dir()

            # --- Single-trial path (DET, or STOCH-n_trials=1) ---
            if not multi_trial:
                result = _new_result(
                    probe_id, tier, pairing, prediction, threshold,
                    citation, classification, n_trials, trial_index=0,
                )
                _run_one_trial(fn, result, args, kwargs)
                (run_dir / f"{probe_id}.json").write_text(
                    json.dumps(result, indent=2, default=str)
                )
                return result

            # --- Multi-trial path (STOCH with n_trials > 1) ---
            t_loop_start = time.time()
            trial_results: list[dict] = []
            for i in range(n_trials):
                tr = _new_result(
                    probe_id, tier, pairing, prediction, threshold,
                    citation, classification, n_trials, trial_index=i,
                )
                _run_one_trial(fn, tr, args, kwargs)
                (run_dir / f"{probe_id}_trial_{i:03d}.json").write_text(
                    json.dumps(tr, indent=2, default=str)
                )
                trial_results.append(tr)
            loop_elapsed = round(time.time() - t_loop_start, 3)

            # Tally outcomes.
            outcome_tally: dict[str, int] = {}
            for tr in trial_results:
                key = tr["outcome"] or "harness_error"
                outcome_tally[key] = outcome_tally.get(key, 0) + 1
            harness_errors = outcome_tally.get("harness_error", 0)
            countable_n = n_trials - harness_errors
            violations = sum(
                outcome_tally.get(o, 0) for o in _VIOLATION_OUTCOMES
            )
            rate = (violations / countable_n) if countable_n > 0 else None
            wilson_low, wilson_high = (
                wilson_ci(violations, countable_n)
                if countable_n > 0 else (None, None)
            )

            # The aggregate's outcome is a verdict-on-the-batch, distinct
            # from per-trial outcomes:
            #   - "pass":         no violations observed (Wilson upper bound
            #                     bounds the residual risk; the paper quotes it)
            #   - "new_finding":  at least one violation observed
            #   - "harness_error": all trials harness-errored (no data)
            if countable_n == 0:
                aggregate_outcome = "harness_error"
            elif violations == 0:
                aggregate_outcome = "pass"
            else:
                aggregate_outcome = "new_finding"

            aggregate = _new_result(
                probe_id, tier, pairing, prediction, threshold,
                citation, classification, n_trials, trial_index=-1,
            )
            aggregate["aggregate"] = {
                "n": countable_n,
                "violations": violations,
                "rate": rate,
                "wilson_z": WILSON_Z_95,
                "wilson_low": wilson_low,
                "wilson_high": wilson_high,
                "harness_errors": harness_errors,
                "outcomes": outcome_tally,
                "elapsed_s_total": loop_elapsed,
                "per_trial_files": [
                    f"{probe_id}_trial_{i:03d}.json" for i in range(n_trials)
                ],
            }
            aggregate["outcome"] = aggregate_outcome
            aggregate["elapsed_s"] = loop_elapsed
            aggregate["notes"] = (
                f"STOCHASTIC aggregate over {n_trials} trials "
                f"(excl. {harness_errors} harness_error). See per-trial "
                f"files for individual receipts + observations."
            )
            (run_dir / f"{probe_id}.json").write_text(
                json.dumps(aggregate, indent=2, default=str)
            )
            return aggregate

        wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
        wrapper.probe_id = probe_id  # type: ignore[attr-defined]
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Agent fixture helpers — model the integration conftest pattern,
# generalized for cross-machine use (Tailscale + per-agent store_dir).
# ---------------------------------------------------------------------------

def free_port() -> int:
    """Bind a transient socket to discover an unused local port."""
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


def stand_up_agent(
    name: str,
    store_dir: Path,
    host: str = "0.0.0.0",
    port: int | None = None,
    advertise_protocol=None,
) -> dict[str, Any]:
    """Stand up a PACTAgent + PACTServer pair. Returns handles.

    Mirrors `tests/integration/conftest.py:_start_agent` but:
      - allows arbitrary host (for Tailscale IPs)
      - threads `advertise_protocol` through (Tier P probes)
      - leaves identity-doc peer-sharing to the caller
    """
    if port is None:
        port = free_port()
    agent = PACTAgent(
        name,
        store_dir=store_dir,
        host=host,
        port=port,
        advertise_protocol=advertise_protocol,
    )
    identity: Identity = agent._ensure_identity()
    server = PACTServer(
        host=host,
        port=port,
        dispatch=agent._dispatch,
        identity_doc=identity.to_identity_document(),
    )
    actual_port = server.start()
    agent.port = actual_port
    agent._server = server
    return {
        "name": name,
        "agent": agent,
        "identity": identity,
        "agent_id": identity.agent_id,
        "public_key": identity.public_key,
        "private_key": identity._private_key,
        "url": f"http://{host}:{actual_port}",
        "server": server,
        "store_dir": store_dir,
    }


def teardown(*handles: dict) -> None:
    """Stop servers; safe to call on partially-set-up handles."""
    for h in handles:
        srv = h.get("server")
        if srv is not None:
            try:
                srv.stop()
            except Exception:
                pass


def cross_share_identities(*handles: dict) -> None:
    """Pre-share peer identity docs so signature verification works
    without an mDNS handshake. Use for cross-machine probes where
    mDNS would not work across the Tailscale boundary."""
    for h_self in handles:
        for h_peer in handles:
            if h_peer is h_self:
                continue
            h_self["agent"]._store.save_peer(
                h_peer["agent_id"],
                h_peer["identity"].to_identity_document(),
            )


# ---------------------------------------------------------------------------
# Cross-machine peer support (Stage 2 cross-tailnet probes)
# ---------------------------------------------------------------------------
#
# Pattern: the Mac (probe-driving side) stands up its agent locally with
# `stand_up_agent`; the remote agent (e.g., on the NUC over Tailscale) is
# pre-spawned via `tests/stage2/_spawn_remote_agent` and reachable at a
# known URL. The Mac probe then constructs a remote handle via
# `stand_up_remote_agent(url, name)` which fetches the remote's
# identity_doc over HTTP and returns a dict-shaped handle that probe
# bodies can use interchangeably with a local `stand_up_agent` handle.
#
# Field compatibility:
#   - agent_id, public_key, url, name      — present on both
#   - identity (object) | identity_doc     — local has object, remote has dict
#   - agent, server, private_key, store_dir — present on local only; None on remote
#   - _remote = True flag on remote handles
#
# Probe bodies that use `nuc["private_key"]` must NOT use a remote handle
# for that role — the remote keeps its private key. For most probe shapes
# the Mac is the requester (uses its own private key) and the remote is
# the responder (uses its own private key on its side, never exposed).

def stand_up_remote_agent(url: str, name: str = "remote", timeout_s: float = 10.0) -> dict[str, Any]:
    """Build a handle for a PACTAgent already running at `url`.

    Fetches identity_doc via GET {url}/pact/v1/identity. Returns a handle
    compatible with `stand_up_agent`'s for the fields probe bodies read
    on a peer (agent_id, public_key, url, identity_doc). Local-only
    fields (agent, server, private_key, store_dir) are None.

    Args:
        url: Base URL of the remote PACTServer (e.g., http://nucnode.tailcf96a0.ts.net:9101)
        name: Logical label for the remote in result JSON / logs.
        timeout_s: HTTP timeout for the identity fetch.

    Raises:
        urllib.error.URLError on transport failure.
        KeyError if the fetched identity_doc is malformed.
    """
    import base64
    import json
    import urllib.request

    fetch_url = url.rstrip("/") + "/pact/v1/identity"
    with urllib.request.urlopen(fetch_url, timeout=timeout_s) as resp:
        identity_doc = json.loads(resp.read())

    return {
        "name": name,
        "agent": None,
        "identity": None,
        "identity_doc": identity_doc,
        "agent_id": identity_doc["agent_id"],
        "public_key": base64.b64decode(identity_doc["public_key"]),
        "private_key": None,
        "url": url,
        "server": None,
        "store_dir": None,
        "_remote": True,
    }


def share_remote_identity_into(local_handle: dict, remote_handle: dict) -> None:
    """Write the remote peer's identity_doc into the local agent's peer
    store. One-way only — the remote auto-trusts via the `identity_doc`
    field that the local agent inlines on each REQ (spec §6.2 v1.1
    addition), so no NUC-side write is required.

    Use this in place of `cross_share_identities` when one side is remote.
    """
    if local_handle.get("_remote"):
        raise ValueError("local_handle is itself remote; need a local handle to populate")
    if not remote_handle.get("_remote"):
        raise ValueError("remote_handle is not remote; use cross_share_identities for two locals")
    local_handle["agent"]._store.save_peer(
        remote_handle["agent_id"],
        remote_handle["identity_doc"],
    )


def maybe_remote_peer(name: str, env_var: str) -> dict | None:
    """If `os.environ[env_var]` is set, build a remote handle pointing at
    that URL; otherwise return None so the probe falls back to a local
    `stand_up_agent`.

    Probes use this for backwards-compatible cross-machine support:

        nuc = maybe_remote_peer("nuc_runner", "STAGE2_NUC_URL") \
              or stand_up_agent("nuc_runner", store_dir, host="127.0.0.1")

    Setting `STAGE2_NUC_URL=http://nucnode.tailcf96a0.ts.net:9101`
    in the env runs the probe cross-tailnet against a pre-spawned remote;
    leaving it unset preserves loopback behavior.
    """
    import os
    url = os.environ.get(env_var)
    if not url:
        return None
    return stand_up_remote_agent(url, name=name)


# ---------------------------------------------------------------------------
# Run-dir summary writer (called by the runner after all probes complete)
# ---------------------------------------------------------------------------

def write_run_summary() -> Path:
    """Aggregate every <probe_id>.json in RUN_DIR into summary.md.

    Output format matches the Stage 2 plan §13.1 — one row per probe,
    columns: tier, probe_id, outcome, elapsed_s. Tier-level rollups
    appended for fold-into supplementary_registry.md.
    """
    rows = []
    if not RUN_DIR.exists():
        # No probes ran in this process — nothing to summarize.
        return RUN_DIR
    for jf in sorted(RUN_DIR.glob("*.json")):
        try:
            data = json.loads(jf.read_text())
            rows.append((
                data.get("tier", "?"),
                data.get("probe_id", jf.stem),
                data.get("outcome", "?"),
                data.get("elapsed_s", 0.0),
            ))
        except Exception:
            rows.append(("?", jf.stem, "parse_error", 0.0))

    lines = ["# Stage 2 run summary", "",
             f"Run directory: `{RUN_DIR.name}`",
             f"Generated: {datetime.now(UTC).isoformat()}",
             "",
             "| Tier | Probe | Outcome | Elapsed (s) |",
             "|---|---|---|---|"]
    for tier, pid, outcome, elapsed in rows:
        lines.append(f"| {tier} | `{pid}` | `{outcome}` | {elapsed} |")

    tier_counts: dict[str, dict[str, int]] = {}
    for tier, _, outcome, _ in rows:
        tier_counts.setdefault(tier, {}).setdefault(outcome, 0)
        tier_counts[tier][outcome] += 1

    lines += ["", "## Per-tier roll-up", ""]
    for tier in sorted(tier_counts):
        bits = ", ".join(
            f"{k}={v}" for k, v in sorted(tier_counts[tier].items())
        )
        lines.append(f"- **{tier}**: {bits}")

    summary_path = RUN_DIR / "summary.md"
    summary_path.write_text("\n".join(lines) + "\n")
    return summary_path
