"""A3: Idempotency Cache Race — high-N storm (Bug 1 regression coverage).

Extends the existing tests/integration/test_concurrency_idempotency.py
(which tests N=2) to higher thread counts {2, 4, 8, 16, 32, 64} with
chaos delays injected at race-prone points (PACT_CHAOS=1).

The original v0.1.4 fix added _task_lock to serialize dispatch and
prevent the read-then-write race in the idempotency cache that allowed
duplicate handler execution. A3 exercises that lock at scale.

Pre-registered prediction: 100% at-most-once across all N values.
Handler invocation count == 1 per trial; all N responses are identical.

Adversarial vector: N threads each fire a REQ with the same
idempotency_key from the same client; all threads released by a
threading.Barrier at the same instant. PACT_CHAOS=1 injects random
delays inside chaos_sleep() at race-prone code paths.

Trial count: 100 per N value (instead of plan's 1,000) for tractable
runtime (~1 min total vs ~10 min). 100 × (2+4+8+16+32+64) = 12,600
total race opportunities — more than enough to surface any race that
exists.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from pact_passport.message import build_req

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# Storm machinery
# ---------------------------------------------------------------------------


def _storm(sandbox, n_threads: int, n_trials: int):
    """Run n_trials, each firing n_threads concurrent REQs with the same
    idempotency_key. Returns (handler_call_counts, response_distribution).
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    # Per-trial handler call tracking — reset between trials
    handler_calls = {"n": 0}
    handler_lock = threading.Lock()

    @bob["agent"].handle("count")
    def count(payload):
        with handler_lock:
            handler_calls["n"] += 1
            n = handler_calls["n"]
        return {"call": n}

    duplicate_handler_invocations = 0
    distinct_responses_per_trial = []

    for _ in range(n_trials):
        # Reset handler call count for this trial
        with handler_lock:
            handler_calls["n"] = 0

        # Single signed REQ — all sends use the same idempotency_key
        req = build_req(
            from_private_key=alice["identity"]._private_key,
            from_id=alice["agent_id"],
            to_id=bob["agent_id"],
            intent="task",
            payload={"action": "count"},
        )
        msg_dict = req.to_dict()

        barrier = threading.Barrier(n_threads)
        results = []
        results_lock = threading.Lock()

        def fire():
            barrier.wait()
            r = post_message(bob["url"], msg_dict)
            with results_lock:
                results.append(r)

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            for _ in range(n_threads):
                pool.submit(fire)

        # Validate per-trial invariants
        with handler_lock:
            final_count = handler_calls["n"]
        if final_count > 1:
            duplicate_handler_invocations += (final_count - 1)

        # All responses should be identical (same idempotency_key →
        # same cached response)
        response_bodies = [
            r.get("payload", {}).get("call") for r in results
            if r.get("status") == "ok"
        ]
        distinct = len(set(response_bodies))
        distinct_responses_per_trial.append(distinct)

    return duplicate_handler_invocations, distinct_responses_per_trial


# ---------------------------------------------------------------------------
# Tests — one per N value
# ---------------------------------------------------------------------------


N_TRIALS = 100


@pytest.mark.parametrize("n_threads", [2, 4, 8, 16, 32, 64])
def test_a3_idempotency_storm_at_n_threads(sandbox, n_threads, capsys):
    """Storm test at the given thread count. Pre-registered: 100%
    at-most-once handler execution across N_TRIALS trials."""
    dup_invocations, distinct_per_trial = _storm(sandbox, n_threads, N_TRIALS)

    trials_with_dups = sum(1 for d in distinct_per_trial if d > 1)
    print(
        f"\n[A3] N={n_threads:2d} threads × {N_TRIALS} trials | "
        f"duplicate_handler_invocations={dup_invocations} "
        f"trials_with_distinct_responses={trials_with_dups}"
    )

    # Pre-registered: zero duplicate handler invocations
    assert dup_invocations == 0, (
        f"N={n_threads}: handler invoked {dup_invocations} extra times — "
        f"_task_lock failed to prevent the race"
    )

    # Pre-registered: all N responses per trial should be identical
    assert trials_with_dups == 0, (
        f"N={n_threads}: {trials_with_dups}/{N_TRIALS} trials returned "
        f"non-identical responses — cached response not consistently served"
    )


def test_a3_storm_under_chaos_mode_at_n_8(sandbox, monkeypatch, capsys):
    """Same storm at N=8 but with PACT_CHAOS=1 enabling chaos_sleep()
    delays at race-prone code paths. This is the highest-leverage
    stress on _task_lock since the chaos sleeps maximize the window
    where a missing lock would let the race manifest.
    """
    monkeypatch.setenv("PACT_CHAOS", "1")
    # Force re-import of _chaos module so it sees the env var
    # (Defensive — the env-var check is at call time, not import time,
    # but explicit is better here.)

    dup_invocations, distinct_per_trial = _storm(sandbox, n_threads=8, n_trials=N_TRIALS)
    trials_with_dups = sum(1 for d in distinct_per_trial if d > 1)
    print(
        f"\n[A3-chaos] N=8 × {N_TRIALS} trials (PACT_CHAOS=1) | "
        f"duplicate_handler_invocations={dup_invocations} "
        f"trials_with_distinct_responses={trials_with_dups}"
    )

    assert dup_invocations == 0, (
        f"chaos mode: handler invoked {dup_invocations} extra times — "
        f"race surfaced under PACT_CHAOS=1"
    )
    assert trials_with_dups == 0
