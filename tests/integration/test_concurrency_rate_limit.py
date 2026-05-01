"""Scenario 2: rate-limit boundary under concurrent fire.

Issue a capability with max_invocations=N. Fire 2N requests simultaneously.
Each request has a unique idempotency key (so idempotency dedup doesn't
mask the test). The shared-goal invariant: exactly N succeed.

If more than N succeed, the invocation counter lost the race
(read-then-write at agent.py:175-185, no lock).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from pact.capability import Caveat, issue_capability
from pact.message import build_req

from tests.integration.conftest import post_message


MAX_INV = 5
TOTAL_FIRES = 10


def test_rate_limit_holds_under_race(sandbox):
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    # Bob issues a capability to Alice with max_invocations=5.
    cap = issue_capability(
        bob["identity"]._private_key,
        bob["agent_id"],
        alice["agent_id"],
        "tick",
        caveats=[Caveat("max_invocations", MAX_INV)],
    )
    bob["agent"]._store.save_capability("bob", cap.to_dict())

    @bob["agent"].handle("tick")
    def tick(payload):
        return {"ok": True}

    barrier = threading.Barrier(TOTAL_FIRES)

    def fire(i: int):
        # Each request gets a fresh idempotency key — we want the rate-limit
        # check to fire on every one, not get short-circuited by the cache.
        req = build_req(
            from_private_key=alice["identity"]._private_key,
            from_id=alice["agent_id"],
            to_id=bob["agent_id"],
            intent="task",
            payload={"action": "tick", "n": i},
            cap_id=cap.cap_id,
            holder_proof_key=alice["identity"]._private_key,
        )
        barrier.wait()
        return post_message(bob["url"], req.to_dict())

    with ThreadPoolExecutor(max_workers=TOTAL_FIRES) as ex:
        results = [ex.submit(fire, i) for i in range(TOTAL_FIRES)]
        responses = [f.result() for f in results]

    successes = [r for r in responses if r.get("status") == "ok"]
    rate_limited = [
        r for r in responses
        if r.get("status") == "error"
        and r.get("fault", {}).get("code") == "rate_limited"
    ]

    assert len(successes) == MAX_INV, (
        f"rate limit allowed {len(successes)} successes, expected exactly {MAX_INV}. "
        f"successes={successes}"
    )
    assert len(rate_limited) == TOTAL_FIRES - MAX_INV, (
        f"expected {TOTAL_FIRES - MAX_INV} rate_limited, got {len(rate_limited)}"
    )
