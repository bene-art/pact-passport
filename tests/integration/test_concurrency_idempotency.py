"""Scenario 1: idempotency under simultaneous double-fire.

The same signed REQ (same idempotency_key) is POSTed twice from two threads
released by a Barrier at the same instant. The shared-goal invariants:

  1. Bob's handler runs exactly once
  2. Both responses are identical
  3. Both responses are well-formed (status: ok)

If the handler runs twice, the idempotency cache lost the race
(read-then-write at agent.py:132-138, no lock).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from pact.message import build_req

from tests.integration.conftest import post_message


def test_idempotency_under_simultaneous_double_fire(sandbox):
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    handler_lock = threading.Lock()
    handler_calls = {"n": 0}

    @bob["agent"].handle("count")
    def count(payload):
        with handler_lock:
            handler_calls["n"] += 1
            n = handler_calls["n"]
        return {"call": n}

    # Single signed REQ — both sends use the same idempotency_key.
    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "count"},
    )
    msg_dict = req.to_dict()

    barrier = threading.Barrier(2)

    def fire():
        barrier.wait()  # release both threads at once
        return post_message(bob["url"], msg_dict)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(fire)
        f2 = ex.submit(fire)
        r1, r2 = f1.result(), f2.result()

    # Shared-goal invariants
    assert r1["status"] == "ok", f"r1 not ok: {r1}"
    assert r2["status"] == "ok", f"r2 not ok: {r2}"
    assert r1["payload"] == r2["payload"], (
        f"responses diverged under race: {r1['payload']} vs {r2['payload']}"
    )
    assert handler_calls["n"] == 1, (
        f"handler ran {handler_calls['n']} times — idempotency broke under race"
    )
