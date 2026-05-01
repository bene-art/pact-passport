"""Scenario 5: receipt log stays performant at scale.

Process N messages and assert:
  1. Disk usage is bounded (not pathologically large per message)
  2. Listing the most recent receipts stays fast

The current store writes one JSON file per receipt + per message. There is
no retention policy and no index. This test documents the threshold at
which the implementation starts to degrade.

N is kept modest to keep the test under 30s on CI; the per-message
budget is what matters.
"""

from __future__ import annotations

import time

from pact.message import build_req

from tests.integration.conftest import post_message


N_MESSAGES = 500
PER_MESSAGE_DISK_BUDGET = 4 * 1024  # 4 KB per message including msg + res + receipt
LIST_BUDGET_SECONDS = 0.5


def _dir_size(path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total


def test_receipt_log_scale(sandbox, tmp_path):
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("echo")
    def echo(payload):
        return {"n": payload.get("n", 0)}

    for i in range(N_MESSAGES):
        req = build_req(
            from_private_key=alice["identity"]._private_key,
            from_id=alice["agent_id"],
            to_id=bob["agent_id"],
            intent="task",
            payload={"action": "echo", "n": i},
        )
        r = post_message(bob["url"], req.to_dict())
        assert r["status"] == "ok"

    bob_dir = tmp_path / "bob"
    disk = _dir_size(bob_dir)
    budget = N_MESSAGES * PER_MESSAGE_DISK_BUDGET

    assert disk < budget, (
        f"bob's store grew to {disk:,} bytes for {N_MESSAGES} messages "
        f"(>{disk/N_MESSAGES:.0f} bytes/msg). budget={budget:,}. "
        "receipt log retention may need bounds."
    )

    # Listing receipts should stay fast even with many files.
    t0 = time.perf_counter()
    receipts = bob["agent"]._store.list_receipts("bob")
    elapsed = time.perf_counter() - t0

    assert len(receipts) == N_MESSAGES, (
        f"expected {N_MESSAGES} receipts, found {len(receipts)}"
    )
    assert elapsed < LIST_BUDGET_SECONDS, (
        f"list_receipts({N_MESSAGES} entries) took {elapsed:.3f}s, "
        f"budget {LIST_BUDGET_SECONDS}s. consider an index or pagination."
    )
