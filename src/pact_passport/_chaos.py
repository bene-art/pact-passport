"""Chaos injection for race-condition testing.

When PACT_CHAOS=1 is set, chaos_sleep() injects a small random delay at
the call site. This widens race windows so concurrency bugs that would
normally surface 1-in-1000 surface 1-in-10. No-op when the env var is unset.
"""

from __future__ import annotations

import os
import random
import time


def chaos_sleep(max_seconds: float = 0.005) -> None:
    """If PACT_CHAOS=1, sleep for a random duration up to max_seconds."""
    if os.environ.get("PACT_CHAOS") == "1":
        time.sleep(random.uniform(0, max_seconds))
