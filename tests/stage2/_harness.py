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
import socket
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
# Probe decorator
# ---------------------------------------------------------------------------

def probe(
    probe_id: str,
    tier: str,
    pairing: dict,
    prediction: str,
    threshold: str,
    citation: str = "",
) -> Callable:
    """Wrap a probe body. Captures pre-registration + outcome + receipts.

    The wrapped function must accept a single `result` dict and mutate it.
    By contract the probe body MUST set `result["outcome"]` to one of:
      "pass", "new_finding", "regression", "harness_error".

    The wrapper writes `<probe_id>.json` to `RUN_DIR` on exit (even on
    exception).
    """
    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs) -> dict:
            t0 = time.time()
            result: dict[str, Any] = {
                "probe_id": probe_id,
                "tier": tier,
                "started_at_utc": datetime.now(UTC).isoformat(),
                "pairing": pairing,
                "pre_registered_prediction": prediction,
                "failure_threshold": threshold,
                "citation": citation,
                "receipts": [],
                "observations": {},
                "outcome": None,
                "elapsed_s": None,
                "notes": "",
            }
            try:
                fn(result, *args, **kwargs)
                if result["outcome"] is None:
                    result["outcome"] = "harness_error"
                    result["notes"] = (
                        "probe body did not set result['outcome']"
                    )
            except Exception as e:
                result["outcome"] = "harness_error"
                result["notes"] = (
                    f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
                )
            result["elapsed_s"] = round(time.time() - t0, 3)
            (_ensure_run_dir() / f"{probe_id}.json").write_text(
                json.dumps(result, indent=2, default=str)
            )
            return result
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
