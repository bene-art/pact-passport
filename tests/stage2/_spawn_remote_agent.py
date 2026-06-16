"""Spawn a long-lived PACTAgent listening for cross-machine Stage 2 probes.

Run on the peer host (e.g., NUC) before the Mac side launches probes
configured with `STAGE2_<role>_URL=http://<peer-host>:<port>`. The Mac
fetches this agent's identity_doc at `/pact/v1/identity` to populate its
peer cache, then sends REQ messages directly to this server.

Usage:
    python -m tests.stage2._spawn_remote_agent <name> [--port N] [--store-dir DIR] [--ready-file FILE]

Behavior:
  - Binds 0.0.0.0:<port>. If --port is 0 (default), a random free port
    is chosen; the actual port appears in the readiness banner and the
    optional readiness file.
  - Prints a single-line readiness banner to stdout:
        PACT_AGENT_READY name=<name> url=<url> agent_id=<aid>
    so the SSH client can grep for it without parsing JSON.
  - Writes a JSON summary to --ready-file (if specified) — useful when
    the SSH stdout is being suppressed or when polling is preferred.
  - Blocks until SIGTERM / SIGINT. The shell that started it via SSH
    can `kill` it to tear down.

Designed to be invoked from the Mac via:
    ssh nuc "<bash -lc> python -m tests.stage2._spawn_remote_agent nuc_runner --port 9101"
followed by a poll of /pact/v1/health before running the probe.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import tempfile
import time
from pathlib import Path

# Import here to keep startup fast and surface env / install issues early.
from tests.stage2._harness import stand_up_agent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Spawn a remote PACTAgent for cross-machine probes.")
    parser.add_argument("name", help="Agent name (e.g., nuc_runner). Surfaces in probe pairings + receipts.")
    parser.add_argument("--port", type=int, default=0,
                        help="Bind port. 0 = pick a free one (printed in banner).")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind interface. Default 0.0.0.0 (all). Restrict to a Tailscale-only IP if needed.")
    parser.add_argument("--store-dir", default=None,
                        help="Persistent identity / receipt store. Default: a fresh tempdir per spawn (identity is fresh each run — fine for one-shot probes).")
    parser.add_argument("--ready-file", default=None,
                        help="Optional path to write a JSON readiness summary on startup.")
    args = parser.parse_args(argv)

    store_dir = Path(args.store_dir) if args.store_dir else Path(tempfile.mkdtemp(prefix="pact_remote_"))
    handle = stand_up_agent(args.name, store_dir, host=args.host, port=args.port)

    summary = {
        "name": handle["name"],
        "url": handle["url"],
        "agent_id": handle["agent_id"],
        "identity_doc": handle["identity"].to_identity_document(),
        "store_dir": str(store_dir),
    }

    # Single-line grep-able banner — must be the first non-blank line on stdout.
    banner = f"PACT_AGENT_READY name={handle['name']} url={handle['url']} agent_id={handle['agent_id']}"
    print(banner)
    sys.stdout.flush()

    if args.ready_file:
        Path(args.ready_file).write_text(json.dumps(summary, indent=2))

    stop_requested = False

    def _stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # Hold the server alive until signalled.
    try:
        while not stop_requested:
            time.sleep(1.0)
    finally:
        try:
            handle["server"].stop()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
