"""R1-cross-machine remote agent.

Specialized variant of `_spawn_remote_agent.py` for the bidirectional
R1 case-study replay. Stands up a PACTAgent on the peer host (NUC)
with the `reformulate` and `synthesize` handlers from the v0.1.3
case study, pre-issues holder-bound caps for both actions, and
exposes a test-mode HTTP control server that lets the Mac side
register itself as the peer and trigger the Step 2 callback flow.

Wire flow this script enables:

    Mac → NUC reformulate    (Mac drives, NUC handler runs)
    NUC → Mac answer         (NUC's reformulate-completion thread fires
                              an outbound REQ to Mac, signed with NUC's
                              private key, presenting Mac-issued cap)
    Mac → NUC synthesize     (Mac drives, NUC handler runs)

Two HTTP servers run side-by-side on the NUC:
  - PACTServer on `--port`              (default 9101) — protocol traffic
  - TestControlServer on `--port + 1`   (default 9102) — research-only
    endpoints used solely by `probe_r1_xmachine_replay`:

      GET  /test/caps/<action>      — returns a NUC-issued cap as JSON
      POST /test/register_peer      — Mac registers { mac_url, mac_identity_doc, cap_answer }
      GET  /test/health             — control-server liveness

The test-control server has NO authentication and exists only for
cross-machine experimental orchestration. Production deployments
MUST NOT run this binary.

Usage:
    python -m tests.stage2._spawn_r1_remote nuc_r1 --port 9101

Lifecycle:
    Same as _spawn_remote_agent — block until SIGTERM. The Mac probe
    invokes via SSH, polls /pact/v1/health for PACTServer ready, then
    posts /test/register_peer before driving Step 1.
"""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import logging
import signal
import socketserver
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from pact_passport import build_req, send_message
from pact_passport.capability import issue_capability

from tests.stage2._harness import stand_up_agent

_LOG = logging.getLogger("r1_remote")


# Shared mutable state between PACTServer handlers and TestControlServer.
class _PeerState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.mac_url: str | None = None
        self.mac_identity_doc: dict | None = None
        self.cap_answer: dict | None = None  # Mac-issued; NUC presents on Step 2.

    def set_peer(self, mac_url: str, mac_identity_doc: dict, cap_answer: dict) -> None:
        with self.lock:
            self.mac_url = mac_url
            self.mac_identity_doc = mac_identity_doc
            self.cap_answer = cap_answer

    def snapshot(self) -> tuple[str | None, dict | None, dict | None]:
        with self.lock:
            return self.mac_url, self.mac_identity_doc, self.cap_answer


# Module-level handles so the TestControlServer handler can reach them
# without threading args through http.server's class-based dispatch.
_PEER_STATE = _PeerState()
_NUC_HANDLE: dict = {}  # populated in main() before TestControlServer starts
_ISSUED_CAPS: dict[str, dict] = {}


class _TestControlHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        # Silence per-request stderr; the harness owns logging.
        pass

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/test/health":
            self._send_json(200, {"status": "ok"})
            return

        if self.path.startswith("/test/caps/"):
            action = self.path[len("/test/caps/"):]
            cap_dict = _ISSUED_CAPS.get(action)
            if cap_dict is None:
                self._send_json(404, {"error": "no cap for action", "action": action})
            else:
                self._send_json(200, {"cap": cap_dict})
            return

        self._send_json(404, {"error": "unknown test endpoint", "path": self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except json.JSONDecodeError as e:
            self._send_json(400, {"error": "bad json", "detail": str(e)})
            return

        if self.path == "/test/register_peer":
            try:
                _PEER_STATE.set_peer(
                    mac_url=body["mac_url"],
                    mac_identity_doc=body["mac_identity_doc"],
                    cap_answer=body["cap_answer"],
                )
            except KeyError as e:
                self._send_json(400, {"error": "missing field", "field": str(e)})
                return

            # Save Mac's identity_doc into NUC's peer store so signatures
            # verify when the Step 2 follow-up REQ comes back through the
            # protocol layer (PACT requires the from_agent's pubkey).
            _NUC_HANDLE["agent"]._store.save_peer(
                body["mac_identity_doc"]["agent_id"],
                body["mac_identity_doc"],
            )
            self._send_json(200, {"status": "registered"})
            return

        self._send_json(404, {"error": "unknown test endpoint", "path": self.path})


class _QuietHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _send_step2_to_mac(reformulated_text: str) -> None:
    """Background-thread callback that fires Step 2 (NUC → Mac answer) after
    NUC's reformulate handler completes Step 1.

    Constructs a REQ signed with NUC's private key, presenting the
    Mac-issued cap_answer + a holder_proof binding to the new msg.id.
    """
    mac_url, mac_id_doc, cap_answer = _PEER_STATE.snapshot()
    if not mac_url or not mac_id_doc or not cap_answer:
        _LOG.warning("step2 callback fired but peer not registered; skipping")
        return

    nuc = _NUC_HANDLE
    try:
        req = build_req(
            from_private_key=nuc["private_key"],
            from_id=nuc["agent_id"],
            to_id=mac_id_doc["agent_id"],
            intent="task",
            payload={"action": "answer", "q": reformulated_text},
            cap_envelope=cap_answer,
            holder_proof_key=nuc["private_key"],
            identity_doc=nuc["identity"].to_identity_document(),
        )
        res = send_message(mac_url, req)
        _LOG.info("step2 sent; mac responded status=%s", res.get("status"))
        # Stash for the Mac probe to verify via /test/health-extended? For
        # now we just log — the Mac side observes Step 2 by watching its
        # own server's receipt cache.
    except Exception as e:
        _LOG.exception("step2 send failed: %s", e)


# Handlers registered on the NUC PACTAgent.
def _reformulate_handler(payload: dict) -> dict:
    """v0.1.3 case-study Step 1 — NUC's reformulate handler.

    Returns the reformulated text synchronously (RES goes back to Mac as
    Step 1's reply). Side effect: spawns a background thread that fires
    Step 2 (NUC → Mac answer) once Mac is registered as a peer.
    """
    reformulated = payload.get("q", "")
    # Mirror v0.1.3 timing (~20ms ollama latency simulation).
    time.sleep(0.02)
    # Trigger Step 2 asynchronously so the Step 1 RES returns immediately.
    threading.Thread(
        target=_send_step2_to_mac,
        args=(reformulated,),
        daemon=True,
    ).start()
    return {"text": reformulated}


def _synthesize_handler(payload: dict) -> dict:
    """v0.1.3 case-study Step 3 — NUC's synthesize handler.

    Synchronous; returns the synthesized text. No follow-up REQs.
    """
    time.sleep(0.02)
    return {"text": payload.get("context", "")[:50] + "..."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="R1 cross-machine remote agent (NUC side).")
    parser.add_argument("name")
    parser.add_argument("--port", type=int, default=9101)
    parser.add_argument("--test-port", type=int, default=None,
                        help="Port for the test-control server (default: --port + 1).")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--store-dir", default=None)
    parser.add_argument("--ready-file", default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    store_dir = Path(args.store_dir) if args.store_dir else Path(tempfile.mkdtemp(prefix="pact_r1_remote_"))
    handle = stand_up_agent(args.name, store_dir, host=args.host, port=args.port)

    # Register the R1 handlers on the PACTAgent.
    handle["agent"].handle("reformulate")(_reformulate_handler)
    handle["agent"].handle("synthesize")(_synthesize_handler)

    # Pre-issue caps for the two NUC-receives actions. holder_id is
    # populated when Mac calls /test/register_peer — we issue them with
    # a placeholder and re-issue when Mac registers, OR we don't need to
    # pre-issue since Mac issues its own caps in turn. Actually: NUC
    # *issues* these caps because NUC is the receiver of these REQs.
    # holder is Mac's agent_id, which we don't know yet. Defer issuance
    # until /register_peer, when we know it.

    _NUC_HANDLE.update(handle)

    # Wrap _PeerState.set_peer so it ALSO issues the caps the moment Mac
    # registers — that's when we learn Mac's agent_id.
    _original_set_peer = _PEER_STATE.set_peer

    def _set_peer_and_issue_caps(mac_url, mac_identity_doc, cap_answer):
        _original_set_peer(mac_url, mac_identity_doc, cap_answer)
        # Issue caps for the two NUC-receives actions, holder = Mac.
        for action in ("reformulate", "synthesize"):
            cap = issue_capability(
                issuer_private_key=handle["private_key"],
                issuer_id=handle["agent_id"],
                holder_id=mac_identity_doc["agent_id"],
                action=action,
            )
            _ISSUED_CAPS[action] = cap.to_dict()

    _PEER_STATE.set_peer = _set_peer_and_issue_caps  # type: ignore[assignment]

    # Stand up the test-control HTTP server on a separate port.
    test_port = args.test_port if args.test_port is not None else args.port + 1
    test_server = _QuietHTTPServer((args.host, test_port), _TestControlHandler)
    test_thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    test_thread.start()

    # Banner + ready file.
    banner = (
        f"PACT_AGENT_READY name={handle['name']} url={handle['url']} "
        f"agent_id={handle['agent_id']} test_url=http://{args.host}:{test_port}"
    )
    print(banner)
    sys.stdout.flush()
    _LOG.info(banner)

    if args.ready_file:
        Path(args.ready_file).write_text(json.dumps({
            "name": handle["name"],
            "url": handle["url"],
            "agent_id": handle["agent_id"],
            "identity_doc": handle["identity"].to_identity_document(),
            "test_url": f"http://{args.host}:{test_port}",
        }, indent=2))

    stop_requested = False

    def _stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        while not stop_requested:
            time.sleep(1.0)
    finally:
        test_server.shutdown()
        try:
            handle["server"].stop()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
