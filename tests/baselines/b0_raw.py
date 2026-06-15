"""B0-RAW — undefended baseline: bare HTTP echo server, no PACT layer.

Used by §12.1 to bound the round-trip floor a defended substrate could
ever achieve. The handler accepts a JSON payload, echoes it back. No
identity, no caps, no holder binding, no receipts — anyone who can
reach the port gets a response.

Exposes a minimal API:

  start_b0_raw(host, port) -> handle
  send_b0_raw(handle["url"], payload, n_trials=30) -> {round_trip_ms_list, ...}
  stop_b0_raw(handle)

The measurement methodology mirrors L-tier's: N round trips, drop the
first as TLS-handshake / DNS / first-page warm-up (irrelevant here but
preserved for shape parity), report median + p95.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        resp = json.dumps({"echo": payload}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):  # noqa: A002 (Python's BaseHTTPRequestHandler convention)
        # Silence per-request stderr; the harness owns logging.
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_b0_raw(host: str = "127.0.0.1", port: int | None = None) -> dict:
    """Start a bare-HTTP echo server and return handle.

    The handle dict mirrors the shape of `_start_agent` in the integration
    fixtures so a probe body can be written symmetrically against PACT
    or B0-RAW depending on which it instantiates.
    """
    port = port or _free_port()
    server = ThreadingHTTPServer((host, port), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return {"server": server, "thread": thread, "url": f"http://{host}:{port}"}


def stop_b0_raw(handle: dict) -> None:
    handle["server"].shutdown()
    handle["server"].server_close()


def send_b0_raw(
    url: str,
    payload: dict | None = None,
    n_trials: int = 30,
    timeout_s: float = 5.0,
) -> dict:
    """Send N POST trials to the B0-RAW echo, return per-trial round-trip ms.

    Returns:
        {
          "n_trials": int,
          "round_trip_ms": list[float],   # one per trial, in order
          "median_ms": float,
          "p95_ms": float,
          "errors": int,                  # transport failures excluded from stats
        }
    """
    payload = payload or {"msg": "ping"}
    body = json.dumps(payload).encode("utf-8")
    trips: list[float] = []
    errors = 0
    for i in range(n_trials):
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                resp.read()
            trips.append((time.perf_counter() - t0) * 1000.0)
        except Exception:
            errors += 1
    if not trips:
        return {"n_trials": n_trials, "round_trip_ms": [], "median_ms": -1.0,
                "p95_ms": -1.0, "errors": errors}
    sorted_trips = sorted(trips)
    median = sorted_trips[len(sorted_trips) // 2]
    p95_idx = max(0, int(0.95 * len(sorted_trips)) - 1)
    return {
        "n_trials": n_trials,
        "round_trip_ms": trips,
        "median_ms": round(median, 3),
        "p95_ms": round(sorted_trips[p95_idx], 3),
        "errors": errors,
    }
