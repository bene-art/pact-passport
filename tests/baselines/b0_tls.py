"""B0-TLS — channel-auth-only baseline: mTLS-only HTTP echo (STUB).

**Status (2026-06-15):** structural scaffold only. The mTLS server +
cert-pinning client are not yet wired; the placeholder `start_b0_tls`
raises NotImplementedError. The §12.1 baseline measurement against
B0-TLS is deferred until this is implemented.

Why a stub now: the `v0.7.1-pre-registration` freeze captures the
*intent* to measure against mTLS-only. Implementing the cert plumbing
before the tag would land code in the freeze that isn't exercised by
Phase A; doing it as a separate v0.7.x patch after tag is cleaner and
documented as deferred work in `STAGE2_CHANGE_PLAN.md`.

Implementation outline (when v0.8 work begins):

  1. Generate a self-signed CA + client/server cert pair in
     `tests/baselines/_certs/` (gitignored; regenerated per-run).
  2. Server: ThreadingHTTPServer wrapped in an SSL context that
     requires client cert; pin to the generated CA.
  3. Client: urllib.request with an SSLContext + client cert; pin
     server cert by SHA-256 fingerprint.
  4. Same echo handler shape as b0_raw — measurement parity is the
     point. The overhead delta vs B0-RAW = pure TLS handshake + record
     layer cost (i.e., what channel-bound peer identity will cost in
     v0.8 C3).
"""

from __future__ import annotations


def start_b0_tls(host: str = "127.0.0.1", port: int | None = None) -> dict:
    """Not yet implemented — see module docstring."""
    raise NotImplementedError(
        "B0-TLS baseline is deferred to v0.8. See tests/baselines/b0_tls.py "
        "docstring for the implementation outline. The §12.1 attribution "
        "table will carry an 'unmeasured' entry for B0-TLS rows until then."
    )


def stop_b0_tls(handle: dict) -> None:
    raise NotImplementedError("B0-TLS deferred")


def send_b0_tls(
    url: str,
    payload: dict | None = None,
    n_trials: int = 30,
    timeout_s: float = 5.0,
) -> dict:
    raise NotImplementedError("B0-TLS deferred")
