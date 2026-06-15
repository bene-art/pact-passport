"""External baselines for §12.1 — measure what PACT adds vs alternatives.

These are NOT ablations (those disable single PACT mechanisms, see
src/pact_passport/_ablations.py). External baselines run the same
overhead/timing probe shape against entirely different stacks so the
paper §5 can frame PACT's cost in context:

  B0-RAW   bare HTTP, no trust layer. The undefended floor.
  B0-TLS   mTLS-only (channel auth via TLS client certs; no caps, no
           holder-binding, no receipts). The channel-auth-only floor.

The §12 attribution narrative reads:
  PACT_round_trip_ms = B0-RAW + (TLS_overhead) + (PACT_overhead)

Subtracting baseline-to-PACT gives the cost-of-trust number. Subtracting
B0-RAW from B0-TLS gives the cost-of-channel-auth alone — useful for
v0.8's planned C3 channel-bound peer identity hardening (which adopts
TLS exporter binding as its mechanism).

Only L-tier overhead probes apply to these baselines. Security probes
(A4, A5, C-convergence, etc.) presume the PACT layer is present; they're
meaningless against raw HTTP. The runner explicitly filters.
"""
