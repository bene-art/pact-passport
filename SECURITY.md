# Security Policy

PACT Passport is a trust protocol. Vulnerabilities in the implementation, the wire spec, or the published package should be reported privately.

## Supported versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.8.x   | Yes       | Current. Pre-registered at `v0.8.0-pre-registration` (commit `f29b56c`). |
| 0.7.x   | Yes       | Previous stable. v0.7 `holder_proof` form is in the §18.7 90-day deprecation window. |
| < 0.7   | No        | Module rename (`pact` → `pact_passport`) and Bug 11 (P_BIND) only fixed from v0.7+. |

The wire spec at `spec/PACT_v1.md` (v1.4.0-draft) is normative. The reference implementation in `src/pact_passport/` is expected to match it; mismatches between the two are themselves in scope. Spec §20 (Security Considerations) is the authoritative threat-model statement.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

**https://github.com/bene-art/pact-passport/security/advisories/new**

Please do not file public issues for suspected vulnerabilities.

Expected response: within 7 days. A coordinated disclosure timeline will be agreed before any public write-up.

## Scope

**In scope:**

- Authentication or authorization bypass in the `pact-passport` package.
- Capability forgery, attenuation bypass, or holder-proof bypass (including the v0.8 domain-separated `pact/hp/v1` + `pact/visa/v1` forms — replay across (cap, audience) pairs would falsify P_BIND).
- Receipt forgery or audit-trail tampering, including bilateral-receipt downgrade (forcing a peer to accept a unilateral receipt where spec §18.6 mandates bilateral).
- `audit_context` (spec §18.2) bypass — submitting REQs without `audit_context` or with malformed/expired/audience-mismatched fields where the receiver should reject. (Note: v0.8.0 ships the library helper but does not enforce at dispatch; v0.8.1 wires enforcement. Bypass reports are still in scope but should call out the version.)
- Wire spec ambiguities that admit unauthorized actions when implemented as written.
- Cryptographic primitive misuse (signature verification, key derivation, canonical JSON, domain-separation strings).
- Cross-platform key corruption or storage faults (e.g. encoding-dependent I/O).
- DoS against the reference HTTP server beyond what the v0.5.3 hardening already mitigates (negative Content-Length, oversize requests, deadline ceiling, slow-loris).
- Fault-taxonomy / HTTP-status mismatches against spec §18.3 (a 401 returned where spec says 403, etc.) — wire-level conformance is part of the security envelope.

**Out of scope:**

- v0.8 deferred features (planned for v0.9 unless otherwise noted): cross-organization capability chains (`trusted_issuers`), cross-machine revocation propagation (`REVOKE` beacon), hash-chained receipts + checkpoint gossip, channel-bound peer identity (Noise / TLS exporter), runtime cost metering + enforcement, post-quantum signatures, per-token cost accounting. These are documented as not present in v0.8.
- Application-level caveat enforcement decisions. v0.8 ships `policy.py` with three profiles (Simple byte-normative templates, Standard predicate registry, Advanced third-party caveats) per spec §18.4 — but the *decision* whether a Standard-profile predicate is satisfied for a given application context is the application's responsibility. Bugs in PACT's `evaluate_caveats` mechanism are in scope; bugs in caller-supplied predicates are not.
- Detection of compromise itself — PACT is a substrate whose job is to make the *response* to externally-detected compromise cheap and aimed (arc-minimization). It does not detect compromise on its own; out-of-band detection signals are an assumed input.
- Network-layer attacks below the protocol (TLS misconfiguration, DNS hijacking, BGP attacks).
- Vulnerabilities in upstream dependencies (`pynacl`, `zeroconf`, `cbor2`, `uvicorn`) — report to those projects directly.
- Resource exhaustion that requires already-trusted holder credentials (revocation is issuer-local by design).

## Disclosure

After a fix is shipped, the advisory will be published with credit to the reporter unless anonymity is requested. CVE assignment will be requested where appropriate.
