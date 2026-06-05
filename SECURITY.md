# Security Policy

PACT Passport is a trust protocol. Vulnerabilities in the implementation, the wire spec, or the published package should be reported privately.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

The wire spec at `spec/PACT_v1.md` is normative. The reference implementation in `src/pact/` is expected to match it; mismatches between the two are themselves in scope.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

**https://github.com/bene-art/pact-passport/security/advisories/new**

Please do not file public issues for suspected vulnerabilities.

Expected response: within 7 days. A coordinated disclosure timeline will be agreed before any public write-up.

## Scope

**In scope:**

- Authentication or authorization bypass in the `pact-passport` package
- Capability forgery, attenuation bypass, or holder-proof bypass
- Receipt forgery or audit-trail tampering
- Wire spec ambiguities that admit unauthorized actions when implemented as written
- Cryptographic primitive misuse (signature verification, key derivation, canonical JSON)
- Cross-platform key corruption or storage faults (e.g. encoding-dependent I/O)
- DoS against the reference HTTP server beyond what the v0.5.3 hardening already mitigates (negative Content-Length, oversize requests, deadline ceiling, slow-loris)

**Out of scope:**

- v0.6 deferred features: cross-organization capability chains, application-level caveat enforcement, cross-machine revocation propagation, post-quantum signatures, per-token cost accounting. These are documented as not present in the current version.
- Network-layer attacks below the protocol (TLS misconfiguration, DNS hijacking, BGP attacks)
- Vulnerabilities in upstream dependencies (`pynacl`, `zeroconf`, `cbor2`, `uvicorn`) — report to those projects directly
- Resource exhaustion that requires already-trusted holder credentials (revocation is issuer-local by design)

## Disclosure

After a fix is shipped, the advisory will be published with credit to the reporter unless anonymity is requested. CVE assignment will be requested where appropriate.
