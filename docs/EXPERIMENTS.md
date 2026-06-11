# What testing PACT taught me about my own protocol

A case study from the v0.1.3 publication. 23 experiments, 5 real bugs, 3 platforms, 2 LLMs across 2 physical machines. Here's what I learned.

> *This document has two parts. Part 1 is the original v0.1.3 case study (5 bugs across 23 experiments). Part 2 covers paper-revision experiments through v0.6.1 that surfaced five additional bugs eight hardening releases later — including one (Bug 10) caught by the CI matrix on the v0.6.0 release push itself — plus a 25-probe cross-machine harness staged for the next experimental window.*

---

## The setup

PACT is a small (under 2,000 LOC) reference implementation of an agent-to-agent trust protocol, drawing on:

- **KERI** (Smith, 2019) for self-certifying identity with pre-rotation commitments
- **Macaroons** (Birgisson et al., 2014) for attenuable, holder-bound capability tokens
- **End-to-end argument** (Saltzer/Reed/Clark, 1984) for pushing verification to agents instead of transport
- **Lamport ordering** (1978) for causal message DAGs

The v0.1 reference implementation shipped in 5 phases over a few weeks. 111 unit tests, formal spec, deterministic test vectors. I thought I was done.

I wasn't. Here's what changed my mind.

---

## The 23 experiments

I ran 23 distinct experiments grouped into six categories, plus 16 of them across two physical machines (a Mac running macOS, a NUC running Windows 11) talking via signed PACT messages.

| Category | Experiments | What I was testing |
|---|---|---|
| Protocol mechanics | A1, A2, A3, A4, A5, A6 | Does the spec actually hold? |
| Real agentic patterns | B1, B2, B3, B4 | Can agents do useful work over PACT? |
| Performance & scale | C1, C2, C3, C4 | Does it stay performant? |
| Security gaps | D1, D2, D3, D4 | What can attackers do? |
| Operational durability | E1, E2, E3 | What survives restart, what doesn't? |
| Cross-platform | F1, F2 | Does it actually work on Windows and Linux? |

Every experiment produced a reproducible script, a measurable outcome, and a writeup-friendly conclusion.

---

## What broke — five real bugs in my own code

### 1. Idempotency cache race
The first experiment I ran fired two simultaneous REQs with the same idempotency key from two threads released by a `Barrier` at the same instant. The protocol promises: "the handler runs once, both sends return the same response."

What actually happened: both sends saw an empty cache, both ran the handler, both wrote back. The handler ran twice with the same key. Different responses returned to the two callers.

I'd looked at the code (`agent.py:132-138`):
```python
if msg.idempotency_key and msg.idempotency_key in self._idempotency_cache:
    cached_res, expires_at = self._idempotency_cache[msg.idempotency_key]
    ...
```

Read-then-write with no synchronization. Under the production `ThreadingHTTPServer` this is a textbook race. I knew it was a race when I read the code. I didn't realize how easy it was to actually trigger.

**Fix:** added a per-agent `_task_lock` that serializes `_handle_task`. The throughput cost (measured later) was acceptable for a v1 protocol library — every real handler takes ≥10ms (LLM calls take 100ms+), so the lock is invisible against actual work. Per-key locking is documented as a future optimization.

### 2. The Windows key corruption bug
Different experiment, much worse outcome. Running the test suite on the NUC, this came back:

```
nacl.exceptions.ValueError: The seed must be exactly 32 bytes long
```

`Identity.create()` succeeded. `Identity.load()` failed. On Windows only.

The next_private_key.bin file on disk was 33 bytes, not 32. One byte too many.

Looking at the bytes, I noticed a `0d 0a` (CRLF) where there should have been just `0a` (LF). Windows was substituting CRLF for LF inside my key file.

The bug was in `store.py:_write_key`:
```python
fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
```

On Windows, `os.open()` defaults to **text mode**, which translates LF bytes to CRLF on write. For text files this is harmless. For binary key material it's catastrophic.

The probability that a randomly-generated 32-byte Ed25519 seed contains at least one `0x0a` byte:
$$1 - (255/256)^{32} \approx 12\%$$

**Roughly one in eight Windows installations of PACT 0.1.2 had silently broken keys.** The user wouldn't see anything wrong — `init` works, you can use the agent, then on the next process restart `Identity.load()` fails.

**Fix:** add `os.O_BINARY` flag on platforms that have it (`hasattr(os, "O_BINARY")` is True only on Windows; the flag doesn't exist on Unix and the open is implicitly binary there).

This is the kind of bug you only find by running the code on a different platform. Test suites alone wouldn't have caught it because all my tests ran on macOS.

### 3. Auth-bypass-by-default
The most embarrassing finding. The protocol's whole pitch is "trust substrate." Then I tested what happens when an unknown agent — one the receiver has never registered — sends a request.

```
[1] Send a signed REQ from rogue agent (mac never registered)
    status: ok
    answer: pwned
    EXPLOIT WORKED: mac_brain ran a real LLM call for an unknown agent

[2] Send a REQ with a JUNK signature (256 zero bytes b64-encoded)
    status: ok
    answer: Oops
    EXPLOIT WORKED: junk signature accepted, handler ran
```

The Mac's `gemma3:12b` literally answered "pwned" to an attacker who had no shared key, no prior handshake, no signature that could verify against anything.

The bug was the conjunction of three default settings:
1. `auto_grant=True` (default in `PACTAgent.__init__`)
2. `agent.py:140-141`: `if sender_pub and not verify_message(...)` — when `sender_pub` is `None` (unknown peer), the conditional short-circuits and verification is skipped entirely
3. `agent.py:188-192`: with no cap in the local store, dispatch falls through to `payload.action` with no auth check

A "trust substrate" library shipping with auth-bypass-by-default is the kind of thing that ends conversations with security-aware reviewers. I filed it as a critical issue. Fixing it is straightforward — flip the default to `auto_grant=False`, reject unknown peers — but it's a v0.2 release because it changes the existing test suite's preconditions.

### 4. Holder-proof bypass
A separate but related issue. PACT's capability tokens include a holder-binding mechanism: the bearer must prove possession of the holder's private key (sign a nonce). The check at `agent.py:165` looks like:

```python
if sender_pub and msg.holder_proof:
    if not verify_holder_proof(msg, sender_pub):
        # reject
```

The `if msg.holder_proof:` guard makes the check **conditional on the attacker's cooperation**. Omit the field, skip the check.

The promise was: "stolen tokens are useless without the holder's private key." The reality was: stolen tokens work fine if the attacker is lazy enough to omit the proof field.

Reproduced live. Filed as a critical issue alongside the auto-grant bypass. Together they form a triangle (with bug #5 below) of authorization-bypass paths that need to land in v0.2.

### 5. Forged delegation chains
The third corner of the triangle. PACT inherits Macaroons' attenuation: Alice issues a cap to Bob, Bob can re-issue it to Carol with *tighter* restrictions. The chain is cryptographically verifiable end-to-end.

Or so I thought. The verifier (`capability.py:247-253`) silently passes when a chain link's key isn't in `known_keys`:

```python
if known_keys and last_delegator in known_keys:
    delegator_key = known_keys[last_delegator]
    if not crypto.verify(signable, sig_bytes, delegator_key):
        return CapabilityResult(False, "Invalid signature from delegator")
# If we don't have the delegator's key, we can still verify the chain links
```

That comment is misleading. Without the key, no signature was checked. A forged chain — claiming "Bob delegated to Eve" when Bob never did — passes silently.

I demonstrated it programmatically. Eve fabricated a cap claiming a delegation chain ending with her own key. The verifier without Bob's key in cache returned `valid=True`. With Bob's key present, the same forgery was caught.

Fix is one paragraph of code. Verifiers must fail-closed when a chain link's key is missing, not silently pass.

---

## What worked — defenses that hold

If I just listed the broken parts I'd be telling half the story. Here's what actually defended correctly when used as designed.

### Tamper detection (A2)
After pre-registering the sender's identity (no auto-grant bypass), I sent three REQs:
1. Clean signed REQ → `ok`
2. Mutated payload byte after signing → `invalid_signature`
3. Flipped signature byte → `invalid_signature`

The cryptographic guarantees are real. They just require the prerequisite setup that the v0.1 defaults skipped.

### Stolen-token attack defenses (A3)
Eve has a copy of Bob's capability token but not Bob's private key. Four attacks:

1. Eve uses cap as herself → `Holder mismatch` (cap.holder = bob, sender = eve)
2. Eve impersonates Bob, signs with her own key → `Invalid signature`
3. Eve modifies the stored cap on disk → `Invalid signature on capability token`
4. Eve forges a cap from scratch with the same cap_id → `Invalid signature on capability token`

All four attacks blocked by different layers of the protocol. The data structures and the signature scheme are sound.

### Replay defense via idempotency (A4)
Captured a signed REQ. Replayed it three times in quick succession. All three returned the same cached response, the handler ran exactly once. Replayed past the deadline: `deadline_exceeded`.

Idempotency works as a replay defense — when the cache hasn't been wiped (see issue #5 about durability).

### Capability lifecycle (A1)
Mac issued a cap to NUC. NUC used it (succeeded). Mac revoked the cap. NUC tried again → `capability_invalid: revoked`. The full lifecycle works across two physical machines.

---

## What I learned about cross-platform

The Linux smoke test on Alpine WSL2 passed 118/118 tests on the first run. Confirmed three-platform coverage (macOS, Linux, Windows).

But Windows took five separate fixes to get green:

1. **Receipt filename colons** — ISO 8601 timestamps contain `:`, illegal in NTFS. Fixed by replacing with `-` in filenames.
2. **The O_BINARY corruption** described above.
3. **POSIX permission tests** — NTFS doesn't have 0o600 in the same way. Skipped these tests on Windows; tracked the actual ACL-aware check as a separate issue.
4. **NTFS file enumeration is slow** — `list_receipts(500)` takes 3.5s on Windows vs 0.16s on macOS. ~20× slower. Adjusted the test budget for Windows; the long-term fix is an index.
5. **Doctor command's permission check** — same root cause as 3.

The third platform always finds bugs the first two missed. Or as I'd put it now: **a "cross-platform" claim before you've actually run on three platforms is a marketing claim, not an engineering one.**

---

## What I learned about agentic patterns

The most fun experiment was running two LLMs in collaboration via PACT:

```
NUC (llama3.2:3b)  →  reformulate user question (45s)
                          ↓
                 PACT signed REQ
                          ↓
Mac (gemma3:12b)   →  draft answer (137s, with model inference)
                          ↓
                 PACT signed RES
                          ↓
NUC (llama3.2:3b)  →  synthesize final 2-sentence answer (46s)
                          ↓
                  Final answer to user
                  + signed audit trail on both sides
```

Two different LLMs, two different machines, two different operating systems. Total round-trip 227 seconds. Both sides have cryptographically verifiable receipts that this exchange happened.

I also implemented tool routing across three different LLM-backed capabilities:

| Task type | Capability | Model | Round-trip |
|---|---|---|---|
| Q&A | `ask_llm` | gemma3:12b | 3.4s |
| Summarization | `summarize` | llama3.2:3b | 4.7s |
| Code review | `code_review` | qwen2.5-coder:7b | 3.9s |

Each task routed to the right specialist via PACT. This is the shape of multi-agent systems. The trust layer underneath needs to exist *somewhere*; if it isn't PACT, it'll be something that looks like PACT but with a different name.

---

## What I learned about my own work

Five things I'd say to anyone building infrastructure code:

### 1. The first cross-platform run will find a bug
The O_BINARY bug is the kind of thing 100% of pure-macOS development would never catch. Standard advice. Now I have direct evidence.

### 2. The first concurrency test will find a bug too
The idempotency race. The textbook read-then-write on a shared dict. I knew it was a race when I read the code; I didn't try to break it until I started writing the experiment. By that point the lock fix was 10 minutes; without the test, the bug would have shipped to production unnoticed.

### 3. "Trust substrate" is a strong claim that needs a posture
PACT shipped with three independent auth-bypass paths in default config. Each defeats the "trust substrate" framing on its own. The protocol *design* is sound — the implementation just hadn't yet decided what its security posture was. Defaults matter. A library that requires careful configuration to be safe is a library that will be deployed unsafely.

### 4. Document what's wrong with your own work
The result of this exercise is 10 open issues with reproducers, root causes, fix paths, and acceptance criteria. Not bugs to bury — bugs to fix in v0.2 with clear scope. Senior engineering is keeping a public list of what's broken in your own code, not hiding it.

### 5. The honest framing wins
The README originally said "minimal trust substrate for agent-to-agent interaction." After this exercise, the README says "v0.1.3 reference implementation. The protocol design is stable; known security and durability gaps are tracked in open issues for v0.2 hardening. Suitable for experimentation, learning, and as a starting point — not yet for production deployment without addressing the linked issues."

The second framing is more useful, more accurate, and more credible. It's also what I'd want to read about anyone else's work.

---

## Status of v0.1.3

What's in this release:

- 5 race-condition test scenarios + sandbox harness
- Concurrency safety fix (per-agent dispatch lock)
- Critical Windows compatibility fix (the O_BINARY corruption)
- Cross-platform receipt filenames
- Three-platform CI green (macOS, Linux, Windows)
- 118 tests passing, 1 documented xfail
- Chaos mode (`PACT_CHAOS=1`) for race-window injection

What's tracked for v0.2:

| Issue | Severity | What |
|---|---|---|
| [#2](https://github.com/bene-art/pact-passport/issues/2) | critical | Auth-bypass-by-default |
| [#3](https://github.com/bene-art/pact-passport/issues/3) | critical | Holder-proof bypass |
| [#8](https://github.com/bene-art/pact-passport/issues/8) | critical | Forged delegation chains pass when delegator key unknown |
| [#4](https://github.com/bene-art/pact-passport/issues/4) | security | Rotation breaks live communication |
| [#5](https://github.com/bene-art/pact-passport/issues/5) | durability | Idempotency cache + invocation counters in-memory only |
| [#9](https://github.com/bene-art/pact-passport/issues/9) | security | No request size limit (slow-loris DoS) |
| [#10](https://github.com/bene-art/pact-passport/issues/10) | security | Cap envelope inline in REQ |
| [#11](https://github.com/bene-art/pact-passport/issues/11) | feature | Streaming response support |

---

## Where this leaves PACT

PACT today is a working v0.1 reference implementation that:
- Demonstrates the protocol concepts cleanly
- Runs across three platforms
- Survived 23 distinct stress tests
- Surfaced and documented its own gaps

It is not yet a production-ready trust protocol. The next milestone is v0.2 with the security hardening above. Until then, deployment scope should be limited to single-trust-domain LANs (your own machines, no third parties) — exactly the constraint I tested under.

Whether PACT continues past v0.2 depends on whether anyone else finds it useful. The *protocol* design — KERI identity + Macaroons capabilities + causal DAG + unilateral receipts — is sound and worth keeping regardless. The reference *implementation* may end up being a stepping stone toward something built into MCP or A2A as their authorization layer, rather than a standalone library. Time will tell.

For now: it works on my machines. It runs my agent stack. The bugs I found are documented and small. That's a real piece of engineering, even if it never becomes a standard.

---

# Part 2: Paper-revision experiments (v0.5.5 → v0.6.0)

Eight hardening releases later, I ran another battery. Different motivation: the v0.1.3 case study had become the core of a paper claiming that minimal substrates have negative-space gaps that hardening rounds don't naturally find. The paper needed to be more than n=1. If the framework that found Bugs 1–5 was real, it should keep finding bugs in the same codebase under further pressure.

It did.

Between 2026-05-05 (v0.5.4 ship) and 2026-06-11 (v0.6.0 ship), 13 new structured experiments + a V-tier sprint surfaced four more bugs in code that had passed every release of v0.2 → v0.5.5. None of them was caught by the 181-test suite. All four are negative-space, same taxonomy as Bugs 1–5: structural gaps under adversarial pressure, not typos.

## The new experiments

| Tier | Experiments | What I was testing |
|---|---|---|
| A (sharpened) | A1–A6 | Spec re-pressure with sharper failure thresholds than v0.1.3 originals |
| B (deep) | B1, B2 Stage 1, B3 | Multi-hop delegation, holder-proof regression, deep chains at K ∈ {3, 5, 7, 10} |
| C (perf + correctness) | C1, C2, C3 Stage 1, C4 | Throughput, concurrent streaming, stream partition, refs[] semantics |
| V (visa) | V1–V7 | The new V-tier trust gradient — over-broad / expired / stolen / escalated visas, plus receipt-fidelity-under-compromise (V3), nonce-replay (V5), parallel-issuance amplification (V6), cross-issuer confusion (V7) |

All experiments pre-registered (target property / adversarial vector / failure threshold / quantified outcome) before execution. Pre-registration is the discipline that makes "I tested it and it passed" mean something different from "I ran code until it stopped throwing." If a probe's prediction doesn't match observation, that's a finding to investigate, not a metric to tune.

## What broke — four more real bugs

### 6. Multi-hop delegation chains fail verification at K ≥ 3

Surfaced by experiment B3 (deep delegation). The verifier at `capability.py:325-335` checked each chain link's signature against `token.parent` — the *final cap's* parent. But each link signed a *different* cap_id at its own attenuation step.

At K = 2 (one delegation link), the last link's parent IS the final token's parent. Test passes. At K ≥ 3, the verifier checks every link against the wrong parent and rejects every legitimate chain.

```python
# v0.5.x verifier (broken at K ≥ 3):
for link in token.delegation_chain:
    expected_parent = token.parent  # WRONG: this is the final cap's parent
    signable = make_link_signable(link, expected_parent, ...)
    if not crypto.verify(signable, link.signature, ...):
        return CapabilityResult(False, "Invalid link signature")
```

`attenuate()` signed the right thing. `verify_capability()` checked the wrong thing. The two agreed at K = 2 and diverged at K ≥ 3. No K ≥ 3 production chains existed because no one tried — three-agent delegation via `cap_envelope` worked (single hop), but deeper chains silently failed.

**Bug class: convenient-value substitution at a layer boundary.** The signing path knew the per-link parent; the verifier path reached for `token.parent` because it was already in scope. Convenient ≠ correct.

**Fix (v0.6.0, issue #29):** added `parent_cap_id` field to `DelegationLink`. Verifier walks the chain checking each link against its OWN recorded parent. Wire change — see breaking-changes list. Pre-v1.3 chains verify at K = 2 with `DeprecationWarning`; v1.4 will drop the fallback.

### 7. Stream partition skipped the server-side receipt write

Surfaced by C3 Stage 1 (Mac-only, no NUC needed — client disconnects mid-stream, observe server state). The substrate makes an explicit claim in spec §3.5: "a receipt exists on the side that wrote it regardless of the other party's cooperation, network partition, or crash."

That was false for streaming. The implementation:

```python
# v0.5.x _run_streaming_handler (broken):
async def _run_streaming_handler(...):
    try:
        async for chunk in handler(payload):
            yield chunk  # <-- BrokenPipeError on client disconnect propagates here
    except Exception as e:
        # ...
    # Receipt write happens here — but BrokenPipeError already escaped
    store.write_receipt(...)
```

When the client disconnected, `BrokenPipeError` propagated up through the yield. The `except Exception` clause did NOT catch it (it's `BaseException`-derived but raised via `GeneratorExit` in some paths), the receipt-write line never executed, and the transport-layer handler at `transport/server.py:164` logged-and-moved-on with a comment claiming the receipt had been written. It hadn't.

The `cancelled` receipt outcome was *specified* in spec §12.9. It was never *emitted* by the code.

**Bug class: order of operations broken across layers.** Each layer made a locally-reasonable assumption; the contract between them was unenforced.

**Fix (v0.6.0, issue #30):** restructured to `try / finally` with `outcome` state variable defaulting to `"cancelled"`. The `finally` block writes the signed receipt on every exit path. Idempotency cache populated only on `outcome == "completed"` so cancelled streams retry cleanly. The §3.5 claim now holds for streaming; §12.9's `cancelled` outcome is now actually emitted.

> *Coda (Bug 10, v0.6.1): the v0.6.0 fix above closed the agent-layer order-of-operations gap, but the transport-layer exception catch enumerated POSIX exception types only — see Bug 10 below for the Windows-variant gap surfaced by the CI matrix on the v0.6.0 release push itself.*

### 8. Rate-limit refusal lost the cap_token context

Surfaced by V3 (receipt-fidelity-under-compromise — second visa use after `max_invocations=1` should rate-limit and leave a receipt that names the visa it refused). `_step_verify_capability` was assigning `ctx.cap_token = token` *after* the rate-limit check:

```python
# v0.5.x dispatch (broken):
def _step_verify_capability(ctx, msg):
    token = lookup_cap(msg.cap_id)
    if rate_limited(token):
        return refuse()  # ctx.cap_token still None — receipt has no visa metadata
    ctx.cap_token = token  # too late
```

The second visa use produced a refusal receipt with no `visa_cap_id`, no `ephemeral_key_fingerprint`, no audit hook to the compromise window V3 was trying to enumerate. The receipt existed; the receipt was useless.

**Bug class: state-binding happens *after* the action it should annotate.** Sister to Bug 7 — same family of "the state-write and the action are in the wrong order." Bug 7's symptom was missing receipts; Bug 8's symptom was under-attributed receipts.

**Fix (v0.6.0):** moved `ctx.cap_token = token` *before* the rate-limit check. Refusal receipts now carry the visa metadata that lets V3's "enumerate the compromise window from receipts alone" test actually do that.

### 9. Rogue-delegator forgery passed chain verification

Surfaced 2026-06-08 when the Bug 6 fix unmasked B1 tests that had been vacuously passing. With per-link `parent_cap_id` checked correctly, the deeper question came into view: the verifier checked link signatures against parent caps, but trusted the child's *declared* `action` and `caveats` without re-deriving them from the chain.

An intermediate delegator with a compromised signing key could mint a child cap whose declared content diverged from any chain of legitimate attenuation steps — widening authority, stripping caveats — and the verifier accepted it. The chain link's signature verified (the rogue delegator had a valid key); the link bound parent_cap_id (Bug 6 fix); but nothing bound the child's *content* to what could legitimately follow from the parent.

**Bug class: trust-child-without-re-derivation.** Sibling to Bug 6. Same family of "the verifier reaches for the convenient value instead of deriving the correct one."

**Fix (v0.6.0):** Macaroons-style chain re-derivation ported to Ed25519. `attenuate()` now signs over `canonical_json({parent_cap_id, action_at_step, caveats_at_step})` — binding the cap's content into each chain link. `verify_capability` walks the chain enforcing (1) action preservation across steps, (2) caveat append-only with canonical-frozenset comparison, (3) final-token consistency with the last link's recorded values. Pre-v1.3 chains accepted at K = 2 with `DeprecationWarning`; v1.4 drops the fallback. Spec §16 codifies.

### 10. Stream-partition transport handler missed the Windows exception variant

Surfaced 2026-06-11 by the CI matrix on the v0.6.0 release push itself. Bug 7's `try/finally` restructure of `_run_streaming_handler` was correct — but the transport-layer catch at `transport/server.py:171` enumerated POSIX exception types only:

```python
# v0.6.0 _send_stream (broken on Windows):
try:
    for chunk_dict in chunks_iter:
        self.wfile.write(...)
        self.wfile.flush()
except (BrokenPipeError, ConnectionResetError):
    # Consumer disconnected — close iterator synchronously so the
    # streaming generator's finally block writes the cancelled
    # receipt before this handler returns.
    chunks_iter.close()
```

On Windows, consumer disconnect raises `ConnectionAbortedError` (WinError 10053). The except clause doesn't match. The exception propagates up, `chunks_iter.close()` is never called, and the streaming generator's `finally` block fires only at GC time — which races the test reading the receipt log immediately after disconnect.

Mac and Linux passed because `BrokenPipeError` matches the catch and `close()` runs synchronously. The 281-test local Mac suite never exercised the Windows path. Only the Windows CI matrix (3 Python versions × `test_c3_stage1_partition_writes_cancelled_receipt`) surfaced the gap, asserting `expected exactly 1 cancelled receipt; got 0`.

**Bug class: platform-incomplete exception enumeration.** Same family as Bug 2 (the v0.1.3 O_BINARY corruption) — Windows-specific runtime behavior diverging from POSIX assumptions baked into otherwise-clean code. Bug 2 was about `os.open()` defaulting to text-mode on Windows; Bug 10 is about `ConnectionAbortedError` substituting for `BrokenPipeError` on Windows. Different mechanisms, same lesson: cross-platform claims need cross-platform CI.

**Fix (v0.6.1):** replaced the explicit tuple with the parent class `ConnectionError`, which covers `BrokenPipeError`, `ConnectionResetError`, AND `ConnectionAbortedError` — and any future platform-specific subclass. Regression test in `tests/test_server.py::test_send_stream_catches_all_connection_error_subclasses` asserts (1) the Python exception hierarchy the fix depends on and (2) the source code uses `ConnectionError`, not the narrower tuple. Pre-v0.6.1 narrowing of the catch will trigger a test failure.

**The framework caught itself.** Bug 10 is an incomplete-fix of Bug 7. Found by CI matrix doing what CI matrices are for — running the test on a platform the local dev box couldn't easily exercise. Logged here as a distinct entry rather than a silent patch because the case-study claim is that adversarial pressure surfaces structural gaps; CI matrix counts as adversarial pressure, and the gap was structural (POSIX-only exception coverage in a multi-platform substrate).

## Stage 2 — cross-machine probe harness (staged)

Beyond the 13 experiments above, v0.6.0 ships a 25-probe pre-registered harness designed for cross-machine runs:

- **A tier (6 probes):** policy injection, cost lying, visa partition, refs forgery, rogue delegator, V-amplification
- **C tier (9 probes in one file):** convergence audit — regression battery for Bugs 1–9
- **L tier (16 probes in one file):** overhead sweep across 4 pairs × 4 scenarios
- **M tier (2 probes):** planted regression, v0.5.5 baseline replay
- **P tier (4 probes):** §16.5 `protocol_advertisement` adversarial — including the load-bearing no-consumption test
- **R tier (1 probe):** v0.1.3 baseline replay
- **S tier (7 probes):** LLM-as-adversary, including a 4-model capability sweep
- **V tier (3 probes):** LLM-refuse / syn-grant / V3-fidelity under model variation

Each probe self-describes via a `@probe` decorator (pairing dict, pre-registered prediction, failure threshold, citation) and writes one JSON to a timestamped results dir. Loopback smoke run on the Mac confirmed 24 of 33 sub-probes execute end-to-end with zero exceptions; the remaining 9 are documented `new_finding` for items whose predictions rely on actual cross-machine behavior (A3 partition, M1/M2 worktree orchestration, P3 MITM) and need the NUC bridge to deliver real results.

Cross-machine results will land in a Part 3 once those runs complete.

## What I learned in Part 2

**1. The framework generalizes across hardening rounds, not just calendar time.** v0.2 through v0.5.5 were eight focused, deliberate hardening releases. Each shipped with care; each ran a 100+ test suite that grew to 181 by v0.5.5. Bugs 6 and 7 persisted latent through all eight. The methodology that found Bugs 1–5 in v0.1 found Bugs 6 and 7 in v0.5.5 with the same shape: pre-register a property, write the adversarial test that would distinguish a passing from a failing implementation, run it, document what you find.

**2. Sibling-class bugs cluster.** Bug 6 fix unmasked Bug 9 (sister: trust-the-child without re-derivation). Bug 7's "order broken across layers" rhymes with Bug 8's "state-binding after action." When you find a bug, the next bugs to look for are its taxonomic siblings.

**3. Pre-registration is the discipline.** Stage 2 probes lock predictions before results. Any mid-run edit shows as a git diff against the pre-registration tag. The friction is the point — it makes post-hoc rationalization visible.

**4. Negative-space holds across 10 bugs and 8 hardening releases.** Zero syntax bugs. Every finding required adversarial pressure to surface; none would have shown up in the 281-test suite without pointing tests at the specific gap. If you only test the happy path, you only find happy-path bugs.

**5. The CI matrix is an adversary too.** Bug 10 was found by CI doing what CI is designed to do — running the test on a platform the dev box doesn't easily exercise. The local 281/281 green on Mac said nothing about Windows. Cross-platform claims require cross-platform CI, not just a "Windows tested" checkbox from months ago. The Bug 10 finding is the framework's first CI-caught bug; logged here as a Part 2 entry rather than a silent patch because that's the bookkeeping the case study commits to.

---

## Where this leaves PACT (v0.6.1)

What's in v0.6.1 (= v0.6.0 + Bug 10 fix + docs pass):

- V-tier visa machinery (request-visa / grant / refusal as a three-tier trust gradient above the v0.5 capability layer)
- `protocol_advertisement` emit-only field (substrate-discovery primitive; PACT itself never reads or acts on a received advertisement)
- Bugs 6 / 7 / 8 / 9 / 10 closed at the reference implementation
- Spec v1.1.0-draft → v1.3.0-draft codifies the wire changes (§14 V-tier, §15 changelog, §16 chain re-derivation + §16.5 protocol_advertisement MUST-NOT, §17 changelog)
- 282 tests across macOS / Linux / Windows (281 from v0.6.0 + 1 Bug 10 regression test)
- 25-probe Stage 2 harness staged for cross-machine runs

The case-study bug battery from v0.1.3 (Bugs 1–5) plus the paper-revision findings (Bugs 6–10) make 10 bugs total. All 10 are closed at the reference implementation. All 10 are negative-space — structural gaps surfaced by adversarial pressure (B-tier deep delegation, C-tier stream partition, V-tier visa receipt fidelity, CI matrix cross-platform coverage). None caught by happy-path tests; all caught when the framework was pointed at the specific gap.

What's next: Part 3 (cross-machine Stage 2 results) when the NUC bridge runs complete. Until then, "10 bugs closed at the reference-implementation level; cross-machine Stage 2 pending" is the honest version of the claim.

---

*The full repository, including all 23 v0.1.3 experiment scripts and the 25-probe Stage 2 harness, is at [github.com/bene-art/pact-passport](https://github.com/bene-art/pact-passport).*
