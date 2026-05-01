# What testing PACT taught me about my own protocol

A case study from the v0.1.3 publication. 23 experiments, 5 real bugs, 3 platforms, 2 LLMs across 2 physical machines. Here's what I learned.

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
| [#2](https://github.com/bene-art/pact-protocol/issues/2) | critical | Auth-bypass-by-default |
| [#3](https://github.com/bene-art/pact-protocol/issues/3) | critical | Holder-proof bypass |
| [#8](https://github.com/bene-art/pact-protocol/issues/8) | critical | Forged delegation chains pass when delegator key unknown |
| [#4](https://github.com/bene-art/pact-protocol/issues/4) | security | Rotation breaks live communication |
| [#5](https://github.com/bene-art/pact-protocol/issues/5) | durability | Idempotency cache + invocation counters in-memory only |
| [#9](https://github.com/bene-art/pact-protocol/issues/9) | security | No request size limit (slow-loris DoS) |
| [#10](https://github.com/bene-art/pact-protocol/issues/10) | security | Cap envelope inline in REQ |
| [#11](https://github.com/bene-art/pact-protocol/issues/11) | feature | Streaming response support |

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

*The full repository, including all 23 experiment scripts, is at [github.com/bene-art/pact-protocol](https://github.com/bene-art/pact-protocol).*
