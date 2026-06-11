# Stage 2 Pre-Registration Change Plan

**Status:** draft for review · **Author:** prepared on branch `claude/pact-passport-1i5z8x`
**Target:** v0.7 + spec v1.3.0-draft · **Current state:** v0.6.1, no git tags yet
**Date:** 2026-06-11

---

## 1. Purpose

Stage 2 is the cross-machine, pre-registered adversarial probe battery
(`tests/stage2/`, 25 probes / 33 sub-probes) that will be run NUC ↔ Mac mini over
Tailscale against real LLMs. This document enumerates **every change that should
land before Stage 2 runs begin**, and — just as importantly — **every change that
must NOT land** until the runs are complete.

It exists because Stage 2 is a *measurement*, not a development sprint. The
methodology (EXPERIMENTS.md Part 2, §"Pre-registration is the discipline") locks
predictions and prompts behind a `v0.7-pre-registration` git tag before execution;
any mid-run edit shows as a diff against that tag. **You do not change the thing
while you are measuring it.** That constraint, not the size of the change, decides
what is in scope here.

---

## 2. The governing constraint: the freeze line

```
  ... v0.7 hardening ...  ──►  [ v0.7-pre-registration TAG ]  ──►  Stage 2 runs  ──►  Part 3 writeup
        (this document)            (the freeze line)              (locked behavior)
```

- **Before the tag:** implementation behavior, probe predictions, and the locked
  prompt dict (`tests/stage2/_prompts.py`) may all change freely.
- **At the tag:** behavior + predictions + prompts are frozen together. They must
  be *mutually consistent* — every probe's `prediction`/`threshold` must match the
  behavior of the code being tagged (see §5, Reconciliation).
- **After the tag:** only the *runner/orchestration* may change, and only with a
  logged deviation in the probe's `result["notes"]` plus a prompt-dict version bump.
  No silent behavior changes.

**Golden rule:** if a change would alter what any probe observes, it lands *before*
the tag or *after* Stage 2 — never silently in between.

---

## 3. Change classes

Each candidate change is sorted into one of four classes. The class — not the
difficulty — determines whether it belongs before the freeze.

### Class 1 — Land before the freeze (safe hardening; does not move any locked prediction)

These are real correctness fixes that no Stage 2 probe depends on. They strengthen
the implementation without changing any value a probe records. Verify each against
§5 before tagging.

| ID | Change | Files | Why safe for Stage 2 |
|----|--------|-------|----------------------|
| C1-a | `verify_receipt` should bind `receipt["agent"]` to the supplied key (derive `agent_id = sha256(alg‖pubkey_b64)` and reject mismatch), or add a resolver-based variant. | `src/pact/receipt.py` | No probe calls `verify_receipt`; probes check protocol-layer `status`. Closes the "API makes the unsafe path the default" gap. |
| C1-b | `create_receipt` reserved-key guard checks against a fixed `RESERVED` frozenset, not the partially-built dict (today `signature` is *not* yet present at merge time, so the docstring's claim is false and injecting it silently corrupts the receipt). | `src/pact/receipt.py` | `extra` is developer-controlled only; no probe exercises it. Pure correctness. |
| C1-c | Validate `outcome` against `{completed, failed, cancelled}` in `create_receipt`. | `src/pact/receipt.py` | All call sites already pass valid values; adds a guardrail without changing behavior. |

> **Recommendation:** treat Class 1 as *optional* for Stage 2. It is safe, but it
> is also **not exercised by Stage 2**, so it adds reconciliation risk for no
> measurement benefit. Prefer to either (a) land all of Class 1 *first*, re-run the
> loopback smoke, then tag; or (b) defer Class 1 to the v0.8 hardening line and tag
> v0.7 as-is. Do **not** interleave Class 1 edits after the tag.

### Class 2 — DO NOT touch before Stage 2 (intentional, pre-registered limitations)

These behaviors are *deliberately* weak and several probes exist to **confirm**
them cross-machine. Silently "fixing" any of these before the runs would invalidate
the corresponding prediction and, in some cases, falsify a sentence already written
into the paper.

| Behavior | Pre-registered as | Probes that lock it | Consequence of an early "fix" |
|----------|-------------------|---------------------|-------------------------------|
| `refs[]` is sender-asserted, **not** receiver-verified against the local receipt store. | C4 known limitation (spec §6.2) | `A4_refs_forgery`, `S5_receipt_mimicry` | A4's `threshold` says a receiver-side `refs[]` check "grew silently (in which case the §6 paper sentence is wrong and must be revised)." Fixing it pre-Stage-2 turns a *confirmation* into a *regression* and breaks the paper claim. |
| Handler cost is **author-honest** (declared, not measured at runtime). | v0.6 visa threat-model boundary (`visa.py` docstring) | `A2_cost_lying` | Runtime metering would change A2's outcome from the predicted "declaration trusted; over-run not enforced." |
| `peer_network_id` is a **naive** IPv4 /24 · IPv6 /48 aggregation key, trivially rotatable. | v0.6 honest limitation (`visa.py` docstring) | `A3_visa_partition`, `A6_v_amplification` | Channel-bound peer identity would change the amplification/partition results. |
| `protocol_advertisement` is **emit-only / MUST-NOT-consume**. | spec §16.5 | `P1_no_consumption`, `P2_uri_variants`, `P3_mitm`, `P4_ad_shaped_output`, `S3_ad_injection` | The "no-consumption" probes are load-bearing; *any* code path that acts on a received advertisement flips them. Leave the field inert. |

> These belong to the **v0.8 / post-Stage-2 hardening roadmap** (see §7). The whole
> point of measuring v0.7 is to document where it is honestly weak; harden *after*
> the measurement, with the change as its own pre-registered before/after.

### Class 3 — Harness & operational readiness (fix before runs; does not touch protocol behavior)

These make Stage 2 *trustworthy* without changing what is being measured. They are
the highest-value pre-Stage-2 work.

| ID | Gap | Where | Action |
|----|-----|-------|--------|
| C3-a | **Receipt-store introspection missing.** `S5_receipt_mimicry` notes: "We don't currently have a clean introspection of the store" — so it asserts the protocol-layer `status` instead of *proving* the fake receipt was not ingested. The probe's "pass" is weaker than its claim. | `tests/stage2/_harness.py`, `src/pact/store.py` | Add a read-only `list_receipts(agent)` helper and have S5/A4 assert the orphan is absent from the authentic store. Harness-only — no protocol change. |
| C3-b | **9 of 33 sub-probes are `new_finding` pending the NUC bridge** (A3 partition, M1/M2 worktree orchestration, P3 MITM). | runner / lab setup | Stand up the NUC ↔ Mac Tailscale bridge and confirm all 33 execute before tagging; otherwise the freeze captures un-runnable probes. |
| C3-c | **Environment provenance not captured in results.** `result` JSON records pairing + timing but not the git SHA, OS/Python versions, or resolved model digests. | `tests/stage2/_harness.py` | Stamp `git rev-parse HEAD`, platform, Python, and Ollama/Claude model identifiers into every `result` dict. Reproducibility is the point of pre-registration. |
| C3-d | **Determinism / teardown robustness** under cross-machine timing (free-port races, partial-setup teardown). | `tests/stage2/_harness.py` | Confirm `teardown` and `free_port` are robust across the Tailscale boundary; document any seed/temperature settings for LLM calls. |

### Class 4 — Version & freeze bookkeeping (the act of freezing)

| ID | Action |
|----|--------|
| C4-a | Bump version `0.6.1 → 0.7.0`; update `CHANGELOG.md`; confirm spec is at v1.3.0-draft (or finalize to v1.3.0 if the wire is stable). |
| C4-b | Reconcile predictions (§5) after Class 1/3 land. |
| C4-c | Create the **`v0.7-pre-registration`** annotated tag. This is the freeze line. After this, §2's after-tag rules apply. |

---

## 4. Mapping to the earlier receipt audit

For traceability, the receipt-layer findings from the prior audit map onto the
classes above:

| Audit finding | Class | Disposition |
|---------------|-------|-------------|
| #1 `verify_receipt` doesn't bind `agent`→key | Class 1 (C1-a) | Safe to land pre-freeze; not exercised by Stage 2. |
| #5 `extra` reserved-key guard bug | Class 1 (C1-b) | Safe to land pre-freeze. |
| #4 `refs`/`outcome` signer-chosen & fabricable | **Class 2** | **Do not fix before Stage 2** — this *is* the C4 limitation A4/S5 confirm. |
| #2 receipt commits to IDs, not content digests | v0.8 roadmap | Wire change; defer past Stage 2. |
| #3 self-asserted timestamps / equivocation | v0.8 roadmap | Needs hash-chained receipts; defer past Stage 2. |
| #6 no domain separation across signed objects | v0.8 roadmap | Wire change; defer past Stage 2. |

---

## 5. Reconciliation gate (mandatory before tagging)

Pre-registration only means something if predictions match the code at the moment
of the tag. After **any** Class 1 or Class 3 change:

1. Re-run the loopback smoke battery on the Mac.
2. For every probe, confirm the observed outcome still matches `prediction` and
   does not cross `threshold`.
3. If a Class 1 change *did* move a prediction, update that probe's `prediction`/
   `threshold` **before** tagging, with a one-line rationale in the probe file. (If
   this happens, reconsider whether the change belongs before Stage 2 at all.)
4. Only then create `v0.7-pre-registration`.

---

## 6. Pre-flight checklist (ordered)

- [ ] Decide Class 1 disposition: land-then-reconcile, or defer to v0.8 (see §3 rec).
- [ ] Land Class 3 harness fixes (C3-a store introspection is the priority).
- [ ] Stand up + smoke-test the NUC ↔ Mac Tailscale bridge (C3-b).
- [ ] Add environment provenance to result JSON (C3-c).
- [ ] Bump to v0.7.0; update CHANGELOG; confirm spec version (C4-a).
- [ ] Run reconciliation gate (§5) — predictions match code.
- [ ] Resolve the freeze/publish question (§8) for `tests/stage2/`.
- [ ] Create `v0.7-pre-registration` tag (C4-c).
- [ ] Run Stage 2; write Part 3.

---

## 7. Out of scope for Stage 2 → v0.8 post-Stage-2 hardening roadmap

These are the genuine security upgrades. Each should ship *after* Stage 2 as its
own pre-registered before/after, so the measurement shows the improvement:

- Hash-chained, content-bound receipts (`prev_receipt_hash` + REQ/RES digest) +
  checkpoint gossip → tamper-evident, equivocation-detectable audit (closes #2/#3).
- Domain-separation tags / COSE envelopes across all signed objects (closes #6).
- Channel-bound peer identity (Noise/TLS exporter) replacing naive `peer_network_id`.
- Runtime cost metering + enforcement, replacing author-honest declarations.
- Secure-by-construction verification API (resolver-based, typed results).

---

## 8. Open decisions (need a human call)

1. **Class 1 in or out?** Recommend: land all three, run §5 reconciliation, then
   tag — *or* defer entirely to v0.8. Do not half-land.
2. **Spec version at freeze:** keep `v1.3.0-draft`, or finalize to `v1.3.0`?
3. **Freeze/publish status of `tests/stage2/`.** `tests/stage2/__init__.py` states
   the package is "local-only — not pushed during the May → October paper-review
   freeze," yet the probes are committed and tracked in git. Today (2026-06-11) is
   inside that window. Decide whether the harness (and this document) should be
   pushed to the public remote now, or kept on a private branch until the freeze
   lifts. This plan was written to branch `claude/pact-passport-1i5z8x`; confirm
   before it goes to `main`.
```
