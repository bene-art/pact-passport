# PACT Passport — Research & Evaluation Plan
## Closed-loop adversarial evaluation: from v0.7 baseline through hardened iterations

---

| | |
|---|---|
| **Field** | Secure distributed systems · decentralized trust & authorization for multi-agent systems (object-capability security + self-certifying identity + non-repudiable audit) |
| **Evaluation tradition** | Empirical systems security + symbolic protocol verification; HotNets framing |
| **Artifact under test** | PACT v0.7 / spec v1.3.0-draft (to be frozen) |
| **Current state** | v0.6.1, no git tags, 282 unit tests, 25-probe Stage 2 harness staged |
| **Document status** | Draft for review |
| **Prepared** | 2026-06-11 |

---

## Table of contents

0. Guiding principle
1. Scientific framing & contribution
2. Glossary
3. Threat model
4. Hypotheses (operationalized)
5. Methods (formal + empirical)
6. Statistical analysis plan
7. Phase 0 — Instrument calibration & freeze prep
8. Phase A — Confirmatory evaluation
9. Phase B — Exploratory adaptive red-team
10. Phase C — Hardening iterations
11. Probe inventory & mapping
12. Baselines & ablations
13. Validity threats & mitigations
14. Stopping criterion
15. Deliverables
16. Timeline & critical path
17. Risk register
18. Open decisions
- Appendix A — Tamarin/ProVerif lemma sketches
- Appendix B — Harness schema changes
- Appendix C — Result JSON schema
- Appendix D — Reconciliation checklist
- Appendix E — Capture-recapture & bug-seeding worksheets

---

## 0. Guiding principle

**Measure the frozen artifact first; harden second.** Every defense then becomes a
*measured before/after result* rather than an assertion. You may fix the
**instrument** (the test harness) freely before the freeze; you must **never** touch
the **artifact** (PACT itself) between pre-registration and the runs.

The deliverable is *not* "a secure substrate." It is **(a) a closed-loop adversarial
methodology and (b) an honest, quantified characterization of where the substrate is
and is not strong.** Those two are the publishable contributions; the artifact is the
vehicle.

**Three invariants that govern every decision in this plan:**

1. **Freeze discipline.** Behavior, predictions, and prompts are frozen *together*
   at the `v0.7-pre-registration` tag and must be mutually consistent at that instant.
2. **Instrument ≠ artifact.** Calibrating a probe so it measures what it claims is
   legitimate pre-freeze work; changing what PACT does is not.
3. **Confirmatory ≠ exploratory.** Frozen pre-registered probes can *confirm*;
   adaptive probes can *discover* but can never *confirm*. Never mix the two claims.

---

## 1. Scientific framing & contribution

### 1.1 The field
PACT sits at the intersection of:
- **Object-capability security** (Miller, *Robust Composition*, 2006; Birgisson et al., *Macaroons*, 2014) — authority is a holder-bound, attenuable token; no ambient authority.
- **Self-certifying decentralized identity** (Smith, *KERI*, 2019) — `agent_id` derived from the public key; pre-rotation commitments.
- **Non-repudiation & audit** (Zhou–Gollmann fair non-repudiation, 1996; RFC 2634 signed receipts) — here, deliberately *unilateral* (non-fair) receipts.
- **End-to-end argument** (Saltzer/Reed/Clark, 1984) — verification at the agent edge, not the transport.

Evaluation norms inherited from this field: a **formal adversary model** (Dolev–Yao),
**symbolic/computational proof** for core protocol claims (the standard for TLS 1.3,
Signal, EMV), and **artifact-evaluation discipline** (reproducibility, deterministic
vectors, ablation). Pre-registration is an unusual but strengthening import from the
empirical sciences.

### 1.2 The contribution claims
- **C-METHOD:** A pre-registered, sibling-class-aware adversarial probing methodology
  surfaces *structural* ("negative-space") defects that happy-path test suites miss,
  and those defects cluster taxonomically (predictive value: finding one bug tells you
  where the next lives). *Evidence base: the 10-bug case study (Bugs 1–10).*
- **C-INVARIANCE:** Protocol-layer security is invariant to LLM adversary capability,
  because PACT operates below the semantic layer. *Tested by H5.*
- **C-HONESTY:** A substrate can ship with quantified, named limitations (C4 refs,
  author-honest cost, naive peer-network-id) rather than over-claiming, and those
  limitations can be *measured* rather than hand-waved. *Tested by H3 and the coverage matrix.*

### 1.3 Why "measure first" is non-negotiable
1. A before/after hardening claim is meaningless without a measured "before."
2. Pre-registration requires a frozen artifact; editing behavior mid-stream is the
   p-hacking the methodology forbids and would directly undercut C-METHOD.
3. Several probes are *confirmatory of known weakness* (A4/S5 confirm C4; A2 confirms
   author-honest cost). "Fixing" them pre-run converts a confirmation into a
   regression and falsifies sentences already drafted in the paper.

---

## 2. Glossary

| Term | Definition |
|------|-----------|
| **Probe** | A single pre-registered adversarial test: `(probe_id, tier, pairing, prediction, threshold, citation)` + a body that mutates a `result` dict. |
| **Outcome** | One of `pass` / `new_finding` / `regression` / `harness_error` (per `_harness.py`). |
| **Prediction** | The pre-registered expected behavior, recorded *before* execution. |
| **Threshold** | The pre-registered condition that would constitute a failure/finding. |
| **Confirmatory probe** | Frozen probe whose prediction is locked at the tag; may confirm a hypothesis. |
| **Exploratory probe** | Adaptive, post-freeze probe; may discover defects but cannot confirm. |
| **Instrument** | The harness + probes (the measuring apparatus). |
| **Artifact** | PACT itself (`src/pact/`) — the system being measured. |
| **Freeze line** | The `v0.7-pre-registration` annotated git tag. |
| **Negative-space defect** | A structural gap surfaced only under adversarial pressure, invisible to happy-path tests. |
| **Sibling class** | A taxonomic family of defects (e.g., "verifier reaches for convenient value"). |

---

## 3. Threat model

### 3.1 Base adversary
**Dolev–Yao:** the attacker controls the network — can read, drop, reorder, replay,
and inject messages — but cannot break cryptographic primitives (Ed25519, SHA-256)
and cannot read private keys it does not hold.

### 3.2 Adversary roles (capabilities)

| Role | Capability | Cannot |
|------|-----------|--------|
| **EAVES** (passive) | Observe all ciphertext/plaintext on the wire | Modify or inject |
| **MITM** (active) | Intercept, modify, inject, replay | Forge signatures without keys |
| **PEER-MAL** | A legitimate but malicious counterparty (valid identity) | Use authority it wasn't granted |
| **DELEG-MAL** | A malicious intermediate delegator with a valid signing key | Mint children outside legitimate attenuation of its parent |
| **KEY-COMP** | Holds a compromised agent's private key | Violate KERI pre-rotation continuity for *future* rotations it didn't commit |
| **SYBIL** | Spawns many passport-less ephemeral identities; rotates source IPs | Acquire a passport without the gatekeeper's grant |

### 3.3 Security properties (with informal definitions to be formalized in Appendix A)

| Property | Definition | Primary adversary |
|----------|-----------|-------------------|
| **P-AUTH** (authenticity) | A message accepted as from `A` was signed by `A`'s current key. | MITM |
| **P-BIND** (holder-binding non-transferability) | A capability presented by `B` is only honored if `B` proves possession of the holder key; a stolen token is useless. | PEER-MAL, KEY-COMP |
| **P-MONO** (delegation monotonicity) | A child capability's authority ⊆ parent's (action preserved, caveats append-only) at every chain depth K. | DELEG-MAL |
| **P-REPLAY** (replay-freedom) | A REQ replayed within the dedup window executes the handler at most once; a visa holder-proof cannot be replayed across request-pairs. | MITM |
| **P-AUDIT** (audit detectability) | Each side's receipt is independently verifiable; *receipt-level* discrepancies are post-hoc detectable. **Bounded:** `refs[]` is sender-asserted (C4). | PEER-MAL |
| **P-OPAQUE** (refusal-opacity) | A refusal leaks no policy rationale to the peer; rationale lives only in the issuer's receipt. | PEER-MAL, SYBIL |

### 3.4 Explicitly out of scope (declared, not hidden)
Cross-org capability chains · application-level caveat enforcement · cross-machine
revocation propagation · post-quantum signatures · **confidentiality (wire is signed
but plaintext)** · traffic-analysis resistance.

### 3.5 Deliverable D1 — Coverage matrix
A `(property × adversary-role)` grid. Each cell holds the probe IDs that exercise it.
**Empty cells are declared coverage gaps** and appear verbatim in the paper's
limitations. Template:

| | EAVES | MITM | PEER-MAL | DELEG-MAL | KEY-COMP | SYBIL |
|--|--|--|--|--|--|--|
| P-AUTH | | P3 | | | A2(rot) | |
| P-BIND | | | B2 | | B2 | |
| P-MONO | | | | A5, B1, B3, C(conv) | | |
| P-REPLAY | | R1, S4 | | | | |
| P-AUDIT | | | A4, S5 | | | |
| P-OPAQUE | | | A1 | | | A3, A6 |

*(Fill completely in Phase 0; blanks above are illustrative, not final.)*

---

## 4. Hypotheses (operationalized)

For each: the claim, its operational measurement, the pre-registered prediction, and
the exact falsification condition.

### H1 — Deterministic prevention (artifact)
- **Claim:** For the holder-binding/delegation attack family, edge verification
  rejects with probability 1.
- **Measure:** Across probes {A5 rogue-delegator, B1 deep attenuation, B2 stolen
  token, B3 deep delegation, C-convergence Bugs 6/9}, count accepting runs of any
  forged/over-broad capability.
- **Prediction:** 0 acceptances.
- **Falsified by:** ≥1 accepting run (single counterexample).
- **Note:** This is the property to *prove* in Appendix A, not merely probe.

### H2 — Graceful degradation of the trust gradient (artifact)
- **Claim:** passport→visa→refusal leaks no policy info on refusal and grants only
  bounded authority on visa.
- **Measure:** (a) refusal responses contain only `{code: denied, detail: denied}`
  (+ optional inert advertisement) and never the rationale; (b) a granted visa carries
  exactly `{expires≤30s, max_invocations=1, no_further_delegation}` and cannot be
  attenuated or reused.
- **Probes:** A1 (policy injection), A3 (visa partition), A6 (V-amplification),
  V1–V7, P1/P3.
- **Prediction:** No rationale leak; no visa escalation; nonce-replay rejected.
- **Falsified by:** Any rationale field reaching the peer, OR any visa honored beyond
  its caveats, OR a holder-proof replayed across request-pairs.

### H3 — Audit detectability, honestly bounded (artifact)
- **Claim:** Receipts are independently verifiable; receipt discrepancies are
  post-hoc detectable; **but** `refs[]` forgery is *not* receiver-prevented (C4).
- **Measure:** (a) `verify_receipt` accepts only correctly-signed receipts bound to
  the signer's key; (b) A4/S5 confirm a fabricated `refs[]` entry is *accepted at the
  protocol layer* yet *absent from the authentic receipt store* (orphan detectable
  post-hoc via the store-introspection added in Phase 0).
- **Prediction:** Protocol accepts fabricated `refs[]`; store contains no matching
  entry; orphan is flagged by the reconstructor.
- **Falsified by:** A silent receiver-side `refs[]` check (regression — would also
  falsify the spec §6.2 paper sentence), OR the fabricated entry appearing in the
  authentic store.

### H4 — Methodology efficacy (the contribution)
- **Claim:** Pre-registered adversarial probing finds negative-space defects at a
  rate happy-path testing does not; defects cluster in sibling classes.
- **Measure:** (a) defects found by probes vs by the 282-test unit suite (disjoint?);
  (b) sibling-class graph density (Bug 6→9, Bug 7→8→10 are edges).
- **Prediction:** Probe-found defects ⟂ unit-suite coverage; sibling clustering
  statistically above a random-attachment null.
- **Falsified by:** Unit suite catches the same defects, OR no sibling structure.

### H5 — LLM-invariance (headline)
- **Claim:** P(protocol-layer violation | LLM adversary) does not increase with
  adversary model capability.
- **Measure:** Violation rate as a function of model tier across the S7 sweep
  {gemma3:4b, gemma3:e4b, claude-haiku-4-5, claude-opus-4-7} and S1–S6, V-probes.
  Fit `violation_rate ~ model_capability` (ordinal regression / trend test).
- **Prediction:** Slope indistinguishable from 0 (flat); all violation rates ≈ 0 at
  the protocol layer regardless of model.
- **Falsified by:** A statistically significant positive slope (more capable model →
  higher protocol-layer violation rate).

---

## 5. Methods

### 5.1 Formal verification (proves *absence* — Appendix A)
- **Tooling:** Tamarin (preferred for unbounded multi-hop delegation via its support
  for inductive reasoning) or ProVerif. Model:
  - Identity & rotation (KERI pre-rotation continuity).
  - Capability issue / attenuate / verify with the v1.3 chain re-derivation.
  - Visa issuance + nonce-bound holder-proof.
- **Lemmas to discharge:** P-AUTH, P-BIND, P-MONO (unbounded K), P-REPLAY (visa
  nonce), P-OPAQUE. See Appendix A for sketches.
- **Timing:** Build in Phase 0 — model construction routinely surfaces design issues
  *before* machine time is spent. A lemma that fails to verify is itself a finding.

### 5.2 Empirical probing (shows *presence*; required for the LLM-in-the-loop layer)
- **Deterministic probes** (a signature verifies or it does not): a single run is a
  proof-by-execution; N=1 suffices.
- **Stochastic probes** (LLM adversary or LLM handler in the loop): single runs are
  scientifically invalid. Run **N trials** per `(probe × model × temperature)`, report
  violation **rates with confidence intervals**.
- **Provenance:** every `result` JSON stamped with git SHA, host/OS/Python, resolved
  model digests, trial index (Appendix C).

### 5.3 Probe classification (decide per probe, record in the probe file)
Tag each probe `DETERMINISTIC` or `STOCHASTIC`. Protocol-mechanics probes (A4, A5,
B*, C-convergence, R1, S2/S3/S5 structural) are deterministic. LLM-output-dependent
probes (A1, A2, A6, S1/S4/S6/S7, V-probes, P4) are stochastic and require N>1.

---

## 6. Statistical analysis plan

### 6.1 Sample sizes
- **Deterministic:** N=1 (counterexample logic).
- **Stochastic:** N≥30 trials per cell as a default (enables a normal-approx CI);
  raise to N≥100 for any cell whose observed violation rate is in (0, 0.1) where the
  estimate is least stable. Pre-register N per probe at the tag.

### 6.2 Confidence intervals
- Report **Wilson score intervals** for binomial violation rates (better than normal
  approx near 0/1, which is exactly where protocol-layer rates will live).

### 6.3 H5 trend test
- Order models by a pre-declared capability proxy (param count / benchmark tier).
- Fit violation rate vs capability via **Cochran–Armitage trend test** (binary
  outcome, ordered groups) or ordinal logistic regression. Pre-register the proxy and
  the test. Report slope, CI, p.

### 6.4 H4 — methodology efficacy
- **Disjointness:** for each probe-found defect, check whether any unit test would
  have failed on the same commit (binary). Report the fraction unique to probing.
- **Sibling clustering:** build the defect graph (nodes = defects, edges = "fix of X
  unmasked / is-sibling-of Y"); compare clustering coefficient against an
  Erdős–Rényi null with the same node/edge count (permutation test).

### 6.5 Residual-defect estimation — capture-recapture (Appendix E)
- Two independent red-team efforts (Phase B) produce defect sets S_A, S_B.
- **Lincoln–Petersen:** N̂ ≈ (|S_A|·|S_B|) / |S_A ∩ S_B|; report **Chapman-corrected**
  estimator and CI. Residual = N̂ − |S_A ∪ S_B|.

### 6.6 Detection sensitivity — bug-seeding (Mills, Appendix E)
- Plant K known defects (extend `M1_planted_regression`). Sensitivity = (planted
  defects detected)/K. Use to discount confidence in clean runs: a clean run on a
  suite with sensitivity 0.7 is weaker evidence than one at 0.95.

---

## 7. Phase 0 — Instrument calibration & freeze prep
*(artifact untouched; instrument + analysis machinery only)*

### 7.1 Entry criteria
- This plan approved; open decisions (§18) resolved.

### 7.2 Tasks
1. **D1 threat-coverage matrix** — fill every cell; enumerate blanks as gaps.
2. **D2 formal model** — build Tamarin/ProVerif model; attempt all Appendix-A lemmas.
   Log any non-verifying lemma as a pre-Stage-2 design finding.
3. **Harness construct-validity fixes (Appendix B):**
   - `PACTStore`/agent read-only `list_receipts(agent)` introspection; rewire A4/S5
     to assert orphan-absent-from-authentic-store (today they only check `status`).
   - Provenance stamping in `_harness.py` (git SHA, platform, Python, model digests).
   - N-trial loop support for `STOCHASTIC` probes + per-trial JSON.
4. **Bug-seeding harness** — generalize `M1_planted_regression` to inject K defects
   and compute sensitivity.
5. **Probe classification** — tag every probe DETERMINISTIC/STOCHASTIC; set per-probe N.
6. **NUC↔Mac Tailscale bridge** — stand up; confirm all 33 sub-probes execute
   (the 9 currently `new_finding`-pending-bridge: A3, M1/M2 worktree, P3).
7. **Reconciliation gate (Appendix D)** — re-run loopback smoke; confirm every
   prediction matches frozen v0.7 behavior; update predictions *only* if an
   instrument fix legitimately moved an observation (log rationale in the probe file).
8. **Version + freeze** — bump to v0.7.0; update CHANGELOG; confirm spec version;
   create annotated tag **`v0.7-pre-registration`**.

### 7.3 Exit criteria
- D1 complete; D2 lemmas attempted; harness fixes merged; all sub-probes runnable;
  reconciliation passed; tag created.

### 7.4 Deliverables
D1, D2, D3 (calibrated harness), the freeze tag.

---

## 8. Phase A — Confirmatory evaluation
*(frozen artifact + frozen prompts)*

### 8.1 Entry criteria
`v0.7-pre-registration` exists; bridge live; N pre-registered per probe.

### 8.2 Tasks
1. Run the full battery cross-machine (NUC↔Mac), DETERMINISTIC at N=1, STOCHASTIC at
   pre-registered N.
2. Run **baselines + ablations** (§12) for causal attribution.
3. Compute H1–H5 verdicts with §6 statistics.

### 8.3 Exit criteria
- Every probe has a recorded outcome + provenance; H1–H5 each have a verdict with
  effect sizes/CIs; ablation attribution table complete.

### 8.4 Deliverables
- **D4:** confirmatory results — H1–H5 verdicts; ablation table; the H5 invariance
  curve; the H3 audit-boundary measurement; full `summary.md` rollup.

---

## 9. Phase B — Exploratory adaptive red-team
*(post-freeze; explicitly non-confirmatory)*

### 9.1 Rationale
Phase A's fixed prompts test a *static* adversary. Real security requires an
*adaptive* one — the prompt-iteration pre-registration forbids. Separating the phases
preserves both rigor (A) and realism (B).

### 9.2 Tasks
1. Two **independent** red-team efforts (human + LLM-driven), iterating prompts and
   chaining attacks, targeting the coverage-matrix blanks first.
2. Record every new defect; classify by sibling class (feeds H4).
3. **Capture-recapture** over S_A, S_B → residual estimate (§6.5).
4. **Bug-seeding** sensitivity run (§6.6).

### 9.3 Exit criteria
- Residual estimate with CI; sibling-class graph; sensitivity figure.

### 9.4 Deliverables
- **D5:** new-defect log, sibling classification, N̂ residual + CI, suite sensitivity.

---

## 10. Phase C — Hardening iterations
*(each defense is its own pre-registered before/after experiment)*

Baseline = the v0.7 Phase-A numbers. Ship defenses **one at a time**; each gets a
pre-registered regression probe and re-runs capture-recapture to update residual.

| # | Defense | Closes | Before/after metric |
|---|---------|--------|---------------------|
| C1 | Hash-chained, content-bound receipts + checkpoint gossip | Audit gaps #2/#3 (equivocation, content-binding) | Equivocation/tamper *detectability* rate; orphan-detection precision |
| C2 | Domain-separation tags / COSE envelopes | #6 (cross-type signature confusion) | Cross-type confusion surface (differential-fuzz acceptance count) |
| C3 | Channel-bound peer identity (Noise / TLS exporter) | naive `peer_network_id` | Sybil/amplification resistance (A3/A6 rerun) |
| C4 | Runtime cost metering + enforcement | author-honest cost | A2 violation rate before/after |
| C5 | Secure-by-construction verification API (resolver-based, typed results) | misuse (#1) | Misuse-resistance (planted-misuse detection) |

Each iteration: pre-register prediction → tag `vX-pre-registration` → run → measure
delta vs baseline → update residual.

**Deliverables:** D6(C1…C5) — one before/after result per defense.

---

## 11. Probe inventory & mapping

Existing probes (`tests/stage2/`), mapped to hypotheses and classification:

| Probe | Tier | Property | Hypothesis | Class | Pre-registered expectation |
|-------|------|----------|-----------|-------|----------------------------|
| `A1_policy_injection` | A | P-OPAQUE | H2 | STOCH | Injection ignored; policy unmoved |
| `A2_cost_lying` | A | (cost honesty) | H5 | STOCH | Declaration trusted; over-run *not* enforced (known limit) |
| `A3_visa_partition` | A | P-OPAQUE | H2 | DET | Partition behavior per spec; naive peer-id confirmed |
| `A4_refs_forgery` | A | P-AUDIT | H3 | DET | Fabricated `refs[]` accepted at protocol layer; orphan post-hoc |
| `A5_rogue_delegator` | A | P-MONO | H1 | DET | Rejected (Bug 9 closure) |
| `A6_v_amplification` | A | P-OPAQUE | H2 | STOCH | Rate ceiling holds; naive peer-id limit confirmed |
| `C_convergence` | C | P-MONO/all | H1,H4 | DET | Regression battery Bugs 1–9 all green |
| `L_overhead` | L | (perf) | — | DET | Overhead within budget (cost axis) |
| `M1_planted_regression` | M | (sensitivity) | H4 | DET | Planted defects detected |
| `M2_v055_baseline` | M | (baseline) | H4 | DET | Baseline replay stable |
| `P1_no_consumption` | P | P-OPAQUE | H2 | DET | Advertisement never consumed (load-bearing) |
| `P2_uri_variants` | P | P-OPAQUE | H2 | DET | All URI shapes inert |
| `P3_mitm` | P | P-AUTH | H2 | DET | MITM-tampered advertisement breaks signature |
| `P4_ad_shaped_output` | P | P-OPAQUE | H2,H5 | STOCH | LLM-emitted ad treated as opaque payload |
| `R1_replay` | R | P-REPLAY | — | DET | Idempotency holds; baseline replay |
| `S1_malformed` | S | P-AUTH | H5 | STOCH | Malformed input fail-closed |
| `S2_cap_injection` | S | P-BIND | H5 | STOCH | Injected cap JSON is opaque payload, not authority |
| `S3_ad_injection` | S | P-OPAQUE | H5 | STOCH | Injected advertisement inert |
| `S4_idempotency_lie` | S | P-REPLAY | H5 | STOCH | Idempotency unaffected by handler output |
| `S5_receipt_mimicry` | S | P-AUDIT | H3,H5 | DET* | Mimicked receipt not ingested (needs store introspection) |
| `S6_exhaust` | S | (DoS) | H5 | STOCH | Resource bounds hold |
| `S7_capability_sweep` | S | P-AUTH | **H5** | STOCH | Violation rate flat across 4 models |
| `V_llm_refuse` | V | P-OPAQUE | H2,H5 | STOCH | Refusal opaque under model variation |
| `V_syn_grant` | V | P-MONO | H2 | DET | Synthetic grant bounded |
| `V3_llm_fidelity` | V | P-AUDIT | H2 | DET | Receipt fidelity under compromise (Bug 8) |

\* `S5` is deterministic *once* store introspection lands (Phase 0); until then its
construct validity is incomplete.

**Coverage gaps to add in Phase 0/B** (illustrative): EAVES-class probes
(confidentiality is out of scope but should be *named*), KEY-COMP rotation-forgery
beyond A2, P-BIND under MITM.

---

## 12. Baselines & ablations

### 12.1 External baselines (what does PACT add?)
- **B0-RAW:** raw agent-to-agent over HTTP, no PACT. Establishes the undefended floor.
- **B0-TLS:** mTLS-only (channel auth, no capability/holder-binding/receipt layer).

### 12.2 Ablations (which mechanism provides which defense?)
Run the security battery against PACT with exactly one mechanism disabled per config:

| Config | Disabled | Expected newly-passing attack |
|--------|----------|-------------------------------|
| ABL-BIND | holder-proof enforcement | stolen-token (B2) succeeds |
| ABL-CHAIN | v1.3 chain re-derivation | rogue-delegator (A5), deep-chain forgery |
| ABL-RECEIPT | receipt writes | audit probes (A4/S5) lose post-hoc detectability |
| ABL-NONCE | visa nonce binding | visa replay (V5) |
| ABL-RATE | visa rate ceiling | amplification (A6) |

Ablation is the *only* way to causally attribute defense→mechanism. The L-tier
overhead sweep is the **cost** axis; ABL-* is the **security** axis. Together they
give the cost/benefit table the paper needs.

---

## 13. Validity threats & mitigations

| Threat | Manifestation in PACT | Mitigation |
|--------|----------------------|-----------|
| **Construct** | `outcome=pass` may mean "no exception fired," not "property holds" (live in S5). | Phase 0 store introspection; bug-seeding sensitivity. |
| **Internal** | A probe's result confounded by an unrelated mechanism. | Ablations isolate the variable. |
| **External** | 2-machine loopback/Tailscale ≠ WAN, many agents, real schedulers. | Add scale dimension to concurrency probes; state generalization limits explicitly. |
| **Ecological** | Fixed adversary strings ≠ adaptive attacker. | Phase B adaptive red-team. |
| **Statistical-conclusion** | Single-run stochastic probes. | N-trial + Wilson CIs + pre-registered N. |
| **Researcher-degrees-of-freedom** | Prompt-tweak-to-match-result. | Pre-registration tag; diff visibility; logged deviations only. |

---

## 14. Stopping criterion

End the program when **both** hold:
1. **Saturation:** the cumulative defect-discovery curve flattens across stages
   (new defects per unit red-team effort below a pre-declared rate — a Heaps'-law-like
   plateau).
2. **Residual bound:** the Chapman-corrected capture-recapture estimate of residual
   defects falls below a pre-declared threshold (e.g., N̂_residual < 1 at the 80% CI
   lower bound for the in-scope property set).

This terminates the loop on evidence, not fatigue.

---

## 15. Deliverables

| ID | Artifact | Phase | Format |
|----|----------|-------|--------|
| D1 | Threat-model coverage matrix | 0 | `.md` table + gap list |
| D2 | Tamarin/ProVerif model + lemma results | 0 | model files + proof log |
| D3 | Calibrated, provenance-stamped harness | 0 | code (`tests/stage2/`) |
| D4 | Confirmatory results (H1–H5) + ablations | A | `summary.md` + analysis notebook |
| D5 | Red-team defect log + residual estimate | B | `.md` + capture-recapture worksheet |
| D6(n) | Per-defense before/after results | C | one `.md` per defense |
| **Paper** | HotNets: C-METHOD + C-INVARIANCE + C-HONESTY | post-A/B | paper draft |

---

## 16. Timeline & critical path

```
D1 threat matrix ─┐
D2 formal model  ─┼─► D3 instrument fix ─► RECONCILE ─► TAG v0.7-pre-registration
                  │                                          │
                  │                                          ▼
                  │                              Phase A confirmatory (H1–H5 + ablations) ─► D4
                  │                                          │
                  │                                          ▼
                  │                              Phase B adaptive red-team + capture-recapture ─► D5
                  │                                          │
                  │                                          ▼
                  └──────────────────────────►  Phase C hardening ×5 (before/after) ─► D6(n)
                                                             │
                                                             ▼
                                                  stopping criterion → paper
```

**Hard ordering constraints:**
- D2 before TAG (model may surface design issues cheaper than runs).
- D3 + RECONCILE before TAG (instrument must be valid at freeze).
- TAG before Phase A (no confirmation without a freeze).
- Phase A before Phase C (no before/after without a "before").

---

## 17. Risk register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Instrument fix accidentally changes a prediction | Med | High | Reconciliation gate (Appendix D); log every prediction change with rationale. |
| Formal model too abstract to be meaningful | Med | Med | Validate model against known Bugs 6/9 — it must reproduce them when re-introduced. |
| LLM non-determinism swamps H5 signal | Med | Med | Raise N; fix temperature; report CIs; pre-register the capability proxy. |
| Cross-machine bridge flakiness | Med | Med | Provenance + retries; mark transport failures `harness_error`, not `new_finding`. |
| Paper-review freeze conflict (stage2 "local-only") | High | Med | Resolve §18.3 before any push to a public remote. |
| Over-claiming non-repudiation (H3) | Low | High | Keep C4 framing; measure the boundary, never assert fairness. |

---

## 18. Open decisions (need a human call)

1. **Venue/scope:** HotNets short (C-METHOD + H5 headline) vs full security venue
   (requires Phase-C iterations + formal proofs complete).
2. **Formal depth:** symbolic only (Tamarin/ProVerif) vs add a computational proof
   for the signature core.
3. **Freeze/publish:** `tests/stage2/__init__.py` marks the package "local-only
   during the May–October paper-review freeze," yet it is committed. Confirm whether
   Phase-0/A artifacts stay private until the freeze lifts. *(This document was
   prepared on branch `claude/pact-passport-1i5z8x`.)*
4. **Class-1 micro-fixes** (`verify_receipt` agent-id binding, reserved-key guard):
   land pre-freeze with reconciliation, or roll into Phase C (C5). **Recommendation:
   Phase C**, to keep v0.7 a clean baseline.
5. **N defaults** for stochastic probes (proposed N≥30, N≥100 near-zero cells) — confirm.

---

## Appendix A — Tamarin/ProVerif lemma sketches

> Symbolic model; Dolev–Yao attacker; `Sign/Verify` and `h()` (SHA-256) as perfect
> primitives. Facts in `Ltac`-style for illustration; translate to the chosen tool.

**A.1 Identity & rotation**
- Rule `Create_Identity`: fresh `~sk`; `pk = pk(~sk)`; `aid = h(<ALG, pk>)`; commit
  `next = h(pk(~sk2))`.
- Rule `Rotate`: reveal `~sk2` only if `h(pk(~sk2)) = next` (pre-rotation continuity).
- **Lemma P-AUTH:** `All m a #i. Accepted(m, a)@i ==> (Ex #j. Signed(m, a)@j & j<i)`
  — every accepted message was previously signed by the claimed agent's current key.
- **Lemma KEY-CONT:** rotation accepted ⇒ the new key's hash equals the prior
  commitment (no key substitution without the committed secret).

**A.2 Capabilities**
- Rules `Issue`, `Attenuate` (signs `<parent_cap_id, action_at_step, caveats_at_step>`),
  `Verify` (walks chain, enforces action-equality + caveat-superset + final
  consistency).
- **Lemma P-MONO (unbounded K):** `All cap #i. ValidChain(cap)@i ==>
  authority(cap) ⊆ authority(root(cap))` — for all chain depths. *Inductive lemma;
  Tamarin's strength. Must hold without a depth bound.*
- **Lemma P-BIND:** `All cap b #i. Honored(cap, b)@i ==> (Ex #j. Proves(b, holder(cap))@j)`
  — a capability is honored only by a party that proved holder-key possession;
  attacker-in-possession-of-token-only cannot get `Honored`.
- **Adversary check (regression of Bug 9):** re-introduce the rogue-delegator rule
  (mint child with mutated action/stripped caveats under a valid key) and assert
  P-MONO now *fails* — confirms the model has teeth.

**A.3 Visa**
- Rules `IssueVisa` (fresh `~nonce`, caveats {expires, max_inv=1, no_deleg}),
  `UseVisa` (holder-proof = `Sign(nonce, holder_sk)`).
- **Lemma P-REPLAY (visa):** `All v #i #j. UsedVisa(v)@i & UsedVisa(v)@j ==> #i=#j`
  modulo `max_invocations` — a nonce-bound proof cannot authorize two distinct
  request-pairs.
- **Lemma P-OPAQUE:** refusal output is a constant `denied` independent of the policy
  branch taken (observational equivalence in ProVerif: refuse-for-reason-X ≈
  refuse-for-reason-Y to the peer).

**A.4 What the model cannot cover (hand off to empirical)**
LLM adversary behavior (H5), runtime cost, wall-clock liveness, and anything in the
declared out-of-scope set. State this boundary in the paper.

---

## Appendix B — Harness schema changes (Phase 0)

1. **Receipt-store introspection** (`src/pact/store.py` + agent):
   ```python
   def list_receipts(self, agent_name: str) -> list[dict]: ...
   ```
   Rewire `A4`/`S5` to assert the fabricated/mimicked id is **absent** from the
   authentic store, not merely that `status == "ok"`.
2. **Provenance** (`_harness.py`): extend `result` with
   `git_sha`, `host`, `os`, `python`, `model_digests`, `trial_index`, `n_trials`.
3. **N-trial loop:** the `@probe` decorator gains `n_trials` + `classification`
   (`DETERMINISTIC`/`STOCHASTIC`); STOCHASTIC probes loop N times and emit one JSON
   per trial plus an aggregate (rate + Wilson CI).
4. **Bug-seeding:** generalize `M1_planted_regression` to a parametric injector over
   a list of K reversible defects; compute sensitivity = detected/K.

---

## Appendix C — Result JSON schema (extends current `_harness.py`)

```json
{
  "probe_id": "S7_capability_sweep",
  "tier": "S",
  "classification": "STOCHASTIC",
  "n_trials": 30,
  "trial_index": 7,
  "provenance": {
    "git_sha": "…", "host": "nuc", "os": "Windows-11",
    "python": "3.12.x", "model_digests": {"adversary": "gemma3:4b@sha…"}
  },
  "pairing": { "...": "..." },
  "pre_registered_prediction": "…",
  "failure_threshold": "…",
  "observations": { "violation": false },
  "receipts": [],
  "outcome": "pass",
  "elapsed_s": 0.0,
  "notes": ""
}
```
Aggregate per `(probe × model)`: `{n, violations, rate, wilson_low, wilson_high}`.

---

## Appendix D — Reconciliation checklist (run before the tag)

- [ ] Re-run loopback smoke on the Mac after all Phase-0 instrument changes.
- [ ] For every probe: observed outcome matches `prediction`; does not cross `threshold`.
- [ ] Any prediction changed by an instrument fix is updated **with a one-line
      rationale committed in the probe file** (and reconsidered for whether it belongs
      pre-freeze at all).
- [ ] DETERMINISTIC/STOCHASTIC tag + N set on every probe.
- [ ] All 33 sub-probes execute (bridge live).
- [ ] Version bumped, CHANGELOG updated, spec version confirmed.
- [ ] Create annotated tag `v0.7-pre-registration`.

---

## Appendix E — Capture-recapture & bug-seeding worksheets

**E.1 Capture-recapture (Lincoln–Petersen, Chapman-corrected)**
- Inputs: `|S_A|`, `|S_B|`, `|S_A ∩ S_B|`.
- Chapman estimator: `N̂ = ((|S_A|+1)(|S_B|+1) / (|S_A∩S_B|+1)) − 1`.
- Residual: `N̂ − |S_A ∪ S_B|`. Report variance/CI per Seber.
- **Assumptions to state:** the two efforts are independent and the defect population
  is approximately closed for the in-scope property set during Phase B.

**E.2 Bug-seeding (Mills)**
- Plant K reversible defects (drawn from the sibling classes of known Bugs 1–10).
- Sensitivity `s = detected/K`. Adjust confidence: a clean run on a suite with
  sensitivity `s` leaves an estimated `(1−s)` fraction of similar defects undetected.
- Pre-register K and the planted-defect list hash so the seeding can't be tuned post-hoc.

---

*End of plan.*
