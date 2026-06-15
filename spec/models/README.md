# PACT Formal Models

Symbolic models discharging the security claims of [`PACT_v1.md`](../PACT_v1.md)
under a Dolev–Yao attacker with perfect `Sign/Verify` and `h()` (SHA-256).

These models implement the lemma sketches in
[`PACT_RESEARCH_PLAN.md` §Appendix A](../../../../Desktop/PACT_HotNets_Paper/PACT_RESEARCH_PLAN.md)
and are part of the Stage 2 pre-registration evidence: they ship under the
`v0.7-pre-registration` tag so any later spec change is visible as a diff
against a machine-checkable artifact.

## Layout

| File | Tool | What it models | Lemmas |
|---|---|---|---|
| `pact_core.spthy` | Tamarin | Identity inception + rotation, capability issue/attenuate/verify, visa issuance/use | P-AUTH, KEY-CONT, P-MONO (unbounded K), P-BIND, P-REPLAY |
| `pact_opaque.pv` | ProVerif | Visa refusal observable behavior | P-OPAQUE (observational equivalence) |
| `PROOF_LOG.md` | — | Per-lemma verification result + design implication of any non-verifying lemma | — |

## Tool split

Tamarin handles **inductive** reasoning (P-MONO over unbounded chain depth K)
and **trace** properties (authentication, freshness, replay). ProVerif handles
**observational equivalence** (P-OPAQUE: refusal output is indistinguishable
across policy branches). Either tool alone would force an awkward encoding of
the other tool's natural property; using each for what it does best keeps the
models legible.

## Install

### Tamarin

```bash
brew install --cask tamarin-prover/tap/tamarin-prover
# (requires brew tap tamarin-prover/tap first if not cached)
```

Sanity check:

```bash
tamarin-prover test
```

### ProVerif

```bash
brew install opam
opam init -y
opam install -y proverif
eval $(opam env)
```

Alternative (no OCaml on host): `docker run --rm -v $PWD:/work bnp/proverif /work/pact_opaque.pv`.

## Verify

From this directory:

```bash
# Tamarin — proves all lemmas; ~minutes wall clock
tamarin-prover --prove pact_core.spthy

# ProVerif — checks the equivalence query
proverif pact_opaque.pv
```

For one lemma at a time, use `--prove=LEMMA_NAME`. Falsified lemmas print an
attack trace; expected handling per lemma is documented in `PROOF_LOG.md`.

## What the models do NOT cover

Per §A.4 of the research plan, the symbolic boundary stops here:

- LLM adversary behavior (covered by Stage 2 empirical probes, hypothesis H5).
- Runtime cost (declarative-honest in v0.7; runtime metering is v0.8 roadmap).
- Wall-clock liveness, side-channel timing.
- Anything in the declared out-of-scope set
  ([`D1_threat_coverage_matrix.md`](../../../../Desktop/PACT_HotNets_Paper/D1_threat_coverage_matrix.md)
  Gap classes B and C).

The paper §6 must continue to name these as model boundaries, not as proven.

## Re-verification policy

Any change to `pact_core.spthy` or `pact_opaque.pv` after the
`v0.7-pre-registration` tag MUST:

1. Re-run both provers.
2. Update `PROOF_LOG.md` with the new result + elapsed.
3. If a lemma changed status (was VERIFIED, now NON-VERIFYING or vice versa),
   that is a finding for the paper §6 (post-tag) or for the v0.8 hardening
   roadmap (the spec changed and the model now disagrees).
