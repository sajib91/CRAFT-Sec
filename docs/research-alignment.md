# CRAFT-Sec — Research Alignment and Integrity Contract

**Status:** Phase 0 approved. No experiments have been run and no results are reported.
**Version:** 0.1.0
**Date:** 2026-11-10
**Companion document:** [architecture.md](architecture.md)

This document maps the stated research goals of CRAFT-Sec to concrete architectural mechanisms and defines what the system may and may not claim. It is a binding engineering contract: a feature is not "research-complete" until its gate here is satisfied.

---

## 1. Scope and evidence caveat

The project brief identifies six research focus areas:

1. SAE-based vulnerability feature extraction.
2. Counterfactual multi-feature interaction analysis.
3. Interaction-aware adaptive activation steering.
4. Explainable vulnerability detection.
5. Repository-aware automated repair.
6. Independent security and functional verification.

The full paper text, equations, and section numbers were **not supplied** with this task. This document therefore maps to the stated focus areas, not to specific paper equations, figures, or claims. When the paper text is available, a traceability addendum must map each paper component to a module, metric, and gate. No citation, dataset, or experimental number is invented here.

**No empirical results are reported in this document.** Any table cell marked *not measured* is a placeholder for a future, genuinely executed evaluation.

---

## 2. Claim taxonomy

Every user-visible result carries a `claim_kind`. The UI and exported reports must render it. The schema validator rejects results without one.

| `claim_kind` | Meaning | Permitted wording | Forbidden wording |
|--------------|---------|-------------------|-------------------|
| `observed` | Directly measured output of a tool or model at a recorded version | "Semgrep reported…", "the model's logit was…" | "therefore the code is vulnerable" |
| `computed` | Deterministic or seeded derivation from observed values | "the score changed by…", "the estimated interaction effect was…" | "this proves causation" |
| `inferred` | Model-based interpretation with uncertainty | "feature #1234 is associated with…", "the labeler suggested…" | "feature #1234 means…" (without provenance/confidence) |
| `hypothesis` | Proposed explanation or repair not yet verified | "proposed repair", "expected to address…" | "fixed", "secure", "verified" |
| `verified` | Passed a named verification profile, with scope stated | "verified against profile P; checks A, B passed" | "secure", "vulnerability eliminated" |

Additional required metadata on results:

```json
{
  "claim_kind": "computed",
  "provenance": {
    "producer": "counterfactual.engine",
    "producer_version": "0.1.0",
    "model_id": "...",
    "model_revision": "...",
    "sae_artifact_sha256": "...",
    "snapshot_id": "snp_...",
    "config_hash": "...",
    "created_at": "2026-11-10T12:00:00Z"
  },
  "limitations_ref": "LIM-CF-03"
}
```

A result that cannot populate provenance cannot be labelled `computed` or `verified`.

---

## 3. Focus-area alignment

| Focus area | Architectural mechanism | Evidence produced | Verification | Claim boundary |
|------------|-------------------------|-------------------|--------------|----------------|
| SAE-based vulnerability feature extraction | `models/runtime.py` captures activations at declared hooks; `sae/*` encodes with a registered, checksummed SAE; `features/extractor.py` aggregates to spans/files | Sparse feature activations, feature cards, reconstruction/sparsity stats | Hook shape checks, SAE compatibility checks, encode/decode tests, artifact checksum tests | Features describe a specific model/SAE checkpoint, not an abstract "vulnerability concept" |
| Counterfactual multi-feature interaction analysis | `counterfactual/*` applies named interventions to activations; computes single, pairwise, higher-order effects, Shapley samples, minimal flip sets | Effect sizes, interaction indices, CIs, validity/drift reports, budgets | Brute-force equivalence for small feature sets; seed determinism; cache-key tests; validity thresholds | Interventional effect on the detector's score under a defined intervention — not real-world causality |
| Interaction-aware adaptive activation steering | `steering/planner.py` selects features from interaction results; `steerer.py` adds decoder-direction vectors under guardrails; `evaluate.py` runs paired generations | Steering plan, applied norms, paired security/functional outcomes | Guardrail tests, compatibility tests, paired evaluation harness | Measured change on a defined evaluation set; may not generalize; not a security guarantee |
| Explainable vulnerability detection | `detection/*` fuses static and SAE evidence; `explain/graph.py` builds an evidence graph; UI renders claims + provenance | Findings, score semantics, evidence links, feature attributions, gaps | Score-kind validation, evidence-link tests, UI claim-kind tests | Heuristic risk is not a probability; explanations are evidence-linked, not authoritative |
| Repository-aware automated repair | `repair/context.py` uses tree-sitter symbols, imports, call sites, tests; `generator.py` proposes a schema-constrained diff; extension applies after approval | Patch, touched symbols, rationale, risk notes | Diff/path/hash validation, shadow application, independent verification | A verified patch is verified only against the stated profile and available checks |
| Independent security and functional verification | `verification/verifier.py` consumes patch + snapshot only, runs analyzers and tests in a sandbox, compares against baseline | Security findings delta, test results, verdict, logs | Independence tests, sandbox isolation tests, baseline-aware policy tests | "Verified" is profile-scoped; missing tests or sandbox downgrade the verdict |

---

## 4. SAE integrity protocol

### 4.1 What "genuine SAE feature extraction" requires

1. A local white-box model loaded in-process, with a known revision and architecture.
2. A registered SAE artifact whose manifest matches the base model, revision, layer, hook point, SAE type, width, and `d_model`.
3. Activations captured from that model at that hook on the actual input.
4. Encoding through the artifact's learned weights.
5. Feature activations tied to token spans via a validated alignment map.

If any item is missing, the capability is **unavailable**. There is no fallback that "estimates" SAE features from static rules, embeddings, or hand-crafted vectors.

### 4.2 Artifact manifest (required fields)

```json
{
  "artifact_id": "sae_...",
  "base_model": "org/model",
  "model_revision": "commit-sha",
  "layer": 12,
  "hook_point": "model.layers.12",
  "sae_type": "relu",
  "width": 16384,
  "l0": 64,
  "d_model": 768,
  "decoder_sha256": "...",
  "artifact_sha256": "...",
  "license": "...",
  "training_card": { "dataset": "...", "notes": "..." },
  "eval": { "reconstruction_loss": null, "dead_feature_fraction": null },
  "status": "registered"
}
```

`null` means "not measured". It is never replaced with a guessed value. Registration fails if required compatibility fields are missing.

### 4.3 Compatibility checks

- Exact match on base model identifier, revision, layer, hook point, `d_model`, and SAE type.
- Shape validation of encoder/decoder/biases before inference.
- Checksum validation of the artifact file.
- Hook-point existence and output-shape check on a dry run.
- A mismatch is reported as `E_SAE_INCOMPATIBLE` with the specific field; no nearest-match substitution.

### 4.4 No-simulation rule

- Production code paths must never generate synthetic activations, synthetic feature values, or synthetic feature labels.
- Unit tests may use toy SAE tensors to validate arithmetic. Such fixtures are stored under `tests/fixtures/`, marked `synthetic-test-only`, and cannot be registered in the production registry.
- Demo mode, if ever added, must be visibly labelled `synthetic demo` and must not write to experiment records or capability discovery.

### 4.5 Feature cards and labelling

Each feature card records:

- feature index, decoder norm, activation frequency, dead/live status;
- top activating spans with file, line, token, and activation value;
- label (if any), `label_source` (`human`, `auto_interp`, `none`), labeler model/prompt hash, confidence;
- known caveats (polysemanticity, corpus dependence).

Auto-interpretation is optional. If used, it is an `inferred` claim and never presented as ground truth. Without it, the UI shows "unlabelled feature #N" plus examples.

### 4.6 Metrics that must be reported with any SAE result

- Reconstruction error on the analysed batch.
- Feature sparsity (L0) and activation density.
- Dead-feature fraction, if the artifact card provides it.
- Hook/shape validation result.
- Artifact checksum and compatibility status.
- Token-alignment coverage.

These are descriptive measurements, not evidence that the SAE is "good" for security.

### 4.7 Gate G-SAE

Enabled only when: compatible artifact registered; checksum verified; encode/decode finite; hook shapes match; alignment coverage recorded; tests pass. Otherwise the capability remains disabled in `/capabilities`.

---

## 5. Counterfactual semantics

### 5.1 Target metric

Let `m(x)` be the detector's numeric score for a specific finding class on input `x`, with `score_kind` recorded. Counterfactual analysis is defined only when `m` is numeric and reproducible under the recorded configuration.

### 5.2 Interventions

| Intervention | Definition | Scope |
|--------------|------------|-------|
| `ablate(feature_i, α)` | Remove `α · f_i · d_i` from the activation at the SAE hook, where `d_i` is the decoder direction | Model-internal |
| `clamp(feature_i, v)` | Move the activation along `d_i` so the feature takes value `v` | Model-internal |
| `add(feature_i, α)` | Add `α · d_i` to the activation | Model-internal |
| `token_edit` | Change the input text (e.g., remove a dangerous API call) | Input-level |
| `evidence_mask` | Remove a static evidence item from the detector's input | Detector-internal |

`token_edit` is not an activation intervention. Results must name the intervention family; the two are never pooled without a label.

### 5.3 Effect definitions

For a feature set `S`, define the ablated score `m_S = m(x with features in S ablated)` and `ν(S) = m_S − m(∅)`.

- Single-feature effect: `Δ_i = ν({i})`.
- Pairwise interaction: `I_ij = ν({i,j}) − ν({i}) − ν({j})`.
- Higher-order interaction (inclusion–exclusion): `I_S = Σ_{T⊆S} (−1)^{|S|−|T|} ν(T)`.
- Shapley value for feature `i`: average marginal contribution over sampled permutations, with a confidence interval.

Exhaustive evaluation is limited to `|S| ≤ 3` by default. Above that, use seeded sampling with a recorded budget and report variance. The result states `estimator: exhaustive | sampled`, `samples`, and `ci_method`.

### 5.4 Minimal flip search

A counterfactual flip set is a set of feature ablations that moves `m` across the decision threshold. Implementation: greedy forward selection, then backward elimination, then re-verification of the flip. The result reports `minimality: local`, not global optimality. If no flip is found within budget, report `not_found_within_budget`, not "no counterfactual exists".

### 5.5 Validity checks

Every intervention is checked for:

- **Drift:** activation norm change and reconstruction error change relative to the unmodified run; thresholds recorded in config.
- **Finiteness:** no NaN/Inf in activations or scores.
- **Faithfulness:** top-ranked features must move the score more than size-matched random feature sets on a held-out sample; otherwise the ranking is marked `unsupported`.
- **Determinism:** repeated runs with the same seed and config produce identical results for deterministic stages; GPU nondeterminism is reported, not hidden.

Invalid interventions are excluded from headline effects and listed separately. They are never silently averaged in.

### 5.6 Claim boundary

Counterfactual results mean: *under this model, this SAE artifact, this hook, this intervention definition, and this detector, the score changed by Δ.* They do **not** mean:

- that the feature causes the vulnerability in the real world;
- that removing the feature makes code secure;
- that the detector's score is a calibrated probability;
- that the effect generalizes beyond the evaluated inputs.

The UI must display this scope next to effect values.

### 5.7 Gate G-CF

Enabled only when: genuine feature run exists; detector returns a numeric score; intervention engine validates hooks; budgets enforced; exhaustive results match brute force on small fixtures; sampled estimates report CIs; drift/faithfulness checks run.

---

## 6. Steering protocol

### 6.1 Prerequisites

- White-box local model with accessible internal activations.
- Compatible SAE with decoder directions at a validated hook.
- Counterfactual results identifying candidate features.
- A functional-evaluation harness with a defined test command or an explicit `no_tests` state.
- Explicit user opt-in for the steering run.

API-only models are unsupported. There is no prompt-only imitation of activation steering.

### 6.2 Plan derivation

The planner ranks features by:

1. negative ablation effect on the vulnerability score (removing the feature lowers risk);
2. interaction structure (avoid redundant or antagonistic features);
3. decoder-direction norm and stability;
4. guardrail feasibility (combined norm budget).

The plan records selected features, weights, layer, token scope, norm budget, and the evidence used. Weights are heuristic unless a fitted policy is trained and evaluated; `plan_kind` states which.

### 6.3 Application guardrails

- Add `v = Σ w_i d_i` at the declared hook, with per-token and sequence-level norm clipping.
- Cap the perturbation relative to the residual norm; record the applied norm.
- Restrict to allowlisted layers and token spans.
- Do not alter temperature, top-p, or the tokenizer.
- Abort the run on non-finite activations or excessive drift.
- Log the exact plan and seeds for reproducibility.

### 6.4 Evaluation

Paired design: generate with and without steering for the same prompts, seed, model, and decoding settings. Measure:

- security-relevant outcomes via named analyzers/detector, with versions and thresholds;
- functional outcomes via the available test suite or execution checks;
- drift/quality proxies (e.g., compile/parse success), clearly labelled as proxies;
- effect sizes with confidence intervals and sample sizes.

Report negative and null results. Do not select a favourable subset post hoc without disclosure.

### 6.5 Claim boundary

A steering result means: *on this evaluation set, with this model/SAE/plan, the measured security and functional outcomes changed by X.* It does not establish general security improvement, absence of new vulnerabilities, or preservation of behaviour beyond the tests run.

### 6.6 Gate G-STEER

Enabled only when: model + SAE compatible; counterfactual results exist; guardrail tests pass; paired evaluation harness runs; results include security and functional outcomes; opt-in recorded. Otherwise steering remains unavailable.

---

## 7. Detection and explainability

### 7.1 Evidence classes

| Class | Source | Label |
|-------|--------|-------|
| Static rule match | Semgrep, Bandit, CodeQL, Joern | `static` |
| Structural pattern | tree-sitter queries | `structural` |
| Model-internal feature | SAE activations | `sae_feature` |
| Learned classifier score | Detector head | `model_score` |
| Human annotation | User feedback | `human_label` |

Evidence classes are never merged without retaining their source. A finding can cite multiple classes; the UI shows each separately.

### 7.2 Score semantics

- `heuristic`: a documented, deterministic combination of evidence (e.g., weighted rule matches). Rendered as a risk band and labelled "heuristic risk", never "probability".
- `model_logit`: raw model output. Labelled "model score (not calibrated)".
- `calibrated`: produced by a fitted calibrator on a held-out labelled set. Requires a calibrator artifact, dataset card, split hash, and reported calibration metrics (e.g., Brier score, ECE). Until those exist, the value cannot be emitted.

No default weights are presented as research findings. Weights are configuration and are recorded in the run manifest.

### 7.3 Explanation graph

Nodes: finding, evidence item, feature, intervention effect, verification check. Edges: `supports`, `contradicts`, `derived_from`, `verified_by`. Every node has `claim_kind`, provenance, and a limitations reference. Gaps (e.g., "no SAE available") are explicit nodes, not omitted.

### 7.4 UI wording rules

- "Heuristic risk: high (0.72)" — not "72% likely vulnerable".
- "SAE feature #1234 (unlabelled; top examples…)" — not "SQL injection feature".
- "Interaction effect: +0.18 (95% CI …)" — not "feature pair causes vulnerability".
- "Verified against profile standard; tests A/B passed; Semgrep clean" — not "secure".

### 7.5 Gate G-DET

Enabled only when: score kind enforced; calibration blocked without artifacts; evidence graph builds; UI renders provenance and limitations; heuristic weights documented.

---

## 8. Repository-aware repair

### 8.1 Context assembly

The repair context includes, within a token budget:

- the finding location and surrounding code with line numbers;
- enclosing function/class and symbol signatures from tree-sitter;
- imports and relevant call sites;
- related tests and fixtures;
- repository conventions (e.g., existing validation helpers);
- security guidance tied to the rule/CWE, with source and version.

Ordering is deterministic; provenance is recorded. Secrets and files excluded by ignore rules are not included.

### 8.2 Patch generation constraints

- Output is schema-constrained: per-file unified diff, base hash, touched symbols, rationale, risk notes.
- Only files within the project root and in scope may be touched.
- No new dependencies by default; no binary files; no generated/vendor files.
- Public API changes require explicit flagging.
- The generator receives no tool access and no ability to write files.
- Repository content is treated as untrusted data; instructions embedded in code are not obeyed.

### 8.3 Application

- The backend never writes user source.
- The extension shows the diff, requires approval, revalidates hashes, and applies via `WorkspaceEdit`.
- Stale patches, path escapes, and out-of-scope changes are rejected.
- Every application is audited.

### 8.4 Functional preservation

A repair is not described as behaviour-preserving merely because it compiles. Preservation is assessed by:

- baseline test results before the patch;
- the same tests after the patch, in the same environment;
- only tests that passed at baseline are required to pass after; pre-existing failures are reported separately;
- additional checks (parse, type check, build) when configured;
- explicit `inconclusive` when coverage is absent or insufficient.

### 8.5 Gate G-REPAIR

Enabled only when: context assembly is deterministic; patch schema validates; hash/path checks pass; extension approval flow works; shadow application succeeds; audit logging works.

---

## 9. Independent verification

### 9.1 Independence rules

- The verifier receives the patch, the base snapshot, and the verification profile. It does not receive the generator's rationale, confidence, or feature explanations.
- Verification runs as a separate job with its own run record.
- Security checks rerun named analyzers on the patched shadow workspace and compare finding fingerprints to baseline.
- Functional checks run the project's configured commands in the sandbox.
- The verifier may not "repair the repair" or silently modify the patch.

### 9.2 Baseline-aware policy

- Capture baseline security findings and test outcomes before applying the patch.
- Required outcomes: target finding resolved (or explicitly reclassified with evidence), no new high-severity findings under the profile, baseline-passing tests still pass.
- Flaky tests are detected by reruns where budget allows; unresolved flakes are reported and excluded from the pass claim with disclosure.

### 9.3 Verdicts

| Verdict | Meaning |
|---------|---------|
| `verified` | All required checks in the named profile passed |
| `partially_verified` | Some checks passed; others unavailable or inconclusive |
| `failed` | A required check failed |
| `inconclusive` | Insufficient evidence (no tests, flaky suite, analyzer error) |
| `not_run` | Verification was not attempted (e.g., no adequate sandbox) |

The verdict always includes the profile, checks, versions, and scope. "Verified" never means "secure in general".

### 9.4 Gate G-VERIFY

Enabled only when: sandbox isolation tests pass for the selected backend; baseline capture works; security delta comparison works; functional checks are baseline-aware; verdict policy is enforced; independence test confirms rationale is not consumed.

---

## 10. Reproducibility contract

Every research run records a `RunManifest`:

- project snapshot ID and manifest hash; git commit and dirty flag;
- extension, backend, and contract versions;
- Python/Node/OS/CPU/GPU/driver versions;
- model ID, revision, tokenizer revision, dtype, quantization;
- SAE artifact hash and compatibility fields;
- analyzer versions and rule-pack hashes;
- seeds and deterministic flags;
- canonical config JSON and its hash;
- dataset IDs, versions, and hashes (when applicable);
- start/end timestamps and pseudonymous host ID;
- result artifact hashes;
- skipped stages and reasons;
- warnings and degradations.

### 10.1 Determinism tiers

| Tier | Meaning |
|------|---------|
| `deterministic` | Same inputs/config/seed produce byte-identical results (e.g., manifest hashing, schema validation) |
| `seeded` | Seeded stochastic process; results expected to match within documented tolerance |
| `nondeterministic` | Hardware/library nondeterminism; variance reported, exact reproduction not claimed |

Each stage declares its tier. GPU results are not labelled deterministic without evidence.

### 10.2 Export

Experiment bundles include manifest, config, result summaries, and artifact hashes. Source code and feature-card snippets are excluded unless the user opts in. Bundles are self-describing: schema versions and a README are included.

### 10.3 Gate G-REPRO

Enabled only when: manifest fields are populated for every research job; config hashing is stable; export omits secrets by default; rerun comparison tests pass for deterministic stages; nondeterminism is disclosed.

---

## 11. Evaluation plan

No values are filled in. Each row defines what must be measured before a claim can be made.

| ID | Question | Metrics | Required evidence | Status |
|----|----------|---------|-------------------|--------|
| RQ1 | Does SAE-derived evidence improve detection over static baselines? | Precision, recall, F1, AUROC; calibration metrics only if calibrated | Labelled dataset card, split hashes, baseline configs, seeds, CIs | Not measured |
| RQ2 | Do pairwise/higher-order interactions add information beyond single features? | Interaction effect sizes, out-of-sample predictive gain, faithfulness | Fixed feature sets, budgets, estimator variance, ablation tests | Not measured |
| RQ3 | Does interaction-aware steering change security outcomes without breaking function? | Vulnerability rate by named analyzers, test pass rate, effect sizes with CIs | Paired generations, fixed decoding, evaluation harness, negative results | Not measured |
| RQ4 | Does repository-aware repair increase independently verified repair success? | Verified repair rate, regression rate, patch scope/minimality | Baseline-aware verification, profile definitions, blinded review where possible | Not measured |
| RQ5 | Are explanations useful and correctly interpreted by developers? | Task accuracy, time, trust calibration | Human-subject protocol, consent/IRB where required | Not planned in MVP |

Evaluation datasets must be licensed, versioned, and hashed. If a dataset cannot be redistributed, the manifest records access instructions and split hashes without embedding the data. No benchmark number may appear in the UI or docs until the corresponding run is exported and linked.

---

## 12. Limitations register

| ID | Limitation | Affected component | Disclosure |
|----|------------|--------------------|------------|
| LIM-SAE-01 | SAE features depend on a specific model, revision, layer, and hook | SAE, features | Capability card + result provenance |
| LIM-SAE-02 | SAE features may be polysemantic or dead | Features, explanations | Feature card stats + "unlabelled" default |
| LIM-SAE-03 | Auto-interp labels are model-generated hypotheses | Feature cards | `label_source` + confidence |
| LIM-CF-01 | Interventions are off-distribution and may be invalid | Counterfactual | Drift/validity report; invalid results excluded |
| LIM-CF-02 | Higher-order interaction estimation is budget-limited | Counterfactual | Estimator, samples, CIs, budget |
| LIM-CF-03 | Effects are model-internal, not real-world causal effects | Counterfactual, UI | Scope statement on every result |
| LIM-CF-04 | Flip sets are locally minimal, not globally minimal | Counterfactual | `minimality: local` |
| LIM-STEER-01 | Steering may degrade capability or fluency | Steering | Paired evaluation + guardrails |
| LIM-STEER-02 | Steering benefits may not generalize beyond the evaluation set | Steering | Scope statement + sample size |
| LIM-DET-01 | Heuristic scores are not probabilities | Detection, UI | `score_kind` + risk-band wording |
| LIM-DET-02 | Calibration requires representative labelled data | Detection | Calibrator artifact required; otherwise blocked |
| LIM-REP-01 | Repairs may be incomplete or introduce new issues | Repair | Independent verification + risk notes |
| LIM-REP-02 | Test suites may be absent, weak, or flaky | Verification | Baseline-aware policy + `inconclusive` |
| LIM-VER-01 | Verification coverage is bounded by available checks and sandbox | Verification | Profile + verdict scope |
| LIM-VER-02 | Static analyzers have false positives/negatives | Detection, verification | Analyzer versions + explicit tool attribution |
| LIM-REPRO-01 | GPU/library nondeterminism limits exact reproduction | Experiments | Determinism tier + variance |
| LIM-ENV-01 | CodeQL/Joern may be unavailable or version-dependent | Static adapters | Capability discovery + warnings |

Each limitation ID must appear in the relevant module's documentation and, where user-visible, in the UI.

---

## 13. What tests do and do not establish

Unit and integration tests establish:

- mechanical correctness of encoding, decoding, effects, and estimators on controlled fixtures;
- schema and contract compliance;
- safety properties (path containment, sandbox policy, redaction, approval gates);
- graceful degradation.

They do **not** establish:

- that SAE features are semantically meaningful for security;
- that counterfactual effects generalize;
- that steering improves security in practice;
- that repairs are correct beyond the checks run;
- that the detector is accurate or calibrated.

Those require the evaluation plan in §11 with real models, real artifacts, and real data. Conflating the two is a research-integrity violation.

---

## 14. Reporting checklist

Every reported result must include:

1. `claim_kind` and scope statement.
2. Model ID/revision, SAE hash, hook point, and compatibility status.
3. Snapshot ID and manifest hash; dataset ID/version/hash.
4. Analyzer names, versions, and rule-pack hashes.
5. Seeds, decoding settings, and determinism tier.
6. Sample size and confidence intervals where applicable.
7. Budgets and skipped stages.
8. Known limitations (IDs from §12).
9. Negative and null results.
10. Link to the exported experiment bundle.

A result missing any required item is labelled `incomplete` and cannot be used in a paper, README, or UI headline.

---

## 15. Traceability matrix

| Requirement | Architecture module | Primary tests | Gate |
|-------------|---------------------|---------------|------|
| SAE feature extraction | `models/*`, `sae/*`, `features/*` | Hook shapes, artifact compatibility, encode/decode, alignment | G-SAE |
| Counterfactual single/pairwise/higher-order | `counterfactual/*` | Formula vs brute force, sampling CIs, drift, cache | G-CF |
| Interaction-aware steering | `steering/*` | Planner ranking, guardrails, paired evaluation | G-STEER |
| Explainable detection | `detection/*`, `explain/*`, webviews | Score-kind, evidence links, UI wording | G-DET |
| Repository-aware repair | `repair/*`, extension patch flow | Context determinism, diff/path/hash validation, approval | G-REPAIR |
| Independent verification | `verification/*`, `sandbox/*` | Independence, baseline policy, isolation | G-VERIFY |
| Reproducibility | `experiments/*`, `artifacts/*` | Manifest completeness, config hash, export redaction | G-REPRO |
| Limitations | `LIMITATIONS.md`, result schemas | Presence checks, UI rendering | Release checklist |

---

## 16. Change control

- Changes to claim semantics, score kinds, intervention definitions, or verdict rules require a schema version bump and an update to this document.
- Changes to SAE compatibility rules require re-registration of affected artifacts.
- Any new user-visible metric must declare its claim kind, provenance, and limitations before merge.
- A phase cannot be marked complete while a gate it claims to satisfy is disabled or untested.
- When the paper text becomes available, add a section-level traceability addendum; do not retrofit claims to code that does not support them.
