# JSON Schemas

This directory is the single source of truth for CRAFT-Sec frontend/backend
payloads. Every schema is Draft 2020-12 JSON Schema and is consumed by both the
Python engine tests and the JavaScript extension tests.

## Contracts

| Contract | Schema | Purpose |
|---|---|---|
| `ScanRequest` | `scan-request.json` | File scan context, optional selection, consent-gated source text |
| `ScanResult` | `scan-result.json` | Scan status, findings, scope, and availability |
| `VulnerabilityFinding` | `vulnerability-finding.json` | Finding identity, location, CWE, severity, evidence, score, and remediation |
| `FeatureExtractionResult` | `feature-extraction-result.json` | Measured SAE features and coverage |
| `CounterfactualResult` | `counterfactual-result.json` | Model-internal intervention effects |
| `SteeringResult` | `steering-result.json` | Explicit-opt-in steering plan and limited evaluation |
| `ExplanationResult` | `explanation-result.json` | Evidence-grounded claims and explanation graph |
| `RepairCandidate` | `repair-candidate.json` | Reviewable patch proposal; always requires approval |
| `VerificationResult` | `verification-result.json` | Security/functional checks and verdict |
| `ExperimentMetadata` | `experiment-metadata.json` | Reproducibility metadata and artifact references |

`common.json` holds shared definitions. `manifest.json` maps contract names to
schemas and fixtures. `VERSION` records the contract version.

## Conventions

- JSON field names are camelCase.
- Every schema declares `$id` under `https://craftsec.local/schemas/v1/`.
- Objects set `additionalProperties: false` unless extensibility is deliberate.
- Research results carry provenance. Calibrated scores additionally carry a
  calibrator artifact, dataset identity, split hash, Brier score, and expected
  calibration error.
- Fixtures contain no credentials and no real source contents.

## Score semantics

A `riskScore` always carries `value`, `kind`, and `interpretation`:

| `kind` | Allowed `interpretation` | Range | Meaning |
|---|---|---|---|
| `heuristic` | `heuristic_risk` | `[0, 1]` | Documented deterministic combination; never a probability |
| `model_logit` | `model_score_not_calibrated` | any number | Raw model score; never a probability |
| `calibrated` | `calibrated_probability` | `[0, 1]` | Fitted on a held-out labelled set with recorded calibration evidence |

Only `kind: "calibrated"` may be rendered as a probability. A heuristic or
model-logit score must not be labelled, formatted, or described as one.

## Availability semantics

`analysisAvailable: false` means the analysis stage did not produce a result.
Schemas therefore require empty `findings`, `features`, `effects`, `claims`, or
`checks`, and require verification to report `not_run`. An empty findings list is
not a clean result.

## Tests

The same manifest, schemas, and fixtures are validated from both runtimes:

```bash
cd security-engine && ../.venv/bin/python -m pytest tests/contract -q
npm --workspace vscode-extension test
```

The suites validate every schema against the Draft 2020-12 metaschema, accept
each valid fixture, reject each invalid fixture for the intended keyword, and
check the score, location, approval, and unavailable-analysis rules.

Schema changes require a `VERSION` bump and migration notes.

## Relationship to the current HTTP surface

The versioned FastAPI server still returns interim operation envelopes whose
analysis stages are explicitly `unavailable`. These schemas define the payloads
that detector and analysis implementations must emit as those stages become
available; a response is not a full result until it validates against the
relevant schema and reports `analysisAvailable: true`.
