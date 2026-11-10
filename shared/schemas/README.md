# JSON Schemas

This directory is the single source of truth for all VS Code ↔ security-engine payloads.

Expected schemas (Phase 2):

- `common.json` — IDs, timestamps, provenance, claim kind, pagination.
- `error.json` — problem-details envelope.
- `capabilities.json` — models, SAEs, analyzers, sandbox backends, feature gates.
- `project.json`, `job.json`, `events.json`.
- `finding.json`, `feature.json`, `counterfactual.json`, `steering.json`.
- `repair.json`, `verification.json`, `experiment.json`.

Conventions:

- JSON Schema draft 2020-12.
- Every schema declares `$id` and `additionalProperties: false` unless extensibility is deliberate.
- Research results require `claim_kind` and `provenance`.
- Scores require `score_kind`; `calibrated` requires a calibrator artifact reference.
- No credentials or source contents in examples.

`VERSION` records the current contract version.
