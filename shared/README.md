# Shared Contracts

`shared/` is the frontend/backend contract boundary.

- `schemas/` contains the JSON Schema source of truth for every cross-process payload.
- `generated/` is reserved for checked-in Pydantic models and Ajv validators produced from those schemas. It currently contains only its README; no generation script exists yet.
- `fixtures/contracts/` contains valid and invalid payload examples used by the shared contract tests.

Rules:

- A payload is not accepted unless it validates against its schema.
- Generated files are not edited by hand; regeneration tooling has not been added yet.
- Schema changes require a contract version bump and migration notes.
- Secrets, tokens, and full source code must never appear in contract fixtures.
