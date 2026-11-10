# Shared Contracts

`shared/` is the frontend/backend contract boundary.

- `schemas/` contains the JSON Schema source of truth for every cross-process payload.
- `generated/` contains checked-in Pydantic models and Ajv validators produced from those schemas.
- `fixtures/` contains valid and invalid payload examples used by contract tests.

Rules:

- A payload is not accepted unless it validates against its schema.
- Generated files are not edited by hand; regenerate them with the scripts added in Phase 2.
- Schema changes require a contract version bump and migration notes.
- Secrets, tokens, and full source code must never appear in contract fixtures.
