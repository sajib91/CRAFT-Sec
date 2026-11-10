# Architecture Decision Records

Formal ADRs will live in this directory as `NNNN-short-title.md`.

The initial decisions are recorded in [the architecture document](../architecture.md#19-architecture-decision-records):

- ADR-001: local sidecar backend rather than in-process Python
- ADR-002: REST + SSE rather than WebSocket
- ADR-003: JSON Schema as the shared contract source of truth
- ADR-004: extension is the sole writer of user source
- ADR-005: capability-gated research features; no simulation
- ADR-006: SQLite + content-addressed artifact store
- ADR-007: Docker required for execution-based verification
- ADR-008: mandatory claim-kind metadata

Rules:

- An ADR records context, decision, alternatives, and consequences.
- Reversing an accepted decision requires a superseding ADR.
- Contract or claim-semantics changes also require a schema version bump and updates to the research alignment document.
