# Security Engine Limitations

The HTTP API and file inspection are implemented. No research analysis component
is implemented as of this phase. This file tracks component-specific limitations
as each module is built.

The authoritative limitation register is maintained in
[docs/research-alignment.md](../docs/research-alignment.md#12-limitations-register).
Every research component must reference the relevant `LIM-*` identifiers here
before its capability is exposed.

## Current status

- File and workspace scans inspect real files and report hashes, sizes, languages,
  and discovered source URIs.
- No static analyzer adapter (Semgrep, Bandit, CodeQL, Joern) is connected.
- No evidence-fusion detector exists; scan findings are always empty with an
  explicit `analysisAvailable: false`.
- No SAE artifact has been registered or validated.
- No model activations have been captured.
- No counterfactual effect has been computed.
- No steering run has been performed.
- No repair has been proposed, applied, or verified.
- No benchmark or evaluation result exists.
- The VS Code extension connects to this server over the versioned HTTP API and
  performs health checks, file scans, selection detection requests, and workspace
  scans. It does not start or supervise the server. Research analysis stages still
  report explicit `unavailable` results.

## API limitations

- All analysis endpoints return `200` with `partial` operation status and explicit
  `unavailable` stages. Their result objects contain no findings, scores, features,
  effects, patches, or verdicts.
- Verification returns `verdict: "not_run"` because no verifier or adequate
  sandbox exists.
- Scans return an empty `findings` array. This is not a clean bill of health.
- The API is synchronous. There is no job queue, SSE stream, cancellation
  endpoint, or persisted analysis record.
- Workspace scans discover files but do not parse or analyze them.
- Workspace roots must be inside `CRAFTSEC_WORKSPACE_ROOTS`, which defaults to the
  process working directory. Requested roots and files are resolved; escaping
  symlinks are rejected.
- Binary and non-UTF-8 files are rejected. Files over `CRAFTSEC_MAX_FILE_BYTES`
  and workspaces over `CRAFTSEC_MAX_WORKSPACE_FILES` are rejected rather than
  silently truncated.
- Bearer auth is optional and configured at process launch. There is no user
  account system, token rotation, or multi-user authorization.
- The root index, `/docs`, `/redoc`, and `/openapi.json` are not protected by the
  bearer middleware. Run the server on loopback or a trusted network.
- CORS is disabled by default and accepts only an exact origin allowlist. No
  wildcard is permitted.
- There is no Host-header allowlist, DNS-rebinding defense, or rate limiter beyond
  request-size limits. Do not expose the server directly to an untrusted network.
- Request bodies are size-checked while streaming, but FastAPI still buffers each
  accepted JSON body in memory.
- Logs are structured JSON and exclude request bodies and source text, but no
  separate audit store exists.
- No shared-schema code generation or contract-drift test between the extension
  and engine is implemented yet.

## Non-negotiable constraints

- Missing capabilities are reported as unavailable and are never simulated.
- Heuristic scores are not probabilities.
- Counterfactual effects are model-internal interventions, not real-world causal effects.
- Execution-based verification requires an adequate sandbox.
- Repairs require explicit user approval before application; the engine never
  writes user source.
