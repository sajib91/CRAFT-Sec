# Benchmark Harness

Planned responsibilities:

- Load a pinned benchmark configuration and verify its hashes.
- Select tasks and datasets from versioned cards.
- Run the security engine in isolated jobs with fixed seeds and budgets.
- Score security and functional outcomes using named, versioned tools.
- Emit a `RunManifest` and exportable result bundle.
- Refuse to report a result when required evidence is missing.

No harness code exists yet. Execution-based scoring will require an adequate sandbox; if none is available, execution results are marked `not_run`.
