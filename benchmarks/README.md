# Benchmarks

Benchmark task definitions, harness code, configurations, dataset cards, and results for CRAFT-Sec.

## Status

There are no benchmark results and no bundled datasets. This directory is scaffolding for evaluations that will follow the protocol in [../docs/research-alignment.md](../docs/research-alignment.md).

## Structure

| Path | Purpose |
|------|---------|
| `configs/` | Pinned benchmark configurations (models, SAEs, seeds, analyzers) |
| `datasets/` | Dataset cards and access instructions; no data blobs |
| `harness/` | Runner, scoring adapters, and sandbox integration |
| `tasks/` | Task definitions and scoring rubrics |
| `results/` | Generated results; gitignored by default |

## Rules

- Results must be reproducible from a recorded manifest (model revision, SAE hash, seeds, analyzer versions, dataset split hash).
- Security claims must name the analyzer/detector and version.
- Functional claims must name the test command and baseline.
- Negative and null results are retained.
- No benchmark number may be published without a linked experiment bundle and documented limitations.
