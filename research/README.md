# Research Workspace

This directory holds research configuration, evaluation protocols, dataset cards, and experiment records for CRAFT-Sec.

## Status

No experiment has been run. No dataset, model, SAE artifact, benchmark result, or metric is included in this repository.

## Structure

| Path | Purpose |
|------|---------|
| `configs/` | Versioned experiment configurations (model, SAE, seeds, budgets) |
| `datasets/` | Dataset cards, licenses, hashes, and access instructions; no data blobs |
| `evaluation/` | Metrics, statistical methods, and evaluation protocols |
| `experiments/` | Generated run records and exports; ignored by git by default |
| `protocols/` | Pre-registration, evaluation plans, and human-study protocols |

## Research integrity

- Every reported result must follow the claim taxonomy and reporting checklist in [docs/research-alignment.md](../docs/research-alignment.md).
- SAE features require a genuine compatible artifact; missing capabilities are not simulated.
- Heuristic scores are not probabilities.
- Counterfactual effects are model-internal interventions, not real-world causal effects.
- Negative and null results are recorded, not omitted.
- Datasets must be licensed and versioned; do not commit data without explicit redistribution rights.
