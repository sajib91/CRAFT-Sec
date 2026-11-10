# Test Fixtures

This directory holds small, deterministic fixtures used by unit and integration tests.

## Synthetic SAE policy

Tests may construct toy SAE tensors to verify arithmetic (for example, a random orthogonal decoder). Such fixtures must be:

- labelled `synthetic-test-only`;
- kept small and deterministic;
- excluded from the production SAE registry and all research results;
- never used to generate user-visible feature claims.

Production code must never synthesize activations or feature values that were not measured from a genuine model and a compatible SAE artifact.
