# Security Engine Limitations

No security engine component is implemented as of Phase 1. This file will track component-specific limitations as each research module is built.

The authoritative limitation register is maintained in [docs/research-alignment.md](../docs/research-alignment.md#12-limitations-register). Every research component must reference the relevant `LIM-*` identifiers here before its capability is exposed.

## Current status

- No SAE artifact has been registered or validated.
- No model activations have been captured.
- No counterfactual effect has been computed.
- No steering run has been performed.
- No repair has been proposed, applied, or verified.
- No benchmark or evaluation result exists.

## Non-negotiable constraints

- Missing capabilities are reported as unavailable and are never simulated.
- Heuristic scores are not probabilities.
- Counterfactual effects are model-internal interventions, not real-world causal effects.
- Execution-based verification requires an adequate sandbox.
- Repairs require explicit user approval before application.
