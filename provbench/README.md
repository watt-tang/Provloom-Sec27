# ProvBench

ProvBench is the fixed benchmark used by the USENIX Security 2027 Cycle 1
ProvLoom artifact. It contains 776 cases:

- Confirmed violations: 398
- Benign lookalikes: 179
- Trusted allowed: 120
- Review / coverage: 79

Execution characteristics:

- Complete counterfactual pairs: 142
- Multi-file cases: 199
- LLM-mediated cases: 316
- Network / external cases: 579

Directory layout:

- `cases/`: public Skill case bundles evaluated by ProvLoom and baselines
- `fixtures/`: synthetic runtime fixtures and local mock-service inputs
- `ground_truth/`: evaluator-only ground truth
- `manifest.jsonl`: frozen 776-case manifest
- `schema/`: manifest, fixture, and ground-truth schemas
- `scripts/`: integrity and distribution validators

Internal case identifiers retain the historical `BV3-*` prefix for compatibility
with frozen result artifacts and evaluator code. The benchmark name for the
artifact and paper is ProvBench.
