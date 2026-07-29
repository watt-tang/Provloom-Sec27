# ProvLoom Benchmark v3

ProvLoom Benchmark v3 evaluates whether an analysis system can recover complete attack or policy-relevant chains from complex natural-language Agent Skill documentation. The primary tasks are source recovery, sink recovery, ordered operation and edge recovery, complete-chain recovery, intermediate-object and carrier recovery, minimal-witness recovery, false-closure avoidance, coverage-state attribution, trusted-flow distinction, static-runtime alignment, and contradiction recovery.

Detection precision, recall, and F1 are secondary metrics.

Tested content lives under `samples/`. Ground truth, scenario cards, and fixture expectations are physically separated under `ground_truth_private/`, `scenario_cards_private/`, and `fixtures/`.

Authoring constraints:

- Tested `SKILL.md` files are natural-language Markdown.
- No structured `skill-actions` carry ground truth.
- Ground truth uses the independent ontology in `schema/ontology.md`.
- Fixtures use synthetic assets, sandbox paths, and local mock services only.
- Ground truth is fixed before running ProvLoom or any evaluated system.

The benchmark currently contains the full 800-sample construction target. Ground-truth and fixture validation pass for all samples.
