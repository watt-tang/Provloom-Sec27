# Construction Report

ProvLoom Benchmark v3 has reached the 800-sample construction target generated with the `benchmark-v3-author` skill. Ground truth is stored separately from tested Skill text and uses a tool-agnostic ontology.

Final checkpoint coverage:

- 800 complete natural-language Markdown Skill samples.
- 800 independent scenario cards with writing plans.
- 800 private ground-truth files using the independent ontology.
- 800 safe fixture files using synthetic assets and local or mock-only behavior.
- 160 counterfactual pairs.
- 240 LLM-mediated samples.
- 593 network or external-platform samples.
- 200 multi-file samples.
- All 800 tested Skill bodies satisfy the requested 700-1200 word range; strict word-count range is 701-922.

Validation checkpoint:

- `benchmark_v3/scripts/validate_all.py benchmark_v3` passed for all 800 samples.
- Representative deterministic replay was run across early, middle, and latest samples; all returned exit code 0 with no timeouts.
- Split counts are development=120, blind-heldout=480, challenge-heldout=200.
- Split hash: ce6a2473de9afdc48ba9d857b5bad54d41d6becf9def65c17a116edc542edd4f.

Statistical note:

The 800-sample total supports overall proportion metrics with conservative 95% confidence interval margin below +/-5 percentage points. The 400 confirmed-violation subset supports violation-only proportion estimates at similar scale. Category and smaller outcome strata must still report their own, wider confidence intervals where applicable.
