# Analyst Review Protocol

This protocol is not a completed human study. It is a reproducible review checklist
for the frozen formal-776 artifacts.

Review unit: one Benchmark v3 sample with ground truth, SKILL.md, ProvLoom
unified-analysis.json, runtime-chains.json, runtime graph, and evaluator row.

Questions:
1. Is the malicious/benign binary prediction correct?
2. If malicious, does the reported witness establish source-to-sink closure?
3. Does the witness identify the expected endpoint?
4. Does the witness preserve expected intermediate artifact structure?
5. Are missing relays due to carrier-level runtime modeling, true execution miss,
   ontology mismatch, or evaluator normalization failure?
6. If false positive, is the cause trust/authorization, benign-lookalike false
   closure, instrumentation gap, or policy scoring?
7. If false negative, is the cause path not triggered, runtime failure, missing
   carrier visibility, allowlist/trust downgrade, or policy scoring?

Recommended outputs: adjudicated label, explanation level (L1/L2/L3), mismatch
category, and free-text rationale. Do not tune analyzer or thresholds during
review.
