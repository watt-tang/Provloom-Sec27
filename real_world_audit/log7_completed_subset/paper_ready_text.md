# Completed-Subset Sampled Audit Text

## Setup

The supporting real-world rerun in `/mnt/e/log7` contains 617 scheduled Skills, 465 completed executions, and 152 skipped executions. We treat the completed executions as the sampling boundary for a lightweight manual audit package rather than as a fully labeled benchmark.

## Why This Is Not a Population-Level Accuracy Benchmark

The log7 rerun is a candidate-risk corpus with an explicit execution-availability boundary. Completed executions reflect what could be exercised under the current sandbox, trigger, adapter, and credential setup; they are not a random sample of the public Skill ecosystem, and they do not carry gold labels by default.

## What The Sampled Audit Still Adds

We generate a stratified audit pack over 29 completed cases spanning chain-backed critical findings, partial-evidence medium findings, note-like or local-output suspected benign-FP clusters, upload-like or mirror-like outward workflows, LLM-decision-heavy cases, and representative low-risk cases. This does not replace benchmark metrics, but it does improve external credibility by making the completed subset auditable, by reducing cherry-picking risk, and by forcing explicit error-analysis notes for the exact clusters that remain hard to calibrate.

## Sampling Boundary

The pack is `code-generated` from `results.jsonl` and remains `sampled-manual-review-pending` until a reviewer fills the annotation sheet. Tables that compare prediction to manual labels are therefore exported as placeholders with pending fields instead of invented accuracies.