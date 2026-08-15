# Evaluation Bug Report

Bug description: the previous exploratory evaluator used a helper equivalent to
`str(value).split(':', 1)[0]` for path-like comparison. That is safe for
file-field labels such as `path:FIELD`, but unsafe for URL endpoints because
`http://localhost:20001/path` collapses to `http`.

Affected metrics: prior endpoint and chain-level exploratory diagnostics in
`results/paper_usenix/explanation_metric_audit/` may over-count endpoint
matches whenever URL strings were compared through that helper.

Expected impact: previous `L2_endpoint_correct` and some sink granularity
matches should be treated as provisional. This root-cause diagnosis preserves
those old artifacts and writes corrected contract-specific metrics under
`root_cause_diagnosis/structural_explanation/`.

Scope: evaluation-only bug. It does not touch ProvLoom analyzer, runtime,
ground truth, predictions, or benchmark samples.

Corrected evaluator version: `provloom-root-cause-normalization-v1` in
`structural_explanation/normalization_rules.yaml`.
