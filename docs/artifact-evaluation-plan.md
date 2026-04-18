# Artifact Evaluation Plan

## Artifact Directories

- `artifacts/runs/<execution_id>/`
  - runtime execution artifacts for API and dynamic benchmark runs
- `artifacts/benchmark/benchmark-summary.json`
  - structured benchmark output across the selected baselines
- `artifacts/benchmark/benchmark-summary.csv`
  - baseline-level summary table for paper-ready reporting
- `artifacts/benchmark/cases/<analysis_mode>/<case_id>/`
  - benchmark-side per-case result snapshots

## Reproduction Steps

1. Ensure Docker is available.
2. Run:
   - `python3 scripts/run_benchmark.py --datasets-root ./datasets`
3. Review:
   - `artifacts/benchmark/benchmark-summary.json`
   - `artifacts/benchmark/benchmark-summary.csv`

## Expected Outputs

- Four baseline summaries: `static_only`, `rule_only`, `rule_plus_epg`, `epg_with_filtering`
- Per-case status showing `completed` or `skipped`
- Non-empty benchmark output with endpoint, edge, chain, root-cause, and latency metrics
- For the current expanded suite: 50 total cases, with dynamic baselines completing 43 and skipping 7 `dynamic_runnable=false` cases

## Review Procedure

- Pick a malicious case from the JSON summary.
- Open its `artifact_dir` or `benchmark_case_dir`.
- Compare:
  - GT source/sink
  - predicted `primary_chain`
  - predicted `root_cause_detail`
  - `graph_summary.summary_scope`

## Audit Notes

- `graph_summary.summary_scope=execution_provenance_graph` means a dynamic EPG summary.
- `graph_summary.summary_scope=abstract_skill_graph` means a static action-level graph summary.
- `dynamic_runnable=false` cases are intentionally skipped in dynamic baselines and should not be treated as runtime failures.
