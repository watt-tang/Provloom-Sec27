# Real-World Sampled GT Audit

This directory contains a deterministic, machine-assisted ground-truth audit pack for the completed real-world rerun in `/mnt/e/log7`.

## Scope

- Source rerun: `/mnt/e/log7`
- Completed execution boundary: `465` completed runs out of `617` scheduled runs
- Fixed sampling seed: `20260424`
- Target sample size: `96`
- Actual sampled size: `96`

Only completed executions are in scope for this audit pack. Skipped cases remain out of scope because they were not exercised end-to-end under the rerun environment.

## Strata

Every completed case is assigned to exactly one stratum using a documented precedence order:

1. `suspected_benign_fp_note_report_inventory`
2. `upload_or_mirror_outward`
3. `chain_backed_critical`
4. `representative_low_risk`
5. `llm_decision_heavy`
6. `partial_evidence_medium`

The note/report/inventory bucket is evaluated before the outward-transfer bucket because the audit is meant to explicitly stress-test likely benign false-positive clusters. The outward-transfer bucket is evaluated before chain-backed critical cases so explicit transfer semantics are preserved as their own review stratum.

## Files

- `sample_manifest.csv`: one row per sampled case with detector outputs, trace summaries, endpoint summaries, and snippet references.
- `initial_gt_labels.jsonl`: machine-assisted provisional labels plus supporting evidence for each sampled case.
- `human_review_sheet.csv`: review sheet with machine-assisted fields and blank human annotation columns.
- `summary_tables.md`: corpus counts, stratum counts, and provisional label distributions.

## Labeling Protocol

- `gt_risk` is limited to `malicious`, `benign`, or `ambiguous`.
- `gt_chain_valid` is limited to `true`, `false`, or `unknown`.
- Every exported label is machine-assisted and provisional.
- `needs_human_review` is always `true` until a reviewer fills `human_decision`.
- No precision, recall, or accuracy claims should be computed from this directory until human review is complete.

Suggested review order:

1. Confirm the sampled skill root and execution artifact directory are readable.
2. Check `primary_chain`, `external_endpoints`, and `trace_summary` before reading the local snippets.
3. Compare the machine-assisted label against the run evidence and the local skill text.
4. Fill `human_decision`, `human_gt_behavior`, `human_gt_chain_valid`, `human_gt_root_cause`, and `human_notes` in `human_review_sheet.csv`.

## Paper-Ready Framing

The `/mnt/e/log7` rerun covers `617` scheduled skills, of which `465` completed and `152` were skipped. This audit pack should therefore be described as a sampled manual-audit set over the completed execution boundary, not as a full real-world correctness benchmark.

We deterministically sampled `96` completed cases across six predefined strata to create a lightweight manual-audit layer that is reproducible, inspectable, and suitable for error analysis. The machine-assisted labels exported here are provisional only: they organize reviewer effort, but they are not gold labels and they do not justify end-to-end accuracy claims before human decisions are recorded.

## Snapshot

| Metric | Value |
| --- | ---: |
| Completed runs | 465 |
| Sampled runs | 96 |
| Machine-assisted `malicious` | 3 |
| Machine-assisted `benign` | 13 |
| Machine-assisted `ambiguous` | 80 |
| High confidence | 11 |
| Medium confidence | 46 |
| Low confidence | 39 |
| `gt_chain_valid=true` | 3 |
| `gt_chain_valid=false` | 19 |
| `gt_chain_valid=unknown` | 74 |