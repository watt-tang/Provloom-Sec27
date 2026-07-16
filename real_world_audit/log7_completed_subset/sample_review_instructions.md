# log7 Sample Review Instructions

This pack is for a completed-subset sampled audit, not a population-level accuracy benchmark.

## Minimal Manual Workflow

1. Open the sampled skill root and the referenced execution artifact directory.
2. Inspect `primary_chain`, detected behaviors, and root-cause fields before reading the full trace.
3. Fill `manual_label` with `malicious`, `benign`, or `uncertain` only after checking whether an actual source-to-outward path exists.
4. Use `manual_root_cause` only when the execution evidence supports a concrete mechanism.
5. Keep `manual_notes` short and evidence-backed; mention whether the concern is note-like, helper-like, upload-like, or chain-backed.

## Boundary Rules

- Treat `completed_full` as the sampling boundary; skipped cases are out of scope for the sampled audit sheet.
- Do not convert this audit into overall precision/recall claims.
- When evidence is incomplete, record `uncertain` and keep `needs_manual_review=true`.