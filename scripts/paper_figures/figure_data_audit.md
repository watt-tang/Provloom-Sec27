# Figure data audit

- Figure 3(b): 579/316/199 are from `artifacts/paper_usenix/metrics.json` and
  `benchmark_methodology/distribution.json`. Counterfactual pairs are omitted:
  the frozen artifacts report 160 pairs, but only 142 pairs with >=2 formal
  samples (and 143 complete formal pairs), so pair/case units are not uniform.
- Figure 4(b): 62 corrected benign decisions are from
  `artifacts/paper_usenix/static_vs_full/analysis.json`.
- Figure 6(b): the plotted 103/3/1/0 taxonomy is the paper-level frozen
  diagnosis used in `artifacts/paper_usenix/root_cause_diagnosis/summary.md`.
  A second frozen file, `fn_taxonomy_v2/summary.json`, instead records
  103 authorization/trust, 2 target-reached/no-carrier, 1 execution, and
  1 environment/dependency. This discrepancy is preserved here and not
  silently reconciled.
