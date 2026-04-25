# Paper Update Changelog

## Updated Files

- `Latex/ACSAC.tex`
  - Switched the paper's controlled benchmark narrative from the older 50-case description to `benchmark_v2`.
  - Updated Abstract, Introduction, Evaluation Setup, Benchmark Credibility, Main Results, Error Analysis, Discussion/Future Work, and Conclusion.
  - Replaced the old benchmark tables with the latest `benchmark_v2` numbers:
    - total cases: 139
    - static-only: completed 139, skipped 0, malicious 100, benign 39
    - rule-only / rule+EPG / EPG+filtering: completed 115, skipped 24, malicious 76, benign 39
    - detection rate: all 1.0
    - false positive rate: static 0.0, rule-only 0.1026, rule+EPG 0.0, EPG+filtering 0.0
    - endpoint accuracy / edge-level F1 / complete-chain rate / partial-chain usefulness:
      - static-only 0.8182
      - rule-only 0.0
      - rule+EPG 1.0
      - EPG+filtering 1.0
    - root-cause accuracy:
      - static-only 1.0
      - rule-only 0.7895
      - rule+EPG 1.0
      - EPG+filtering 1.0
  - Tightened the caveats so that:
    - `0 FP` is stated only as a benchmark-bound result
    - the 24 skipped dynamic cases are described as an evaluation boundary, not a system failure
    - the real-world rerun remains supporting evidence, not a fully labeled benchmark

- `scripts/render_benchmark_summary_tables.py`
  - Added a lightweight exporter that renders coverage/results tables from an exported benchmark summary JSON.
  - This keeps benchmark summary tables synchronized with repository summaries instead of hand-copying numbers.

- `benchmark_v2/generated/benchmark_v2_results_tables.md`
  - Code-generated Markdown table export from `benchmark_v2/generated/benchmark_v2_all_modes_summary.json`.

- `benchmark_v2/generated/benchmark_v2_results_tables.tex`
  - Code-generated LaTeX table export from `benchmark_v2/generated/benchmark_v2_all_modes_summary.json`.

## Why These Changes

- The repository already contains a stronger, manifest-derived benchmark asset in `benchmark_v2/`, so the paper should report that benchmark directly instead of leaving it as a side note.
- The strongest new paper value is not only the larger case count. It is the stronger evaluation story:
  - family-based expansion
  - hard-benign pressure
  - malicious/benign lookalike discrimination
  - explicit dynamic-evaluation boundary
- The updated results sharpen the intended claim:
  - `rule_only` still detects malicious behavior
  - but `rule_only` still has explainability metrics of `0.0`
  - provenance-backed baselines retain strong but non-perfect explainability metrics on the dynamic benchmark boundary
  - benign false-positive control improves to `0` only within the benchmark boundary

## Insertable Paragraphs

### 1. benchmark_v2 Design Paragraph

`benchmark_v2` expands the paper's controlled evaluation from the earlier small benchmark to a 139-case manifest-defined suite with 100 malicious cases and 39 benign cases. The expansion is organized around risk-mechanism families rather than around superficial variation: direct sensitive exfiltration, staged or relay exfiltration, unauthorized external transfer, unsafe command construction, LLM-induced unsafe action, mixed multi-hop flows, policy-benign but suspicious outward actions, and a dedicated hard-benign pack. This makes the benchmark better aligned with the paper's actual claim, which is about semantic attack-chain recovery and evidence-backed discrimination, not merely about whether a detector can fire on a handful of obvious malicious examples.

### 2. Why This Is Not Case Inflation

The benchmark expansion should not be read as simple case inflation. The additional cases were introduced to preserve or deliberately perturb the security semantics that matter for explanation: source sensitivity, relay structure, sink policy, outward-looking artifact style, and root-cause ambiguity. In particular, benchmark_v2 adds family-preserving malicious variants, approved-but-suspicious benign outward cases, and explicit lookalike pairs that keep the relay shape and surface form similar while flipping the underlying security meaning. The goal is therefore not to make the benchmark larger for its own sake, but to make success on the benchmark more credible as evidence of semantic discrimination.

### 3. Hard-Benign Justification Paragraph

The dedicated hard-benign pack is an important part of benchmark_v2 because explanation-oriented security analysis is often bottlenecked by benign cases that look risky on the surface. Note-, report-, inventory-, and mirror-style workflows are especially important here: they can present outward-looking names, generated artifacts, helper-command structure, or public-fetch-plus-local-write patterns that overlap with malicious exfiltration language while still remaining benign under the benchmark definition. Treating these cases as first-class benchmark material prevents false-positive control from being evaluated only on easy benigns and makes residual over-alerting directly inspectable in the same semantic language used by the paper's error analysis.

### 4. Benchmark-Bound Zero-FP Caveat Paragraph

The zero false-positive result for the provenance-backed baselines must be interpreted narrowly. In this paper, `0 FP` means that no benign cases were incorrectly flagged within the benchmark_v2 evaluation boundary, i.e., within the 39 benign benchmark cases and the 115 dynamically evaluated cases used in the controlled study. It should not be rewritten as a claim that the system has eliminated false positives in general deployment settings. Outside the benchmark, real-world workloads remain noisier, less uniformly labeled, and subject to execution-availability constraints, which is why the larger real-world rerun is presented only as supporting evidence rather than as a population-level accuracy benchmark.

## Notes for Follow-On Edits

- If the paper later wants a separate benchmark-design subsection, the strongest repository-backed sources are:
  - `benchmark_v2/generated/summary_tables.md`
  - `benchmark_v2/generated/pair_mapping.md`
  - `benchmark_v2/paper/benchmark_v2_design.tex`
  - `benchmark_v2/paper/hard_benign_pack.tex`
- If the paper later wants automatically inserted benchmark-result tables, the new exporter can be reused instead of hand-maintaining numbers.
