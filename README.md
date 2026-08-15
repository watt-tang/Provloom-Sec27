# ProvLoom

ProvLoom is a carrier-aware runtime provenance system for Skill security
analysis. It combines instruction provenance, runtime provenance, cross-layer
alignment, policy evaluation, and evidence closure to produce binary
predictions and review status on ProvBench.

This repository is prepared as an anonymous USENIX Security 2027 Cycle 1
artifact. It contains the current ProvLoom implementation, the final 776-case
ProvBench corpus, frozen ProvBench result summaries, baseline comparisons,
ablation summaries, and reproducibility scripts.

## Repository Structure

- `app/`: ProvLoom implementation, including static analysis, dynamic replay,
  provenance construction, policy evaluation, and adjudication.
- `provbench/`: final ProvBench cases, fixtures, ground truth, manifest, schema,
  and validators.
- `scripts/`: evaluation, baseline, ablation, figure, and validation scripts.
- `results/`: frozen paper-facing summaries for ProvBench, baselines, ablations,
  evidence/closure analysis, cost, and error analysis.
- `docs/`: artifact notes that are useful for reviewers.
- `docker/`: sandbox runtime support.
- `latex/USENIX_2027_Cycle1_Provloom/`: paper source used as the artifact truth
  source.

## Environment Setup

ProvLoom uses Python 3.10+ and the Python standard library for the core artifact
checks. Full dynamic replay additionally requires Docker and an LLM API key.

```bash
python3 -m compileall app scripts provbench
```

For full dynamic scans, set an API key outside the repository:

```bash
export PROVLOOM_SCAN_API_KEY=...
```

## Running ProvBench Checks

```bash
python3 scripts/validate_provbench.py
python3 provbench/scripts/check_distribution.py provbench
```

Expected benchmark counts:

- Total: 776
- Confirmed violations: 398
- Benign lookalikes: 179
- Trusted allowed: 120
- Review / coverage: 79
- Complete counterfactual pairs: 142
- Multi-file cases: 199
- LLM-mediated cases: 316
- Network / external cases: 579

## Running ProvLoom

Smoke-test one case:

```bash
python3 scripts/run_provbench_full_scan.py \
  --benchmark-root provbench \
  --output-root results/provbench/full_smoke \
  --sample-ids BV3-0001
```

Re-evaluate the frozen full-system summary:

```bash
python3 scripts/run_provbench_full_scan.py \
  --evaluate-only \
  --output-root results/provbench/full \
  --ground-truth-dir provbench/ground_truth
```

The internal `BV3-*` case IDs are retained only for compatibility with frozen
artifacts and scripts; the benchmark name is ProvBench.

## Running Ablations

```bash
python3 scripts/validate_results.py
```

The paper-facing ablation table reports:

- Full: P 0.882, R 0.731, F1 0.799
- Static only: P 0.847, R 1.000, F1 0.917
- Event only: P 0.789, R 0.628, F1 0.699
- No alignment: P 0.858, R 0.653, F1 0.742
- No policy: P 0.583, R 0.942, F1 0.720

## Reproducing Paper Tables

```bash
python3 scripts/validate_results.py
```

Expected main results on ProvBench:

- Static: precision 0.847, recall 1.000, F1 0.917
- Full: precision 0.882, recall 0.731, F1 0.799
- Violation closure: precision 0.863, recall 0.618, F1 0.720
- Evidence closure: precision 1.000, recall 0.616, F1 0.762
- Benign lookalikes: 179, with zero Full ProvLoom false positives

Baseline comparison:

- AI-Infra-Guard: TP/TN 101/373, FP/FN 5/297, P 0.953, R 0.254, F1 0.401
- Cisco Skill Scanner: TP/TN 312/340, FP/FN 38/86, P 0.891, R 0.784, F1 0.834
- SkillScan: TP/TN 144/360, FP/FN 18/254, P 0.889, R 0.362, F1 0.514

## Artifact Scope

The artifact intentionally includes the implementation, ProvBench, formal
evaluation summaries, baseline comparison summaries, ablation summaries, and
paper-table generation code.

Real-world raw artifacts are excluded from the anonymous artifact because they
contain third-party public packages, large execution traces, and findings under
responsible disclosure. The paper reports only aggregate real-world figures:
6,000 public skill samples, 5,590 completed scans, 93.2% completion, 47.8%
dynamic replay share, median completed scan time 7.3 s, 95th percentile scan
time 445.6 s, median 10,190 tokens per dynamic replay, and 21 manually confirmed
malicious public skills after evidence review.

The 21 confirmed cases are not a prevalence estimate and are not represented by
raw evidence packages in this repository.

`scripts/paper_usenix_eval.py` documents the table-generation path used for the
paper-facing summaries. The anonymous artifact validates the frozen summaries
with `scripts/validate_results.py` because raw per-sample real-world artifacts
and large internal execution traces are outside the submitted artifact scope.

## Anonymous Artifact Notes

Do not commit API keys, raw LLM request logs, real-world scan packages, crawler
caches, downloaded third-party skills, sandbox runtime output, or local paths.
Run the validation and secret scans described in the final artifact report
before pushing.
