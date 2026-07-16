# ProvLoom Artifact: Evidence-Typed Skill-Level Provenance-Chain Explanation

## Overview

ProvLoom is an artifact for evaluating explanation quality in Skill-level security analysis under bounded execution evidence. The system reconstructs runtime-observed provenance chains in `source -> relay -> sink` form from bounded Skill executions, and separately represents instruction-derived latent setup or maintenance chains when those steps are documented but not directly executed in runtime telemetry.

This artifact is designed for explanation-quality evaluation on selected or alerted Skills. It is not framed as an end-to-end malicious-Skill detector, and it is not intended for ecosystem-level prevalence estimation.

## What This Artifact Supports

- Benchmark v2 coverage and metric reporting.
- Rule-only vs Rule+EPG explanation comparison.
- Static screening vs chain-level explanation comparison.
- Real-world candidate-risk audit calibration.
- Case-level inspection of manifests, outputs, recovered chains, and audit notes.

## Directory Layout

```text
provloom_artifact/
README.txt
install.sh
use.txt
license.txt
CHECK_ANONYMITY.md
clean_for_submission.sh
artifact/
log8/
real_world_audit/
scripts/
claims/
```

- `artifact/log8/` contains the latest Benchmark v2 and baseline outputs.
- `artifact/real_world_audit/` contains anonymized high/critical audit materials.
- `artifact/scripts/` contains scripts to summarize or recompute tables.
- `claims/` contains claim-specific run scripts.

## Benchmark v2

Benchmark v2 in this artifact is manifest-defined with:

- 139 total cases.
- 100 malicious cases.
- 39 benign cases.

Evaluation scope:

- `static_only` evaluates all 139 cases.
- Dynamic baselines evaluate 115 runnable cases.
- 24 non-runnable malicious cases are skipped in dynamic evaluation.

Reported metrics include:

- endpoint accuracy
- edge-level F1
- complete-chain rate
- partial-chain usefulness
- root-cause accuracy
- false-positive rate
- latency

Scores should be interpreted as semantic chain-recovery performance under the artifact's evidence model, not as universal malicious-Skill detection performance.

## Real-World Audit

The real-world candidate-risk rerun is externally prefiltered and risk-focused. It is used for calibration, not as a random sample and not as a prevalence study.

High/critical audit outcomes include:

- confirmed malicious
- ambiguous / requires review
- benign / security-tool false positives

Instruction-derived chains should be interpreted as latent, document-supported evidence unless the corresponding behavior is directly observed in runtime telemetry.

## Quick Start

```bash
bash install.sh
bash claims/claim1_benchmark_chain_recovery/run.sh
bash claims/claim2_static_screening_vs_chain_explanation/run.sh
bash claims/claim3_real_world_audit_calibration/run.sh
```

## Anonymity

This artifact is prepared for double-blind review.

It should not contain:

- author names
- affiliations
- personal emails
- local absolute paths
- Git history
- private tokens
- non-anonymous repository URLs

Run the cleanup check before packaging:

```bash
./clean_for_submission.sh
```

## Limitations

- Not a prevention system.
- Not kernel-complete provenance.
- Not full marketplace scanning.
- Not complete supply-chain verification.
- Real-world audit is not a precision/recall or prevalence study.
- Some dynamic cases are skipped because they require unavailable credentials, external platforms, or nondeterministic LLM-mediated behavior.
