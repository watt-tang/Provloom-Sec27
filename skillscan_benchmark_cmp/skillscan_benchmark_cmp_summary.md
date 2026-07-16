# SkillScan Benchmark v2 Comparison

## Setup

- SkillScan code: `/root/projects/ProvLoom/skillscan`
- Static backend: `skill-security-scan==1.0.0` from `/root/projects/ProvLoom/skillscan/.venv/lib/python3.10/site-packages`
- Rules: `/root/projects/ProvLoom/skillscan_results/skillscan_rules.yaml`
- Benchmark manifest: `/root/projects/ProvLoom/benchmark_v2/generated/benchmark_v2_manifest.json`
- Cases scanned: 147
- Successful scans: 147
- Failed scans: 0
- Outputs:
  - Per-case JSON: `/root/projects/ProvLoom/skillscan_benchmark_cmp/per_case_reports`
  - JSONL: `/root/projects/ProvLoom/skillscan_benchmark_cmp/skillscan_benchmark_results.jsonl`
  - CSV: `/root/projects/ProvLoom/skillscan_benchmark_cmp/skillscan_benchmark_results.csv`
  - Metrics: `/root/projects/ProvLoom/skillscan_benchmark_cmp/skillscan_benchmark_metrics.json`
  - Raw log: `/root/projects/ProvLoom/skillscan_benchmark_cmp/raw_output.txt`

Actual command:

```bash
cd /root/projects/ProvLoom
source /root/projects/ProvLoom/skillscan/.venv/bin/activate
python /root/projects/ProvLoom/skillscan_benchmark_cmp/run_skillscan_benchmark_cmp.py
```

## Main Binary Comparison

Two comparison policies are reported:

- `any_hit`: any static rule hit means the case is flagged.
- `risk_level`: only `risk_level != SAFE` means the case is flagged.

### Risk-Level Policy

| TP | FP | FN | TN | Precision | Recall | Specificity | Accuracy | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 104 | 43 | 0.0% | 0.0% | 100.0% | 29.3% | 0.0% |

### Any-Hit Policy

| TP | FP | FN | TN | Precision | Recall | Specificity | Accuracy | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 96 | 22 | 8 | 21 | 81.4% | 92.3% | 48.8% | 79.6% | 86.5% |

## Distribution

- Ground truth: {'malicious': 104, 'benign': 43}
- SkillScan risk levels: {'SAFE': 147}
- Rule hit counts: {'NET001': 114, 'CMD001': 4}
- Risk-level false positives: 0
- Risk-level false negatives: 104
- Any-hit false positives: 22
- Any-hit false negatives: 8

## By Family, Risk-Level Policy

| Family | N | Mal | Benign | TP | FP | FN | TN | Recall | Specificity | Risk levels |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| direct_sensitive_exfiltration | 16 | 16 | 0 | 0 | 0 | 16 | 0 | 0.0% | 0.0% | {'SAFE': 16} |
| hard_benign_note_report_inventory | 29 | 0 | 29 | 0 | 0 | 0 | 29 | 0.0% | 100.0% | {'SAFE': 29} |
| llm_induced_unsafe_action | 12 | 12 | 0 | 0 | 0 | 12 | 0 | 0.0% | 0.0% | {'SAFE': 12} |
| mixed_multi_hop_flow | 12 | 12 | 0 | 0 | 0 | 12 | 0 | 0.0% | 0.0% | {'SAFE': 12} |
| policy_benign_but_suspicious | 14 | 0 | 14 | 0 | 0 | 0 | 14 | 0.0% | 100.0% | {'SAFE': 14} |
| staged_or_relay_exfiltration | 36 | 36 | 0 | 0 | 0 | 36 | 0 | 0.0% | 0.0% | {'SAFE': 36} |
| unauthorized_external_transfer | 16 | 16 | 0 | 0 | 0 | 16 | 0 | 0.0% | 0.0% | {'SAFE': 16} |
| unsafe_command_construction | 12 | 12 | 0 | 0 | 0 | 12 | 0 | 0.0% | 0.0% | {'SAFE': 12} |

## By Family, Any-Hit Policy

| Family | N | Mal | Benign | TP | FP | FN | TN | Recall | Specificity | Total issues |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| direct_sensitive_exfiltration | 16 | 16 | 0 | 16 | 0 | 0 | 0 | 100.0% | 0.0% | 16 |
| hard_benign_note_report_inventory | 29 | 0 | 29 | 0 | 8 | 0 | 21 | 0.0% | 72.4% | 8 |
| llm_induced_unsafe_action | 12 | 12 | 0 | 12 | 0 | 0 | 0 | 100.0% | 0.0% | 12 |
| mixed_multi_hop_flow | 12 | 12 | 0 | 12 | 0 | 0 | 0 | 100.0% | 0.0% | 12 |
| policy_benign_but_suspicious | 14 | 0 | 14 | 0 | 14 | 0 | 0 | 0.0% | 0.0% | 14 |
| staged_or_relay_exfiltration | 36 | 36 | 0 | 36 | 0 | 0 | 0 | 100.0% | 0.0% | 36 |
| unauthorized_external_transfer | 16 | 16 | 0 | 16 | 0 | 0 | 0 | 100.0% | 0.0% | 16 |
| unsafe_command_construction | 12 | 12 | 0 | 4 | 0 | 8 | 0 | 33.3% | 0.0% | 4 |

## Representative Cases

| Case | GT | Family | Risk | Issues | Evidence |
| --- | --- | --- | --- | --- | --- |
| v2_direct_note_passwd | malicious | direct_sensitive_exfiltration | SAFE | 1 | `NET001` `SKILL.md:24` `"url": "https://httpbin.org/post",` |
| v2_direct_report_hostname | malicious | direct_sensitive_exfiltration | SAFE | 1 | `NET001` `SKILL.md:24` `"url": "https://httpbin.org/post",` |
| v2_direct_export_group | malicious | direct_sensitive_exfiltration | SAFE | 1 | `NET001` `SKILL.md:24` `"url": "https://httpbin.org/post",` |
| v2_direct_mirror_os_release | malicious | direct_sensitive_exfiltration | SAFE | 1 | `NET001` `SKILL.md:24` `"url": "https://httpbin.org/post",` |
| v2_direct_report_passwd | malicious | direct_sensitive_exfiltration | SAFE | 1 | `NET001` `SKILL.md:24` `"url": "https://httpbin.org/post",` |

## Interpretation for ProvLoom Comparison

SkillScan is useful as a static screening baseline: under the `any_hit` policy it catches visible URL and command indicators in benchmark Skill instructions. Its own risk-score threshold is conservative on this synthetic v2 suite: all cases remain `SAFE` because most cases contain only one static indicator line.

The comparison also exposes the expected limitation: benign lookalikes and policy-approved upload/relay cases can still be flagged because static scanning sees URLs, local file actions, and command-like strings without proving a closed source-relay-sink provenance chain.

ProvLoom should be compared as a provenance explanation system rather than merely a higher/lower detector: its key advantage is distinguishing observed runtime chains, instruction-derived latent chains, hybrid evidence, and no-closed-chain cases.
