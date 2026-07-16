# Real-World GT Audit Summary Tables

All figures below are code-generated from `/mnt/e/log7` plus the deterministic sampled audit set. These are descriptive counts only. They are not accuracy, precision, or recall claims.

## Corpus Boundary

| Field | Value |
| --- | ---: |
| Scheduled executions | 617 |
| Completed executions | 465 |
| Skipped executions | 152 |
| Failed executions | 0 |
| Target sample size | 96 |
| Actual sampled cases | 96 |

## Completed Cases by Stratum

| Stratum | Completed Cases | Sampled Cases |
| --- | ---: | ---: |
| `suspected_benign_fp_note_report_inventory` | 5 | 5 |
| `upload_or_mirror_outward` | 27 | 24 |
| `chain_backed_critical` | 140 | 20 |
| `llm_decision_heavy` | 39 | 20 |
| `representative_low_risk` | 8 | 8 |
| `partial_evidence_medium` | 246 | 19 |

## Provisional Machine-Assisted Label Distribution

| Label | Count |
| --- | ---: |
| `malicious` | 3 |
| `benign` | 13 |
| `ambiguous` | 80 |

## Provisional Chain-Validity Distribution

| `gt_chain_valid` | Count |
| --- | ---: |
| `true` | 3 |
| `false` | 19 |
| `unknown` | 74 |

## Confidence Distribution

| Confidence | Count |
| --- | ---: |
| `high` | 11 |
| `medium` | 46 |
| `low` | 39 |

## Sampled Mechanism-Class Distribution

| Mechanism Class | Count |
| --- | ---: |
| `ambiguous_connected_workflow` | 41 |
| `overprivileged_external_transfer` | 21 |
| `unsafe_command_construction` | 18 |
| `unsafe_dataflow_design` | 16 |

## Endpoint Evidence in Sampled Cases

| Endpoint Bucket | Count |
| --- | ---: |
| Cases with any endpoint evidence | 96 |
| Cases with non-LLM endpoint evidence | 20 |
| Cases with only LLM-provider or unresolved endpoint evidence | 76 |

## Paper-Ready Note

This table set describes a sampled manual-audit layer over the completed `/mnt/e/log7` executions. It should be cited as a reproducible completed-subset audit pack, not as a full real-world correctness benchmark.