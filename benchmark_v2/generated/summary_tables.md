# benchmark_v2 Summary Tables

All counts below are `manifest-derived` from `benchmark_v2/generated/benchmark_v2_manifest.json`.

## Family Summary

| Family | Cases |
| --- | ---: |
| `direct_sensitive_exfiltration` | 16 |
| `hard_benign_note_report_inventory` | 29 |
| `llm_induced_unsafe_action` | 12 |
| `mixed_multi_hop_flow` | 12 |
| `policy_benign_but_suspicious` | 14 |
| `staged_or_relay_exfiltration` | 36 |
| `unauthorized_external_transfer` | 16 |
| `unsafe_command_construction` | 12 |

## Malicious / Benign Split

| Polarity | Cases |
| --- | ---: |
| `benign` | 43 |
| `malicious` | 104 |

## Dynamic-Runnable Coverage

| Evaluation Status | Cases |
| --- | ---: |
| `dynamic_runnable` | 123 |
| `partially_stubbed` | 12 |
| `static_evaluable` | 12 |

## Lookalike Pair Summary

| Pair Groups | Count |
| --- | ---: |
| `lookalike_group_id` groups | 16 |
| Malicious members | 16 |
| Benign members | 16 |

## Hard Benign Subtype Summary

| Camouflage Style | Cases |
| --- | ---: |
| `audit` | 6 |
| `export` | 2 |
| `helper` | 3 |
| `inventory` | 4 |
| `mirror` | 5 |
| `note` | 4 |
| `report` | 5 |