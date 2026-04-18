# Benchmark Plan

## Dataset Split

- `datasets/skills/benign/`: benign cases with real local or network behavior
- `datasets/skills/malicious/`: malicious cases with explicit benchmark targets
- `datasets/ground_truth/*.json`: one GT file per case

## Taxonomy

- Sensitive file exfiltration
- Direct sensitive exfiltration variants
- Command execution misuse
- Unauthorized external network transfer
- Indirect exfiltration via temp or buffer files
- LLM-induced unsafe tool invocation
- Prompt-injection-flavored unsafe action variants
- Hard benign file-plus-network cases with public-only data
- Hard benign relay chains with no sensitive source
- Hard benign legal shell-command cases
- Hard benign LLM-routed safe tool choices

## Ground Truth Structure

Each case defines:

- `case_id`
- `is_malicious`
- `expected_behaviors`
- `expected_source_nodes`
- `expected_sink_nodes`
- `expected_primary_chain`
- `expected_root_cause`
- `dynamic_runnable`
- optional `notes`

## Main Baselines

- `static_only`
- `rule_only`
- `rule_plus_epg`
- `epg_with_filtering`

`rule_plus_epg` is the unfiltered EPG baseline kept for continuity with the original artifact. `epg_with_filtering` adds a lightweight chain-export filter while preserving the same detection stage and metric definitions.

## Metric Definitions

- `detection_rate`: fraction of malicious cases whose expected behaviors are all detected
- `false_positive_rate`: fraction of benign cases predicted as malicious
- `endpoint_accuracy`: source and sink endpoints match GT
- `edge_level_f1`: F1 over consecutive chain edges
- `complete_chain_rate`: exact GT primary-chain match
- `partial_chain_usefulness`: predicted chain preserves GT source-to-sink direction
- `root_cause_accuracy`: malicious-case accuracy on fine-grained root-cause labels
- `avg_latency_ms`: average runtime per completed case

## Root Cause Labels

Implemented fine-grained labels:

- `unsafe_dataflow_design`
- `unsafe_command_construction`
- `llm_decision_induced_action`
- `overprivileged_tool_use`
- `unknown`
- `prompt_injection_suspected` for compatibility with the existing coarse label set

Coarse compatibility mapping:

- `unsafe_dataflow_design` -> `skill_design`
- `unsafe_command_construction` -> `skill_design`
- `overprivileged_tool_use` -> `skill_design`
- `llm_decision_induced_action` -> `llm_decision`
- `prompt_injection_suspected` -> `prompt_injection_suspected`
- `unknown` -> `unknown`

## Ablation Status

Implemented today:

- `static_only`
- `rule_only`
- `rule_plus_epg`
- `epg_with_filtering`

Methodological note:

- filtering only affects the exported explanation chain
- filtering does not change the detection rules
- root-cause outputs now include an evidence bundle with telemetry references, graph references, and tool or LLM references
