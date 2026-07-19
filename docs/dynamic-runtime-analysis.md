# Dynamic Runtime Analysis Migration Note

ProvLoom dynamic analysis is an evidence-bounded runtime provenance system. It reports review evidence, coverage, and provenance chains; it does not make a final malicious/benign truth claim.

## Architecture

Runtime telemetry is normalized into `RuntimeEvent` records with stable event IDs, actor/object fields, operation, taint IDs, evidence level, raw source, and raw reference. Existing Docker sandbox, strace logs, runtime wrapper events, endpoint resolution, and legacy EPG exports remain available. The new runtime layer adds marker-aware taint propagation, Runtime Provenance Graph (RPG), deterministic chain recovery, policy evidence, and coverage analysis.

Flow:

`Synthetic marker sources -> runtime/tool/strace events -> RuntimeEvent -> taint propagation -> Runtime Provenance Graph -> deterministic ChainRecovery -> policy/coverage/explanation`

## Evidence Levels

- `confirmed`: direct marker or marker variant appears in a payload/value, a tainted file is explicitly uploaded, or a structured tool/file/pipe relation proves propagation.
- `conservative`: provenance is continuous but an opaque transformation prevents byte-level confirmation.
- `candidate`: behavior is suspicious or temporally related, such as sensitive read followed by connect, but payload/file/tool propagation is missing.

`connect()` alone never creates confirmed exfiltration.

## Coverage States

Supported states are `triggered_and_observed`, `triggered_but_partially_observed`, `instruction_seen_but_not_executed`, `not_triggered`, `unsupported_tool`, `unsupported_environment`, `external_state_missing`, `user_confirmation_missing`, `endpoint_unavailable`, `execution_failed`, `timeout`, and `analysis_error`.

## CLI

Use the module entry point in this repository:

```bash
python -m provloom dynamic run <skill_path> --config configs/dynamic-analysis.example.json
python -m provloom dynamic trace <run_id>
python -m provloom dynamic graph <run_id>
python -m provloom dynamic explain <run_id>
python -m provloom dynamic validate-config --config configs/dynamic-analysis.example.json
python -m provloom dynamic export <run_id> --format json
python -m provloom dynamic export <run_id> --format md
```

When packaged with a console entry point, the equivalent command is `provloom dynamic ...`.

## Artifacts

Dynamic runs write:

- `runtime-events-v2.jsonl`
- `runtime-provenance-graph.json`
- `runtime-chains.json`
- `dynamic-analysis.json`

Legacy `normalized-events.jsonl`, `epg.json`, and `attack-chain.json` are retained for compatibility.

## Runtime Instruction Lift

When enabled, files materialized under the Skill root with configured instruction extensions are registered as `RuntimeInstruction` artifacts. The lift adapter enforces max depth, max files, max file size, closure containment, and duplicate hash suppression. Generated text is untrusted content, not a system instruction.

## Current Boundaries

This implementation does not provide CPU instruction-level taint, byte-level memory DIFT, implicit control-flow taint, or whole-system eBPF/FUSE capture. Adapter interfaces and event schemas are structured so eBPF/FUSE backends can later emit the same `RuntimeEvent` schema.
