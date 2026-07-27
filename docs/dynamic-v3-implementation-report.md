# Dynamic v3 Implementation Report

## Modified Files

- `app/dynamic/models.py`
- `app/dynamic/event_schema.py`
- `app/dynamic/marker_registry.py`
- `app/dynamic/propagation.py`
- `app/dynamic/graph.py`
- `app/dynamic/chain_recovery.py`
- `app/dynamic/coverage.py`
- `app/dynamic/policy.py`
- `app/dynamic/analyzer.py`
- `app/dynamic/alignment.py`
- `app/dynamic/closure_lift.py`
- `app/dynamic/config.py`
- `app/runtime/container_runtime.py`
- `app/runner/models.py`
- `app/runner/trace_parser.py`
- `app/telemetry/normalizer.py`
- `app/telemetry/collector.py`
- `app/taint/propagation.py`
- `app/taint/sink_tracker.py`
- `app/analyzer/rules.py`
- `app/backend/api.py`
- `app/backend/schemas.py`
- `app/instruction/orchestrator.py`
- `test/test_dynamic_runtime_analysis_v2.py`
- `test/test_dynamic_runtime_analysis_v3.py`
- `test/test_trace_parser_network_resolution.py`

## Key Implementation

Dynamic canonical analysis is now reused across API, CLI, `analyze_trace`, and telemetry report generation. `DynamicRuntimeAnalyzer.analyze_execution()` accepts optional normalized events so callers can normalize once and analyze once.

Runtime events, edges, and chains now carry evidence strength, observation source, carrier type/location, hash-derived status, instrumentation visibility, raw references, transformations, and instrumentation gaps.

Taint propagation now separates concrete taint from process context. Concrete taint comes from marker observations, reversible encodings, structured tool references, file copy/rename, and explicit tainted file upload. Process read-before-output, opaque payload, and temporal read-before-connect are candidate/context evidence only.

The provenance graph now inserts carrier-aware `DataObject` nodes and prevents multi-carrier edge merging.

Chain recovery now emits canonical v3 chain types. Confirmed confidentiality requires concrete source-to-carrier-to-sink evidence and rejects connect-only, process-context-only, hash-only, instruction-simulation-only, or instrumentation-gap paths.

Coverage now distinguishes runtime confirmed, target reached no flow, path not triggered, environment missing, instrumentation gap, execution failed, timeout, unsupported operation, and insufficient coverage.

Policy evaluation only treats `confidentiality_confirmed` as a confidentiality violation candidate. Trusted auth headers, hash-derived flows, process context, and connect-only chains are not raw secret exfiltration.

Runtime instruction lift is explicitly labeled `instruction_simulation`; it is not real Agent re-execution and cannot close confirmed chains.

Static-runtime alignment now emits a runtime-only certificate by default and can align against provided static artifacts by normalized path/domain/tool/action keys.

## Schema Changes

`schema_version` is now `runtime-analysis-v3`. Old event JSON remains loadable via `RuntimeEvent.from_dict()`.

New event fields:

- `evidence_strength`
- `observation_source`
- `carrier_type`
- `carrier_location`
- `derived_from_hash`
- `instrumentation_visibility`
- `raw_event_id`
- `trace_file`
- `trace_line`

New chain fields:

- `evidence_strengths`
- `raw_references`
- `transformations`
- `instrumentation_gaps`
- `confidence`
- `minimality_score`
- `metadata.minimal_witness`

## Tests

Baseline before modification:

- `python3 -m unittest discover -s test -p 'test_dynamic*.py'`: 30 passed
- `python3 -m unittest discover -s test -p 'test_trace_parser_network_resolution.py'`: 1 passed
- `python3 -m unittest discover -s test -p 'test_adapter_layer.py'`: 5 passed
- `python3 -m unittest discover -s test -p 'test_trigger_synthesis.py'`: 5 passed

Final verification:

- `python3 -m unittest discover -s test -p 'test_dynamic*.py'`: 38 passed
- `python3 -m unittest discover -s test -p 'test_trace_parser_network_resolution.py'`: 1 passed
- `python3 -m unittest discover -s test -p 'test_adapter_layer.py'`: 5 passed
- `python3 -m unittest discover -s test -p 'test_trigger_synthesis.py'`: 5 passed
- `python3 -m unittest discover -s test -p 'test_static_analysis_v2.py'`: 53 passed
- `python3 -m compileall app test`: passed

Docker/e2e tests were executed in the final validation round with the official image `skill-runtime-sandbox:dynamic-v3`.

## Compatibility

Old report fields such as `runtime_events_v2`, `runtime_chains`, `runtime_coverage`, `runtime_policy_violations`, and legacy coverage names remain available. Legacy coverage names are preserved in `coverage.metadata.legacy_coverage_state`.

Legacy chain names are preserved in `chain.metadata.legacy_chain_type`, while canonical decisions use v3 `chain_type`.

## Remaining Limitations

- No eBPF or FUSE symbolic reads.
- No TLS MITM; HTTPS payload is visible only through wrapper-level structure or plaintext before encryption.
- No byte-level in-process DIFT.
- No true recursive Agent re-execution for generated instructions.
- Compression/encryption reversal and split-across-events marker reconstruction remain unsupported.

## Next Steps

1. Add Docker e2e tests with local mock HTTP sink, curl HTTP/HTTPS, subprocess writes, file upload, timeout, and unavailable endpoint.
2. Reduce static-runtime alignment noise from interpreter/library runtime-only nodes.
3. Persist raw trace file and line numbers from trace parser into `RuntimeEvent.trace_file` and `trace_line`.
4. Add stronger artifact identity checks for download-execute chains.
5. Replace legacy EPG augmentation as a decision input with canonical v3 chain summaries.

## Official-Image Final E2E

Earlier source-mounted E2E results were preliminary only. Final validation used the rebuilt official image:

- Image: `skill-runtime-sandbox:dynamic-v3`
- Image id: `sha256:b8f114fa58cfe522a45c5e07d0b86bb53a15de1d8a301f983e21e849dcbcaabb`
- Fingerprint: `71c962d5de631e79d96696cd503ef9f2f088ebc4090fd3386edee0e2f0196178`
- Source-mounted runtime: false

Final carrier probes:

- `secret_read_no_llm_prompt`: no flow, benign
- `secret_marker_into_llm_prompt`: confirmed trusted `llm_context`, benign
- `secret_trusted_authorization_header`: confirmed trusted `http_header`, benign
- `secret_untrusted_json_body`: confirmed untrusted `http_body`, malicious

Static v2 result is now passed into API, CLI, telemetry/report, and Dynamic alignment. `unified_explanation` is emitted alongside raw static and dynamic artifacts.
