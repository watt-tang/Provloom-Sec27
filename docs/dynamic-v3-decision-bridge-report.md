# Dynamic v3 Decision Bridge Implementation Report

## Root Cause

The E2E untrusted JSON body probe produced a confirmed Dynamic v3 confidentiality chain and a Dynamic v3 policy violation, but `app.analyzer.rules.analyze_trace` wrote legacy `risk_score` and `final_decision` after attaching Dynamic v3 details. The legacy risk engine in `app.analyzer.decision_engine` and `app.analyzer.risk_scoring` does not consume `DynamicAnalysisResult.policy_violations`, so the top-level report could remain `0 / benign` even when `runtime_policy_violations` was non-empty.

## Files Changed

- `app/dynamic/assessment.py`: adds `CanonicalAssessment`, canonical mapping, consistency validation, and legacy-compatible report application.
- `app/analyzer/rules.py`: applies canonical Dynamic v3 after legacy scoring, preserving legacy fields while making top-level fields canonical.
- `app/dynamic/analyzer.py`: persists canonical assessment fields in `dynamic-analysis.json`.
- `app/backend/api.py` and `app/backend/schemas.py`: expose canonical and legacy fields through API responses.
- `app/telemetry/collector.py`: emits canonical fields for collector-built execution reports and uses `SourceRegistry` for confidential-source hints.
- `app/runtime/container_runtime.py`: records privacy-preserving tainted LLM context metadata before LLM requests.
- `app/dynamic/event_schema.py`: normalizes tainted LLM request metadata into `llm_request` RuntimeEvents.
- `app/dynamic/chain_recovery.py`, `app/dynamic/graph.py`, `app/dynamic/propagation.py`, and `app/dynamic/policy.py`: treat `llm_context` as a concrete carrier, reject endpoint-only process-context candidates, and permit configured trusted LLM providers.
- `app/dynamic/config.py`: adds trusted SiliconFlow LLM provider defaults for the current probe environment.
- `app/taint/source_registry.py` and `app/taint/propagation.py`: distinguish public/low/confidential source sensitivity, exclude `/etc/hosts` from default high-sensitive sources, and include `.provloom/private/**` as private input.
- `test/test_dynamic_canonical_assessment.py` and `test/test_dynamic_runtime_analysis_v3.py`: add regression coverage for canonical decisions, LLM context telemetry, trusted service flows, and candidate pollution.
- `docs/dynamic-analysis-v3.md`: documents the decision bridge, LLM carrier, privacy contract, trusted LLM policy, and candidate tightening.

## Canonical Decision Mapping

| Dynamic v3 condition | Canonical status | Top-level decision | Risk score |
|---|---|---|---|
| `policy_violation_count > 0` | `violation_confirmed` | `malicious` | `80` |
| candidate chain or instrumentation gap | `review_required` | `needs_review` | `30` |
| timeout/crash/missing source/path/sink/env without confirmed violation | `execution_incomplete` | `needs_review` | `30` |
| completed no-flow or permitted confirmed flow with no violation | `no_violation_observed` | `benign` | `0` |

Legacy outputs are retained as `legacy_risk_score` and `legacy_final_decision`. The unprefixed `risk_score` and `final_decision` are canonical Dynamic v3 compatibility values.

## LLM Telemetry and Privacy

The runtime records tainted LLM context as structured metadata before the HTTP request is sent. It only stores taint ids, role, carrier location, content hash, byte count, provider/model/endpoint metadata, and redacted structural previews. It does not persist full prompts, plaintext secrets, or API keys.

`llm_context` is now a confirmed carrier when the runtime has structured taint metadata tying a tainted tool result to `messages[i].content`. Trusted configured LLM providers can carry a confirmed but permitted service flow; untrusted providers are evaluated as normal network sinks.

Tainted runtime previews are redacted at event serialization boundaries. Tainted tool stdout, LLM response previews, HTTP request configs, syscall payload previews, and raw syscall strings are represented with byte counts and SHA-256 hashes instead of plaintext. Internal propagation still uses raw in-memory values before serialization.

`DockerRunner` also scrubs marker/API-key-shaped strings from `trace.log*` after parsing, so raw strace artifacts do not retain synthetic marker plaintext after analysis.

## Candidate Pollution Fix

Candidate recovery no longer treats `process_context + endpoint_only` as enough evidence for a confidentiality candidate. At least one source-related carrier must exist. `/etc/hosts` is no longer a default high-sensitivity source, while `.provloom/private/**`, credential adapter state, `/etc/shadow`, `/root/**`, `/proc/**`, `/sys/**`, and `/var/run/**` remain confidential defaults.

## Tests

Final run in this workspace:

- `python3 -m unittest discover -s test -p 'test_dynamic*.py'`: 49 tests, 0 failures, 0 skipped.
- `python3 -m unittest discover -s test -p 'test_trace_parser*.py'`: 1 test, 0 failures, 0 skipped.
- `python3 -m unittest discover -s test -p 'test_adapter_layer.py'`: 5 tests, 0 failures, 0 skipped.
- `python3 -m unittest discover -s test -p 'test_trigger_synthesis.py'`: 5 tests, 0 failures, 0 skipped.
- `python3 -m unittest discover -s test -p 'test_static_v2*.py'`: 0 tests matched, command completed successfully.
- `python3 -m compileall app test`: completed successfully.

## Carrier Probe Rerun

Final E2E rerun output:

`artifacts/runs/dynamic-carrier-probes/carrier-probe-post-decision-fix-rollup.json`

The final rerun used source-mounted runtime code because rebuilding `skill-runtime-sandbox:latest` did not complete in this environment. The container still ran under Docker with strace and the same skill inputs.

| Case | Expected chain | Expected policy | Expected canonical result |
|---|---|---|---|
| secret read, not in prompt | none | `0` | `no_violation_observed` |
| marker enters trusted LLM prompt | confirmed `llm_context` trusted flow | `0` | `no_violation_observed` |
| trusted Authorization header | confirmed `http_header` authentication | `0` | `no_violation_observed` |
| untrusted JSON body | confirmed `http_body` confidentiality | `1` | `violation_confirmed` |

Final run ids:

- `secret_read_no_llm_prompt`: `dynamic-carrier-secret_read_no_llm_prompt-postfix-srcmount-d06194d4`
- `secret_marker_into_llm_prompt`: `dynamic-carrier-secret_marker_into_llm_prompt-postfix-srcmount-d1e40795`
- `secret_trusted_authorization_header`: `dynamic-carrier-secret_trusted_authorization_header-postfix-srcmount-1eb22739`
- `secret_untrusted_json_body`: `dynamic-carrier-secret_untrusted_json_body-postfix-srcmount-b8e5968c`

All four had `exit_code=0`, `consistency_status=ok`, and `plaintext_stored=false` for tainted report/runtime-event fields. A final marker scan of the four run directories found no marker plaintext in JSON/JSONL artifacts or raw trace files. The untrusted JSON body probe now reports `policy_violation_count=1`, `risk_score=80`, and `final_decision=malicious`.

## Remaining Limits

This change does not add eBPF, FUSE symbolic reads, TLS MITM, byte-level DIFT, in-process Python value tracking, compression/encryption reversal, or recursive real Agent execution for runtime-generated instructions. Encrypted payload visibility still requires wrapper-level structured HTTP metadata or plaintext syscall previews.
