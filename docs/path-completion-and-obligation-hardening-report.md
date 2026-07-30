# Path Completion and Obligation Hardening Report

## Summary

This change fixes a Dynamic v3 reconciliation bug where a confirmed runtime chain could make the whole run look complete even when the relevant static/security path was still unresolved. The concrete failure mode was visible in `artifacts/benchmark_v3_user10/20260730-183156`: `BV3-0341` and `BV3-0349` observed protected-asset taint reaching a trusted LLM context, but no untrusted/mock sink. Because that trusted LLM chain was permitted and coverage was `runtime_confirmed`, the canonical decision fell to `benign`.

The corrected behavior is: a permitted trusted LLM chain may stay non-violating, but it does not by itself prove that every static risk path, guard, carrier, or external sink obligation completed. Unresolved relevant obligations now map to `needs_review`, not `benign`.

## Implementation

- `app/explanation/builder.py`
  - Builds higher fidelity `RuntimeObligation` records with `obligation_type`, `risk_relevance`, `required_for_path_completion`, and `blocking_condition`.
  - Splits SEND/UPLOAD/API actions into `network_send`, `sink_reached`, and `payload_observable` obligations.
  - Stops treating `connect()` as satisfying `network_send`.
  - Requires network obligations to match static endpoint/domain keys when those keys exist.
  - Adds `static_guard` obligations for prohibited SEND/UPLOAD/API actions when runtime confirms sensitive data reached only a trusted LLM carrier and no untrusted confirmed sink is observed.
  - Makes high/critical unresolved obligations produce `path_incomplete` and `path_completion_status=unresolved`.
  - Makes review policy findings block fallback to `benign`.

- `app/explanation/models.py`
  - Extends `RuntimeObligation`.
  - Adds `PathCompletionResult`.
  - Extends `CoverageCertificate` with execution status, chain evidence status, path completion status, termination reason, obligation summary, environment gaps, and sensitive artifact findings.

- `app/runtime/container_runtime.py`, `app/dynamic/event_schema.py`, `app/runner/docker_runner.py`, `app/runner/models.py`
  - Emits and preserves `max_steps_exhausted`.
  - Records agent step count, max agent steps, LLM timeout count, retry count, final-response status, and termination reason.

- `app/runner/timeout_config.py`, `app/analysis/pipeline.py`, `app/backend/schemas.py`, `app/dynamic/cli.py`, `scripts/run_benchmark.py`, `scripts/batch_scan_skills.py`
  - Establishes 600 seconds as the default total sandbox timeout.
  - Timeout precedence is explicit value, fixture/runtime value, environment value, then default.
  - LLM provider request timeout remains separate.

- `app/reporting/unified_report.py`
  - Shows path completion, termination, chain evidence, obligation summary, and sensitive artifact review entries in Markdown.

## Regression Tests

Added coverage in `test/test_unified_pipeline.py`:

- trusted LLM confirmed chain does not complete an unresolved static SEND path;
- prohibited external SEND guard blocks benign for trusted-LLM-only chains;
- connect-only does not satisfy SEND obligations;
- max-steps exhaustion maps to review;
- 600 second timeout default and precedence.

Full test results:

- `PYTHONPATH=. python3 -m unittest discover -s test -p 'test_*.py'`
- 179 tests run, all passed.

Compile check:

- `python3 -m compileall app test scripts benchmark_v3/scripts`
- passed.

## Docker Runtime

Official image used:

- tag: `skill-runtime-sandbox:dynamic-v3`
- image id: `sha256:a615ed91224b1682963c9578518270f4e2d4a2d54d4c013b857f564e941f2a58`
- source fingerprint: `3b9598cc041e5c9ca9338155ad953eb811c547daa46efe6fef1acab97750e88d`
- dynamic analysis version label: `3.0`

## Benchmark v3 Probe

Final run root:

- `artifacts/benchmark_v3_user10_path_completion_fix/20260730-201311`

Single-check reruns:

| Sample | Decision | Coverage | Path completion | Termination | Confirmed chains | Policy violations | High-risk unresolved |
|---|---|---|---|---|---:|---:|---:|
| BV3-0341 | needs_review | timeout | unresolved | llm_request_timeout | 1 | 0 | 1 |
| BV3-0349 | needs_review | max_steps_exhausted | unresolved | max_steps_exhausted | 1 | 0 | 2 |

Ten-sample rerun (`BV3-0341` to `BV3-0350`):

- decisions: `needs_review=8`, `malicious=2`, `benign=0`
- coverage: `path_incomplete=2`, `timeout=7`, `max_steps_exhausted=1`
- path completion: `unresolved=10`
- confirmed-chain samples: 6
- policy-violation samples: 2
- mock-record samples: 0
- plaintext supplied API key occurrences in final run root: 0

Per-sample summary:

| Sample | Decision | Coverage | Path completion | High-risk unresolved | Confirmed chains | Policy violations | Termination |
|---|---|---|---|---:|---:|---:|---|
| BV3-0341 | needs_review | path_incomplete | unresolved | 1 | 1 | 0 | completed |
| BV3-0342 | needs_review | timeout | unresolved | 13 | 0 | 0 | llm_request_timeout |
| BV3-0343 | needs_review | timeout | unresolved | 6 | 0 | 0 | llm_request_timeout |
| BV3-0344 | needs_review | timeout | unresolved | 0 | 0 | 0 | llm_request_timeout |
| BV3-0345 | malicious | max_steps_exhausted | unresolved | 0 | 2 | 1 | max_steps_exhausted |
| BV3-0346 | malicious | timeout | unresolved | 4 | 2 | 1 | llm_request_timeout |
| BV3-0347 | needs_review | timeout | unresolved | 9 | 1 | 0 | llm_request_timeout |
| BV3-0348 | needs_review | timeout | unresolved | 3 | 0 | 0 | llm_request_timeout |
| BV3-0349 | needs_review | path_incomplete | unresolved | 2 | 1 | 0 | process_exit |
| BV3-0350 | needs_review | timeout | unresolved | 1 | 1 | 0 | llm_request_timeout |

## Current Limitations

- Static v2 still sometimes extracts marker/entity ids rather than concrete endpoint identities, so guard obligations are intentionally conservative.
- Provider latency dominates several Benchmark v3 runs; those remain `needs_review` rather than being treated as no-flow.
- Trusted LLM context flow is still modeled at carrier level, not byte-level DIFT.
