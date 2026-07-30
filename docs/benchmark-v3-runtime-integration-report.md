# Benchmark v3 Runtime Integration Report

Date: 2026-07-30

## Executive Summary

This change integrates Benchmark v3 replay with the current ProvLoom dynamic runtime without modifying Benchmark v3 samples, labels, splits, fixtures, or ground truth. The analyzer consumes only public execution inputs: fixture sandbox files, protected asset classification, mock service configuration, required commands, environment, trigger input, and timeout profile. Ground truth files are not loaded by the replay adapter or analyzer.

Stage A canary did not meet the required gate for running stratified40/development. A full 12-sample development canary completed, but only 2 of 6 confirmed-violation canaries produced complete policy-violating source-to-sink chains. Therefore Stage B and Stage C were intentionally not run.

## First 100 Failure Roots

The first 100 run at `artifacts/benchmark_v3_first100_full_system/20260730-004929/` produced 100 artifacts but 0 confirmed violations. The observed root causes were:

| Failure type | Execution cause | Observation available | Missing capability | Fix implemented |
|---|---|---|---|---|
| Localhost mock refused | Benchmark endpoints were `localhost:<port>` inside the skill container, but no same-container service was started | HTTP connection failure, no receipt | In-container fixture mock service | `app/runner/fixture_mock_server.py`, `app/runner/fixture_orchestrator.py`, Docker runner startup |
| Synthetic secret untainted | Fixture files were not registered as protected runtime sources | File/tool reads existed but `taint_ids` empty | Fixture protected asset registration and value variants | `app/taint/source_registry.py`, `app/dynamic/marker_registry.py`, `app/dynamic/propagation.py` |
| Missing tools | Sandbox lacked `git` and common shell utilities | exit 127 / tool failure | Official image dependency set and preflight metadata | `docker/sandbox/Dockerfile`, `app/dynamic/coverage.py` |
| Timeout ambiguity | exit 143/long model calls collapsed into generic failure | exit code only | termination metadata and LLM error telemetry | `app/runner/docker_runner.py`, `app/runtime/llm_client.py`, `app/runtime/container_runtime.py` |
| False contradictions | Execution-incomplete runs still emitted endpoint contradictions | contradictions with no confirmed runtime chain | coverage-aware contradiction suppression | `app/dynamic/alignment.py` |

## Fixture Orchestration

Implemented `FixtureOrchestrator` in `app/runner/fixture_orchestrator.py`.

Capabilities:

- Materializes fixture sandbox files/directories into the mounted skill workspace.
- Registers fixture protected assets into `protected-assets.json`.
- Writes mock service config into `fixture-runtime.json`.
- Writes required command metadata into `required-commands.json`.
- Collects mock service receipts and fixture-created mutations.
- Copies all public files from a Benchmark sample directory into the replay bundle, including nested reference files. It does not read `ground_truth_private`.

The replay adapter is in `app/benchmark/replay_adapter.py`. It records `ground_truth_loaded_by_analyzer: false` and omits expected verdict, expected chain, expected sink, expected carrier, and ground truth from analyzer input.

## Mock Service Architecture

Implemented `app/runner/fixture_mock_server.py`.

The mock service runs inside the same Docker container as the skill, so `http://localhost:<port>/...` resolves correctly for Benchmark fixtures. It supports GET, POST, PUT, PATCH, DELETE, query strings, headers, raw body, form-like bodies, and multipart filename extraction. Receipts are written under `/artifacts/mock-services/`.

The receipt records method, host, port, path, query keys, header names, body length, body SHA-256, uploaded filenames, response status, and privacy metadata. It does not store full request body, full API keys, or full synthetic secret plaintext.

## Protected Asset Registration

`SourceRegistry` now loads fixture protected assets from `PROVLOOM_FIXTURE_PROTECTED_ASSETS` or an artifacts path. Fixture assets take precedence over broad system rules and preserve sensitivity/category/matcher metadata.

Registered value variants include raw, Base64, Hex, URL-encoded, and JSON-escaped forms. These variants are registered into `TaintRegistry` so wrapper-observed tool results, LLM context, and HTTP payloads can be carrier-scanned without process-level overtaint.

## Carrier Propagation

Implemented or fixed:

- file read to tool output taint
- protected value variants to HTTP JSON/body matching
- LLM tool result to later LLM context
- LLM-context taint to subsequent tool call arguments
- tool input taint to tool output
- mock receipt to strong `network_send` evidence
- post-confirmation failures no longer erase confirmed chains

Still incomplete:

- download to execute artifact identity is only partially modeled
- reverse-shell/remote-control behavior is not yet recovered as a policy violation
- review-coverage samples can still collapse to benign when only trusted LLM context is observed
- contradiction suppression is improved but old canary artifacts still show residual contradictions in incomplete runs

## Sandbox Dependency and Image

Official image: `skill-runtime-sandbox:dynamic-v3`

Final rebuilt image:

- image id: `sha256:d22c915dbb08d548940165680f57c0c0979fe677c413ae7b501c373915d183c9`
- source fingerprint: `df62fa3f3dd2fee11cedf6ec2fa9558447141d8b88e4d6775bc66b4b32ec1ccd`
- build timestamp: `2026-07-30T09:59:52Z`

Installed tool smoke:

- git 2.47.3
- curl 8.14.1
- wget 1.25.0
- tar 1.35
- gzip 1.13
- unzip 6.00
- jq 1.7.1
- coreutils 9.7
- Python 3.10.20

## Timeout and LLM Failure Handling

`OpenAICompatibleClient` now normalizes socket/URL timeouts into a RuntimeError. `LLMAgentSkillRuntime` catches LLM request failures, emits a privacy-preserving `llm:error` event, and returns exit 70 without a traceback. `RuntimeEventFactory` converts this into `llm_error`; `CoverageAnalyzer` maps provider timeout to `timeout` and other provider request failure to `environment_missing`.

Smoke result:

- artifacts: `artifacts/benchmark_v3_canary/smoke_llm_redaction/llm-redaction-smoke`
- coverage: `environment_missing`
- `llm_error_events`: 1
- public `llm-config.json` API key: `***redacted***`
- stderr traceback: false

## Canary Results

Full 12-sample development canary:

- run root: `artifacts/benchmark_v3_canary/20260730-173024`
- replay success: 12/12
- expected outcomes: 6 confirmed_violation, 2 benign_lookalike, 2 trusted_allowed, 2 review_coverage
- decisions: 2 malicious, 4 needs_review, 6 benign
- coverage: 8 runtime_confirmed, 4 execution_failed
- confirmed-violation malicious recall: 2/6
- complete-chain confirmed-violation recall: 2/6
- benign false violation: 0/2
- trusted false violation: 0/2
- exact provided API key hits: 0 after artifact redaction

Per-sample summary:

| sample | expected | decision | coverage | chains | violations | mock receipts |
|---|---|---|---|---:|---:|---:|
| BV3-0342 | confirmed_violation | needs_review | execution_failed | 0 | 0 | 0 |
| BV3-0343 | confirmed_violation | malicious | runtime_confirmed | 2 | 1 | 1 |
| BV3-0344 | confirmed_violation | malicious | runtime_confirmed | 2 | 1 | 1 |
| BV3-0345 | confirmed_violation | needs_review | execution_failed | 0 | 0 | 0 |
| BV3-0346 | confirmed_violation | benign | runtime_confirmed | 1 | 0 | 0 |
| BV3-0350 | confirmed_violation | needs_review | execution_failed | 0 | 0 | 0 |
| BV3-0542 | benign_lookalike | benign | runtime_confirmed | 1 | 0 | 0 |
| BV3-0551 | benign_lookalike | needs_review | execution_failed | 0 | 0 | 0 |
| BV3-0768 | trusted_allowed | benign | runtime_confirmed | 1 | 0 | 0 |
| BV3-0769 | trusted_allowed | benign | runtime_confirmed | 1 | 0 | 0 |
| BV3-0789 | review_coverage | benign | runtime_confirmed | 1 | 0 | 0 |
| BV3-0790 | review_coverage | benign | runtime_confirmed | 1 | 0 | 0 |

After LLM timeout handling, BV3-0343 was rerun once at `artifacts/benchmark_v3_canary/single-20260730-180449/runs/single-BV3-0343`. It produced a confirmed source-to-trusted-LLM-context chain but did not reach the mock sink because the external model request timed out; final coverage was `timeout`, not generic `execution_failed`.

## Stratified40 and Development

Not run. Stage A did not satisfy the canary gate. Placeholder artifacts were created:

- `artifacts/benchmark_v3_stratified40/NOT_RUN.txt`
- `artifacts/benchmark_v3_development/NOT_RUN.txt`

## Benchmark Overfitting Controls

- Benchmark v3 files are unchanged.
- No sample ID branches were added.
- Ground truth files are not read by `BenchmarkV3ReplayAdapter`.
- Expected sink/carrier/chain/verdict are not passed to the analyzer.
- HTTP connect/request attempt alone still does not close confirmed exfiltration.
- Process-level automatic overtaint was not restored.
- Mock service receipts provide sink reachability and payload observability, but chain recovery still requires taint evidence.

## Tests

Added `test/test_benchmark_v3_runtime_integration.py`.

Coverage includes:

- fixture protected asset registration without ground truth
- mock capture privacy
- raw protected marker to untrusted JSON body chain
- sink unavailable classification
- missing command classification
- LLM provider timeout classification
- incomplete execution does not create endpoint contradiction
- public LLM config API key redaction
- Docker localhost mock + protected asset E2E

Final commands:

- `python3 -m unittest discover -s test -p 'test_*.py'`: 174 tests, OK
- `python3 -m compileall app test scripts benchmark_v3/scripts`: OK
- exact API key leakage scan over benchmark_v3 artifacts: 0 hits

## Current Limitations

1. Canaries relying on multiple real LLM turns remain unstable under current external provider latency.
2. Download/extract/execute and reverse-shell policy chains need stronger non-confidentiality chain recovery.
3. Review-coverage semantics still need stricter coverage-obligation integration; some review samples become benign when only trusted LLM context is confirmed.
4. Contradiction suppression should be rerun on fresh canaries after the LLM timeout fix; old full-canary artifacts predate that fix.
5. Docker build context is large, making official image rebuild slow.

