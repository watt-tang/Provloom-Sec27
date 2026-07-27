# Dynamic v3 Final Validation Report

Date: 2026-07-27

## Verdict

ProvLoom Dynamic v3 is frozen as:

`ProvLoom Dynamic v3: evidence-graded, carrier-aware, coverage-aware runtime provenance analysis`.

The final validation used the official Docker image, not a source-mounted runtime.

## Official Image

- Tag: `skill-runtime-sandbox:dynamic-v3`
- Image id: `sha256:b8f114fa58cfe522a45c5e07d0b86bb53a15de1d8a301f983e21e849dcbcaabb`
- Fingerprint: `71c962d5de631e79d96696cd503ef9f2f088ebc4090fd3386edee0e2f0196178`
- Source mount used: false
- Build info copied into each run artifact: yes

## Docker Root Cause And Fix

The official rebuild previously stalled because Docker was sending a very large repository context. `.dockerignore` now excludes `.git`, `artifacts`, caches, docs, tests, and scripts. `DockerRunner` now supports explicit reuse vs force rebuild and build timeout.

## Carrier Probes

Rollup: `artifacts/runs/dynamic-carrier-probes/carrier-probe-official-image-v3-rollup.json`

| Case | Coverage | Chains | Carrier | Policy | Canonical | Final | Privacy |
|---|---:|---:|---|---:|---|---|---|
| secret_read_no_llm_prompt | target_reached_no_flow | 0 | none | 0 | no_violation_observed | benign | clean |
| secret_marker_into_llm_prompt | runtime_confirmed | 1 | llm_context | 0 | no_violation_observed | benign | clean |
| secret_trusted_authorization_header | runtime_confirmed | 1 | http_header | 0 | no_violation_observed | benign | clean |
| secret_untrusted_json_body | runtime_confirmed | 1 | http_body | 1 | violation_confirmed | malicious | clean |

All four runs used `source_mount_used=false`, shared the final fingerprint, and had clean API-key and plaintext marker scans.

## Static v2 And Full Regression

- Static v2 real suite: `test/test_static_analysis_v2.py`, 53 passed
- Dynamic discovery: 49 passed
- Full discovery: 157 passed
- Compileall: passed
- Skipped: 0
- Failures/errors: 0

## Static-Dynamic Alignment

Rollup: `artifacts/runs/static-dynamic-alignment-probes/alignment-probe-official-image-v3-rollup.json`

| Case | Alignment | Contradiction | Policy | Canonical |
|---|---|---|---:|---|
| local_only_read_write | partially_aligned | none | 0 | no_violation_observed |
| official_api_authorization | partially_aligned | none | 0 | no_violation_observed |
| declared_official_runtime_untrusted | contradicted | declared_official_endpoint_runtime_unrelated_endpoint | 1 | violation_confirmed |
| static_no_network_runtime_exfil | contradicted | static_no_network_action_runtime_network_flow; declared_official_endpoint_runtime_unrelated_endpoint | 1 | violation_confirmed |
| declared_artifact_a_executes_b | partially_aligned | none | 0 | no_violation_observed |

API/CLI/report path now passes complete Static v2 result into Dynamic alignment and emits `unified_explanation`.

## Privacy

No final probe artifact contains the probe secret marker or API-key-shaped `sk-...` token. Static v2 now ignores `.provloom/private/**` and `.provloom/adapters/credential_state/**` by default to avoid persisting private source plaintext in static semantic units.

## Freeze Rules

- Four carrier probes are permanent regression probes.
- Five alignment probes are permanent regression probes.
- Any confirmed policy violation mapped to benign is a failure.
- Any candidate/instrumentation gap mapped to benign is a failure.
- Any plaintext secret in artifacts is a failure.
- Dynamic v3 semantics should not be changed without rerunning this validation set.

## Known Limits

- No eBPF or FUSE symbolic reads.
- No TLS MITM or decrypted HTTPS payload capture.
- No byte-level in-process DIFT.
- RuntimeInstructionLift remains simulation-only.
- Alignment still has noisy runtime-only nodes from interpreter/library activity.

