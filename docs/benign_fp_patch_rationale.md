# Note-Like / Local-Output Benign-FP Patch Rationale

## Patched files

- `app/analyzer/decision_engine.py`
- `app/analyzer/risk_scoring.py`
- `test/test_dynamic_decision_regression.py`

## Problem

Two rules were over-escalating benign note-like and local-output cases:

1. `generated_artifact_external_transfer` could fire for a locally generated artifact even when no external sink existed.
2. `overprivileged_outward_tool_action` treated any external `http_request` tool surface as outward transfer pressure, including benign `GET`-only public fetches followed by local note writes.

This created the residual benchmark false positives around:

- `benign_local_note`
- `benign_local_report`
- `benign_local_inventory`
- `benign_helper_listing`
- `benign_public_fetch_audit_note`
- `benign_public_mirror_note`

## Minimal patch

- Require `generated_artifact_external_transfer` to have an evidence-backed external sink instead of only a medium-sensitivity generated artifact plus permissive sink semantics.
- Restrict `overprivileged_outward_action` to true outward sink semantics:
  - `PUBLIC_UPLOAD_OR_POST`
  - `CALLBACK_OR_WEBHOOK`
  - `LLM_MEDIATED_UNKNOWN_SINK`
  - `UNKNOWN_NETWORK_SINK`
- Exclude `PUBLIC_FETCH_ONLY` from that escalation path.

## Before / After Expected Behavior

### Before

- Local-only note/report/inventory writes could be labeled `needs_review` with `generated_artifact_external_transfer`.
- Public fetch + local audit note or mirror note could be labeled `needs_review` with `overprivileged_outward_tool_action`.

### After

- Local-only note/report/inventory/helper-listing cases stay `benign` unless a real outward sink is present.
- GET-only public fetch followed by a local note stays `benign`.
- Malicious outward transfers remain alerting because they still satisfy the evidence-backed external sink requirement.

## Validation status

- `code patch`: completed
- `synthetic regression coverage`: completed
- `full dynamic benchmark rerun`: requires-rerun

## Rerun TODO

- Re-run dynamic benchmark modes on the original 50-case suite to confirm the six targeted benign cases drop from `needs_review` to `benign`.
- Re-run benchmark_v2 dynamic modes on the hard-benign slice first, before a full 139-case dynamic sweep.
- Re-run the completed-subset log7 audit after any future scoring changes to confirm note-like cluster counts move in the expected direction.
