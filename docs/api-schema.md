# ProvLoom API Schema

## POST /analyze-skill

Request model: `app.backend.schemas.AnalyzeSkillRequest`.

Required:
- `skill_path: string`

Optional:
- `input_payload: object`
- `timeout_seconds: integer` from 1 to 3600; default is 600 seconds when omitted
- `network_policy: "default" | "disabled"`
- `analysis_mode: "rule_only" | "rule_plus_epg" | "static_only"`
- `llm_config: object`

Current behavior:
- `analysis_mode=static_only` uses Static v2 through `app.analysis.pipeline.analyze_skill_bundle()`.
- Dynamic modes use the same canonical pipeline after Docker execution.
- Total sandbox timeout resolves as: explicit request value, then fixture/runtime value, then `PROVLOOM_TIMEOUT_SECONDS` or `PROVLOOM_TOTAL_TIMEOUT_SECONDS`, then the 600 second default. LLM provider request timeout remains separate from the total sandbox timeout.
- Top-level `risk_score`, `final_decision`, `canonical_*`, `coverage_state`, and report paths are canonical fields.
- Legacy fields are retained as compatibility fields: `legacy_static_result`, `legacy_risk_score`, `legacy_final_decision`.

Response model: `app.backend.schemas.AnalyzeSkillResponse`.

Unified fields:
- `static_analysis_version`
- `dynamic_analysis_version`
- `alignment_version`
- `assessment_version`
- `unified_analysis`
- `unified_analysis_path`
- `unified_explanation_report_path`
- `alignments`
- `contradictions`
- `aligned_paths`
- `instruction_only_paths`
- `runtime_only_paths`
- `coverage_certificate`
- `policy_findings`
- `minimal_witnesses`
- `limitations`

Generated artifacts:
- `unified-analysis.json`
- `unified-explanation.md`
- `canonical-analysis-result.json`
- legacy dynamic artifacts when runtime execution is performed

Privacy:
- `llm_config.to_public_dict()` excludes API keys.
- Runtime LLM context telemetry stores taint ids, hashes, counts, and redacted previews, not full prompts.
