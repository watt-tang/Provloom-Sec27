# Static Instruction Analysis

ProvLoom Static v2 builds an instruction-derived provenance explanation. It does not decide whether a skill is malicious or benign, and a closed static chain only means the loaded artifacts contain evidence for a complete potential path. Runtime occurrence must be confirmed by Dynamic Runtime Analysis.

## Architecture

The production path is:

1. Artifact Loader
2. Semantic Unit Parser
3. Deterministic Extractor
4. Optional Span-grounded LLM Action Extractor adapter
5. Grounding Validator
6. Action Normalizer
7. Entity Resolver
8. Typed Instruction Provenance Graph
9. Deterministic Path Validator
10. Static Explanation Report

Static v2 defaults to deterministic/offline analysis and does not call an external LLM unless `llm_enabled=true` is explicitly configured. When enabled, the OpenAI-compatible adapter only reviews span-grounded candidate actions and can suppress or re-modality actions before graph/path validation. The API key is read from `PROVLOOM_STATIC_LLM_API_KEY`; keys are not written to reports.

## Evidence Model

Every loaded file becomes `static_artifacts_v2` with a stable artifact id, hash, status, and load reason. Every parseable document or code fragment becomes a `static_semantic_units` record with line and byte-offset bounds. Actions, mentions, entities, resolutions, graph edges, and chains refer back to those units.

Graph edge evidence levels are:

- `explicit`: directly expressed by source text, code, or config.
- `resolved`: established by deterministic alias, variable, path, or URL resolution.
- `inferred`: controlled inference with supporting evidence but no direct expression.
- `uncertain`: ambiguous entity or relation.

## Modality

Actions carry one of `required`, `recommended`, `optional`, `conditional`, `prohibited`, `example_only`, `descriptive`, `hypothetical`, `quoted_untrusted`, or `unknown`.

`prohibited`, `example_only`, `hypothetical`, `quoted_untrusted`, and `descriptive` actions cannot form a closed executable static chain. `conditional` and `optional` actions keep their condition and are not upgraded to unconditional closed paths.

## Path Templates

Implemented deterministic templates include credential/data exfiltration, download and execute, dropper or multi-stage execution, persistence, destructive modification, permission expansion, reverse shell, ransomware, resource abuse, privilege escalation, agent lifecycle persistence, and conservative instruction-policy behaviors. Paths are recovered only along existing typed graph edges and entity continuity. Keyword co-occurrence never closes a path.

Static v2 now separates four orthogonal fields:

- `status` / `path_status`: whether a path structure is `closed`, `partial`, `uncertain`, `isolated`, `contradicted`, or `none`.
- `capability_type`: what capability the path describes, such as `credential_authentication`, `credential_exfiltration`, `declared_dependency_install`, `untrusted_download_execute`, `permission_request`, or `privilege_escalation`.
- `policy_status`: whether the capability is expected, trusted, untrusted, insufficiently contextualized, or undeclared.
- `alert_status`: whether the chain is a `violation`, `review`, `capability_only`, `unresolved`, or `none`.

`status=closed` is not a malicious/benign prediction and is not a policy violation by itself. Binary policy evaluation must use `alert_status == "violation"`.

Chain statuses are:

- `closed`: source, propagation/action, and sink are continuous and grounded.
- `partial`: a relevant path fragment exists, but a critical link or sink is missing.
- `isolated`: security-relevant actions exist without a supported path.
- `uncertain`: a chain may exist, but key entity links or grounding are ambiguous.
- `contradicted`: explicit contradictory evidence blocks the path.
- `none`: no supported security-relevant path was formed.

## Deterministic Policy Rules

Credential paths are classified as:

- `credential_authentication`: a credential is used in Authorization, Bearer, API-key, OAuth, SDK-client, or login context for a trusted or credential-matched service.
- `credential_exposure`: a credential is written to local logs, stdout, cache, reports, or temporary files without a proven untrusted external sink.
- `credential_exfiltration`: a concrete sensitive source is read and the same data object is consumed as body, payload, form, message, attachment, upload file, diagnostic bundle, or equivalent content sent to an untrusted endpoint.

Credential exfiltration requires explicit source evidence, shared data-object continuity, concrete endpoint binding, payload/upload evidence, non-suppressed modality, and no unresolved critical entity. A credential mention and a network action in the same skill, file, section, or time order do not close an exfiltration path.

Download/execute paths require artifact identity continuity. `curl URL -o /tmp/x.py` followed by `python /tmp/x.py`, unique coreference to the downloaded artifact, or pipe-to-shell establishes continuity. Basename similarity, adjacent text, package installs, or unrelated `download` and `execute` actions do not. Standard package-manager installs are classified as `declared_dependency_install` and `capability_only`.

Permission paths distinguish `permission_request`, `permission_expansion`, and `privilege_escalation`. Ordinary `chmod +x` is treated as execution preparation, not privilege escalation. High-risk boundary crossings include setuid/setgid modes, `/etc/sudoers`, Docker socket permission changes, sandbox disabling, container escape, root shell acquisition, and system user/group changes.

Entity resolution records `resolution_strength` as `strong`, `medium`, or `weak`. Closed paths may use strong deterministic links and unique medium coreference, but weak links such as basename equality, same section, same skill, or keyword overlap cannot support a closed critical edge.

Canonical chain deduplication uses capability, canonical source, normalized action sequence, canonical sink, modality, and condition. Per capability, only the strongest primary chains are emitted; duplicate evidence is counted in `duplicate_suppressed_count`.

## Deterministic Data Flow

Static v2 includes bounded deterministic analyzers for Python, Shell, and JavaScript/TypeScript. These analyzers emit ordinary span-grounded actions and mentions; they do not create policy alerts directly.

- Python uses AST for environment reads, file reads, simple assignment, containers, formatted strings, bounded function returns, `requests`/`httpx`/`aiohttp` sinks, sockets, and subprocess curl payloads.
- Shell tracks simple variable assignment, command substitution, environment expansion, curl/wget payload/header/upload/download roles, pipes, file relay, archive extraction, downloaded-artifact execution, and common persistence/resource/reverse-shell patterns.
- JavaScript/TypeScript tracks `process.env`, `fs` reads, simple object/body propagation, `fetch`/`axios`, `FormData` uploads, child-process execution, and JSON config imports.

Unsupported dynamic constructs are recorded as limitations or left as review/uncertain evidence. They are not promoted to closed violations.

## Review And Attribution

Review chains include a `review_reason`, such as `missing_data_continuity`, `missing_artifact_identity`, `ambiguous_entity`, `unknown_endpoint_trust`, `unsupported_language_construct`, `unsupported_attack_template`, `ambiguous_modality`, `cross_artifact_gap`, `partial_source`, `partial_sink`, `policy_boundary_missing`, `analysis_coverage_gap`, or `instruction_semantics_ambiguous`.

False-negative attribution can be run over a saved deterministic report:

```bash
python3 scripts/analyze_static_false_negatives.py \
  --eval-report artifacts/static_deterministic_dev/report.json \
  --report-only \
  --output-json artifacts/static_deterministic_dev/fn_attribution.json \
  --output-md artifacts/static_deterministic_dev/fn_attribution.md
```

Attribution labels such as CI/PI/MIXED and B1-B15 are used only for evaluation reporting. They are not inputs to the analyzer or path validator.

## Coverage

Coverage states include `fully_loaded`, `partially_loaded`, `unsupported_artifact`, `oversized_artifact`, `parse_failure`, `llm_extraction_failure`, `grounding_failure`, `unresolved_entities`, `path_validation_complete`, and `analysis_error`.

No closed static chain is not a safety verdict. Ignored files, unsupported artifacts, parse failures, and ambiguous entities are recorded as coverage limitations.

## CLI

```bash
python3 -m provloom static validate-config --config configs/static-analysis.example.json
export PROVLOOM_STATIC_LLM_API_KEY=...
python3 -m provloom static run /path/to/skill --run-id STATIC001 --config configs/static-analysis.example.json
python3 -m provloom static artifacts STATIC001
python3 -m provloom static actions STATIC001
python3 -m provloom static entities STATIC001
python3 -m provloom static graph STATIC001 --summary
python3 -m provloom static explain STATIC001
python3 -m provloom static export STATIC001 --format json
python3 -m provloom static export STATIC001 --format md
```

Run artifacts are saved under `artifacts/static-runs/<run_id>/`.

Deterministic development-split evaluation:

```bash
python3 scripts/evaluate_static_deterministic.py \
  --malicious-paths artifacts/malskillbench_static_100/sample_paths.txt \
  --benign-paths artifacts/malskillbench_static_100_benign/sample_paths.txt \
  --output-json artifacts/static_deterministic_dev/report.json \
  --output-md artifacts/static_deterministic_dev/report.md
```

Held-out split generation:

```bash
python3 scripts/run_static_heldout.py \
  --malicious-root /path/to/MalSkillBench/Dataset/Skills/malware \
  --benign-root /path/to/MalSkillBench/Dataset/Skills/benign \
  --sample-size 500 \
  --seed 20260721 \
  --run
```

The evaluator writes `path_exists` per sample plus missing-path counts in the summary. Missing sample paths are a data coverage problem and must not be interpreted as true benign behavior.

## Dynamic Alignment

Static entities include `runtime_alignment_keys` for later joining with Dynamic Runtime Analysis objects:

- File-like entities: `relative_path`, `basename`, `normalized_path`.
- Endpoints: `scheme`, `domain`, `port`, `path`.
- Executables: `command`, `script`.
- Environment variables: `name`.

Static never fabricates runtime events or runtime confirmation.

## Canonical Reconciliation Update

Static v2 is now the canonical static analyzer for API `analysis_mode=static_only` and for the shared analysis pipeline. The unified pipeline is:

`Skill Bundle -> StaticV2Result -> Runtime Execution -> DynamicV3Result -> StaticRuntimeReconciliation -> CoverageCertificate -> PolicyFinding -> CanonicalAssessment -> API/CLI/batch/report`.

Static evidence remains instruction-supported evidence. A Static v2 violation or review path does not automatically become runtime confirmation; it is mapped into `PolicyFinding(origin="static", evidence_status="instruction_supported")` and reconciled with runtime observations when present.

Unified reconciliation preserves original Static v2 ids for artifacts, units, actions, entities, edges, and static chains. Unaligned static paths are reported as `instruction_only_paths`; runtime-only paths are separate from contradictions.

## Migration Notes

The legacy `app.analyzer.instruction_chain.analyze_instruction_chain()` remains compatible and still returns existing `instruction_*` fields. It now also includes Static v2 fields such as `static_artifacts_v2`, `deterministic_mentions`, `resolved_entities`, `instruction_provenance_graph`, `static_chains`, `static_coverage`, and `static_analysis_summary`.

The older instruction bundle analyzer remains available for historical benchmarks. New integrations should prefer `app.static.static_report.analyze_static_bundle()` or `python3 -m provloom static run`.

## Current Limits

The implementation is not whole-program static analysis, binary decompilation, Semia SDL, verbalization-similarity validation, Datalog detection, or automatic malicious/benign classification. The optional LLM adapter only filters span-grounded candidate actions; deterministic graph construction, path validation, and policy classification still decide chains. Shell and language dataflow are conservative and limited to high-confidence patterns, simple references, and explicit evidence.
