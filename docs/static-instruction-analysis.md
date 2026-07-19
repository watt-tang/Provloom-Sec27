# Static Instruction Analysis

ProvLoom Static v2 builds an instruction-derived provenance explanation. It does not decide whether a skill is malicious or benign, and a closed static chain only means the loaded artifacts contain evidence for a complete potential path. Runtime occurrence must be confirmed by Dynamic Runtime Analysis.

## Architecture

The production path is:

1. Artifact Loader
2. Semantic Unit Parser
3. Deterministic Extractor
4. Span-grounded LLM Action Extractor adapter
5. Grounding Validator
6. Action Normalizer
7. Entity Resolver
8. Typed Instruction Provenance Graph
9. Deterministic Path Validator
10. Static Explanation Report

The default LLM adapter is deterministic/offline. It records prompt metadata and preserves the adapter boundary, but it does not call an external model unless a future adapter is configured.

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

Implemented deterministic templates include credential/data exfiltration, download and execute, dropper or multi-stage execution, persistence, destructive modification, permission expansion, and untrusted instruction to dangerous action. Paths are recovered only along existing typed graph edges and entity continuity. Keyword co-occurrence never closes a path.

Chain statuses are:

- `closed`: source, propagation/action, and sink are continuous and grounded.
- `partial`: a relevant path fragment exists, but a critical link or sink is missing.
- `isolated`: security-relevant actions exist without a supported path.
- `uncertain`: a chain may exist, but key entity links or grounding are ambiguous.
- `contradicted`: explicit contradictory evidence blocks the path.
- `none`: no supported security-relevant path was formed.

## Coverage

Coverage states include `fully_loaded`, `partially_loaded`, `unsupported_artifact`, `oversized_artifact`, `parse_failure`, `llm_extraction_failure`, `grounding_failure`, `unresolved_entities`, `path_validation_complete`, and `analysis_error`.

No closed static chain is not a safety verdict. Ignored files, unsupported artifacts, parse failures, and ambiguous entities are recorded as coverage limitations.

## CLI

```bash
python3 -m provloom static validate-config --config configs/static-analysis.example.json
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

## Dynamic Alignment

Static entities include `runtime_alignment_keys` for later joining with Dynamic Runtime Analysis objects:

- File-like entities: `relative_path`, `basename`, `normalized_path`.
- Endpoints: `scheme`, `domain`, `port`, `path`.
- Executables: `command`, `script`.
- Environment variables: `name`.

Static never fabricates runtime events or runtime confirmation.

## Migration Notes

The legacy `app.analyzer.instruction_chain.analyze_instruction_chain()` remains compatible and still returns existing `instruction_*` fields. It now also includes Static v2 fields such as `static_artifacts_v2`, `deterministic_mentions`, `resolved_entities`, `instruction_provenance_graph`, `static_chains`, `static_coverage`, and `static_analysis_summary`.

The older instruction bundle analyzer remains available for historical benchmarks. New integrations should prefer `app.static.static_report.analyze_static_bundle()` or `python3 -m provloom static run`.

## Current Limits

The implementation is not whole-program static analysis, binary decompilation, Semia SDL, verbalization-similarity validation, Datalog detection, or automatic malicious/benign classification. The default LLM adapter is intentionally offline and deterministic. Shell and language dataflow are conservative and limited to high-confidence patterns, simple references, and explicit evidence.
