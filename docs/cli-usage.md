# ProvLoom CLI Usage

## Static

```bash
python3 -m app.static.cli run /path/to/skill --run-id STATIC-RUN
```

Outputs in `artifacts/static-runs/<run-id>/`:
- `static-analysis.json`
- `static-explanation.md`
- `instruction-provenance-graph.json`
- `unified-analysis.json`
- `unified-explanation.md`

## Dynamic

```bash
python3 -m app.dynamic.cli run /path/to/skill --run-id RUN-ID --network-policy default
```

Outputs in `artifacts/runs/<run-id>/`:
- `normalized-events.jsonl`
- `runtime-events-v2.jsonl`
- `runtime-provenance-graph.json`
- `runtime-chains.json`
- `dynamic-analysis.json`
- `unified-analysis.json`
- `unified-explanation.md`
- `canonical-analysis-result.json`

Unified reports show the three primary Dynamic v3 axes separately:
- Security/risk-chain evidence: `risk_chain_status`
- Runtime execution completeness: `execution_completion`
- Per-static-path security coverage: `static_path_results` and `primary_static_path_status`

`export` prefers unified artifacts when present:

```bash
python3 -m app.dynamic.cli export RUN-ID --format md
python3 -m app.dynamic.cli export RUN-ID --format json
```

Notes:
- Dynamic CLI defaults to the official `skill-runtime-sandbox:dynamic-v3` image.
- Dynamic CLI defaults to a 600 second total sandbox timeout. Override it with `--timeout-seconds`; fixture/runtime and environment defaults are used only when no explicit value is provided.
- Override with `--image-name` or `PROVLOOM_SANDBOX_IMAGE` when running development images.
- Candidate flows, instrumentation gaps, timeouts, and execution failures require review; they are not mapped to benign.
- Confirmed violations remain malicious even if execution later times out or exhausts agent steps; those conditions are reported under execution completion.
