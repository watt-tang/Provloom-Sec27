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
