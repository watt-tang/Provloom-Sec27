# Default Image, Alignment Noise, and Benchmark Audit

Date: 2026-07-29

## Executive Summary

本轮只完成两项小修复并审计 Benchmark，未修改 Benchmark 样本、标签、ground truth、manifest 或生成脚本。

- 默认正式 Docker image 已统一为 `skill-runtime-sandbox:dynamic-v3`。
- API、Dynamic CLI、batch scan、benchmark runner 都保留 image 覆盖能力或继承 `DockerRunner` 覆盖能力。
- 执行报告现在输出 `sandbox_image`、`sandbox_image_id`、`source_fingerprint` 和 `runtime_build_info`。
- alignment 前增加 runtime scope 分类；Python runtime、系统库、CA certificate、pip/npm/cache、模型缓存和临时依赖路径默认进入 `internal_unresolved`，不再污染默认 runtime-only 展示。
- 原始 RuntimeEvent、runtime graph 和 JSON alignment 记录仍完整保留。
- 当前 Benchmark 结论：`datasets/` 与 `benchmark_v2/` 都是模板化为主；`benchmark_v2/` 是 manifest/spec 驱动的系统生成集合，不等同于真实自然语言 Skill 分布。

Official image verification:

| Field | Value |
|---|---|
| image tag | `skill-runtime-sandbox:dynamic-v3` |
| image id | `sha256:3edd62386e7d19e4813027a5256e9d72858989f4c26e7bd3e88807bf00ed2b7e` |
| source fingerprint | `2edabae52808f2db08d5ea9068df3f7c03412a34dc9fec070f70c032000482ee` |
| dynamic version | `3.0` |

## Default Docker Image

### Implementation

`DockerRunner` now exposes one default image constant:

- `app/runner/docker_runner.py:27`: `DEFAULT_SANDBOX_IMAGE = "skill-runtime-sandbox:dynamic-v3"`
- `app/runner/docker_runner.py:43-57`: constructor accepts optional `image_name`; default is `image_name or PROVLOOM_SANDBOX_IMAGE or DEFAULT_SANDBOX_IMAGE`
- `app/runner/docker_runner.py:328-365`: build path tags the same image and passes `IMAGE_TAG`, `SOURCE_FINGERPRINT`, `BUILD_TIMESTAMP`, and `DYNAMIC_ANALYSIS_VERSION`

The Dockerfile default and labels are aligned:

- `docker/sandbox/Dockerfile:6-12`: default `IMAGE_TAG=skill-runtime-sandbox:dynamic-v3`; labels include image tag, source fingerprint, and dynamic analysis version
- `docker/sandbox/Dockerfile:20-24`: `/opt/skill_sandbox/runtime-build-info.json` persists the same metadata into runtime artifacts

### Entry Points

| Entry | Default image path | Override |
|---|---|---|
| API dynamic/static request | `app/backend/api.py:22`, `app/backend/api.py:70-81` use global `DockerRunner()` | `PROVLOOM_SANDBOX_IMAGE` through `DockerRunner` |
| Dynamic CLI | `app/dynamic/cli.py:14`, `app/dynamic/cli.py:27-34`, `app/dynamic/cli.py:79-90` | `--image-name` |
| Batch scan | `scripts/batch_scan_skills.py:63`, `scripts/batch_scan_skills.py:399-411`, `scripts/batch_scan_skills.py:1267-1273` | `--image-name` |
| Benchmark runner | `scripts/run_benchmark.py:21`, `scripts/run_benchmark.py:43-58`, `scripts/run_benchmark.py:82-97` | `--image-name` |

### Image Metadata Output

- `app/runner/models.py:174-199`: `SandboxExecution` includes `sandbox_image_id`, `source_fingerprint`, `runtime_build_info`
- `app/runner/docker_runner.py:86-89`: image is built/inspected before execution
- `app/runner/docker_runner.py:310-316`: returned execution includes image id and fingerprint from runtime build info or image metadata
- `app/analysis/pipeline.py:224-228`: canonical dynamic report includes `sandbox_image`, `sandbox_image_id`, `source_fingerprint`, and `runtime_build_info`
- `app/backend/schemas.py:174-176`: API response schema exposes the same fields
- `app/dynamic/cli.py:94-101`: CLI summary prints image tag/id/fingerprint
- `scripts/run_benchmark.py:82-88`: benchmark summary includes the image tag used
- `scripts/batch_scan_skills.py:1267-1273`: batch manifest records the configured image tag

## Alignment Runtime Internal Noise

### Implementation

The filter is a scope classifier before unresolved alignment records are finalized, not a deletion pass:

- `app/explanation/builder.py:51-65`: builds static/runtime items before alignment
- `app/explanation/builder.py:77-92`: splits unresolved alignment records into `relevant_unresolved` and `internal_unresolved`
- `app/explanation/builder.py:200-219`: unmatched runtime items are classified as `internal_unresolved` only when they are runtime-internal, untainted, and unrelated to runtime chains
- `app/explanation/builder.py:271-280`: chain-related runtime ids are re-included
- `app/explanation/builder.py:283-290`: tainted items are re-included
- `app/explanation/builder.py:293-345`: runtime internal patterns cover `/opt/skill_sandbox`, Python stdlib/site-packages, CA cert paths, pip/npm caches, model caches, apt/cache paths, temp dependency paths, `.pyc`, and `__pycache__`
- `app/explanation/builder.py:348-360`: `SourceRegistry` prevents medium/high/critical sensitive paths from being filtered as internal
- `app/explanation/builder.py:778-795`: `runtime_only_paths` excludes internal unresolved ids by default
- `app/explanation/models.py:90-101`: `UnifiedExplanationResult` schema now contains `relevant_unresolved` and `internal_unresolved`
- `app/analysis/pipeline.py:341-368`: canonical report summary preserves total unresolved counts and both split lists

### Semantics

Default Markdown/runtime-only display now focuses on relevant unresolved behavior. JSON keeps the full alignment record list, including `internal_unresolved`, so audits can still recover every runtime item and its reason.

Re-inclusion conditions currently implemented:

- Exact/semantic match to static entity/action/path via `_best_match`
- Runtime item has taint ids or source metadata
- Runtime item participates in a confirmed/candidate recovered runtime chain
- Sensitive source classification from `SourceRegistry` is medium/high/critical

Not implemented in this small patch:

- A separate target-action configuration object. Target actions are covered indirectly when they align with static actions or appear in chains.

## Benchmark Audit

### Current Runner

`scripts/run_benchmark.py` is the current executable benchmark entry:

- `scripts/run_benchmark.py:43-49`: default datasets root is `datasets`
- `scripts/run_benchmark.py:100-129`: discovers cases from `datasets/skills/{benign,malicious}` and loads matching `datasets/ground_truth/*.json`
- `scripts/run_benchmark.py:132-145`: required ground truth fields are fixed schema fields

Current `datasets/` count from filesystem:

- `datasets/skills/benign`: 25 cases
- `datasets/skills/malicious`: 25 cases

### Benchmark Generators, Templates, Seeds, Manifests, Labels

| Item | Files | Evidence |
|---|---|---|
| v1/current dataset generator | `scripts/expand_benchmark_suite.py` | `skill_markdown()` template at lines `13-34`; writes SKILL.md and ground truth at `37-50`; templated direct/staged/public/benign cases at `53-120`, `438-620` |
| v2 generator | `scripts/generate_benchmark_v2.py` | `CaseSpec` schema at `60-85`; `skill_markdown()` template at `125-136`; `ground_truth_payload()` at `138-150`; combinatorial case construction at `990-1128`; writes SKILL.md/ground truth at `1287-1296`; writes manifest at `1310-1345`; main regenerates dataset at `1573-1584` |
| v2 seeds | `scripts/generate_benchmark_v2.py` | `SENSITIVE_SOURCES` at `22-27`; `PUBLIC_SEEDS` at `28-37`; style nouns at `38-47`; command seeds at `1089-1095` |
| v2 manifest | `benchmark_v2/generated/benchmark_v2_manifest.json` | `generated_by` at line `2`; version and dataset root at `3-5`; first case fields at `8-24` |
| hard benign manifest | `benchmark_v2/hard_benign_pack/manifest.csv` | manifest columns at line `1`; repeated seed/review rows at `2-12` |
| label/ground truth fields | `scripts/generate_benchmark_v2.py` and `scripts/expand_benchmark_suite.py` | labels are emitted in JSON by `ground_truth_payload()` or per-case `ground_truth` dictionaries, not inferred from independent annotation |
| pair/lookalike mapping | `scripts/generate_benchmark_v2.py` | pair construction at `1129-1274`; writes pair mapping at `1348-1370` |
| schema | `benchmark_v2/schema/case_schema.json`, generated by `scripts/generate_benchmark_v2.py` | schema writer at `1505-1556` |

`benchmark_v2/generated/benchmark_v2_manifest.json` currently contains 147 cases: 104 malicious and 43 benign. The breakdown observed from the manifest is:

| Field | Distribution |
|---|---|
| family | direct 16; staged/relay 36; unauthorized transfer 16; unsafe command 12; LLM-induced 12; mixed multi-hop 12; hard benign 29; policy benign 14 |
| evaluation_status | dynamic_runnable 123; static_evaluable 12; partially_stubbed 12 |
| source_type | sensitive local file 84; generated artifact 34; public file 29 |
| sink_type | external endpoint 76; upload-like endpoint 20; local-only 41; approved endpoint 10 |
| trigger_type | direct tool call 78; mixed trigger 40; command construction 17; LLM-mediated choice 12 |

### Natural Language Assessment

The samples contain grammatical full sentences, but the natural-language instructions are largely fixed templates with slots:

- v1 direct exfil uses fixed wording: description/body/actions are format strings over `path`, `action_suffix`, and URL; `scripts/expand_benchmark_suite.py:53-100`
- v1 staged exfil uses fixed wording over `sensitive_path`, `staged_path`, and body; `scripts/expand_benchmark_suite.py:103-170`
- v2 SKILL.md always follows the same YAML + heading + body + `skill-actions` layout; `scripts/generate_benchmark_v2.py:125-136`
- v2 direct/staged/benign variants are generated by loops over path/style/variant; `scripts/generate_benchmark_v2.py:990-1128`

Observed sample SKILL.md files confirm the generated pattern:

- `datasets/skills/malicious/malicious_sensitive_exfil_direct/SKILL.md`: fixed direct read/send wording plus structured `skill-actions`
- `datasets/skills/malicious/malicious_indirect_exfil_json_wrap/SKILL.md`: fixed read/stage/send wording plus structured `skill-actions`
- `benchmark_v2/datasets/skills/malicious/v2_direct_report_passwd/SKILL.md`: same direct template with `report` and `/etc/passwd` slots
- `benchmark_v2/datasets/skills/malicious/v2_staged_audit_hostname_tool/SKILL.md`: same staged template with `audit`, `/etc/hostname`, and `cat` slot
- `benchmark_v2/datasets/skills/benign/v2_policy_benign_report_upload/SKILL.md`: same public-source/approved-endpoint template

Answer to the required classification: **模板化为主**.

It is not “接近真实自然语言分布”. It has some manually chosen families, style nouns, variants, and rationale text, so it is not a single trivial template. But the actual Skill instructions and action blocks are overwhelmingly generated from a small set of function templates and Cartesian products over paths, URLs, commands, style nouns, and variants.

### Benchmark Gap From Real Skills

Current gaps:

- Low wording entropy: many samples differ only by path, style noun, endpoint, command, or variant name.
- Structured action block dominates semantics; real Skills often spread intent across prose, scripts, install steps, examples, config files, and tool wrappers.
- Limited implicit instruction coverage: few hidden/conditional/multi-document or distractor-heavy instructions.
- Limited cross-file natural language: extra files are mostly seed data, not independent instruction carriers.
- Endpoint and sensitive source distributions are narrow: `httpbin.org`, `/etc/*`, `runtime_output/*`, public seed files.
- LLM-mediated cases are marked static/non-runnable or partially stubbed; they do not represent independent LLM-written operational instructions.

Results most exposed to template leakage or rule adaptation:

- Rules matching `read_file` followed by `http_request` against `https://httpbin.org/post`.
- Rules relying on exact action ids like `read_sensitive_source`, `send_stage`, `send_outward_payload`.
- Static extraction keyed to repeated words: "Reads", "stages", "posts", "external endpoint", "approved endpoint".
- Benign/malicious discrimination around fixed `approved=1`, `public/*`, and `runtime_output/*` patterns.
- Root-cause labels tied directly to generator family names.

## Tests

Commands executed:

```bash
python3 -m unittest discover -s test -p 'test_default_image_and_alignment_scope.py'
python3 -m unittest discover -s test -p 'test_unified_pipeline.py'
python3 -m unittest discover -s test -p 'test_*.py'
python3 -m compileall app test scripts
```

Results:

| Command | Result |
|---|---|
| `test_default_image_and_alignment_scope.py` | 3 tests passed |
| `test_unified_pipeline.py` | 6 tests passed |
| full unittest discovery | 166 tests passed, 0 failed, 0 errors |
| compileall | passed |

New regression coverage:

- API/CLI/batch/benchmark default image consistency: `test/test_default_image_and_alignment_scope.py:18-50`
- runtime internal unresolved split and report filtering: `test/test_default_image_and_alignment_scope.py:52-90`
- sensitive/static-related path anti-regression: `test/test_default_image_and_alignment_scope.py:92-130`

## Files Modified In This Round

Task-related files touched by this round:

1. `app/runner/docker_runner.py`
2. `app/runner/models.py`
3. `app/analysis/pipeline.py`
4. `app/backend/schemas.py`
5. `app/dynamic/cli.py`
6. `app/explanation/builder.py`
7. `app/explanation/models.py`
8. `app/explanation/validator.py`
9. `app/reporting/unified_report.py`
10. `scripts/run_benchmark.py`
11. `scripts/batch_scan_skills.py`
12. `docker/sandbox/Dockerfile`
13. `test/test_default_image_and_alignment_scope.py`
14. `docs/cli-usage.md`
15. `docs/provloom-system-hardening-report.md`
16. `docs/dynamic-implementation-audit.md`
17. `docs/default-image-alignment-noise-and-benchmark-audit.md`

No commits or pushes were performed.
