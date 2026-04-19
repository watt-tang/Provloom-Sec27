# ProvLoom: Skill Runtime Security Sandbox

ProvLoom is an execution-based security sandbox and attack-chain analysis system for `SKILL.md`-driven Skills, designed to recover analyst-facing explanations from real runtime behavior rather than from static text alone.

## Overview

Skills are automation or agent tasks described through `SKILL.md`, often combined with local files, helper scripts, tool calls, network actions, and, in some cases, LLM-mediated decisions. This execution model makes security analysis difficult for three reasons:

- Risk is often multi-step rather than single-event.
- LLM and tool decisions can introduce causality that is not explicit in the source text.
- A detector may flag suspicious behavior without explaining how a risky outcome actually formed.

ProvLoom addresses this problem as a runtime security research system. It executes Skills inside a Docker sandbox, collects runtime telemetry, builds an execution provenance graph, reconstructs a semantic attack chain, and attributes a root cause such as unsafe dataflow design, unsafe command construction, or LLM-induced unsafe action. The emphasis is explainability: the system is designed to recover why a risky outcome forms, not only whether a risky behavior occurred.

## Key Features

- Sandbox execution of Skills in isolated Docker containers.
- Runtime telemetry collection over file, process, network, tool-call, and LLM events.
- Execution provenance graph construction from normalized telemetry.
- Semantic attack-chain reconstruction as source -> optional relay -> sink.
- Root-cause attribution over unsafe dataflow, unsafe command construction, overprivileged tool use, and LLM-mediated unsafe actions.
- Benchmark-oriented reporting for artifact evaluation and case-level inspection.

## System Architecture

ProvLoom follows a simple execution-to-explanation pipeline:

```text
SKILL.md / Skill bundle
        ↓
ProvLoom runtime in Docker sandbox
        ↓
Runtime telemetry collection
        ↓
Normalized events and execution provenance graph
        ↓
Primary chain recovery
        ↓
Analyst-facing explanation with root cause
```

In practical terms, the system turns observed execution evidence into an explanation artifact that can be inspected at multiple levels: event stream, graph structure, primary chain, and root-cause summary.

## Execution Model

This repository is not a static linter over `SKILL.md`.

- Dynamic modes execute the Skill inside a Docker sandbox.
- The runtime is implemented inside this repository: the benchmark runs through `app/runtime/container_runtime.py`, which executes `SKILL.md`-driven Skills and records telemetry.
- Dynamic execution is used for runtime baselines such as `rule_only`, `rule_plus_epg`, and `epg_with_filtering`.
- `static_only` does not execute the Skill. It analyzes declared structure and action definitions only.
- Cases marked `dynamic_runnable=false` are intentionally skipped in dynamic modes. This mainly affects benchmark scenarios that depend on external LLM behavior or are treated as design-level rather than execution-level cases.

This distinction is important for interpretation: not every benchmark case is dynamically executable, and not every score reflects the same evidence regime.

## Benchmark & Evaluation

The repository includes an artifact-oriented benchmark with 50 cases:

- 25 malicious cases
- 25 benign cases

The malicious families include:

- direct sensitive exfiltration
- staged or relay-based exfiltration
- unauthorized external transfer
- unsafe command construction
- LLM-induced unsafe action

The benign families include:

- public reads and public fetches
- public uploads and relay-shaped benign flows
- local transforms and helper workflows
- note-like or report-like local-output cases

The benchmark intentionally mixes execution-level and LLM-level risk families. Dynamic coverage is therefore incomplete by design:

- `static_only` covers all benchmark cases.
- Dynamic modes skip cases with `dynamic_runnable=false`.
- A score of `1.0` should be read as task-defined success for semantic attack-chain recovery under the artifact's evidence model, not as a claim that real-world Skill security is solved.

## Example Output

An example analyst-facing attack chain may look like:

```text
source: /workspace/skill/secrets/customer_list.csv
relay:  tool call "Send Export"
sink:   https://httpbin.org/post
root cause: overprivileged tool use
```

At a higher level, ProvLoom aims to recover the minimal semantically sufficient causal path explaining why the risky outcome forms, rather than replaying every operational event in the runtime trace.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/watt-tang/clawguard_sandbox.git
cd clawguard_sandbox
```

### 2. Check prerequisites

ProvLoom uses the Python standard library for the API layer. No extra Python package installation is required for the current MVP, but you do need:

- Python 3
- Docker

The runtime sandbox builds a Docker image on first execution.

### 3. Run the benchmark

```bash
python3 scripts/run_benchmark.py --datasets-root ./datasets
```

### 4. Inspect results

Aggregate benchmark outputs are written to:

```text
artifacts/benchmark/
```

Per-case outputs are written under:

```text
artifacts/benchmark/cases/<analysis_mode>/<case_id>/
```

Runtime execution artifacts are written under:

```text
artifacts/runs/<execution_id>/
```

### 5. Optional: start the API service

```bash
python3 -m app.main --host 0.0.0.0 --port 8000
```

The API exposes runtime analysis through `app/backend/api.py`.

## Project Structure

Key directories:

- `app/runtime/`: ProvLoom runtime, `SKILL.md` parsing, and runtime execution logic.
- `app/runner/`: Docker sandbox lifecycle management and trace handling.
- `app/analyzer/`: rule analysis, risk scoring, chain recovery, and attribution logic.
- `app/telemetry/`: telemetry normalization and execution reporting.
- `scripts/`: benchmark generation and benchmark execution entry points.
- `artifacts/`: runtime artifacts, benchmark summaries, and case-level outputs.
- `datasets/`: benchmark Skills and ground-truth files.
- `docs/`: artifact notes, benchmark plans, case-study notes, and research-facing documentation.
- `Latex/`: paper sources and artifact-writing material.

## Limitations

ProvLoom is a research system with explicit scope boundaries.

- It is not a prevention or enforcement system.
- Telemetry is incomplete by design and does not provide kernel-complete provenance.
- Some benchmark families, especially LLM-level cases, are not dynamically executed.
- Dynamic traces may include operational noise such as loader activity or environment setup.
- A correct semantic chain does not imply exact replay of every runtime event.

These limitations are intentional and should be considered when interpreting benchmark results.

## Research Contribution

From a systems and artifact perspective, the repository contributes:

- A concrete formulation of semantic attack-chain recovery for `SKILL.md`-driven Skills.
- An execution-based analysis pipeline that combines runtime telemetry with provenance reasoning.
- An explainability-oriented security workflow that prioritizes source-relay-sink recovery and root-cause attribution over detection alone.
- A benchmarkable artifact that supports case-level inspection, not only aggregate metrics.

## Intended Audience

This repository is written for:

- security researchers studying execution-based analysis of agent or workflow systems
- artifact evaluators and paper reviewers
- developers extending the runtime, telemetry, or analysis pipeline

If you are looking for a static policy checker, this is the wrong abstraction. ProvLoom is intended for runtime, evidence-backed analysis.
