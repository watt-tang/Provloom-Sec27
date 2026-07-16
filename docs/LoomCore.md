# LoomCore: A Lightweight OpenClaw-Style Execution Kernel for ProvLoom

## Abstract

LoomCore is the execution kernel used by ProvLoom to expose a security-relevant runtime surface for Skill analysis. It is intentionally lightweight: it aligns with OpenClaw-style Skill execution semantics (tool-centric, step-driven, LLM-orchestrated workflows), while prioritizing explanation-oriented telemetry for triage rather than platform completeness. LoomCore is therefore not a full OpenClaw reimplementation, not an OS-level provenance collector, and not a full static analyzer. Its role is to provide structured runtime evidence that supports ProvLoom's provenance reconstruction and root-cause attribution pipeline.

## 1. Design Position in ProvLoom

ProvLoom targets explainable Skill risk triage through a multi-stage pipeline:

1. telemetry normalization;
2. execution provenance graph (EPG) construction;
3. observed primary-chain reconstruction;
4. instruction-level latent-chain recovery;
5. root-cause and evidence-type attribution.

LoomCore is the runtime substrate that produces the execution traces consumed by these stages. It sits between Skill execution and provenance analysis, exposing a stable, analyzable event stream (`runtime-events.jsonl`, `normalized-events.jsonl`) and deterministic artifact outputs.

## 2. Scope and Non-Goals

### 2.1 In-Scope

- Skill-level execution with explicit tool invocation semantics.
- Security-relevant action capture for file/process/network/tool/LLM events.
- Event linking sufficient for causal explanation and chain reconstruction.
- Reproducible artifact export for benchmark and case-study evaluation.

### 2.2 Out-of-Scope

- Kernel-complete system provenance (e.g., full syscall dependency closure).
- eBPF-grade host observability and fleet-level telemetry ingestion.
- Full OpenClaw runtime compatibility and production multi-tenant orchestration.
- Sound-and-complete static verification of all Skill control/data flows.

## 3. OpenClaw-Style Alignment

LoomCore follows OpenClaw-style execution principles at the security surface:

- **Tool as execution primitive.** Actions are normalized around tool calls (e.g., `read_file`, `write_file`, `run_command`, `http_request`).
- **Step-centric orchestration.** LLM and tool activities are organized by `step_id` and parent-child linkage.
- **Hybrid observability.** High-level semantic events (tool/LLM) are fused with low-level runtime traces (file/process/network) for cross-layer reasoning.
- **Artifactized replayability.** Each run exports stable analysis inputs and outputs for auditing.

This alignment is functional rather than exhaustive: LoomCore reproduces the analysis-critical surface, not the full platform feature set.

## 4. Kernel Architecture

LoomCore is implemented as a compact execution-and-telemetry kernel with four logical layers.

### 4.1 Skill Runtime Adapter

The runtime adapter parses Skill definitions and executes actions through a constrained tool catalog. Each action emits structured `tool_call` start/finish events with configuration, status, and previews, forming the semantic backbone of later attribution.

### 4.2 Telemetry Collection Layer

LoomCore collects heterogeneous runtime evidence:

- `tool_call` events from the action executor;
- `llm` events for request/response decision points;
- process/file/network trace records from runtime instrumentation;
- optional data-flow hints derived from sensitive reads and outbound connections.

### 4.3 Telemetry Normalization Layer

ProvLoom canonicalizes collected events into a single `NormalizedEvent` schema with:

- stable `event_id` and `execution_id`,
- `timestamp`,
- `event_type`,
- `step_id`,
- `parent_event_id`,
- typed metadata payload.

Normalization resolves cross-source linkage (e.g., LLM request -> tool call -> process/file/network traces), producing an ordering and reference structure suitable for graph construction.

### 4.4 Provenance Interface Layer

The normalized stream is consumed by downstream analyzers to build EPG nodes/edges and support:

- source-to-sink primary-chain extraction,
- instruction-level latent-chain inference,
- evidence-backed root-cause attribution.

LoomCore does not embed policy verdict logic as its primary responsibility; it exports provenance-ready evidence for analyzer modules.

## 5. Security-Relevant Execution Surface

LoomCore models four primary operation classes:

1. **Data acquisition:** local reads (including sensitive paths).
2. **Data transformation/staging:** command or file-write mediated relays.
3. **Decision mediation:** LLM steps that influence downstream action choice.
4. **Data egress:** outbound HTTP/network endpoints.

This surface is deliberately minimal but sufficient for common Skill risk patterns (e.g., read-then-exfiltration, unsafe command construction, overprivileged outbound transfer, LLM-induced risky action selection).

## 6. Event Semantics and Causal Linking

LoomCore uses explicit event semantics to preserve explanation fidelity:

- **Temporal order:** total ordering by `(timestamp, event_id)`.
- **Execution lineage:** parent-child references across LLM/tool/trace events.
- **Step affinity:** shared `step_id` for decision-to-action grouping.
- **Endpoint semantics:** normalized sink labeling (URL/domain/IP roles and resolution state) for analyst-meaningful sink attribution.

These properties allow ProvLoom to reconstruct concise chains that are semantically interpretable, rather than raw trace dumps.

## 7. Why Lightweight Matters

A lightweight kernel is a deliberate design tradeoff:

- It reduces runtime and integration complexity for rapid triage experiments.
- It keeps the telemetry contract stable across benchmark runs.
- It prioritizes explanation quality over exhaustive observability.

For ProvLoom's stated goal (explanation-oriented security triage prototype), this tradeoff improves reproducibility and reviewability without claiming full-system completeness.

## 8. Reliability and Reproducibility Properties

LoomCore contributes to reproducibility through:

- deterministic artifact layout per execution,
- canonical normalized event export (`normalized-events.jsonl`),
- stable interfaces between runtime capture and analyzer stages,
- explicit evidence references used in final attribution outputs.

These properties support paper claims about auditable and repeatable analysis.

## 9. Limitations

LoomCore inherits known limitations from its intentional scope:

- possible blind spots for channels not represented in the captured surface;
- no guarantee of complete provenance closure at OS/kernel granularity;
- dependence on available instrumentation quality for trace-level events;
- analyst-facing chain reconstruction may compress paths and omit benign runtime noise.

Accordingly, LoomCore should be interpreted as an analysis kernel for risk explanation, not a prevention-enforcement boundary.

## 10. Summary

LoomCore provides ProvLoom with a compact, OpenClaw-style execution kernel that captures the right security-relevant runtime semantics for provenance-centric explanation. By design, it bridges Skill execution and attribution-grade evidence while remaining lightweight, reproducible, and aligned with ProvLoom's non-goal of avoiding full platform or OS-level provenance replication.
