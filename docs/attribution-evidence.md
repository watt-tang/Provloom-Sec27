# Attribution Evidence

This note explains why root-cause attribution in the benchmark is evidence-backed rather than label-only.

## Principle

Each predicted root cause is exported together with a small evidence bundle:

- supporting telemetry references,
- relevant graph nodes and graph edges,
- implicated tool calls,
- implicated LLM steps when present.

The goal is to let a reviewer inspect why the label was assigned instead of accepting a bare class name.

## Evidence Fields

Each case result may include:

- `root_cause_detail`
- `root_cause_evidence.summary`
- `root_cause_evidence.tool_refs`
- `root_cause_evidence.llm_refs`
- `root_cause_evidence.telemetry_refs`
- `root_cause_evidence.graph_node_ids`
- `root_cause_evidence.graph_edge_refs`

## Label-to-Evidence Mapping

### `unsafe_dataflow_design`

Backed by:

- a recovered primary source-to-sink chain,
- file and network telemetry,
- graph node and edge references that connect source, relay, and sink.

### `unsafe_command_construction`

Backed by:

- `run_command` tool calls,
- shell-enabled or templated command declarations,
- matching `execve` telemetry when available.

### `overprivileged_tool_use`

Backed by:

- outward `http_request` tool calls,
- local generated artifacts such as `runtime_output/*`,
- graph edges that connect the artifact to the network sink.

### `llm_decision_induced_action`

Backed by:

- LLM event records,
- LLM step identifiers,
- the downstream tool invocation selected after the LLM step.

### `prompt_injection_suspected`

Backed by:

- prompt-like instruction markers in the Skill markdown or LLM metadata,
- downstream risky tool choices that follow the injected instruction pattern.

## Review Guidance

When reviewing a case, the intended order is:

1. Check the predicted `root_cause_detail`.
2. Read the short evidence summary.
3. Verify the cited tool or LLM step.
4. Confirm the graph node or edge references in the exported artifacts.

This review flow is the practical meaning of the claim:

`attribution is evidence-backed, not label-only`.
