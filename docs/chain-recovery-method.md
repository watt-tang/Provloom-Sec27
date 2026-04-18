# Chain Recovery Method

This note documents how the benchmarked system chooses the exported `primary_chain`.

## Goal

The exported chain is not a replay of every runtime event. It is a compact analyst-facing path that answers:

- where the risky data starts,
- what relay step carries it forward,
- where it exits the sandbox.

The chain is therefore a semantic explanation artifact rather than a syscall-level trace dump.

## Source Candidate Selection

The analyzer ranks file nodes before running path search.

Priority order:

1. Tool-linked sensitive files such as `/etc/*` that are explicitly connected to declared Skill actions.
2. Tool-linked generated local artifacts such as `runtime_output/*`.
3. Tool-linked public or bundled local files.
4. Trace-only sensitive files.
5. Trace-only generated local artifacts.
6. Everything else.

This ranking prevents the exported source from being dominated by runtime side effects such as loader or resolver reads when the benchmarked Skill itself manipulates a clearer source artifact.

## Sink Candidate Selection

Network endpoints are ranked by analyst relevance:

1. Declared URL endpoints such as `https://httpbin.org/post`.
2. Tool-linked network nodes reached through `http_request` actions.
3. Raw process-level IP:port connections.

This choice keeps the sink aligned with the benchmark ground truth and with what a reviewer would consider the intended exfiltration target.

## Path Search

Once source and sink candidates are prepared, the analyzer runs a shortest-path search over the execution provenance graph.

Edges traversed:

- forward edges for all graph relations,
- reverse traversal for causal and dataflow relations such as `causes` and `flows_to`.

## Multi-Path Ranking

If multiple source-to-sink paths exist, the analyzer picks the best path by the following ordering:

1. Shorter path length.
2. Fewer known noise nodes.
3. Better source priority as defined above.
4. Preference for declared URL sinks over raw transport endpoints.
5. Stable lexical tie-breaking on source and sink labels.

This makes path choice deterministic and reviewable rather than arbitrary.

## Relay Identification

Intermediate nodes are labeled as relays when they are not the first or last node and belong to one of these types:

- `file`
- `data`
- `process`
- `tool_call`

Relays capture the analyst-relevant bridge between source and sink. Examples include:

- staged files in `runtime_output/`,
- `run_command` steps that read a staged buffer,
- `http_request` tool calls that move data to the sink.

## Chain Compression

The analyzer exports a compressed chain instead of the full graph walk.

Compression rules:

- keep the first node as the source,
- keep the last node as the sink,
- keep relay nodes that are analyst-meaningful,
- drop duplicate consecutive nodes,
- when filtering is enabled, drop intermediate noise files and noise data nodes.

Compression affects explanation readability only. It does not change the detection stage.

## Filtering Mode

`epg_with_filtering` applies a lightweight noise filter before exporting the chain.

The filter marks common runtime-noise files such as:

- `/etc/ld.so.cache`
- locale and certificate files
- Python runtime and loader files

The filter is intentionally conservative:

- it does not remove detection evidence,
- it only affects which nodes appear in the exported chain,
- it keeps source, relay, and sink nodes that remain needed for the explanation.
