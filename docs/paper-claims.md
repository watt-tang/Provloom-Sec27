# Paper Claims

## One-Sentence Version

We present a runtime security sandbox for Skills that reconstructs attack chains from normalized telemetry graphs and attributes root causes, enabling more explainable and reproducible security analysis than static or rule-only baselines.

## Three Claims

1. Dynamic graph-based telemetry analysis improves source-to-sink attack-chain recovery over static-only and rule-only baselines.
2. Root-cause attribution is more informative when runtime telemetry is normalized and linked into an execution graph.
3. Stable artifacts and benchmark outputs make Skill security analysis reproducible and auditable.

## Core Contributions

- A Skill-oriented runtime sandbox with normalized telemetry events.
- Execution provenance graph construction over runtime artifacts.
- Primary attack-chain reconstruction and root-cause attribution.
- A reproducible benchmark workflow with ground truth, baseline comparison, and exportable artifacts.

## Non-Contributions

- We do not claim kernel-complete provenance or eBPF-level observability.
- We do not claim exhaustive coverage of all covert or side-channel exfiltration strategies.
- We do not claim a production-grade prevention system; this is an analysis and evidence-generation prototype.
