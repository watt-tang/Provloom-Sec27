# Related Work Notes

## Representative Papers

### 1. AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents
- Source: https://arxiv.org/abs/2406.13352
- One-line summary: AgentDojo provides a dynamic benchmark with realistic tasks and security test cases for evaluating prompt injection attacks and defenses in tool-using LLM agents.
- Difference from our system: AgentDojo is an evaluation environment for robustness; our system is an analysis pipeline that explains a concrete execution through telemetry normalization, provenance graph construction, chain recovery, and root-cause attribution.

### 2. InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents
- Source: https://arxiv.org/abs/2403.02691
- One-line summary: InjecAgent benchmarks indirect prompt injection risk across many tool-integrated LLM agents and shows that these agents are vulnerable to attacks that hide instructions in external content.
- Difference from our system: InjecAgent measures vulnerability and attack success; our system focuses on post-hoc explanation of how the risky behavior forms in an execution rather than on benchmark-scale attack measurement alone.

### 3. Design Patterns for Securing LLM Agents against Prompt Injections
- Source: https://arxiv.org/abs/2506.08837
- One-line summary: This paper proposes principled design patterns for building LLM agents with stronger resistance to prompt injection and discusses their security-utility trade-offs.
- Difference from our system: The design-pattern paper is prescriptive and defense-oriented; our system is descriptive and forensic, emphasizing explainability over prevention.

### 4. ALASTOR: Reconstructing the Provenance of Serverless Intrusions
- Source: https://www.usenix.org/conference/usenixsecurity22/presentation/datta
- One-line summary: ALASTOR reconstructs provenance across serverless function executions to support forensic tracing and root-cause analysis for serverless intrusions.
- Difference from our system: ALASTOR targets serverless workflows and platform-level auditing, while our system targets Skill executions and uses benchmarked outputs to evaluate semantic chain recovery and root-cause attribution.

### 5. PROGRAPHER: An Anomaly Detection System based on Provenance Graph Embedding
- Source: https://www.usenix.org/system/files/usenixsecurity23-yang-fan.pdf
- One-line summary: PROGRAPHER performs anomaly detection over provenance graph snapshots and reports suspicious indicators to reduce analyst workload in APT-style investigations.
- Difference from our system: PROGRAPHER is a provenance-based detector optimized for anomaly detection and indicator ranking; our system uses provenance primarily to recover semantic attack chains and explain how the risk forms in a smaller, Skill-centered runtime setting.

### 6. Provably-Safe Multilingual Software Sandboxing using WebAssembly
- Source: https://www.usenix.org/conference/usenixsecurity22/presentation/bosamiya
- One-line summary: This paper shows how WebAssembly can be used to run untrusted multilingual code in a provably safe sandbox with strong safety guarantees and practical performance.
- Difference from our system: The Wasm sandboxing paper is about secure isolation of untrusted code execution itself; our system assumes a sandboxed runtime and concentrates on telemetry-driven security analysis after or during execution.
