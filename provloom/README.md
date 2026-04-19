# ProvLoom

> Lightweight runtime security sandbox for Skills.

ProvLoom is the repository's native runtime and analysis sandbox. It executes `SKILL.md`-driven Skills inside an isolated environment, records telemetry across file, process, network, tool-call, and LLM activity, and exports artifacts for security review.

## What It Is

- A self-hosted runtime implemented in this repository.
- A sandbox for reproducible Skill execution and telemetry capture.
- A benchmark-oriented analysis pipeline for provenance graphs, attack chains, and root-cause attribution.

## What It Is Not

- It is not a wrapper around an external runtime API.
- It does not depend on a proprietary external runtime engine.
- It is not a static-only checker.

## Runtime Surface

- `app/runtime/skill_parser.py` parses `SKILL.md` and executable action blocks.
- `app/runtime/container_runtime.py` executes actions and emits runtime events.
- `app/runtime/llm_client.py` drives LLM-mediated Skill execution through an OpenAI-compatible API.

## Positioning

ProvLoom is best described as a lightweight runtime security sandbox for Skills, with its own embedded runtime modes such as `provloom-embedded` and agent-driven execution through `deepseek-agent`.
