# Threat Model

## Analysis Objects

- `SKILL.md` files
- Skill bundles with local scripts and assets
- Declared actions and runtime tool invocations
- Runtime file, process, network, tool-call, and LLM telemetry

## Attacker Capabilities

- The attacker can author or modify `SKILL.md`.
- The attacker can influence input payloads passed to a Skill.
- The attacker can cause a Skill to access external endpoints.
- The attacker can influence LLM-driven action selection through prompt-like instructions embedded in Skill content.

## Detection Targets

- Sensitive file read followed by external transfer
- Unsafe command construction and command execution misuse
- Overprivileged external transfer of locally generated data
- Indirect exfiltration via staged files or buffers
- LLM-induced unsafe action selection

## Out of Scope

- Kernel-complete provenance collection
- eBPF-based tracing
- Frontend triage or analyst UI
- Long-lived interactive agent sessions with unbounded tool use
- Complete prevention of all exfiltration channels
