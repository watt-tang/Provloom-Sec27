from __future__ import annotations

import json
import subprocess
import sys

from app.reporting.skill_report import generate_markdown


def complete_result() -> dict:
    return {
        "skill_id": "skill-1",
        "skill_name": "demo",
        "skill_path": "/skills/demo",
        "repository": "repo/demo",
        "scan_time": "2026-05-10T00:00:00Z",
        "scanner_version": "1.0.0",
        "rule_version": "rules-1",
        "status": "success",
        "final_risk": "critical",
        "evidence_type": "observed_runtime",
        "root_cause": "unsafe_dataflow_design",
        "primary_chain": {
            "source": "/etc/passwd",
            "relay": "Write File runtime_output/passwd.txt",
            "sink": "https://example.test/upload",
        },
        "observed_runtime_chain": {
            "source": "/etc/passwd",
            "relay": "runtime_output/passwd.txt",
            "sink": "https://example.test/upload",
        },
        "instruction_derived_chain": {
            "trust_boundary": "SKILL.md",
            "control_transfer": "Send report",
            "impact_sink": "https://example.test/upload",
        },
        "runtime_events": [
            {
                "timestamp": "2026-05-10T00:00:02Z",
                "event_type": "network_connect",
                "actor": "python",
                "action": "post",
                "object": "runtime_output/passwd.txt",
                "target": "https://example.test/upload",
                "raw": "POST https://example.test/upload",
            }
        ],
        "instruction_evidence": [
            {
                "file": "SKILL.md",
                "line": 8,
                "evidence_type": "instruction",
                "matched_text": "Send report",
                "chain_role": "control_transfer",
            }
        ],
        "findings": [
            {
                "finding_id": "f-low",
                "severity": "low",
                "rule_id": "LOW001",
                "rule_name": "Low Rule",
                "file": "b.md",
                "line": 10,
                "evidence_type": "static",
                "description": "desc",
                "matched_text": "low",
                "recommendation": "fix low",
            },
            {
                "finding_id": "f-critical",
                "severity": "critical",
                "rule_id": "CRIT001",
                "rule_name": "Critical Rule",
                "file": "a.md",
                "line": 1,
                "matched_text": "critical",
                "recommendation": "fix critical",
                "chain": {"source": "a", "relay": "b", "sink": "https://example.test"},
            },
        ],
        "indicators": [{"indicator": "url", "severity": "info", "evidence": "https://example.test"}],
        "rule_hits": [{"rule_id": "NET001", "severity": "high", "pattern": "https://example.test"}],
        "behaviors": [{"behavior": "sensitive_file_read", "description": "reads sensitive file"}],
        "files": [{"path": "SKILL.md", "file_type": "markdown", "matched": True, "highest_risk": "critical", "evidence_count": 2}],
        "recommendation": "top-level fix",
    }


def test_complete_single_skill_json() -> None:
    md = generate_markdown(complete_result())

    assert md.startswith("# Single-Skill Evidence Explanation Report")
    assert "| Skill ID | skill-1 |" in md
    assert "| Closed Chain | true |" in md
    assert "| Reviewer Action | Immediate manual review required |" in md
    assert "## 3. Evidence-Type Classification" in md
    assert "## 4. Primary Chain Explanation" in md
    assert "| Sink crosses trust boundary | pass |" in md
    assert "## 15. Human Reviewer Checklist" in md
    assert '"closed_chain": true' in md
    assert md.index("### Finding 1: Critical Rule") < md.index("### Finding 2: Low Rule")


def test_only_primary_chain_without_findings() -> None:
    data = {
        "risk_level": "high",
        "primary_chain": {"source": "source.txt", "relay": "Send", "sink": "https://example.test"},
    }
    md = generate_markdown(data)

    assert "source.txt -> Send -> https://example.test" in md
    assert "The JSON result does not include finding-level records." in md


def test_only_observed_runtime_chain() -> None:
    md = generate_markdown({"observed_runtime_chain": {"source": "s", "relay": "r", "sink": "https://x.test"}})

    assert "runtime-observed candidate chain" in md
    assert "| Derived evidence_type | observed_runtime |" in md
    assert "s -> r -> https://x.test" in md


def test_only_instruction_derived_chain() -> None:
    md = generate_markdown(
        {"instruction_derived_chain": {"trust_boundary": "doc", "control_transfer": "Send", "impact_sink": "webhook"}}
    )

    assert "instruction-derived candidate chain" in md
    assert "| Derived evidence_type | instruction_derived |" in md
    assert "doc -> Send -> webhook" in md
    assert "must not be described as a runtime attack" in md


def test_runtime_and_instruction_chains() -> None:
    md = generate_markdown(
        {
            "observed_runtime_chain": {"source": "s", "relay": "r", "sink": "k"},
            "instruction_derived_chain": {"trust_boundary": "t", "control_transfer": "c", "impact_sink": "i"},
        }
    )

    assert "| Derived evidence_type | hybrid |" in md
    assert "## 5. Runtime-Observed Evidence" in md
    assert "## 6. Instruction-Derived Evidence" in md


def test_evidence_type_missing_derives_from_structure() -> None:
    md = generate_markdown({"observed_runtime_chain": {"source": "s", "relay": "r", "sink": "k"}})

    assert "| Evidence type source | derived_from_json_structure |" in md


def test_provloom_final_risk_level_overrides_legacy_risk_level() -> None:
    md = generate_markdown(
        {
            "final_risk_level": "critical",
            "risk_level": "low",
            "chain_evidence_type": "instruction_derived",
            "instruction_chain_recovered": True,
            "instruction_chain": [{"source": "doc", "action": "persistence_setup", "target": "cron"}],
        }
    )

    assert "| Final Risk | critical |" in md
    assert "| Evidence Type | instruction_derived |" in md
    assert "| Closed Chain | true |" in md


def test_static_supply_chain_risk_can_supply_final_risk_and_closed_chain() -> None:
    md = generate_markdown(
        {
            "risk_level": "low",
            "static_supply_chain_risk": {"closed_risk_path": True, "level": "critical"},
        }
    )

    assert "| Final Risk | critical |" in md
    assert "| Closed Chain | true |" in md


def test_instruction_chain_steps_render_with_step_evidence() -> None:
    md = generate_markdown(
        {
            "dynamic_chain_observed": False,
            "instruction_chain_recovered": True,
            "instruction_chain": [
                {
                    "source": "skill_bundle_documentation",
                    "action": "external_agent_install",
                    "target": "external_agent",
                    "evidence_source": "SKILL.md",
                    "evidence_type": "document_instruction",
                    "observed_at_runtime": False,
                    "confidence": "medium",
                    "raw_snippet": "install agent",
                },
                {
                    "source": "external_agent",
                    "action": "persistence_setup",
                    "target": "recurring_execution",
                    "evidence_source": "setup.sh",
                    "evidence_type": "document_instruction",
                    "observed_at_runtime": False,
                    "confidence": "high",
                    "raw_snippet": "launchctl load",
                },
            ],
        }
    )

    assert "skill_bundle_documentation --external_agent_install--> external_agent --persistence_setup--> recurring_execution" in md
    assert "| 1 | skill_bundle_documentation | external_agent_install | external_agent | SKILL.md | document_instruction | false | medium | install agent |" in md
    assert "Boundary Classification: instruction-derived latent chain; not a runtime-observed attack." in md


def test_observed_runtime_evidence_uses_primary_chain_when_evidence_type_observed() -> None:
    md = generate_markdown(
        {
            "evidence_type": "observed_runtime",
            "primary_chain": {"source": "s", "relay": "r", "sink": "https://runtime.test"},
        }
    )

    section5 = md.split("## 5. Runtime-Observed Evidence", 1)[1].split("## 6. Instruction-Derived Evidence", 1)[0]
    assert "Runtime chain source: primary_chain" in section5
    assert "s -> r -> https://runtime.test" in section5
    assert "No runtime-observed evidence was provided" not in section5


def test_hybrid_outputs_runtime_and_instruction_machine_summary() -> None:
    md = generate_markdown(
        {
            "evidence_type": "hybrid",
            "primary_chain": {"source": "runtime-source", "relay": "runtime-relay", "sink": "https://runtime.test"},
            "instruction_chain": [{"source": "doc", "action": "persistence_setup", "target": "cron"}],
            "instruction_chain_recovered": True,
        }
    )

    assert "runtime-source -> runtime-relay -> https://runtime.test" in md
    assert "doc --persistence_setup--> cron" in md
    assert '"runtime_chain": {' in md
    assert '"instruction_chain_summary": {' in md


def test_instruction_validity_uses_latent_chain_checks() -> None:
    md = generate_markdown(
        {
            "instruction_chain_recovered": True,
            "instruction_chain": [{"source": "doc", "action": "global_environment_modification", "target": "global_execution_environment"}],
        }
    )

    assert "| Has trust boundary | pass |" in md
    assert "| Has control transfer | pass |" in md
    assert "| Has impact sink | pass |" in md
    assert "| Path crosses trust boundary | pass |" in md
    assert "| Latent chain closed | pass |" in md
    assert "| Sink crosses trust boundary |" not in md


def test_skipped_status_is_reported_even_without_skipped_reason() -> None:
    md = generate_markdown({"status": "skipped"})

    assert "* Scan Status: skipped" in md
    assert "runtime execution skipped does not invalidate instruction-derived evidence" in md


def test_instruction_action_root_cause_mapping() -> None:
    md = generate_markdown(
        {
            "root_cause": "unknown",
            "instruction_chain": [
                {"source": "doc", "action": "remote_script_or_binary_acquisition", "target": "script"},
                {"source": "script", "action": "persistence_setup", "target": "cron"},
            ],
        }
    )

    assert "| Root Cause | supply_chain_setup |" in md


def test_no_closed_chain_only_indicators() -> None:
    md = generate_markdown({"risk_level": "high", "indicators": [{"indicator": "url", "evidence": "http://x"}]})

    assert "weak-indicator-based result" in md
    assert "| Closed Chain | false |" in md
    assert "Inspect weak indicators before escalation" in md
    assert "| 1 | url | indicators |" in md


def test_safe_risk_action_is_review_optional() -> None:
    md = generate_markdown({"risk_level": "safe", "indicators": [{"indicator": "url"}]})

    assert "| Reviewer Action | Review optional |" in md


def test_critical_closed_chain_action() -> None:
    md = generate_markdown({"final_risk": "critical", "primary_chain": {"source": "s", "relay": "r", "sink": "https://x"}})

    assert "Immediate manual review required" in md


def test_medium_closed_chain_action() -> None:
    md = generate_markdown({"final_risk": "medium", "primary_chain": {"source": "s", "relay": "r", "sink": "https://x"}})

    assert "Manual review recommended" in md


def test_missing_final_risk_action() -> None:
    md = generate_markdown({"primary_chain": {"source": "s", "relay": "r", "sink": "https://x"}})

    assert "Risk level missing; manual triage required" in md


def test_runtime_events() -> None:
    md = generate_markdown({"runtime_events": [{"type": "file_read", "process": "python", "target": "/tmp/a"}]})

    assert "### 5.2 Runtime Event Table" in md
    assert "| 1 | file_read | python | not available | not available | /tmp/a | not available | not available |" in md


def test_instruction_evidence() -> None:
    md = generate_markdown({"instruction_evidence": [{"path": "SKILL.md", "line_number": 2, "text": "upload", "role": "impact_sink"}]})

    assert "### 6.2 Local Instruction Evidence" in md
    assert "| 1 | SKILL.md | 2 | not available | upload | impact_sink |" in md


def test_errors() -> None:
    md = generate_markdown({"errors": [{"type": "ParseError", "message": "bad", "location": "input"}]})

    assert "### 12.1 Errors" in md
    assert "| 1 | ParseError | bad | input | not available |" in md


def test_skipped_reason() -> None:
    md = generate_markdown({"skipped_reason": "not runnable"})

    assert "* Skipped Reason: not runnable" in md


def test_missing_all_optional_fields() -> None:
    md = generate_markdown({"skill_name": "minimal"})

    assert "| evidence_type | missing |" in md
    assert "No runtime-observed evidence was provided" in md
    assert "No remediation or recommendation text was provided" in md


def test_deterministic_output_for_same_json() -> None:
    data = complete_result()

    assert generate_markdown(data) == generate_markdown(json.loads(json.dumps(data, ensure_ascii=False)))


def test_cli_generates_matching_markdown(tmp_path) -> None:
    src = tmp_path / "single_skill_result.json"
    dst = tmp_path / "single_skill_result.md"
    src.write_text(json.dumps(complete_result(), ensure_ascii=False), encoding="utf-8")

    subprocess.run(
        [sys.executable, "scripts/generate_skill_report.py", "--input", str(src), "--output", str(dst)],
        check=True,
    )

    assert dst.read_text(encoding="utf-8") == generate_markdown(complete_result())
