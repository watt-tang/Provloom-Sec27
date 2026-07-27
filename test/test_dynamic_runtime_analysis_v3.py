from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.analyzer.rules import analyze_trace
from app.dynamic.alignment import StaticRuntimeAligner
from app.dynamic.analyzer import DynamicRuntimeAnalyzer, analyze_runtime_events
from app.dynamic.config import DynamicAnalysisConfig
from app.dynamic.event_schema import RuntimeEventFactory
from app.dynamic.marker_registry import TaintRegistry
from app.dynamic.models import RuntimeEvent
from app.runner.models import ResourceUsage, SandboxExecution, TraceArtifacts
from app.telemetry.collector import build_execution_report
from app.telemetry.normalizer import build_normalized_events


def _fixture(test_name: str):
    config = DynamicAnalysisConfig(sensitive_source_patterns=["/secret/**"])
    registry = TaintRegistry(run_id=f"RUN-{test_name}", config=config.marker, seed=test_name)
    source = registry.register_source(source_type="credential", source_location="/secret/api_key")
    factory = RuntimeEventFactory(session_id=f"RUN-{test_name}", skill_id="skill-under-test")
    return config, registry, source, factory


def _execution(tmp: Path) -> SandboxExecution:
    return SandboxExecution(
        execution_id="single-run-test",
        skill_path=str(tmp),
        skill_file="SKILL.md",
        sandbox_image="test",
        runtime_name="unit",
        command=["python3"],
        exit_code=0,
        timed_out=False,
        stdout="",
        stderr="",
        trace_artifacts=TraceArtifacts(),
        file_events=[],
        network_events=[],
        process_events=[],
        tool_calls=[],
        llm_events=[],
        data_flows=[],
        resource_usage=ResourceUsage(),
        artifacts_dir=str(tmp),
    )


class DynamicRuntimeAnalysisV3Tests(unittest.TestCase):
    def test_connect_only_never_confirms_confidentiality(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="file_read", process_id=1, actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="read", data_preview=source.marker),
            ev.create(timestamp=2, event_type="network_connect", process_id=1, actor_type="process", actor_id="PROC:1", object_type="network", object_id="NET:https://example.test", operation="connect", metadata={"url": "https://example.test"}),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)

        self.assertFalse([chain for chain in result.chains if chain.chain_type == "confidentiality_confirmed"])
        self.assertFalse([chain for chain in result.chains if chain.chain_type == "confidentiality_candidate"])

    def test_hash_only_flow_is_not_original_secret_exfiltration(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="network_send", process_id=2, actor_type="process", actor_id="PROC:2", object_type="network", object_id="NET:https://evil.test", operation="send", metadata={"url": "https://evil.test", "body": source.variants["sha256"]}),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)

        self.assertFalse([chain for chain in result.chains if chain.chain_type == "confidentiality_confirmed"])
        self.assertFalse(result.policy_violations)

    def test_process_context_does_not_taint_constant_file_or_upload(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="file_read", process_id=3, actor_type="process", actor_id="PROC:3", object_type="file", object_path="/secret/api_key", operation="read", data_preview=source.marker),
            ev.create(timestamp=2, event_type="file_write", process_id=3, actor_type="process", actor_id="PROC:3", object_type="file", object_path="runtime_output/constant.txt", operation="write", data_preview="constant", metadata={"output_from_tainted_input": True}),
            ev.create(timestamp=3, event_type="file_upload", process_id=3, actor_type="process", actor_id="PROC:3", object_type="network", object_id="NET:https://evil.test/upload", operation="upload", metadata={"url": "https://evil.test/upload", "upload_file_path": "runtime_output/constant.txt"}),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)

        self.assertFalse([chain for chain in result.chains if chain.chain_type == "confidentiality_confirmed"])
        constant_write = [event for event in result.runtime_events if event.object_path == "runtime_output/constant.txt"][0]
        self.assertEqual(constant_write.taint_ids, [])
        self.assertEqual(constant_write.metadata.get("context_taint_ids"), [source.taint_id])

    def test_tls_invisible_payload_is_instrumentation_gap(self) -> None:
        config, registry, _source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="network_send", process_id=4, actor_type="process", actor_id="PROC:4", object_type="network", object_id="NET:https://secure.test", operation="send", metadata={"url": "https://secure.test", "encrypted_payload_invisible": True}, instrumentation_visibility="encrypted_payload_invisible"),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)

        self.assertEqual(result.coverage.coverage_state, "instrumentation_gap")
        self.assertIn("encrypted_payload_invisible", result.coverage.missing_observations)

    def test_structured_taint_sink_http_body_closes_confirmed_chain(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="sensitive_source", process_id=None, actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="source", taint_ids=[source.taint_id], evidence_level="confirmed"),
            ev.create(timestamp=2, event_type="network_send", process_id=None, actor_type="tool", actor_id="TOOL:send_secret", object_type="network", object_id="NET:https://evil.test/post", operation="send", taint_ids=[source.taint_id], evidence_level="confirmed", evidence_strength="structured_relation", carrier_type="http_body", carrier_location="body", metadata={"destination": "https://evil.test/post", "network_evidence_level": "tainted_payload_observed"}),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)

        self.assertTrue([chain for chain in result.chains if chain.chain_type == "confidentiality_confirmed"])
        self.assertTrue(result.policy_violations)

    def test_runtime_event_old_json_loads_and_file_object_id_is_stable(self) -> None:
        payload = {
            "event_id": "EVOLD",
            "timestamp": 1.0,
            "event_type": "file_read",
            "process_id": 1,
            "parent_process_id": None,
            "session_id": "RUN",
            "skill_id": "skill",
            "actor_type": "process",
            "actor_id": "PROC:1",
            "object_type": "file",
            "object_id": "FILE:/secret/api_key",
            "object_path": "/secret/api_key",
            "operation": "read",
            "taint_ids": [],
            "evidence_level": "unknown",
            "raw_source": "strace",
            "raw_reference": "trace-1",
            "metadata": {},
        }

        loaded = RuntimeEvent.from_dict(payload)
        created = RuntimeEventFactory(session_id="RUN", skill_id="skill").create(event_type="file_read", timestamp=1, object_type="file", object_path="/tmp/a", operation="read")

        self.assertEqual(loaded.observation_source, "strace_syscall")
        self.assertEqual(created.object_id, "FILE:/tmp/a")

    def test_multi_carrier_edges_are_not_merged(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        events = [
            ev.create(timestamp=1, event_type="network_send", process_id=5, actor_type="process", actor_id="PROC:5", object_type="network", object_id="NET:https://evil.test", operation="send", metadata={"url": "https://evil.test", "headers": {"X-Token": source.marker}}),
            ev.create(timestamp=2, event_type="network_send", process_id=5, actor_type="process", actor_id="PROC:5", object_type="network", object_id="NET:https://evil.test", operation="send", metadata={"url": "https://evil.test", "body": source.marker}),
        ]

        result = analyze_runtime_events(events, config=config, registry=registry)
        send_edges = [edge for edge in result.graph.edges if edge.edge_type == "SENDS"]

        self.assertGreaterEqual(len(send_edges), 2)
        self.assertIn("http_header", {edge.carrier_type for edge in send_edges})
        self.assertIn("http_body", {edge.carrier_type for edge in send_edges})

    def test_static_runtime_alignment_reports_endpoint_contradiction(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        result = analyze_runtime_events(
            [ev.create(timestamp=1, event_type="network_send", process_id=6, actor_type="process", actor_id="PROC:6", object_type="network", object_id="NET:https://evil.test", operation="send", metadata={"url": "https://evil.test", "body": source.marker})],
            config=config,
            registry=registry,
        )
        static_result = {"entities": [{"entity_id": "E1", "alignment_keys": {"domain": "official.test"}}], "actions": []}

        alignment = StaticRuntimeAligner().align(graph=result.graph, chains=result.chains, coverage=result.coverage, static_result=static_result)

        self.assertEqual(alignment["status"], "contradicted")
        self.assertTrue(alignment["contradictions"])

    def test_provided_dynamic_result_prevents_duplicate_analysis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-v3-") as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "SKILL.md").write_text("name: empty\nruntime: sequential\nactions: []\n", encoding="utf-8")
            execution = _execution(tmp)
            normalized = build_normalized_events(execution)
            dynamic_result = DynamicRuntimeAnalyzer(skill_root=execution.skill_path).analyze_execution(execution, normalized)

            with patch("app.analyzer.rules.DynamicRuntimeAnalyzer.analyze_execution", side_effect=AssertionError("duplicate analyze")):
                analyze_trace(execution, analysis_mode="rule_only", normalized_events=normalized, dynamic_result=dynamic_result)
            with patch("app.telemetry.collector.DynamicRuntimeAnalyzer.analyze_execution", side_effect=AssertionError("duplicate analyze")):
                build_execution_report(execution, normalized_events=normalized, dynamic_result=dynamic_result)


if __name__ == "__main__":
    unittest.main()
