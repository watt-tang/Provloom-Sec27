from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from app.analyzer.rules import analyze_trace
from app.dynamic.assessment import assess_dynamic_result, canonical_from_dict, validate_consistency
from app.dynamic.analyzer import DynamicAnalysisResult, analyze_runtime_events
from app.dynamic.config import DynamicAnalysisConfig
from app.dynamic.event_schema import RuntimeEventFactory, runtime_events_from_normalized
from app.dynamic.marker_registry import TaintRegistry
from app.dynamic.models import CoverageReport, RuntimeChain, RuntimeProvenanceGraph
from app.runner.models import ResourceUsage, SandboxExecution, TraceArtifacts
from app.runtime.container_runtime import LLMAgentSkillRuntime, SkillToolExecutor
from app.runtime.skill_parser import SkillAction, SkillDefinition
from app.taint.source_registry import SourceRegistry
from app.telemetry.normalizer import NormalizedEvent, build_normalized_events


def _fixture(name: str, *, trusted_llm: bool = True):
    config = DynamicAnalysisConfig(sensitive_source_patterns=["/secret/**"])
    if not trusted_llm:
        config.trusted_llm_providers = []
        config.trusted_llm_provider_domains = []
    registry = TaintRegistry(run_id=f"RUN-{name}", config=config.marker, seed=name)
    source = registry.register_source(source_type="credential", source_location="/secret/api_key")
    factory = RuntimeEventFactory(session_id=f"RUN-{name}", skill_id="skill-under-test")
    return config, registry, source, factory


def _execution(tmp: Path, *, exit_code: int = 0) -> SandboxExecution:
    (tmp / "SKILL.md").write_text("---\nname: probe\nruntime: provloom-embedded\n---\n```skill-actions\n[]\n```\n", encoding="utf-8")
    return SandboxExecution(
        execution_id="canonical-test",
        skill_path=str(tmp),
        skill_file="SKILL.md",
        sandbox_image="test",
        runtime_name="unit",
        command=["python3"],
        exit_code=exit_code,
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


class DynamicCanonicalAssessmentTests(unittest.TestCase):
    def test_policy_violation_overrides_legacy_benign(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        dynamic = analyze_runtime_events(
            [
                ev.create(timestamp=1, event_type="sensitive_source", actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="source", taint_ids=[source.taint_id], evidence_level="confirmed"),
                ev.create(timestamp=2, event_type="network_send", actor_type="tool", actor_id="TOOL:send", object_type="network", object_id="NET:https://evil.test/post", operation="send", taint_ids=[source.taint_id], evidence_level="confirmed", evidence_strength="structured_relation", carrier_type="http_body", carrier_location="body", metadata={"destination": "https://evil.test/post", "body": source.marker}),
            ],
            config=config,
            registry=registry,
        )
        with tempfile.TemporaryDirectory(prefix="provloom-canonical-") as tmpdir:
            execution = _execution(Path(tmpdir))
            report = analyze_trace(execution, analysis_mode="rule_only", normalized_events=build_normalized_events(execution), dynamic_result=dynamic)

        self.assertEqual(report["policy_violation_count"], 1)
        self.assertEqual(report["canonical_assessment"]["status"], "violation_confirmed")
        self.assertNotEqual(report["final_decision"], "benign")
        self.assertGreaterEqual(report["risk_score"], 80)
        self.assertTrue(any(factor["code"] == "dynamic_v3_policy_violation" for factor in report["triggered_factors"]))

    def test_trusted_authorization_header_is_confirmed_but_permitted(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        config.trusted_egress_allowlist = ["network:NET:https://trusted.test/auth"]
        dynamic = analyze_runtime_events(
            [
                ev.create(timestamp=1, event_type="sensitive_source", actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="source", taint_ids=[source.taint_id], evidence_level="confirmed"),
                ev.create(timestamp=2, event_type="network_send", actor_type="tool", actor_id="TOOL:auth", object_type="network", object_id="NET:https://trusted.test/auth", operation="send", taint_ids=[source.taint_id], evidence_level="confirmed", evidence_strength="structured_relation", carrier_type="http_header", carrier_location="headers.authorization", metadata={"destination": "https://trusted.test/auth", "headers": {"Authorization": "Bearer [TAINT]"}}),
            ],
            config=config,
            registry=registry,
        )
        assessment = assess_dynamic_result(dynamic)

        self.assertTrue([chain for chain in dynamic.chains if chain.chain_type == "confidentiality_confirmed"])
        self.assertFalse(dynamic.policy_violations)
        self.assertEqual(assessment.status, "no_violation_observed")
        self.assertEqual(assessment.canonical_final_decision, "benign")

    def test_candidate_and_instrumentation_gap_require_review(self) -> None:
        candidate = RuntimeChain(
            chain_id="RC1",
            chain_type="confidentiality_candidate",
            source="source:T1",
            sink="network:NET:https://example.test",
            taint_ids=["T1"],
            ordered_nodes=["source:T1", "network:NET:https://example.test"],
            ordered_edges=["E1"],
            supporting_event_ids=["EV1"],
            evidence_level="candidate",
        )
        dynamic = DynamicAnalysisResult(
            runtime_events=[],
            graph=RuntimeProvenanceGraph(session_id="RUN"),
            chains=[candidate],
            coverage=CoverageReport("insufficient_coverage", missing_observations=["payload_not_observed"]),
            policy_violations=[],
            taint_sources=[],
        )
        assessment = assess_dynamic_result(dynamic)

        self.assertEqual(assessment.status, "review_required")
        self.assertEqual(assessment.canonical_final_decision, "malicious")
        self.assertTrue(assessment.review_required)

    def test_target_reached_no_flow_is_benign_and_execution_failed_is_review(self) -> None:
        no_flow = DynamicAnalysisResult([], RuntimeProvenanceGraph(session_id="RUN"), [], CoverageReport("target_reached_no_flow"), [], [])
        failed = DynamicAnalysisResult([], RuntimeProvenanceGraph(session_id="RUN"), [], CoverageReport("execution_failed"), [], [])

        self.assertEqual(assess_dynamic_result(no_flow).canonical_final_decision, "benign")
        self.assertEqual(assess_dynamic_result(failed).canonical_final_decision, "benign")
        self.assertTrue(assess_dynamic_result(failed).review_required)

    def test_llm_context_request_becomes_confirmed_carrier_without_plaintext(self) -> None:
        normalized = [
            NormalizedEvent(
                event_id="llm-request-1",
                timestamp="2026-01-01T00:00:00Z",
                execution_id="RUN",
                step_id="step-2",
                event_type="llm_step",
                source="runtime",
                parent_event_id=None,
                metadata={
                    "event": "request",
                    "provider": "siliconflow",
                    "model": "deepseek-ai/DeepSeek-V3.2",
                    "base_url": "https://api.siliconflow.cn/v1",
                    "endpoint_host": "api.siliconflow.cn",
                    "taint_ids": ["T001"],
                    "evidence_level": "confirmed",
                    "evidence_strength": "structured_relation",
                    "carrier_type": "llm_context",
                    "carrier_location": "messages[3].content",
                    "plaintext_stored": False,
                    "llm_context_observations": [
                        {
                            "carrier_location": "messages[3].content",
                            "role": "user",
                            "taint_ids": ["T001"],
                            "content_sha256": "abc",
                            "byte_count": 12,
                            "redacted_preview": "[TOOL_RESULT_WITH_TAINT:T001]",
                            "plaintext_stored": False,
                        }
                    ],
                },
            )
        ]
        events = runtime_events_from_normalized(normalized, session_id="RUN", skill_id="skill")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "llm_request")
        self.assertEqual(events[0].carrier_type, "llm_context")
        self.assertEqual(events[0].taint_ids, ["T001"])
        serialized = str(events[0].to_dict())
        self.assertNotIn("PROBE_SECRET_MARKER", serialized)
        self.assertNotIn("sk-", serialized)

    def test_trusted_and_untrusted_llm_provider_policy(self) -> None:
        trusted_config, trusted_registry, trusted_source, trusted_ev = _fixture(self.id() + "-trusted")
        trusted = analyze_runtime_events(
            [
                trusted_ev.create(timestamp=1, event_type="sensitive_source", actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="source", taint_ids=[trusted_source.taint_id], evidence_level="confirmed"),
                trusted_ev.create(timestamp=2, event_type="llm_request", actor_type="agent", actor_id="AGENT:step-2", object_type="network", object_id="NET:https://api.siliconflow.cn/v1", operation="send", taint_ids=[trusted_source.taint_id], evidence_level="confirmed", evidence_strength="structured_relation", carrier_type="llm_context", carrier_location="messages[3].content", metadata={"provider": "siliconflow", "endpoint_host": "api.siliconflow.cn"}),
            ],
            config=trusted_config,
            registry=trusted_registry,
        )
        untrusted_config, untrusted_registry, untrusted_source, untrusted_ev = _fixture(self.id() + "-untrusted", trusted_llm=False)
        untrusted = analyze_runtime_events(
            [
                untrusted_ev.create(timestamp=1, event_type="sensitive_source", actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="source", taint_ids=[untrusted_source.taint_id], evidence_level="confirmed"),
                untrusted_ev.create(timestamp=2, event_type="llm_request", actor_type="agent", actor_id="AGENT:step-2", object_type="network", object_id="NET:https://unknown-llm.test/v1", operation="send", taint_ids=[untrusted_source.taint_id], evidence_level="confirmed", evidence_strength="structured_relation", carrier_type="llm_context", carrier_location="messages[3].content", metadata={"provider": "unknown", "endpoint_host": "unknown-llm.test"}),
            ],
            config=untrusted_config,
            registry=untrusted_registry,
        )

        self.assertTrue([chain for chain in trusted.chains if chain.chain_type == "confidentiality_confirmed"])
        self.assertFalse(trusted.policy_violations)
        self.assertTrue(untrusted.policy_violations)

    def test_runtime_llm_metadata_redacts_tainted_tool_result(self) -> None:
        definition = SkillDefinition(skill_root=".", skill_file="SKILL.md", name="s", description="", runtime="deepseek-agent", actions=[])
        runtime = LLMAgentSkillRuntime(
            definition=definition,
            input_payload={},
            context={},
            executor=type("Executor", (), {"get_tool_catalog": lambda self, actions: []})(),
            emit_func=lambda *args, **kwargs: "",
            llm_config={"base_url": "https://api.siliconflow.cn/v1", "api_key": "sk-test-secret", "model": "m", "provider": "siliconflow"},
        )
        runtime._message_taint_ids[1] = ["T001"]
        metadata = runtime._llm_context_metadata(
            [
                {"role": "system", "content": "system prompt"},
                {"role": "user", "content": "Tool result contains PROBE_SECRET_MARKER_20260727"},
            ]
        )

        self.assertEqual(metadata["taint_ids"], ["T001"])
        self.assertFalse(metadata["plaintext_stored"])
        self.assertNotIn("PROBE_SECRET_MARKER", str(metadata))
        self.assertNotIn("system prompt", str(metadata))
        self.assertNotIn("sk-test-secret", str(metadata))

    def test_sensitive_read_file_runtime_event_redacts_stdout_preview(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-runtime-redact-") as tmpdir:
            root = Path(tmpdir)
            secret_dir = root / ".provloom" / "private"
            secret_dir.mkdir(parents=True)
            secret = "PROBE_SECRET_MARKER_20260727_UNIT"
            (secret_dir / "secret.txt").write_text(secret, encoding="utf-8")
            events = []
            executor = SkillToolExecutor(
                root,
                {"execution_id": "redact-test"},
                lambda category, event, payload, step_id=None, parent_event_id=None: events.append(payload) or f"{category}-{event}",
            )
            action = SkillAction(id="read_secret", type="read_file", name="Read Secret", config={"path": ".provloom/private/secret.txt"})
            stdout = StringIO()
            with redirect_stdout(stdout):
                result = executor.execute_action(action)

        finish = events[-1]
        self.assertEqual(result["_taint_ids"], finish["output_taint_ids"])
        self.assertFalse(finish["stdout_plaintext_stored"])
        self.assertIn("stdout_sha256", finish)
        self.assertNotIn(secret, str(finish))
        self.assertEqual(stdout.getvalue(), "")

    def test_process_context_endpoint_only_and_etc_hosts_do_not_create_candidate(self) -> None:
        config, registry, source, ev = _fixture(self.id())
        result = analyze_runtime_events(
            [
                ev.create(timestamp=1, event_type="file_read", process_id=1, actor_type="process", actor_id="PROC:1", object_type="file", object_path="/secret/api_key", operation="read", data_preview=source.marker),
                ev.create(timestamp=2, event_type="network_connect", process_id=1, actor_type="process", actor_id="PROC:1", object_type="network", object_id="NET:https://example.test", operation="connect", instrumentation_visibility="endpoint_only"),
            ],
            config=config,
            registry=registry,
        )

        self.assertFalse([chain for chain in result.chains if chain.chain_type == "confidentiality_candidate"])
        hosts_match = SourceRegistry().match_path("/etc/hosts")
        self.assertIsNotNone(hosts_match)
        self.assertEqual(hosts_match.sensitivity, "public")

    def test_legacy_canonical_compatibility_and_consistency_validator(self) -> None:
        legacy = canonical_from_dict({})
        errors = validate_consistency(
            {
                "canonical_assessment": {"status": "violation_confirmed"},
                "policy_violation_count": 1,
                "risk_score": 0,
                "final_decision": "benign",
                "coverage_state": "runtime_confirmed",
            }
        )

        self.assertEqual(legacy.status, "review_required")
        self.assertIn("policy_violation_with_benign_decision", errors)
        self.assertIn("policy_violation_below_violation_threshold", errors)


if __name__ == "__main__":
    unittest.main()
