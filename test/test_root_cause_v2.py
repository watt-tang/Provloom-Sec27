from __future__ import annotations

import unittest

from app.analyzer.root_cause_v2 import (
    DRIVER_LLM_DECISION,
    DRIVER_MIXED,
    EVIDENCE_ADAPTER_LIMITED,
    MECHANISM_BENIGN_PUBLIC_RELAY,
    MECHANISM_ECOSYSTEM_COUPLED_EXTERNALIZATION,
    MECHANISM_PROMPT_MEDIATED_ACTION,
    MECHANISM_UNSAFE_COMMAND_CONSTRUCTION,
    MECHANISM_UNSAFE_DATAFLOW_DESIGN,
    infer_root_cause_v2,
)


class RootCauseV2Tests(unittest.TestCase):
    def test_dataflow_external_transfer(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="skill_design",
            legacy_root_cause_detail="unsafe_dataflow_design",
            detected_behaviors=["network_access", "sensitive_file_read", "read_then_exfiltration"],
            source_assessment={"sensitivity": "HIGH_SENSITIVITY", "from_public_lineage": False, "label": "/etc/passwd"},
            sink_assessment={"is_external": True, "semantics": "PUBLIC_UPLOAD_OR_POST"},
            primary_chain=[{"node_type": "file"}, {"node_type": "tool_call"}, {"node_type": "network_endpoint"}],
            root_cause_evidence={"graph_node_ids": ["a", "b", "c"], "graph_edge_refs": [{"source_node_id": "a", "target_node_id": "b"}]},
            execution_outcome="completed_full",
            skip_category=None,
            trigger_used=["prompt_normal_task"],
            trigger_hits=["prompt_normal_task"],
            enabled_adapters=[],
            llm_involved=False,
            analysis_mode="rule_plus_epg",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_UNSAFE_DATAFLOW_DESIGN)
        self.assertEqual(result["legacy_root_cause_detail"], "unsafe_dataflow_design")

    def test_risky_command_case(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="skill_design",
            legacy_root_cause_detail="unsafe_command_construction",
            detected_behaviors=["process_spawn", "shell_execution"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": False, "semantics": "TOOL_INTERNAL_ENDPOINT"},
            primary_chain=[],
            root_cause_evidence={},
            execution_outcome="completed_full",
            skip_category=None,
            trigger_used=[],
            trigger_hits=[],
            enabled_adapters=[],
            llm_involved=False,
            analysis_mode="rule_only",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_UNSAFE_COMMAND_CONSTRUCTION)

    def test_prompt_induced_case(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="prompt_injection_suspected",
            legacy_root_cause_detail="prompt_injection_suspected",
            detected_behaviors=["network_access"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": True, "semantics": "UNKNOWN_NETWORK_SINK"},
            primary_chain=[],
            root_cause_evidence={},
            execution_outcome="completed_partial",
            skip_category=None,
            trigger_used=["prompt_boundary_task"],
            trigger_hits=[],
            enabled_adapters=[],
            llm_involved=True,
            analysis_mode="rule_only",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_PROMPT_MEDIATED_ACTION)
        self.assertEqual(result["primary_driver"], DRIVER_LLM_DECISION)

    def test_platform_dependent_partial_case(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="unknown",
            legacy_root_cause_detail="unknown",
            detected_behaviors=["network_access"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": True, "semantics": "CALLBACK_OR_WEBHOOK"},
            primary_chain=[{"node_type": "network_endpoint"}],
            root_cause_evidence={},
            execution_outcome="skipped_bounded",
            skip_category="ecosystem_adapter_missing",
            trigger_used=["event_webhook_arrival"],
            trigger_hits=[],
            enabled_adapters=["webhook"],
            llm_involved=False,
            analysis_mode="rule_only",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_ECOSYSTEM_COUPLED_EXTERNALIZATION)
        self.assertEqual(result["evidence_status"], EVIDENCE_ADAPTER_LIMITED)

    def test_benign_public_relay_case(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="unknown",
            legacy_root_cause_detail="unknown",
            detected_behaviors=["network_access", "file_write"],
            source_assessment={"sensitivity": "LOW_SENSITIVITY", "from_public_lineage": True, "label": "public/news.txt"},
            sink_assessment={"is_external": True, "semantics": "PUBLIC_UPLOAD_OR_POST"},
            primary_chain=[{"node_type": "file"}, {"node_type": "network_endpoint"}],
            root_cause_evidence={},
            execution_outcome="completed_full",
            skip_category=None,
            trigger_used=[],
            trigger_hits=[],
            enabled_adapters=[],
            llm_involved=False,
            analysis_mode="rule_only",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_BENIGN_PUBLIC_RELAY)

    def test_llm_involved_but_not_sole_driver(self) -> None:
        result = infer_root_cause_v2(
            legacy_root_cause="skill_design",
            legacy_root_cause_detail="unsafe_dataflow_design",
            detected_behaviors=["network_access", "sensitive_file_read", "read_then_exfiltration"],
            source_assessment={"sensitivity": "HIGH_SENSITIVITY", "from_public_lineage": False, "label": "/etc/hosts"},
            sink_assessment={"is_external": True, "semantics": "PUBLIC_UPLOAD_OR_POST"},
            primary_chain=[{"node_type": "file"}, {"node_type": "tool_call"}, {"node_type": "network_endpoint"}],
            root_cause_evidence={"graph_node_ids": ["a", "b", "c"], "graph_edge_refs": [{"source_node_id": "a", "target_node_id": "b"}]},
            execution_outcome="completed_full",
            skip_category=None,
            trigger_used=["prompt_outward_transfer_probe"],
            trigger_hits=["prompt_outward_transfer_probe"],
            enabled_adapters=[],
            llm_involved=True,
            analysis_mode="rule_plus_epg",
        )
        self.assertEqual(result["mechanism_class"], MECHANISM_UNSAFE_DATAFLOW_DESIGN)
        self.assertEqual(result["primary_driver"], DRIVER_MIXED)
        self.assertNotEqual(result["primary_driver"], DRIVER_LLM_DECISION)


if __name__ == "__main__":
    unittest.main()
