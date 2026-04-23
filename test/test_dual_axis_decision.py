from __future__ import annotations

import unittest

from app.analyzer.dual_axis_decision import (
    EVIDENCE_CHAIN_BACKED,
    EVIDENCE_PARTIAL,
    EVIDENCE_SPECULATIVE,
    SEVERITY_BENIGN,
    SEVERITY_SEVERE,
    SEVERITY_SUBSTANTIAL,
    SEVERITY_WEAK,
    infer_dual_axis_decision,
)


class DualAxisDecisionTests(unittest.TestCase):
    def test_chain_backed_exfiltration(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=95,
            risk_level="critical",
            detected_behaviors=["network_access", "sensitive_file_read", "read_then_exfiltration"],
            source_assessment={"sensitivity": "HIGH_SENSITIVITY"},
            sink_assessment={"is_external": True, "semantics": "PUBLIC_UPLOAD_OR_POST"},
            primary_chain=[{"node_type": "file"}, {"node_type": "tool_call"}, {"node_type": "network_endpoint"}],
            trigger_used=["prompt_normal_task"],
            trigger_hits=["prompt_normal_task"],
            enabled_adapters=["webhook"],
            execution_outcome="completed_full",
            skip_category=None,
            llm_involved=True,
        )
        self.assertEqual(result["severity_label"], SEVERITY_SEVERE)
        self.assertEqual(result["evidence_strength"], EVIDENCE_CHAIN_BACKED)

    def test_outward_action_unknown_source(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=25,
            risk_level="medium",
            detected_behaviors=["network_access"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": True, "semantics": "UNKNOWN_NETWORK_SINK"},
            primary_chain=[{"node_type": "network_endpoint"}],
            trigger_used=["prompt_outward_transfer_probe"],
            trigger_hits=[],
            enabled_adapters=[],
            execution_outcome="completed_partial",
            skip_category="trigger_condition_unsatisfied",
            llm_involved=False,
        )
        self.assertEqual(result["severity_label"], SEVERITY_WEAK)
        self.assertIn(result["evidence_strength"], {EVIDENCE_PARTIAL, EVIDENCE_SPECULATIVE})

    def test_suspicious_command_weak_context(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=30,
            risk_level="medium",
            detected_behaviors=["process_spawn", "shell_execution"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": False, "semantics": "TOOL_INTERNAL_ENDPOINT"},
            primary_chain=[],
            trigger_used=[],
            trigger_hits=[],
            enabled_adapters=[],
            execution_outcome="completed_partial",
            skip_category=None,
            llm_involved=False,
        )
        self.assertIn(result["severity_label"], {SEVERITY_WEAK, SEVERITY_SUBSTANTIAL})
        self.assertEqual(result["evidence_strength"], EVIDENCE_PARTIAL)

    def test_benign_public_relay(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=0,
            risk_level="low",
            detected_behaviors=[],
            source_assessment={"sensitivity": "LOW_SENSITIVITY"},
            sink_assessment={"is_external": False, "semantics": "PUBLIC_FETCH_ONLY"},
            primary_chain=[],
            trigger_used=[],
            trigger_hits=[],
            enabled_adapters=[],
            execution_outcome="completed_full",
            skip_category=None,
            llm_involved=False,
        )
        self.assertEqual(result["severity_label"], SEVERITY_BENIGN)

    def test_partial_evidence_only(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=55,
            risk_level="high",
            detected_behaviors=["network_access", "process_spawn"],
            source_assessment={"sensitivity": "UNKNOWN"},
            sink_assessment={"is_external": True, "semantics": "UNKNOWN_NETWORK_SINK"},
            primary_chain=[{"node_type": "network_endpoint"}],
            trigger_used=["prompt_normal_task"],
            trigger_hits=[],
            enabled_adapters=["messaging"],
            execution_outcome="skipped_bounded",
            skip_category="ecosystem_adapter_missing",
            llm_involved=True,
        )
        self.assertEqual(result["evidence_strength"], EVIDENCE_PARTIAL)

    def test_legacy_risk_compatibility(self) -> None:
        result = infer_dual_axis_decision(
            risk_score=70,
            risk_level="high",
            detected_behaviors=["network_access"],
            source_assessment={"sensitivity": "MEDIUM_SENSITIVITY"},
            sink_assessment={"is_external": True, "semantics": "PUBLIC_UPLOAD_OR_POST"},
            primary_chain=[{"node_type": "file"}, {"node_type": "network_endpoint"}],
            trigger_used=[],
            trigger_hits=[],
            enabled_adapters=[],
            execution_outcome="completed_full",
            skip_category=None,
            llm_involved=False,
        )
        self.assertEqual(result["decision_rationale"]["legacy_risk"]["risk_score"], 70)
        self.assertEqual(result["decision_rationale"]["legacy_risk"]["risk_level"], "high")


if __name__ == "__main__":
    unittest.main()

