from __future__ import annotations

import unittest

from app.analyzer.execution_profiles import PROFILE_BASE_LIGHTWEIGHT, build_execution_plan
from app.analyzer.skip_taxonomy import (
    SKIP_AUTH_OR_EXTERNAL_ACCOUNT_REQUIRED,
    SKIP_ECOSYSTEM_ADAPTER_MISSING,
    SKIP_RESOURCE_BUDGET_EXCEEDED,
    SKIP_TRIGGER_CONDITION_UNSATISFIED,
    build_skip_bundle,
    categorize_skip,
    classify_execution_outcome,
)
from scripts.batch_scan_skills import preflight_taxonomy_category


class SkipTaxonomyTests(unittest.TestCase):
    def test_auth_required_skill_maps_to_auth_category(self) -> None:
        category = categorize_skip(
            skip_reason="llm_skill_requires_api_key",
            capability_profile={"capability_tags": ["requires_external_api_key"]},
            execution_plan={},
            trigger_hits=[],
            budget_exceeded=False,
            static_report={},
        )
        self.assertEqual(category, SKIP_AUTH_OR_EXTERNAL_ACCOUNT_REQUIRED)

    def test_adapter_missing_skill_maps_to_ecosystem_missing(self) -> None:
        cap = {"capability_tags": ["requires_messaging_stack"], "complexity_score": 3}
        plan = build_execution_plan(
            capability_profile=cap,
            requested_profile=PROFILE_BASE_LIGHTWEIGHT,
            allow_profile_promotion=False,
            max_promotion_steps=0,
            default_timeout_seconds=120,
        )
        category = preflight_taxonomy_category(
            capability_profile=type("Cap", (), {"capability_tags": cap["capability_tags"]})(),  # lightweight stub
            execution_plan=plan.to_dict(),
            skip_reason=None,
        )
        self.assertEqual(category, SKIP_ECOSYSTEM_ADAPTER_MISSING)

    def test_trigger_not_satisfied_maps_to_trigger_category(self) -> None:
        category = categorize_skip(
            skip_reason="trigger_condition_unsatisfied",
            capability_profile={"capability_tags": []},
            execution_plan={},
            trigger_hits=[],
            budget_exceeded=False,
            static_report={},
        )
        self.assertEqual(category, SKIP_TRIGGER_CONDITION_UNSATISFIED)

    def test_budget_exceeded_maps_to_budget_category(self) -> None:
        category = categorize_skip(
            skip_reason="",
            capability_profile={"capability_tags": []},
            execution_plan={},
            trigger_hits=[],
            budget_exceeded=True,
            static_report={},
        )
        self.assertEqual(category, SKIP_RESOURCE_BUDGET_EXCEEDED)

    def test_partial_analysis_is_emitted_for_skip(self) -> None:
        bundle = build_skip_bundle(
            skip_category=SKIP_AUTH_OR_EXTERNAL_ACCOUNT_REQUIRED,
            skip_reason="llm_skill_requires_api_key",
            capability_profile={"capability_tags": ["requires_external_api_key"]},
            execution_plan={"effective_profile": "base_lightweight", "profile_config": {"adapters_enabled": []}},
            static_report={
                "detected_behaviors": ["network_access", "process_spawn"],
                "risk_score": 25,
                "root_cause_detail": "overprivileged_tool_use",
                "source_assessment": {"sensitivity": "UNKNOWN"},
                "sink_assessment": {"semantics": "UNKNOWN_NETWORK_SINK"},
            },
            trigger_plan={"trigger_depth": "standard", "budget_class": "medium"},
            trigger_hits=[],
            trigger_used=[],
            budget_exceeded=False,
            status="skipped",
        )
        self.assertTrue(bundle.skip_explanation["whether_partial_analysis_is_meaningful"])
        self.assertTrue(bundle.partial_evidence["observed_behaviors"])
        self.assertIn("provisional", bundle.partial_evidence["evidence_strength"])

    def test_runnable_path_outcome_unchanged(self) -> None:
        outcome = classify_execution_outcome(
            status="completed",
            skip_category=None,
            partial_meaningful=False,
            budget_exceeded=False,
        )
        self.assertEqual(outcome, "completed_full")


if __name__ == "__main__":
    unittest.main()

