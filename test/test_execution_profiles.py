from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.analyzer.capability_inference import infer_capability_profile
from app.analyzer.execution_profiles import (
    PROFILE_ADAPTER_BACKED,
    PROFILE_AUTO,
    PROFILE_BASE_LIGHTWEIGHT,
    PROFILE_BROWSER_LIGHTWEIGHT,
    build_execution_plan,
    update_plan_with_budget_outcome,
)
from app.backend.schemas import LLMConfig
from app.runner.models import ResourceUsage, SandboxExecution, TraceArtifacts
from app.runtime.skill_parser import load_skill_definition
from scripts.batch_scan_skills import scan_one_skill


def _write_skill(root: Path, content: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(content, encoding="utf-8")


def _base_skill_markdown() -> str:
    return """# Minimal Skill

```skill-actions
[
  {
    "id": "write_note",
    "type": "write_file",
    "name": "Write Note",
    "path": "runtime_output/note.txt",
    "content": "ok"
  }
]
```
"""


class _FakeRunner:
    def __init__(self, execution: SandboxExecution) -> None:
        self.execution = execution

    def run(self, **kwargs):  # noqa: ANN003 - test fake
        return self.execution


class ExecutionProfilesTests(unittest.TestCase):
    def test_auto_selection_chooses_browser_when_required(self) -> None:
        capability_profile = {
            "capability_tags": ["requires_browser"],
            "complexity_score": 2,
        }
        plan = build_execution_plan(
            capability_profile=capability_profile,
            requested_profile=PROFILE_AUTO,
            allow_profile_promotion=True,
            max_promotion_steps=1,
            default_timeout_seconds=600,
        )
        self.assertEqual(plan.effective_profile, PROFILE_BROWSER_LIGHTWEIGHT)
        self.assertEqual(plan.selection_source, "auto")

    def test_manual_profile_overrides_auto(self) -> None:
        capability_profile = {
            "capability_tags": ["requires_browser"],
            "complexity_score": 2,
        }
        plan = build_execution_plan(
            capability_profile=capability_profile,
            requested_profile=PROFILE_ADAPTER_BACKED,
            allow_profile_promotion=True,
            max_promotion_steps=1,
            default_timeout_seconds=600,
        )
        self.assertEqual(plan.effective_profile, PROFILE_ADAPTER_BACKED)
        self.assertEqual(plan.selection_source, "manual")

    def test_promotion_is_limited_by_max_steps(self) -> None:
        capability_profile = {
            "capability_tags": [],
            "complexity_score": 0,
        }
        plan = build_execution_plan(
            capability_profile=capability_profile,
            requested_profile=PROFILE_BASE_LIGHTWEIGHT,
            allow_profile_promotion=True,
            max_promotion_steps=0,
            default_timeout_seconds=600,
        )
        update_plan_with_budget_outcome(
            plan=plan,
            timed_out=True,
            memory_peak_bytes=None,
            memory_limit_bytes=None,
        )
        self.assertTrue(plan.budget_exceeded)
        self.assertEqual(plan.promoted_profile, "")
        self.assertEqual(plan.promotion_reason, "budget_exceeded_but_promotion_disabled")

    def test_profile_information_is_written_to_scan_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-profile-scan-") as tmp:
            root = Path(tmp)
            _write_skill(root, _base_skill_markdown())
            definition = load_skill_definition(root, allow_empty_actions=True)
            capability = infer_capability_profile(root, skill_definition=definition)
            plan = build_execution_plan(
                capability_profile=capability.to_dict(),
                requested_profile=PROFILE_AUTO,
                allow_profile_promotion=True,
                max_promotion_steps=1,
                default_timeout_seconds=90,
            )
            execution = SandboxExecution(
                execution_id="fake-exec",
                skill_path=str(root),
                skill_file="SKILL.md",
                sandbox_image="fake",
                runtime_name=definition.runtime,
                command=["python3"],
                exit_code=0,
                timed_out=False,
                stdout="ok",
                stderr="",
                trace_artifacts=TraceArtifacts(),
                file_events=[],
                network_events=[],
                process_events=[],
                tool_calls=[],
                llm_events=[],
                data_flows=[],
                resource_usage=ResourceUsage(
                    memory_limit_bytes=plan.profile_config.memory_limit_mb * 1024 * 1024,
                    memory_peak_bytes=16 * 1024 * 1024,
                ),
                artifacts_dir=str(root),
            )
            result = scan_one_skill(
                skill_root=root,
                definition=definition,
                capability_profile=capability,
                execution_plan=plan.to_dict(),
                trigger_plan={},
                runner=_FakeRunner(execution),
                analysis_mode="rule_only",
                network_policy="default",
                timeout_seconds=plan.profile_config.timeout_seconds,
                provider="siliconflow",
                api_key="",
                base_url="",
                model="",
                force_llm_on_empty_actions=True,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.selected_execution_profile, plan.effective_profile)
            self.assertIsNotNone(result.execution_profile_config)
            self.assertIsNotNone(result.execution_plan)
            self.assertEqual(result.first_attempt_profile, plan.first_attempt_profile)
            self.assertEqual(result.execution_outcome, "completed_full")

    def test_default_path_still_base_lightweight(self) -> None:
        capability_profile = {"capability_tags": [], "complexity_score": 0}
        plan = build_execution_plan(
            capability_profile=capability_profile,
            requested_profile=PROFILE_AUTO,
            allow_profile_promotion=False,
            max_promotion_steps=0,
            default_timeout_seconds=600,
        )
        self.assertEqual(plan.effective_profile, PROFILE_BASE_LIGHTWEIGHT)
        self.assertEqual(plan.execution_mode, "full")


if __name__ == "__main__":
    unittest.main()
