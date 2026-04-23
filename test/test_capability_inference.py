from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.analyzer.capability_inference import (
    CAPABILITY_REQUIRES_BROWSER,
    CAPABILITY_REQUIRES_CALLBACK_OR_WEBHOOK,
    CAPABILITY_REQUIRES_DOCUMENT_OR_OFFICE_STACK,
    CAPABILITY_REQUIRES_EXTERNAL_API_KEY,
    CAPABILITY_REQUIRES_LOCAL_HELPER_TOOLING,
    CAPABILITY_REQUIRES_OAUTH_OR_LOGIN,
    FEASIBILITY_BLOCKED,
    FEASIBILITY_READY,
    PROFILE_ADAPTER_BACKED,
    PROFILE_BASE_LIGHTWEIGHT,
    PROFILE_BROWSER_LIGHTWEIGHT,
    infer_capability_profile,
)
from app.analyzer.rules import analyze_trace
from app.runner.models import ResourceUsage, SandboxExecution, TraceArtifacts


def _write_skill(path: Path, body: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(body, encoding="utf-8")


class CapabilityInferenceTests(unittest.TestCase):
    def test_browser_skill_infers_browser_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-browser-") as tmp:
            root = Path(tmp)
            _write_skill(
                root,
                """# Browser Skill

Use Playwright to open a website and collect DOM text.
""",
            )
            (root / "package.json").write_text(
                '{"dependencies":{"playwright":"^1.0.0"}}',
                encoding="utf-8",
            )
            profile = infer_capability_profile(root)
            self.assertIn(CAPABILITY_REQUIRES_BROWSER, profile.capability_tags)
            self.assertEqual(profile.recommended_profile, PROFILE_BROWSER_LIGHTWEIGHT)

    def test_webhook_skill_infers_adapter_backed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-webhook-") as tmp:
            root = Path(tmp)
            _write_skill(
                root,
                """# Webhook Skill

The workflow waits for a webhook callback and posts status when callback arrives.
""",
            )
            profile = infer_capability_profile(root)
            self.assertIn(CAPABILITY_REQUIRES_CALLBACK_OR_WEBHOOK, profile.capability_tags)
            self.assertEqual(profile.recommended_profile, PROFILE_ADAPTER_BACKED)
            self.assertEqual(profile.execution_feasibility, FEASIBILITY_BLOCKED)

    def test_document_skill_infers_office_stack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-doc-") as tmp:
            root = Path(tmp)
            _write_skill(
                root,
                """# Office Skill

Convert user spreadsheet xlsx into report docx and publish summary.
""",
            )
            (root / "requirements.txt").write_text("openpyxl\npython-docx\n", encoding="utf-8")
            profile = infer_capability_profile(root)
            self.assertIn(CAPABILITY_REQUIRES_DOCUMENT_OR_OFFICE_STACK, profile.capability_tags)
            self.assertEqual(profile.recommended_profile, PROFILE_ADAPTER_BACKED)

    def test_auth_login_skill_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-auth-") as tmp:
            root = Path(tmp)
            _write_skill(
                root,
                """# Auth Skill

Sign in with OAuth login flow, then call API using API key.
""",
            )
            profile = infer_capability_profile(root)
            self.assertIn(CAPABILITY_REQUIRES_OAUTH_OR_LOGIN, profile.capability_tags)
            self.assertIn(CAPABILITY_REQUIRES_EXTERNAL_API_KEY, profile.capability_tags)
            self.assertEqual(profile.execution_feasibility, FEASIBILITY_BLOCKED)
            self.assertTrue(profile.blocking_requirements)

    def test_simple_local_skill_defaults_to_base(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-local-") as tmp:
            root = Path(tmp)
            _write_skill(
                root,
                """# Local Helper Skill

```skill-actions
[
  {
    "id": "run_helper",
    "type": "run_command",
    "name": "Run Helper",
    "command": "python tools/helper.py",
    "shell": true
  }
]
```
""",
            )
            (root / "tools").mkdir(exist_ok=True)
            (root / "tools" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
            profile = infer_capability_profile(root)
            self.assertIn(CAPABILITY_REQUIRES_LOCAL_HELPER_TOOLING, profile.capability_tags)
            self.assertEqual(profile.recommended_profile, PROFILE_BASE_LIGHTWEIGHT)
            self.assertEqual(profile.execution_feasibility, FEASIBILITY_READY)

    def test_unknown_skill_uses_conservative_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-default-") as tmp:
            root = Path(tmp)
            _write_skill(root, "# Simple Skill\n\nNo external integrations.\n")
            profile = infer_capability_profile(root)
            self.assertEqual(profile.capability_tags, [])
            self.assertEqual(profile.recommended_profile, PROFILE_BASE_LIGHTWEIGHT)
            self.assertEqual(profile.execution_feasibility, FEASIBILITY_READY)
            self.assertIn("default:no_strong_capability_signal", profile.inferred_from)

    def test_analyze_trace_contains_capability_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provloom-cap-trace-") as tmp:
            root = Path(tmp)
            _write_skill(root, "# Trace Skill\n\nSimple local skill.")
            execution = SandboxExecution(
                execution_id="exec-capability-trace",
                skill_path=str(root),
                skill_file="SKILL.md",
                sandbox_image="test",
                runtime_name="test-runtime",
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
                artifacts_dir=str(root),
            )
            result = analyze_trace(execution, analysis_mode="rule_only")
            self.assertIn("capability_profile", result)
            self.assertIn("capability_tags", result)
            self.assertIn("recommended_execution_profile", result)
            self.assertIn("execution_feasibility", result)
            self.assertIn("blocking_requirements", result)


if __name__ == "__main__":
    unittest.main()

