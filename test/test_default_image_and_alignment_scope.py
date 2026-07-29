from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from app.backend.api import runner as api_runner
from app.dynamic import cli as dynamic_cli
from app.explanation.builder import build_unified_explanation
from app.runner.docker_runner import DEFAULT_SANDBOX_IMAGE, DockerRunner
from scripts import batch_scan_skills, run_benchmark


class DefaultImageAndAlignmentScopeTests(unittest.TestCase):
    def test_api_cli_batch_and_benchmark_default_to_dynamic_v3_image(self) -> None:
        self.assertEqual(DockerRunner().image_name, DEFAULT_SANDBOX_IMAGE)
        self.assertEqual(api_runner.image_name, DEFAULT_SANDBOX_IMAGE)
        self.assertEqual(batch_scan_skills.build_runner().image_name, DEFAULT_SANDBOX_IMAGE)
        self.assertEqual(run_benchmark.build_runner().image_name, DEFAULT_SANDBOX_IMAGE)

        captured = {}

        class FakeAnalysis:
            artifacts_dir = "artifacts/runs/UNIT"
            dynamic_result = None
            report = {
                "exit_code": 0,
                "timed_out": False,
                "sandbox_image": DEFAULT_SANDBOX_IMAGE,
                "sandbox_image_id": "sha256:test",
                "source_fingerprint": "fingerprint-test",
                "coverage_certificate": {},
                "static_runtime_alignment": {},
                "unified_explanation": {},
            }

        def fake_analyze(*args, **kwargs):
            captured["image"] = kwargs["runner"].image_name
            return FakeAnalysis()

        root = Path(tempfile.mkdtemp(prefix="provloom-cli-image-"))
        (root / "SKILL.md").write_text("Format a local note.\n", encoding="utf-8")
        with patch.object(dynamic_cli, "analyze_skill_bundle", side_effect=fake_analyze), redirect_stdout(io.StringIO()):
            exit_code = dynamic_cli.main(["run", str(root), "--run-id", "UNIT", "--input", "{}"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["image"], DEFAULT_SANDBOX_IMAGE)

    def test_alignment_separates_runtime_internal_unresolved_from_relevant(self) -> None:
        runtime = {
            "schema_version": "runtime-analysis-v3",
            "runtime_events": [
                {
                    "event_id": "EV-INTERNAL",
                    "event_type": "file_read",
                    "object_type": "file",
                    "object_path": "/usr/local/lib/python3.10/os.py",
                    "operation": "read",
                    "metadata": {},
                },
                {
                    "event_id": "EV-NET",
                    "event_type": "network_connect",
                    "object_type": "network",
                    "object_id": "NET:https://example.test",
                    "operation": "connect",
                    "metadata": {"destination": "https://example.test"},
                },
            ],
            "runtime_provenance_graph": {
                "nodes": [
                    {"node_id": "FILE-INTERNAL", "node_type": "File", "label": "FILE:/usr/local/lib/python3.10/os.py", "metadata": {"path": "/usr/local/lib/python3.10/os.py"}}
                ],
                "edges": [],
            },
            "runtime_chains": [],
        }
        unified = build_unified_explanation(skill_id="scope", static_result={}, dynamic_result=runtime).to_dict()

        internal_ids = {rid for item in unified["internal_unresolved"] for rid in item["runtime_ids"]}
        relevant_ids = {rid for item in unified["relevant_unresolved"] for rid in item["runtime_ids"]}
        runtime_only_ids = {rid for item in unified["runtime_only_paths"] for rid in item.get("runtime_ids", [])}

        self.assertIn("FILE-INTERNAL", internal_ids)
        self.assertIn("EV-INTERNAL", internal_ids)
        self.assertIn("EV-NET", relevant_ids)
        self.assertFalse({"FILE-INTERNAL", "EV-INTERNAL"} & runtime_only_ids)

    def test_alignment_does_not_filter_sensitive_or_static_related_paths(self) -> None:
        runtime = {
            "schema_version": "runtime-analysis-v3",
            "runtime_events": [
                {
                    "event_id": "EV-SHADOW",
                    "event_type": "file_read",
                    "object_type": "file",
                    "object_path": "/etc/shadow",
                    "operation": "read",
                    "taint_ids": ["T-SHADOW"],
                    "metadata": {},
                }
            ],
            "runtime_provenance_graph": {
                "nodes": [
                    {"node_id": "FILE-SHADOW", "node_type": "File", "label": "FILE:/etc/shadow", "metadata": {"path": "/etc/shadow"}},
                    {"node_id": "FILE-STATIC-INTERNAL", "node_type": "File", "label": "FILE:/usr/local/lib/python3.10/os.py", "metadata": {"path": "/usr/local/lib/python3.10/os.py"}},
                ],
                "edges": [],
            },
            "runtime_chains": [],
        }
        static_result = {
            "schema_version": "provloom-static-v2",
            "resolved_entities": [{"entity_id": "E-PY", "entity_type": "File", "canonical_value": "/usr/local/lib/python3.10/os.py"}],
            "extracted_actions": [],
            "static_chains": [],
        }
        unified = build_unified_explanation(skill_id="scope", static_result=static_result, dynamic_result=runtime).to_dict()

        internal_ids = {rid for item in unified["internal_unresolved"] for rid in item["runtime_ids"]}
        relevant_ids = {rid for item in unified["relevant_unresolved"] for rid in item["runtime_ids"]}
        aligned_ids = {rid for item in unified["alignments"] if item["status"] == "aligned" for rid in item["runtime_ids"]}

        self.assertNotIn("EV-SHADOW", internal_ids)
        self.assertNotIn("FILE-SHADOW", internal_ids)
        self.assertIn("EV-SHADOW", relevant_ids)
        self.assertIn("FILE-STATIC-INTERNAL", aligned_ids)


if __name__ == "__main__":
    unittest.main()
