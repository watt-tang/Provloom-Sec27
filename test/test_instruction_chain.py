from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.analyzer.instruction_chain import analyze_instruction_chain
from app.analyzer.rules import analyze_static_skill
from app.runtime.skill_parser import load_skill_definition


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DANGEROUS_ROOT = PROJECT_ROOT / "dangerous_skills"


def _write_skill(text: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="provloom-instruction-chain-"))
    (root / "SKILL.md").write_text(text, encoding="utf-8")
    return root


class InstructionChainAnalyzerTests(unittest.TestCase):
    def test_auto_updater_recovers_closed_instruction_chain(self) -> None:
        skill_root = DANGEROUS_ROOT / "auto-updater-2yq87"
        definition = load_skill_definition(skill_root, allow_empty_actions=True)

        result = analyze_static_skill(definition)

        self.assertTrue(result["instruction_chain_recovered"])
        self.assertFalse(result["dynamic_chain_observed"])
        self.assertEqual(result["chain_evidence_type"], "instruction_derived")
        self.assertEqual(result["final_risk_level"], "critical")
        self.assertEqual(result["static_supply_chain_risk"]["level"], "critical")
        actions = [edge["action"] for edge in result["instruction_chain"]]
        self.assertIn("external_agent_install", actions)
        self.assertIn("remote_script_or_binary_acquisition", actions)
        self.assertIn("persistence_setup", actions)
        self.assertIn("bulk_skill_update", actions)
        self.assertTrue(all(edge["observed_at_runtime"] is False for edge in result["instruction_chain"]))
        self.assertIn("not observed", result["final_label_reason"].lower())

    def test_clawhub_bulk_update_with_fixed_password_is_critical_without_persistence(self) -> None:
        result = analyze_instruction_chain(DANGEROUS_ROOT / "cllawhub")

        self.assertTrue(result["instruction_chain_recovered"])
        self.assertEqual(result["static_supply_chain_risk"]["level"], "critical")
        categories = {item["category"] for item in result["instruction_indicators"]}
        self.assertTrue({"remote_acquisition", "fixed_password_archive"} <= categories)
        self.assertIn("fixed_password_archive", categories)
        self.assertIn("bulk_update", categories)
        self.assertNotIn("persistence", categories)
        self.assertIn("bulk skill update", result["static_supply_chain_risk"]["reason"].lower())

    def test_sensitive_capability_external_agent_is_medium_capability_risk(self) -> None:
        result = analyze_instruction_chain(DANGEROUS_ROOT / "ethereum-gas-tracker-abxf0")

        self.assertTrue(result["instruction_chain_recovered"])
        self.assertEqual(result["static_supply_chain_risk"]["level"], "medium")
        self.assertIn("capability", result["static_supply_chain_risk"]["reason"].lower())
        self.assertNotIn("exfiltration", result["static_supply_chain_risk"]["reason"].lower())

    def test_plain_dependency_install_and_public_api_curl_do_not_recover_chain(self) -> None:
        root = _write_skill(
            """---
name: benign-install
description: normal setup notes
---

# Benign Install

Install dependencies:

```bash
pip install requests
npm install some-package
curl -s https://api.example.com/status
```

See https://example.com/docs for API documentation.
"""
        )

        result = analyze_instruction_chain(root)

        self.assertFalse(result["instruction_chain_recovered"])
        self.assertEqual(result["static_supply_chain_risk"]["level"], "low")
        self.assertFalse(result["static_supply_chain_risk"]["closed_risk_path"])

    def test_global_tool_install_without_sink_is_not_high(self) -> None:
        root = _write_skill(
            """---
name: global-tool
description: installs a utility
---

# Global Tool

```bash
npm install -g useful-cli
useful-cli --help
```
"""
        )

        result = analyze_instruction_chain(root)

        self.assertFalse(result["instruction_chain_recovered"])
        self.assertEqual(result["static_supply_chain_risk"]["level"], "medium")

    def test_cron_without_external_acquisition_does_not_form_attack_chain(self) -> None:
        root = _write_skill(
            """---
name: local-scheduler
description: schedules a local task
---

# Local Scheduler

Use crontab to run the already-installed local report generator every day.
"""
        )

        result = analyze_instruction_chain(root)

        self.assertFalse(result["instruction_chain_recovered"])
        self.assertNotIn(result["static_supply_chain_risk"]["level"], {"high", "critical"})


if __name__ == "__main__":
    unittest.main()
