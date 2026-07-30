from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.analysis.pipeline import ExecutionConfig
from app.backend.schemas import LLMConfig
from app.runner.fixture_orchestrator import copy_public_sample_to_bundle
from app.runner.timeout_config import resolve_total_timeout


@dataclass
class BenchmarkReplayBundle:
    sample_id: str
    bundle_path: Path
    execution_config: ExecutionConfig
    fixture: dict[str, Any]
    trigger: str
    adapter_record: dict[str, Any]


class BenchmarkV3ReplayAdapter:
    """Translate public Benchmark v3 fixture execution config into ProvLoom runner inputs."""

    def __init__(self, benchmark_root: str | Path) -> None:
        self.benchmark_root = Path(benchmark_root).resolve()
        self._manifest = self._load_manifest()

    def rows(self, *, split: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        rows = [row for row in self._manifest if split is None or row.get("split") == split]
        return rows[:limit] if limit is not None else rows

    def by_sample_id(self, sample_id: str) -> dict[str, Any]:
        for row in self._manifest:
            if row.get("sample_id") == sample_id:
                return row
        raise KeyError(sample_id)

    def prepare(
        self,
        row: dict[str, Any],
        *,
        output_root: str | Path,
        llm_config: LLMConfig,
        timeout_seconds: int | None = None,
        run_id_prefix: str = "bv3",
    ) -> BenchmarkReplayBundle:
        sample_id = str(row["sample_id"])
        bundle_root = Path(output_root).resolve() / "bundles" / sample_id
        public = copy_public_sample_to_bundle(
            benchmark_root=self.benchmark_root,
            manifest_row=row,
            bundle_root=bundle_root,
        )
        fixture = public["fixture"]
        trigger = str(public["trigger"])
        timeout_resolution = resolve_total_timeout(timeout_seconds, fixture=fixture)
        execution_config = ExecutionConfig(
            input_payload={
                "trigger": trigger,
                "sample_id": sample_id,
                "fixture_id": fixture.get("fixture_id"),
            },
            timeout_seconds=timeout_resolution.total_timeout_seconds,
            network_policy="default",
            analysis_mode="rule_plus_epg",
            llm_config=llm_config,
            run_id=f"{run_id_prefix}-{sample_id}",
            fixture=fixture,
            timeout_resolution=timeout_resolution.to_dict(),
        )
        adapter_record = {
            "fixture_adapter_used": True,
            "ground_truth_loaded_by_analyzer": False,
            "sample_id": sample_id,
            "split": row.get("split"),
            "fixture_id": fixture.get("fixture_id"),
            "mock_service_count": len(fixture.get("mock_services", []) or []),
            "protected_asset_policy": "fixture_classification_or_synthetic_asset_inference",
            "required_commands": list(fixture.get("required_commands", []) or []),
            "trigger_input_used": bool(trigger),
            "forbidden_inputs_omitted": [
                "expected_outcome",
                "expected_chain",
                "expected_sink",
                "expected_carrier",
                "ground_truth",
            ],
        }
        (bundle_root / ".provloom-replay-adapter.json").write_text(
            json.dumps(adapter_record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return BenchmarkReplayBundle(
            sample_id=sample_id,
            bundle_path=bundle_root,
            execution_config=execution_config,
            fixture=fixture,
            trigger=trigger,
            adapter_record=adapter_record,
        )

    def _load_manifest(self) -> list[dict[str, Any]]:
        path = self.benchmark_root / "manifest.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
