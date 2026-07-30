from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CONTROL_FIXTURE_NAMES = {"request.md", "approval-note.md"}


@dataclass
class FixturePreparation:
    fixture_id: str = ""
    fixture_adapter_used: bool = False
    fixture_preparation_status: str = "not_configured"
    mock_services_started: list[dict[str, Any]] = field(default_factory=list)
    protected_assets_registered: list[dict[str, Any]] = field(default_factory=list)
    required_commands_checked: list[dict[str, Any]] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "fixture_adapter_used": self.fixture_adapter_used,
            "fixture_preparation_status": self.fixture_preparation_status,
            "ground_truth_loaded_by_analyzer": False,
            "mock_services_started": self.mock_services_started,
            "protected_assets_registered": self.protected_assets_registered,
            "required_commands_checked": self.required_commands_checked,
            "environment": sorted(self.environment),
            "errors": self.errors,
            "metadata": self.metadata,
        }


class FixtureOrchestrator:
    """Prepare public runtime fixture inputs without exposing expected verdicts/chains."""

    def __init__(self, fixture: dict[str, Any] | None = None, *, fixture_path: str | Path | None = None) -> None:
        if fixture is None and fixture_path:
            fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
        self.fixture = dict(fixture or {})

    @property
    def enabled(self) -> bool:
        return bool(self.fixture)

    def prepare_fixture(self, *, skill_workspace: Path, artifacts_dir: Path) -> FixturePreparation:
        prep = FixturePreparation(
            fixture_id=str(self.fixture.get("fixture_id") or ""),
            fixture_adapter_used=self.enabled,
            fixture_preparation_status="prepared" if self.enabled else "not_configured",
        )
        if not self.enabled:
            return prep

        self._materialize_files(skill_workspace)
        env = self._environment()
        prep.environment = env

        protected_assets = self.register_protected_assets(skill_workspace=skill_workspace)
        prep.protected_assets_registered = protected_assets
        self._write_json(artifacts_dir / "protected-assets.json", {"protected_assets": protected_assets})

        mock_config = self.start_mock_services_config()
        prep.mock_services_started = mock_config.get("services", [])
        self._write_json(artifacts_dir / "fixture-runtime.json", mock_config)

        required = self.preflight_commands_config()
        prep.required_commands_checked = required
        self._write_json(artifacts_dir / "required-commands.json", {"required_commands": required})

        self._write_json(artifacts_dir / "fixture-preparation.json", prep.to_dict())
        return prep

    def register_protected_assets(self, *, skill_workspace: Path) -> list[dict[str, Any]]:
        explicit = self.fixture.get("protected_assets")
        sandbox = self.fixture.get("sandbox", {}) if isinstance(self.fixture.get("sandbox"), dict) else {}
        if explicit is None:
            explicit = sandbox.get("protected_assets")
        if isinstance(explicit, list):
            return [self._asset_record(item, skill_workspace=skill_workspace) for item in explicit if isinstance(item, dict)]

        assets: list[dict[str, Any]] = []
        for rel_path, content in (sandbox.get("files") or {}).items():
            text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, sort_keys=True)
            if not self._looks_like_protected_fixture_asset(rel_path, text):
                continue
            assets.append(
                self._asset_record(
                    {
                        "path": rel_path,
                        "asset_class": "protected_synthetic_data",
                        "sensitivity": "high",
                        "content_source": "fixture_sandbox_file",
                        "source_category": "private_user_data",
                    },
                    skill_workspace=skill_workspace,
                    content=text,
                )
            )
        return assets

    def start_mock_services_config(self) -> dict[str, Any]:
        services: list[dict[str, Any]] = []
        for index, service in enumerate(self.fixture.get("mock_services", []) or []):
            if not isinstance(service, dict):
                continue
            url = str(service.get("url") or "").strip()
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.port:
                continue
            services.append(
                {
                    "service_id": str(service.get("name") or f"mock-{index + 1}"),
                    "url": url,
                    "host": parsed.hostname or "localhost",
                    "port": int(parsed.port),
                    "path_prefix": parsed.path or "/",
                    "response_status": int(service.get("response_status", 200)),
                    "response_body": str(service.get("response_body", "OK\n")),
                }
            )
        return {"services": services, "record_dir": "/artifacts/mock-services"}

    def wait_for_services(self) -> bool:
        return True

    def preflight_commands_config(self) -> list[dict[str, Any]]:
        commands = self.fixture.get("required_commands") or self.fixture.get("required_tools") or []
        if isinstance(commands, dict):
            commands = list(commands)
        return [{"command": str(command), "required": True} for command in commands if str(command).strip()]

    def collect_service_records(self, *, artifacts_dir: Path) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in sorted((artifacts_dir / "mock-services").glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        self._write_json(artifacts_dir / "mock-service-records.json", {"records": records})
        return records

    def collect_fixture_mutations(self, *, mounted_skill_dir: Path, artifacts_dir: Path) -> list[dict[str, Any]]:
        sandbox_files = set((self.fixture.get("sandbox", {}) or {}).get("files", {}) or {})
        mutations: list[dict[str, Any]] = []
        for path in sorted(item for item in mounted_skill_dir.rglob("*") if item.is_file()):
            rel = str(path.relative_to(mounted_skill_dir)).replace("\\", "/")
            if rel in sandbox_files or rel == "SKILL.md":
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            mutations.append({"path": rel, "byte_count": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self._write_json(artifacts_dir / "fixture-mutations.json", {"mutations": mutations})
        return mutations

    def cleanup(self) -> None:
        return None

    def _materialize_files(self, skill_workspace: Path) -> None:
        sandbox = self.fixture.get("sandbox", {}) if isinstance(self.fixture.get("sandbox"), dict) else {}
        for rel_path, content in (sandbox.get("files") or {}).items():
            target = skill_workspace / str(rel_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                target.write_text(content, encoding="utf-8")
            else:
                target.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")
        for item in sandbox.get("directories", []) or []:
            (skill_workspace / str(item)).mkdir(parents=True, exist_ok=True)

    def _environment(self) -> dict[str, str]:
        env = self.fixture.get("environment") or self.fixture.get("env") or {}
        return {str(key): str(value) for key, value in env.items()} if isinstance(env, dict) else {}

    def _asset_record(self, asset: dict[str, Any], *, skill_workspace: Path, content: str | None = None) -> dict[str, Any]:
        rel = str(asset.get("path") or asset.get("source_location") or "")
        target = skill_workspace / rel
        data = content
        if data is None:
            try:
                data = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                data = ""
        asset_id = str(asset.get("asset_id") or f"asset-{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:12]}")
        return {
            "asset_id": asset_id,
            "path": rel,
            "normalized_path": rel,
            "source_type": str(asset.get("source_type") or asset.get("asset_class") or "protected_synthetic_data"),
            "asset_class": str(asset.get("asset_class") or "protected_synthetic_data"),
            "sensitivity": str(asset.get("sensitivity") or "high"),
            "source_category": str(asset.get("source_category") or "private_user_data"),
            "content_source": str(asset.get("content_source") or "fixture"),
            "value_sha256": hashlib.sha256(data.encode("utf-8")).hexdigest() if data else "",
            "value_variants": _value_variants(data),
        }

    @staticmethod
    def _looks_like_protected_fixture_asset(rel_path: str, text: str) -> bool:
        name = Path(rel_path).name
        if name in CONTROL_FIXTURE_NAMES:
            return False
        if not text.strip():
            return False
        if "synthetic" in text.lower():
            return True
        return name not in CONTROL_FIXTURE_NAMES

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def copy_public_sample_to_bundle(*, benchmark_root: Path, manifest_row: dict[str, Any], bundle_root: Path) -> dict[str, Any]:
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    bundle_root.mkdir(parents=True, exist_ok=True)
    sample_file = benchmark_root / manifest_row["sample_path"]
    sample_dir = sample_file.parent
    shutil.copy2(sample_file, bundle_root / "SKILL.md")
    copied = {sample_file.resolve()}
    for src in sorted(item for item in sample_dir.rglob("*") if item.is_file()):
        if src.resolve() in copied:
            continue
        dst = bundle_root / src.relative_to(sample_dir)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    fixture = json.loads((benchmark_root / manifest_row["fixture_path"]).read_text(encoding="utf-8"))
    trigger_id = manifest_row.get("trigger_input_id")
    trigger = ""
    for item in fixture.get("trigger_inputs", []) or []:
        if item.get("id") == trigger_id:
            trigger = str(item.get("text") or "")
            break
    if not trigger and fixture.get("trigger_inputs"):
        trigger = str(fixture["trigger_inputs"][0].get("text") or "")
    return {"fixture": fixture, "trigger": trigger}


def _value_variants(value: str) -> dict[str, str]:
    if not value:
        return {}
    variants = {"raw": value}
    raw_bytes = value.encode("utf-8")
    variants["base64"] = base64.b64encode(raw_bytes).decode("ascii")
    variants["hex"] = raw_bytes.hex()
    variants["url_encoded"] = urllib.parse.quote(value, safe="")
    variants["json_escaped"] = json.dumps(value)[1:-1]
    return variants
