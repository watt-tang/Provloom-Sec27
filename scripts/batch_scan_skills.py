from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analyzer.rules import analyze_static_skill, analyze_trace
from app.analyzer.capability_inference import CapabilityProfile, infer_capability_profile
from app.analyzer.execution_profiles import (
    PROFILE_ADAPTER_BACKED,
    PROFILE_AUTO,
    PROFILE_BASE_LIGHTWEIGHT,
    PROFILE_BROWSER_LIGHTWEIGHT,
    PROFILE_DEEP_EXECUTION,
    build_execution_plan,
    execution_plan_from_dict,
    update_plan_with_budget_outcome,
)
from app.analyzer.trigger_synthesis import (
    TriggerPlan,
    build_trigger_input_payload,
    evaluate_trigger_results,
    synthesize_trigger_plan,
)
from app.analyzer.skip_taxonomy import (
    SKIP_AUTH_OR_EXTERNAL_ACCOUNT_REQUIRED,
    SKIP_ECOSYSTEM_ADAPTER_MISSING,
    SKIP_INSUFFICIENT_EXECUTION_CONTEXT,
    SKIP_RESOURCE_BUDGET_EXCEEDED,
    SKIP_TRIGGER_CONDITION_UNSATISFIED,
    build_skip_bundle,
    categorize_skip,
    classify_execution_outcome,
)
from app.analyzer.dual_axis_decision import infer_dual_axis_decision
from app.analyzer.root_cause_v2 import infer_root_cause_v2
from app.backend.schemas import (
    DEFAULT_LLM_PROVIDER,
    LLMConfig,
    default_llm_api_key,
    default_llm_base_url,
    default_llm_model,
    normalize_llm_provider,
)
from app.reporting.skill_report import generate_report_file
from app.reporting.risk_mapper import map_risk_profile
from app.runner.docker_runner import DockerRunner
from app.runtime.skill_parser import SkillDefinition, load_skill_definition
from app.telemetry.collector import build_execution_report

SUPPORTED_RUNTIMES = {"provloom-embedded", "deepseek-agent", "llm-agent", "llm-native"}
SUPPORTED_ACTION_TYPES = {"read_file", "write_file", "run_command", "http_request"}
LLM_RUNTIMES = {"deepseek-agent", "llm-agent", "llm-native"}
SHELL_BUILTINS = {
    ".",
    ":",
    "[",
    "alias",
    "bg",
    "break",
    "cd",
    "command",
    "continue",
    "echo",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "fc",
    "fg",
    "getopts",
    "hash",
    "jobs",
    "kill",
    "printf",
    "pwd",
    "read",
    "readonly",
    "return",
    "set",
    "shift",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
}
WINDOWS_DRIVE_RE = re.compile(r"^(?P<drive>[a-zA-Z]):[\\/](?P<rest>.*)$")
DISCOVERY_PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
    ".nuxt",
    "coverage",
    ".pytest_cache",
}


@dataclass
class SkillScanResult:
    skill_id: str
    skill_root: str
    skill_file: str
    name: str
    runtime: str
    llm_enabled: bool
    status: str
    skip_reason: str | None = None
    external_dependencies: list[str] | None = None
    detected_behaviors: list[str] | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    risk_level_name: str | None = None
    risk_summary: str | None = None
    capability_profile: dict[str, Any] | None = None
    capability_tags: list[str] | None = None
    recommended_execution_profile: str | None = None
    recommended_trigger_mode: str | None = None
    estimated_budget_class: str | None = None
    execution_feasibility: str | None = None
    blocking_requirements: list[str] | None = None
    selected_execution_profile: str | None = None
    execution_profile_config: dict[str, Any] | None = None
    execution_plan: dict[str, Any] | None = None
    first_attempt_profile: str | None = None
    promoted_profile: str | None = None
    promotion_reason: str | None = None
    budget_exceeded: bool | None = None
    profile_selection_source: str | None = None
    enabled_adapters: list[str] | None = None
    adapter_events_summary: dict[str, Any] | None = None
    synthetic_artifact_summary: dict[str, Any] | None = None
    trigger_plan: dict[str, Any] | None = None
    trigger_depth: str | None = None
    trigger_budget_class: str | None = None
    trigger_generation_rationale: list[str] | None = None
    trigger_used: list[str] | None = None
    trigger_hits: list[str] | None = None
    trigger_unexecuted: list[str] | None = None
    trigger_events_summary: dict[str, Any] | None = None
    execution_outcome: str | None = None
    skip_category: str | None = None
    skip_explanation: dict[str, Any] | None = None
    partial_evidence: dict[str, Any] | None = None
    profile_promotion_recommended: str | None = None
    severity_label: str | None = None
    evidence_strength: str | None = None
    decision_rationale: dict[str, Any] | None = None
    dynamic_chain_observed: bool | None = None
    instruction_chain_recovered: bool | None = None
    chain_evidence_type: str | None = None
    instruction_chain: list[dict[str, Any]] | None = None
    instruction_indicators: list[dict[str, Any]] | None = None
    static_supply_chain_risk: dict[str, Any] | None = None
    instruction_document_scan: dict[str, Any] | None = None
    final_risk_level: str | None = None
    final_label_reason: str | None = None
    primary_chain: list[dict[str, Any]] | None = None
    root_cause: str | None = None
    root_cause_detail: str | None = None
    root_cause_v2: dict[str, Any] | None = None
    trace_summary: dict[str, Any] | None = None
    execution_id: str | None = None
    execution_artifact_dir: str | None = None
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class ProgressTracker:
    def __init__(
        self,
        log_dir: Path,
        total: int,
        config: dict[str, Any],
        initial_totals: dict[str, int] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self.log_dir = log_dir
        self.total = total
        self.progress_path = log_dir / "progress.json"
        self.results_jsonl = log_dir / "results.jsonl"
        self.summary_path = log_dir / "summary.json"
        self.manifest_path = log_dir / "manifest.json"
        self.run_log_path = log_dir / "driver.log"
        totals = {
            "discovered": total,
            "processed": 0,
            "completed": 0,
            "skipped": 0,
            "failed": 0,
        }
        if initial_totals:
            totals.update(initial_totals)
        self.state = {
            "scan_id": uuid.uuid4().hex,
            "started_at": utc_now(),
            "updated_at": utc_now(),
            "status": "running",
            "phase": "initializing",
            "config": config,
            "totals": totals,
            "active_skills": [],
            "last_result_file": None,
        }
        self.progress_path.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        self.results_jsonl.touch()

    def write_manifest(self, payload: dict[str, Any]) -> None:
        self.manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def update_phase(self, phase: str, **extra: Any) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["phase"] = phase
            for key, value in extra.items():
                self.state[key] = value
            self._flush_locked()

    def update_discovery(self, discovered: int, pending: int | None = None) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["totals"]["discovered"] = discovered
            if pending is not None:
                self.state["config"]["pending_skills"] = pending
            self._flush_locked()

    def start_skill(self, current_skill: dict[str, Any]) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["phase"] = "scanning"
            active = [item for item in self.state["active_skills"] if item.get("skill_id") != current_skill.get("skill_id")]
            active.append(current_skill)
            self.state["active_skills"] = active
            self._flush_locked()

    def append_result(self, result: SkillScanResult, result_path: Path) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["totals"]["processed"] += 1
            self.state["totals"][result.status] += 1
            self.state["last_result_file"] = str(result_path)
            self.state["active_skills"] = [
                item for item in self.state["active_skills"] if item.get("skill_id") != result.skill_id
            ]
            line = json.dumps(asdict(result), ensure_ascii=False)
            with self.results_jsonl.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            self._flush_locked()

    def update_last_report(self, report_path: Path) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["last_report_file"] = str(report_path)
            self._flush_locked()

    def finish(self) -> None:
        with self._lock:
            self.state["updated_at"] = utc_now()
            self.state["finished_at"] = utc_now()
            self.state["status"] = "completed"
            self.state["phase"] = "completed"
            self.state["active_skills"] = []
            self._flush_locked()

    def write_summary(self, payload: dict[str, Any]) -> None:
        self.summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.state, ensure_ascii=False))

    def _flush_locked(self) -> None:
        self.progress_path.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")


class CommandAvailabilityProbe:
    def __init__(self, runner: DockerRunner) -> None:
        self.runner = runner
        self._ensured = False
        self._cache: dict[str, bool] = {}
        self._lock = threading.Lock()

    def has(self, command_name: str) -> bool:
        command_name = command_name.strip()
        if not command_name:
            return True
        if command_name in SHELL_BUILTINS:
            return True
        if "/" in command_name or command_name.startswith("."):
            return True
        with self._lock:
            if command_name in self._cache:
                return self._cache[command_name]

        if not self._ensured:
            self.runner._ensure_docker_available()
            self.runner._build_image()
            self._ensured = True
        self._probe_commands([command_name])
        return self._cache.get(command_name, False)

    def _probe_commands(self, command_names: list[str]) -> None:
        pending = [
            name
            for name in command_names
            if name and name not in self._cache and name not in SHELL_BUILTINS and "/" not in name and not name.startswith(".")
        ]
        if not pending:
            return

        quoted = " ".join(shlex.quote(name) for name in pending)
        script = (
            "for c in " + quoted + "; do "
            "if command -v \"$c\" >/dev/null 2>&1; then "
            "printf '%s\\t1\\n' \"$c\"; "
            "else "
            "printf '%s\\t0\\n' \"$c\"; "
            "fi; "
            "done"
        )
        try:
            result = subprocess.run(
                [
                    "timeout",
                    "20s",
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "sh",
                    self.runner.image_name,
                    "-lc",
                    script,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        except Exception:
            result = None

        if result is None or result.returncode not in {0, 124}:
            for name in pending:
                self._cache.setdefault(name, False)
            return

        seen: set[str] = set()
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) != 2:
                continue
            name, flag = parts
            self._cache[name] = flag == "1"
            seen.add(name)

        for name in pending:
            if name not in seen:
                self._cache.setdefault(name, False)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-scan many SKILL.md folders with the ProvLoom sandbox.")
    parser.add_argument("--skills-root", required=True, help="Root directory that contains many skill folders.")
    parser.add_argument("--log-dir", required=True, help="Output directory for progress and scan results.")
    parser.add_argument("--skill-list-csv", help="Optional CSV file used to select a subset of discovered skills.")
    parser.add_argument("--skill-paths-file", help="Optional newline-delimited file listing exact skill directories to scan.")
    parser.add_argument("--analysis-mode", default="epg_with_filtering")
    parser.add_argument("--network-policy", default="default", choices=["default", "disabled"])
    parser.add_argument("--default-timeout-seconds", type=int, default=600)
    parser.add_argument("--timeout-seconds", dest="default_timeout_seconds", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--max-workers", type=int, default=5)
    parser.add_argument(
        "--execution-profile",
        default=PROFILE_AUTO,
        choices=[PROFILE_AUTO, PROFILE_BASE_LIGHTWEIGHT, PROFILE_BROWSER_LIGHTWEIGHT, PROFILE_ADAPTER_BACKED, PROFILE_DEEP_EXECUTION],
    )
    parser.add_argument(
        "--allow-profile-promotion",
        type=lambda v: str(v).strip().lower() in {"1", "true", "yes", "on"},
        default=True,
    )
    parser.add_argument("--max-promotion-steps", type=int, default=1)
    parser.add_argument("--provider", default=DEFAULT_LLM_PROVIDER)
    parser.add_argument("--base-url", default=default_llm_base_url(DEFAULT_LLM_PROVIDER))
    parser.add_argument("--model", default=default_llm_model(DEFAULT_LLM_PROVIDER))
    parser.add_argument("--api-key", default=os.getenv("PROVLOOM_SCAN_API_KEY", default_llm_api_key(DEFAULT_LLM_PROVIDER)))
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--no-resume", dest="resume", action="store_false")
    parser.add_argument(
        "--generate-markdown-reports",
        action="store_true",
        help="Synchronously generate one Markdown report after each per-skill JSON result is written.",
    )
    parser.add_argument(
        "--report-dir",
        help="Directory for generated Markdown reports. Defaults to <log-dir>/reports when --generate-markdown-reports is set.",
    )
    parser.add_argument("--force-llm-on-empty-actions", action="store_true", default=True)
    parser.add_argument("--no-force-llm-on-empty-actions", dest="force_llm_on_empty_actions", action="store_false")
    return parser.parse_args()


def normalize_user_path(raw_path: str) -> Path:
    raw_path = raw_path.strip()
    match = WINDOWS_DRIVE_RE.match(raw_path)
    if match:
        drive = match.group("drive").lower()
        rest = match.group("rest").replace("\\", "/")
        return Path(f"/mnt/{drive}/{rest}").resolve()
    if re.match(r"^[a-zA-Z]\\", raw_path):
        drive = raw_path[0].lower()
        rest = raw_path[2:].replace("\\", "/").lstrip("/")
        return Path(f"/mnt/{drive}/{rest}").resolve()
    return Path(raw_path).expanduser().resolve()


def discover_skills(skills_root: Path) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    for root, dirs, files in os.walk(skills_root):
        dirs[:] = sorted(
            name for name in dirs
            if name not in DISCOVERY_PRUNE_DIRS
            and not name.endswith(".egg-info")
        )
        if "SKILL.md" not in files:
            continue
        skill_root = Path(root).resolve()
        if skill_root not in seen:
            roots.append(skill_root)
            seen.add(skill_root)
    roots.sort()
    return roots


def discover_skills_fast(skills_root: Path) -> list[Path]:
    rg_cmd = [
        "rg",
        "--files",
        str(skills_root),
        "-g",
        "SKILL.md",
        "-g",
        "!.git/**",
        "-g",
        "!node_modules/**",
        "-g",
        "!dist/**",
        "-g",
        "!build/**",
        "-g",
        "!target/**",
        "-g",
        "!__pycache__/**",
        "-g",
        "!.venv/**",
        "-g",
        "!venv/**",
        "-g",
        "!.next/**",
        "-g",
        "!.nuxt/**",
        "-g",
        "!coverage/**",
        "-g",
        "!.pytest_cache/**",
    ]
    try:
        result = subprocess.run(
            rg_cmd,
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception:
        return discover_skills(skills_root)

    if result.returncode not in {0, 1}:
        return discover_skills(skills_root)

    roots: list[Path] = []
    seen: set[Path] = set()
    for raw_line in result.stdout.splitlines():
        candidate = Path(raw_line.strip())
        if not candidate.is_file():
            continue
        skill_root = candidate.parent.resolve()
        if skill_root not in seen:
            roots.append(skill_root)
            seen.add(skill_root)
    roots.sort()
    return roots


def slugify_path(path: Path) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", str(path).strip("/")).strip("._-").lower() or "skill"


def portable_skill_id(skill_id: str) -> str:
    return re.sub(r"^mnt_[a-z]_", "", skill_id.strip().lower())


def load_existing_results(results_dir: Path) -> dict[str, dict[str, Any]]:
    existing: dict[str, dict[str, Any]] = {}
    if not results_dir.exists():
        return existing
    for result_file in sorted(results_dir.glob("*.json")):
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        skill_id = str(payload.get("skill_id") or result_file.stem).strip()
        if not skill_id:
            continue
        existing[skill_id] = payload
    return existing


def build_initial_totals(total_discovered: int, existing_results: dict[str, dict[str, Any]]) -> dict[str, int]:
    totals = {
        "discovered": total_discovered,
        "processed": 0,
        "completed": 0,
        "skipped": 0,
        "failed": 0,
    }
    for payload in existing_results.values():
        status = payload.get("status")
        if status in {"completed", "skipped", "failed"}:
            totals["processed"] += 1
            totals[status] += 1
    return totals


def load_requested_skill_ids(csv_path: Path) -> list[str]:
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    if not rows:
        return []
    import csv

    reader = csv.DictReader(rows)
    requested: list[str] = []
    for row in reader:
        skill_id = str(row.get("skill_id", "")).strip()
        if skill_id:
            requested.append(skill_id)
    return requested


def load_requested_skill_paths(paths_file: Path) -> list[Path]:
    requested: list[Path] = []
    for line in paths_file.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        requested.append(normalize_user_path(raw))
    return requested


def command_name_from_action(action) -> str | None:
    if action.type != "run_command":
        return None
    command = action.config.get("command")
    shell = bool(action.config.get("shell", False))
    if isinstance(command, list):
        tokens = [str(item) for item in command]
    elif isinstance(command, str):
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
    else:
        return None

    if not tokens:
        return None

    if shell and len(tokens) >= 2 and tokens[0] in {"sh", "bash"} and tokens[1] == "-lc":
        try:
            shell_tokens = shlex.split(tokens[2]) if len(tokens) >= 3 else []
        except ValueError:
            shell_tokens = tokens[2].split() if len(tokens) >= 3 else []
        tokens = shell_tokens

    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        tokens.pop(0)
    if not tokens:
        return None
    return tokens[0]


def inspect_skill(
    definition: SkillDefinition,
    probe: CommandAvailabilityProbe,
    force_llm_on_empty_actions: bool,
    api_key_present: bool,
) -> tuple[bool, list[str], str | None]:
    if definition.runtime and definition.runtime not in SUPPORTED_RUNTIMES:
        return False, [], f"unsupported_runtime:{definition.runtime}"

    unsupported_actions = sorted({action.type for action in definition.actions if action.type not in SUPPORTED_ACTION_TYPES})
    if unsupported_actions:
        return False, unsupported_actions, "unsupported_action_type"

    llm_enabled = definition.runtime in LLM_RUNTIMES or (force_llm_on_empty_actions and not definition.actions)
    if llm_enabled and not api_key_present:
        return False, [], "llm_skill_requires_api_key"

    missing_commands: list[str] = []
    for action in definition.actions:
        name = command_name_from_action(action)
        if name and not probe.has(name):
            missing_commands.append(name)

    if missing_commands:
        return False, sorted(set(missing_commands)), "external_dependency_missing"

    return True, [], None


def llm_config_for_skill(
    definition: SkillDefinition,
    provider: str,
    api_key: str,
    base_url: str,
    model: str,
    force_llm_on_empty_actions: bool,
) -> LLMConfig:
    provider_name = normalize_llm_provider(provider)
    resolved_api_key = api_key or default_llm_api_key(provider_name)
    resolved_base_url = base_url or default_llm_base_url(provider_name)
    resolved_model = model or default_llm_model(provider_name)
    llm_enabled = bool(resolved_api_key) and (
        definition.runtime in LLM_RUNTIMES or (force_llm_on_empty_actions and not definition.actions)
    )
    return LLMConfig(
        enabled=llm_enabled,
        provider=provider_name,
        base_url=resolved_base_url,
        api_key=resolved_api_key if llm_enabled else "",
        model=resolved_model,
        temperature=0.0,
        max_steps=8,
    )


def build_result_payload(result: dict[str, Any]) -> dict[str, Any]:
    profile = map_risk_profile(
        risk_score=int(result.get("risk_score", 0)),
        detected_behaviors=list(result.get("detected_behaviors", [])),
    )
    merged = dict(result)
    merged.update(profile)
    capability_profile = dict(merged.get("capability_profile", {}) or {})
    if capability_profile:
        merged.setdefault("capability_tags", list(capability_profile.get("capability_tags", [])))
        merged.setdefault("recommended_execution_profile", capability_profile.get("recommended_profile", ""))
        merged.setdefault("recommended_trigger_mode", capability_profile.get("recommended_trigger_mode", ""))
        merged.setdefault("estimated_budget_class", capability_profile.get("estimated_budget_class", ""))
        merged.setdefault("execution_feasibility", capability_profile.get("execution_feasibility", ""))
        merged.setdefault("blocking_requirements", list(capability_profile.get("blocking_requirements", [])))
    return merged


def preflight_taxonomy_category(
    *,
    capability_profile: CapabilityProfile,
    execution_plan: dict[str, Any],
    skip_reason: str | None,
) -> str | None:
    if skip_reason:
        return None
    tags = set(capability_profile.capability_tags or [])
    selected = str(execution_plan.get("effective_profile", ""))
    if "requires_oauth_or_login" in tags:
        return SKIP_AUTH_OR_EXTERNAL_ACCOUNT_REQUIRED
    needs_adapter = bool(
        {"requires_callback_or_webhook", "requires_document_or_office_stack", "requires_messaging_stack"} & tags
    )
    if needs_adapter and selected not in {PROFILE_ADAPTER_BACKED, PROFILE_DEEP_EXECUTION}:
        return SKIP_ECOSYSTEM_ADAPTER_MISSING
    return None


def _static_partial_report(definition: SkillDefinition | None) -> dict[str, Any]:
    if definition is None:
        return {}
    try:
        return analyze_static_skill(definition, analysis_mode="static_only")
    except Exception:
        return {}


def _dual_axis_for_partial(
    *,
    static_report: dict[str, Any],
    capability_profile: dict[str, Any],
    execution_plan: dict[str, Any],
    trigger_used: list[str],
    trigger_hits: list[str],
    execution_outcome: str,
    skip_category: str | None,
) -> dict[str, Any]:
    profile = map_risk_profile(
        risk_score=int(static_report.get("risk_score", 0)),
        detected_behaviors=list(static_report.get("detected_behaviors", [])),
    )
    return infer_dual_axis_decision(
        risk_score=int(static_report.get("risk_score", 0)),
        risk_level=str(profile.get("risk_level", "unknown")),
        detected_behaviors=list(static_report.get("detected_behaviors", [])),
        source_assessment=static_report.get("source_assessment", {}),
        sink_assessment=static_report.get("sink_assessment", {}),
        primary_chain=list(static_report.get("primary_chain", [])),
        trigger_used=trigger_used,
        trigger_hits=trigger_hits,
        enabled_adapters=list((execution_plan.get("profile_config", {}) or {}).get("adapters_enabled", [])),
        execution_outcome=execution_outcome,
        skip_category=skip_category,
        llm_involved="requires_external_api_key" in set(capability_profile.get("capability_tags", [])),
    )


def _root_cause_v2_for_partial(
    *,
    static_report: dict[str, Any],
    execution_plan: dict[str, Any],
    trigger_used: list[str],
    trigger_hits: list[str],
    execution_outcome: str,
    skip_category: str | None,
    llm_involved: bool,
) -> dict[str, Any]:
    return infer_root_cause_v2(
        legacy_root_cause=str(static_report.get("root_cause", "unknown")),
        legacy_root_cause_detail=str(static_report.get("root_cause_detail", "unknown")),
        detected_behaviors=list(static_report.get("detected_behaviors", [])),
        source_assessment=static_report.get("source_assessment", {}),
        sink_assessment=static_report.get("sink_assessment", {}),
        primary_chain=list(static_report.get("primary_chain", [])),
        root_cause_evidence=static_report.get("root_cause_evidence", {}),
        execution_outcome=execution_outcome,
        skip_category=skip_category,
        trigger_used=trigger_used,
        trigger_hits=trigger_hits,
        enabled_adapters=list((execution_plan.get("profile_config", {}) or {}).get("adapters_enabled", [])),
        llm_involved=llm_involved,
        analysis_mode=str(static_report.get("analysis_mode", "")),
    )


def build_summary_distributions(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    skip_category: dict[str, int] = {}
    execution_outcome: dict[str, int] = {}
    profile_usage: dict[str, int] = {}
    root_cause_v2_mechanism: dict[str, int] = {}
    root_cause_v2_driver: dict[str, int] = {}
    root_cause_v2_evidence: dict[str, int] = {}
    for row in rows:
        sc = str(row.get("skip_category") or "").strip()
        eo = str(row.get("execution_outcome") or "").strip()
        profile = str(row.get("selected_execution_profile") or "").strip()
        root_cause_v2 = row.get("root_cause_v2", {}) or {}
        mechanism = str(root_cause_v2.get("mechanism_class") or "").strip()
        driver = str(root_cause_v2.get("primary_driver") or "").strip()
        evidence_status = str(root_cause_v2.get("evidence_status") or "").strip()
        if sc:
            skip_category[sc] = skip_category.get(sc, 0) + 1
        if eo:
            execution_outcome[eo] = execution_outcome.get(eo, 0) + 1
        if profile:
            profile_usage[profile] = profile_usage.get(profile, 0) + 1
        if mechanism:
            root_cause_v2_mechanism[mechanism] = root_cause_v2_mechanism.get(mechanism, 0) + 1
        if driver:
            root_cause_v2_driver[driver] = root_cause_v2_driver.get(driver, 0) + 1
        if evidence_status:
            root_cause_v2_evidence[evidence_status] = root_cause_v2_evidence.get(evidence_status, 0) + 1
    return {
        "skip_category": skip_category,
        "execution_outcome": execution_outcome,
        "profile_usage": profile_usage,
        "root_cause_v2_mechanism_class": root_cause_v2_mechanism,
        "root_cause_v2_primary_driver": root_cause_v2_driver,
        "root_cause_v2_evidence_status": root_cause_v2_evidence,
    }


def scan_one_skill(
    skill_root: Path,
    definition: SkillDefinition,
    capability_profile: CapabilityProfile,
    execution_plan: dict[str, Any],
    trigger_plan: dict[str, Any],
    runner: DockerRunner,
    analysis_mode: str,
    network_policy: str,
    timeout_seconds: int,
    provider: str,
    api_key: str,
    base_url: str,
    model: str,
    force_llm_on_empty_actions: bool,
) -> SkillScanResult:
    started_at = utc_now()
    llm_config = llm_config_for_skill(
        definition=definition,
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
        force_llm_on_empty_actions=force_llm_on_empty_actions,
    )
    execution_id = uuid.uuid4().hex

    try:
        parsed_trigger_plan = TriggerPlan.from_dict(trigger_plan or {})
        input_payload, prompt_used = build_trigger_input_payload(parsed_trigger_plan)
        profile_cfg = execution_plan.get("profile_config", {})
        execution = runner.run(
            execution_id=execution_id,
            skill_path=str(skill_root),
            input_payload=input_payload,
            timeout_seconds=timeout_seconds,
            network_policy=network_policy,
            llm_config=llm_config,
            memory_limit_mb=int(profile_cfg.get("memory_limit_mb", 256)),
            execution_profile=str(execution_plan.get("effective_profile", PROFILE_BASE_LIGHTWEIGHT)),
            trigger_depth_level=int(profile_cfg.get("trigger_depth_level", 1)),
            telemetry_verbosity=str(profile_cfg.get("telemetry_verbosity", "standard")),
            browser_enabled=bool(profile_cfg.get("browser_enabled", False)),
            adapters_enabled=list(profile_cfg.get("adapters_enabled", [])),
            escalation_allowed=bool(profile_cfg.get("escalation_allowed", False)),
            trigger_plan=parsed_trigger_plan.to_dict(),
            trigger_prompt_used=prompt_used,
        )
        execution_plan_obj = execution_plan_from_dict(
            payload=execution_plan,
            default_timeout_seconds=timeout_seconds,
        )
        update_plan_with_budget_outcome(
            plan=execution_plan_obj,
            timed_out=bool(execution.timed_out),
            memory_peak_bytes=execution.resource_usage.memory_peak_bytes,
            memory_limit_bytes=execution.resource_usage.memory_limit_bytes,
        )
        analysis = analyze_trace(execution, analysis_mode=analysis_mode)
        report = build_result_payload(analysis)
        telemetry = build_execution_report(execution)
        trigger_hits, trigger_unexecuted = evaluate_trigger_results(
            plan=parsed_trigger_plan,
            trigger_used=execution.trigger_used,
            file_events=execution.file_events,
            network_events=execution.network_events,
            process_events=execution.process_events,
            tool_calls=execution.tool_calls,
        )
        derived_skip_category: str | None = None
        if execution_plan_obj.budget_exceeded:
            derived_skip_category = SKIP_RESOURCE_BUDGET_EXCEEDED
        elif execution.trigger_used and not trigger_hits:
            derived_skip_category = SKIP_TRIGGER_CONDITION_UNSATISFIED

        skip_bundle = None
        if derived_skip_category:
            skip_bundle = build_skip_bundle(
                skip_category=derived_skip_category,
                skip_reason=derived_skip_category,
                capability_profile=report.get("capability_profile", capability_profile.to_dict()),
                execution_plan=execution_plan_obj.to_dict(),
                static_report=report,
                trigger_plan=parsed_trigger_plan.to_dict(),
                trigger_hits=trigger_hits,
                trigger_used=execution.trigger_used,
                budget_exceeded=execution_plan_obj.budget_exceeded,
                status="completed",
            )
        execution_outcome = (
            skip_bundle.execution_outcome
            if skip_bundle is not None
            else classify_execution_outcome(
                status="completed",
                skip_category=None,
                partial_meaningful=False,
                budget_exceeded=execution_plan_obj.budget_exceeded,
            )
        )
        dual_axis = report if ("severity_label" in report and "evidence_strength" in report) else _dual_axis_for_partial(
            static_report=report,
            capability_profile=report.get("capability_profile", capability_profile.to_dict()),
            execution_plan=execution_plan_obj.to_dict(),
            trigger_used=execution.trigger_used,
            trigger_hits=trigger_hits,
            execution_outcome=execution_outcome,
            skip_category=skip_bundle.skip_category if skip_bundle is not None else None,
        )
        root_cause_v2 = report.get("root_cause_v2") or _root_cause_v2_for_partial(
            static_report=report,
            execution_plan=execution_plan_obj.to_dict(),
            trigger_used=execution.trigger_used,
            trigger_hits=trigger_hits,
            execution_outcome=execution_outcome,
            skip_category=skip_bundle.skip_category if skip_bundle is not None else None,
            llm_involved=bool(llm_config.enabled),
        )
        return SkillScanResult(
            skill_id=slugify_path(skill_root),
            skill_root=str(skill_root),
            skill_file=definition.skill_file,
            name=definition.name,
            runtime=definition.runtime,
            llm_enabled=llm_config.enabled,
            status="completed",
            detected_behaviors=report["detected_behaviors"],
            risk_score=report["risk_score"],
            risk_level=report["risk_level"],
            risk_level_name=report["risk_level_name"],
            risk_summary=report["risk_summary"],
            capability_profile=report.get("capability_profile", capability_profile.to_dict()),
            capability_tags=report.get("capability_tags", capability_profile.capability_tags),
            recommended_execution_profile=report.get(
                "recommended_execution_profile",
                capability_profile.recommended_profile,
            ),
            recommended_trigger_mode=report.get(
                "recommended_trigger_mode",
                capability_profile.recommended_trigger_mode,
            ),
            estimated_budget_class=report.get(
                "estimated_budget_class",
                capability_profile.estimated_budget_class,
            ),
            execution_feasibility=report.get(
                "execution_feasibility",
                capability_profile.execution_feasibility,
            ),
            blocking_requirements=report.get(
                "blocking_requirements",
                capability_profile.blocking_requirements,
            ),
            selected_execution_profile=execution_plan_obj.effective_profile,
            execution_profile_config=execution_plan_obj.profile_config.to_dict(),
            execution_plan=execution_plan_obj.to_dict(),
            first_attempt_profile=execution_plan_obj.first_attempt_profile,
            promoted_profile=execution_plan_obj.promoted_profile or None,
            promotion_reason=execution_plan_obj.promotion_reason or None,
            budget_exceeded=execution_plan_obj.budget_exceeded,
            profile_selection_source=execution_plan_obj.selection_source,
            enabled_adapters=report.get("enabled_adapters", execution.enabled_adapters),
            adapter_events_summary=report.get("adapter_events_summary", execution.adapter_events_summary),
            synthetic_artifact_summary=report.get("synthetic_artifact_summary", execution.synthetic_artifact_summary),
            trigger_plan=parsed_trigger_plan.to_dict(),
            trigger_depth=parsed_trigger_plan.trigger_depth,
            trigger_budget_class=parsed_trigger_plan.budget_class,
            trigger_generation_rationale=parsed_trigger_plan.generation_rationale,
            trigger_used=execution.trigger_used,
            trigger_hits=trigger_hits,
            trigger_unexecuted=trigger_unexecuted,
            trigger_events_summary=execution.trigger_events_summary,
            execution_outcome=execution_outcome,
            skip_category=skip_bundle.skip_category if skip_bundle is not None else None,
            skip_explanation=skip_bundle.skip_explanation if skip_bundle is not None else None,
            partial_evidence=skip_bundle.partial_evidence if skip_bundle is not None else None,
            profile_promotion_recommended=(
                skip_bundle.profile_promotion_recommended if skip_bundle is not None else (execution_plan_obj.promoted_profile or None)
            ),
            severity_label=dual_axis.get("severity_label"),
            evidence_strength=dual_axis.get("evidence_strength"),
            decision_rationale=dual_axis.get("decision_rationale"),
            dynamic_chain_observed=report.get("dynamic_chain_observed"),
            instruction_chain_recovered=report.get("instruction_chain_recovered"),
            chain_evidence_type=report.get("chain_evidence_type"),
            instruction_chain=report.get("instruction_chain", []),
            instruction_indicators=report.get("instruction_indicators", []),
            static_supply_chain_risk=report.get("static_supply_chain_risk", {}),
            instruction_document_scan=report.get("instruction_document_scan", {}),
            final_risk_level=report.get("final_risk_level"),
            final_label_reason=report.get("final_label_reason"),
            primary_chain=report.get("primary_chain", []),
            root_cause=report.get("root_cause"),
            root_cause_detail=report.get("root_cause_detail"),
            root_cause_v2=root_cause_v2,
            trace_summary={
                **report.get("trace_summary", {}),
                "normalized_event_count": len(telemetry.get("normalized_events", [])),
            },
            execution_id=execution_id,
            execution_artifact_dir=execution.artifacts_dir,
            stdout_preview=execution.stdout[:2000],
            stderr_preview=execution.stderr[:2000],
            started_at=started_at,
            finished_at=utc_now(),
        )
    except Exception as exc:
        raw_reason = str(exc)
        budget_exceeded = "timeout" in raw_reason.lower() or "budget" in raw_reason.lower()
        static_report = _static_partial_report(definition)
        skip_category = categorize_skip(
            skip_reason=raw_reason,
            capability_profile=capability_profile.to_dict(),
            execution_plan=execution_plan,
            trigger_hits=[],
            budget_exceeded=budget_exceeded,
            static_report=static_report,
        )
        skip_bundle = build_skip_bundle(
            skip_category=skip_category,
            skip_reason=raw_reason,
            capability_profile=capability_profile.to_dict(),
            execution_plan=execution_plan,
            static_report=static_report,
            trigger_plan=trigger_plan,
            trigger_hits=[],
            trigger_used=[],
            budget_exceeded=budget_exceeded,
            status="failed",
        )
        dual_axis = _dual_axis_for_partial(
            static_report=static_report,
            capability_profile=capability_profile.to_dict(),
            execution_plan=execution_plan,
            trigger_used=[],
            trigger_hits=[],
            execution_outcome=skip_bundle.execution_outcome,
            skip_category=skip_bundle.skip_category,
        )
        root_cause_v2 = _root_cause_v2_for_partial(
            static_report=static_report,
            execution_plan=execution_plan,
            trigger_used=[],
            trigger_hits=[],
            execution_outcome=skip_bundle.execution_outcome,
            skip_category=skip_bundle.skip_category,
            llm_involved=bool(llm_config.enabled),
        )
        return SkillScanResult(
            skill_id=slugify_path(skill_root),
            skill_root=str(skill_root),
            skill_file=definition.skill_file,
            name=definition.name,
            runtime=definition.runtime,
            llm_enabled=llm_config.enabled,
            status="failed",
            capability_profile=capability_profile.to_dict(),
            capability_tags=capability_profile.capability_tags,
            recommended_execution_profile=capability_profile.recommended_profile,
            recommended_trigger_mode=capability_profile.recommended_trigger_mode,
            estimated_budget_class=capability_profile.estimated_budget_class,
            execution_feasibility=capability_profile.execution_feasibility,
            blocking_requirements=capability_profile.blocking_requirements,
            selected_execution_profile=str(execution_plan.get("effective_profile", PROFILE_BASE_LIGHTWEIGHT)),
            execution_profile_config=dict(execution_plan.get("profile_config", {})),
            execution_plan=dict(execution_plan),
            first_attempt_profile=str(execution_plan.get("first_attempt_profile", "")),
            promoted_profile=None,
            promotion_reason=None,
            budget_exceeded=None,
            profile_selection_source=str(execution_plan.get("selection_source", "")),
            enabled_adapters=[],
            adapter_events_summary={},
            synthetic_artifact_summary={},
            trigger_plan=trigger_plan,
            trigger_depth=str((trigger_plan or {}).get("trigger_depth", "")),
            trigger_budget_class=str((trigger_plan or {}).get("budget_class", "")),
            trigger_generation_rationale=list((trigger_plan or {}).get("generation_rationale", [])),
            trigger_used=[],
            trigger_hits=[],
            trigger_unexecuted=[],
            trigger_events_summary={},
            execution_outcome=skip_bundle.execution_outcome,
            skip_category=skip_bundle.skip_category,
            skip_explanation=skip_bundle.skip_explanation,
            partial_evidence=skip_bundle.partial_evidence,
            profile_promotion_recommended=skip_bundle.profile_promotion_recommended,
            severity_label=dual_axis.get("severity_label"),
            evidence_strength=dual_axis.get("evidence_strength"),
            decision_rationale=dual_axis.get("decision_rationale"),
            dynamic_chain_observed=static_report.get("dynamic_chain_observed"),
            instruction_chain_recovered=static_report.get("instruction_chain_recovered"),
            chain_evidence_type=static_report.get("chain_evidence_type"),
            instruction_chain=static_report.get("instruction_chain", []),
            instruction_indicators=static_report.get("instruction_indicators", []),
            static_supply_chain_risk=static_report.get("static_supply_chain_risk", {}),
            instruction_document_scan=static_report.get("instruction_document_scan", {}),
            final_risk_level=static_report.get("final_risk_level"),
            final_label_reason=static_report.get("final_label_reason"),
            root_cause=static_report.get("root_cause"),
            root_cause_detail=static_report.get("root_cause_detail"),
            root_cause_v2=root_cause_v2,
            execution_id=execution_id,
            error=str(exc),
            started_at=started_at,
            finished_at=utc_now(),
        )


def main() -> int:
    args = parse_args()
    skills_root = normalize_user_path(args.skills_root)
    log_dir = normalize_user_path(args.log_dir)
    skill_list_csv = normalize_user_path(args.skill_list_csv) if args.skill_list_csv else None
    skill_paths_file = normalize_user_path(args.skill_paths_file) if args.skill_paths_file else None
    report_dir = normalize_user_path(args.report_dir) if args.report_dir else (log_dir / "reports")
    log_dir.mkdir(parents=True, exist_ok=True)
    results_dir = log_dir / "skills"
    results_dir.mkdir(parents=True, exist_ok=True)
    if args.generate_markdown_reports:
        report_dir.mkdir(parents=True, exist_ok=True)

    tracker = ProgressTracker(
        log_dir=log_dir,
        total=0,
        config={
            "skills_root": str(skills_root),
            "log_dir": str(log_dir),
            "skill_list_csv": str(skill_list_csv) if skill_list_csv else None,
            "skill_paths_file": str(skill_paths_file) if skill_paths_file else None,
            "analysis_mode": args.analysis_mode,
            "network_policy": args.network_policy,
            "default_timeout_seconds": args.default_timeout_seconds,
            "max_workers": args.max_workers,
            "resume": args.resume,
            "resumed_existing_results": 0,
            "pending_skills": 0,
            "provider": normalize_llm_provider(args.provider),
            "base_url": args.base_url,
            "model": args.model,
            "llm_api_enabled": bool(args.api_key),
            "force_llm_on_empty_actions": args.force_llm_on_empty_actions,
            "generate_markdown_reports": args.generate_markdown_reports,
            "report_dir": str(report_dir) if args.generate_markdown_reports else None,
            "requested_skill_count": 0,
            "missing_requested_skill_count": 0,
            "execution_profile": args.execution_profile,
            "allow_profile_promotion": bool(args.allow_profile_promotion),
            "max_promotion_steps": int(args.max_promotion_steps),
        },
    )
    tracker.update_phase("discovering")

    if not skills_root.exists():
        hint = ""
        if re.match(r"^[a-zA-Z]:", args.skills_root) and not Path(f"/mnt/{args.skills_root[0].lower()}").exists():
            hint = f" WSL 中未发现对应盘符挂载：/mnt/{args.skills_root[0].lower()}"
        raise SystemExit(f"skills root does not exist: {skills_root}.{hint}")

    if skill_paths_file:
        if not skill_paths_file.exists():
            raise SystemExit(f"skill paths file does not exist: {skill_paths_file}")
        discovered = load_requested_skill_paths(skill_paths_file)
    else:
        discovered = discover_skills_fast(skills_root)
    requested_skill_ids: list[str] = []
    missing_requested_skill_ids: list[str] = []
    if skill_list_csv and not skill_paths_file:
        if not skill_list_csv.exists():
            raise SystemExit(f"skill list csv does not exist: {skill_list_csv}")
        requested_skill_ids = load_requested_skill_ids(skill_list_csv)
        requested_exact = set(requested_skill_ids)
        requested_portable = {portable_skill_id(item) for item in requested_skill_ids}
        filtered: list[Path] = []
        matched_exact: set[str] = set()
        matched_portable: set[str] = set()
        for skill_root in discovered:
            skill_id = slugify_path(skill_root)
            portable_id = portable_skill_id(skill_id)
            if skill_id in requested_exact or portable_id in requested_portable:
                filtered.append(skill_root)
                if skill_id in requested_exact:
                    matched_exact.add(skill_id)
                if portable_id in requested_portable:
                    matched_portable.add(portable_id)
        discovered = filtered
        for requested in requested_skill_ids:
            if requested not in matched_exact and portable_skill_id(requested) not in matched_portable:
                missing_requested_skill_ids.append(requested)
    if args.limit:
        discovered = discovered[: args.limit]

    discovered_paths_file = log_dir / "discovered-skill-paths.txt"
    discovered_paths_file.write_text(
        "".join(f"{item}\n" for item in discovered),
        encoding="utf-8",
    )
    existing_results = load_existing_results(results_dir) if args.resume else {}
    pending_skills = [
        (index, skill_root)
        for index, skill_root in enumerate(discovered, start=1)
        if slugify_path(skill_root) not in existing_results
    ]
    tracker.state["config"].update(
        {
            "skill_list_csv": str(skill_list_csv) if skill_list_csv else None,
            "skill_paths_file": str(skill_paths_file) if skill_paths_file else None,
            "resume": args.resume,
            "resumed_existing_results": len(existing_results),
            "pending_skills": len(pending_skills),
            "requested_skill_count": len(requested_skill_ids),
            "missing_requested_skill_count": len(missing_requested_skill_ids),
            "discovered_paths_file": str(discovered_paths_file),
        }
    )
    tracker.state["totals"] = build_initial_totals(len(discovered), existing_results)
    tracker.update_discovery(len(discovered), pending=len(pending_skills))
    tracker.write_manifest(
        {
            "generated_at": utc_now(),
            "skills_root": str(skills_root),
            "count": len(discovered),
            "skills": [str(item) for item in discovered],
            "discovered_paths_file": str(discovered_paths_file),
            "skill_list_csv": str(skill_list_csv) if skill_list_csv else None,
            "skill_paths_file": str(skill_paths_file) if skill_paths_file else None,
            "requested_skill_ids": requested_skill_ids,
            "missing_requested_skill_ids": missing_requested_skill_ids,
            "resume_enabled": args.resume,
            "existing_result_count": len(existing_results),
            "pending_skill_count": len(pending_skills),
            "generate_markdown_reports": args.generate_markdown_reports,
            "report_dir": str(report_dir) if args.generate_markdown_reports else None,
        }
    )
    tracker.update_phase("scanning")

    def generate_markdown_report_for_result(result_path: Path) -> Path | None:
        if not args.generate_markdown_reports:
            return None
        report_path = report_dir / f"{result_path.stem}.md"
        generate_report_file(result_path, report_path)
        tracker.update_last_report(report_path)
        return report_path

    if args.generate_markdown_reports and existing_results:
        for skill_id in sorted(existing_results):
            existing_result_path = results_dir / f"{skill_id}.json"
            if existing_result_path.exists():
                generate_markdown_report_for_result(existing_result_path)

    runner = DockerRunner()
    probe = CommandAvailabilityProbe(runner)
    summary_rows: list[dict[str, Any]] = list(existing_results.values())

    def process_skill(index: int, skill_root: Path) -> SkillScanResult:
        try:
            definition = load_skill_definition(skill_root, allow_empty_actions=True)
        except Exception as exc:
            profile = infer_capability_profile(skill_root=skill_root)
            plan = build_execution_plan(
                capability_profile=profile.to_dict(),
                requested_profile=args.execution_profile,
                allow_profile_promotion=bool(args.allow_profile_promotion),
                max_promotion_steps=max(0, int(args.max_promotion_steps)),
                default_timeout_seconds=max(30, int(args.default_timeout_seconds)),
            )
            trigger_plan = synthesize_trigger_plan(
                capability_profile=profile.to_dict(),
                execution_plan=plan.to_dict(),
                skill_name=skill_root.name,
                skill_description="",
            )
            skip_bundle = build_skip_bundle(
                skip_category=SKIP_INSUFFICIENT_EXECUTION_CONTEXT,
                skip_reason="invalid_skill_definition",
                capability_profile=profile.to_dict(),
                execution_plan=plan.to_dict(),
                static_report={},
                trigger_plan=trigger_plan.to_dict(),
                trigger_hits=[],
                trigger_used=[],
                budget_exceeded=False,
                status="skipped",
            )
            dual_axis = _dual_axis_for_partial(
                static_report={},
                capability_profile=profile.to_dict(),
                execution_plan=plan.to_dict(),
                trigger_used=[],
                trigger_hits=[],
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
            )
            root_cause_v2 = _root_cause_v2_for_partial(
                static_report={},
                execution_plan=plan.to_dict(),
                trigger_used=[],
                trigger_hits=[],
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
                llm_involved=False,
            )
            return SkillScanResult(
                skill_id=slugify_path(skill_root),
                skill_root=str(skill_root),
                skill_file="SKILL.md",
                name=skill_root.name,
                runtime="unknown",
                llm_enabled=False,
                status="skipped",
                skip_reason="invalid_skill_definition",
                capability_profile=profile.to_dict(),
                capability_tags=profile.capability_tags,
                recommended_execution_profile=profile.recommended_profile,
                recommended_trigger_mode=profile.recommended_trigger_mode,
                estimated_budget_class=profile.estimated_budget_class,
                execution_feasibility=profile.execution_feasibility,
                blocking_requirements=profile.blocking_requirements,
                selected_execution_profile=plan.effective_profile,
                execution_profile_config=plan.profile_config.to_dict(),
                execution_plan=plan.to_dict(),
                first_attempt_profile=plan.first_attempt_profile,
                promoted_profile=plan.promoted_profile or None,
                promotion_reason=plan.promotion_reason or None,
                budget_exceeded=plan.budget_exceeded,
                profile_selection_source=plan.selection_source,
                trigger_plan=trigger_plan.to_dict(),
                trigger_depth=trigger_plan.trigger_depth,
                trigger_budget_class=trigger_plan.budget_class,
                trigger_generation_rationale=trigger_plan.generation_rationale,
                trigger_used=[],
                trigger_hits=[],
                trigger_unexecuted=[],
                trigger_events_summary={},
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
                skip_explanation=skip_bundle.skip_explanation,
                partial_evidence=skip_bundle.partial_evidence,
                profile_promotion_recommended=skip_bundle.profile_promotion_recommended,
                severity_label=dual_axis.get("severity_label"),
                evidence_strength=dual_axis.get("evidence_strength"),
                decision_rationale=dual_axis.get("decision_rationale"),
                root_cause_v2=root_cause_v2,
                error=str(exc),
                started_at=utc_now(),
                finished_at=utc_now(),
            )
        capability_profile = infer_capability_profile(
            skill_root=skill_root,
            skill_file=definition.skill_file,
            skill_definition=definition,
        )
        execution_plan = build_execution_plan(
            capability_profile=capability_profile.to_dict(),
            requested_profile=args.execution_profile,
            allow_profile_promotion=bool(args.allow_profile_promotion),
            max_promotion_steps=max(0, int(args.max_promotion_steps)),
            default_timeout_seconds=max(30, int(args.default_timeout_seconds)),
        )
        trigger_plan = synthesize_trigger_plan(
            capability_profile=capability_profile.to_dict(),
            execution_plan=execution_plan.to_dict(),
            skill_name=definition.name,
            skill_description=definition.description,
        )
        llm_config = llm_config_for_skill(
            definition=definition,
            provider=args.provider,
            api_key=args.api_key,
            base_url=args.base_url,
            model=args.model,
            force_llm_on_empty_actions=args.force_llm_on_empty_actions,
        )
        tracker.start_skill(
            {
                "skill_id": slugify_path(skill_root),
                "index": index,
                "total": len(discovered),
                "skill_root": str(skill_root),
                "name": definition.name,
                "runtime": definition.runtime,
                "llm_enabled": llm_config.enabled,
                "recommended_execution_profile": capability_profile.recommended_profile,
                "execution_feasibility": capability_profile.execution_feasibility,
                "capability_tags": capability_profile.capability_tags,
                "selected_execution_profile": execution_plan.effective_profile,
                "selection_source": execution_plan.selection_source,
                "trigger_depth": trigger_plan.trigger_depth,
                "trigger_budget_class": trigger_plan.budget_class,
            }
        )

        runnable, missing, skip_reason = inspect_skill(
            definition=definition,
            probe=probe,
            force_llm_on_empty_actions=args.force_llm_on_empty_actions,
            api_key_present=bool(args.api_key),
        )
        preflight_category = preflight_taxonomy_category(
            capability_profile=capability_profile,
            execution_plan=execution_plan.to_dict(),
            skip_reason=skip_reason,
        )
        if preflight_category:
            runnable = False
            skip_reason = preflight_category

        if not runnable:
            static_report = _static_partial_report(definition)
            skip_category = categorize_skip(
                skip_reason=skip_reason,
                capability_profile=capability_profile.to_dict(),
                execution_plan=execution_plan.to_dict(),
                trigger_hits=[],
                budget_exceeded=False,
                static_report=static_report,
            )
            skip_bundle = build_skip_bundle(
                skip_category=skip_category,
                skip_reason=skip_reason,
                capability_profile=capability_profile.to_dict(),
                execution_plan=execution_plan.to_dict(),
                static_report=static_report,
                trigger_plan=trigger_plan.to_dict(),
                trigger_hits=[],
                trigger_used=[],
                budget_exceeded=False,
                status="skipped",
            )
            dual_axis = _dual_axis_for_partial(
                static_report=static_report,
                capability_profile=capability_profile.to_dict(),
                execution_plan=execution_plan.to_dict(),
                trigger_used=[],
                trigger_hits=[],
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
            )
            root_cause_v2 = _root_cause_v2_for_partial(
                static_report=static_report,
                execution_plan=execution_plan.to_dict(),
                trigger_used=[],
                trigger_hits=[],
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
                llm_involved=bool(llm_config.enabled),
            )
            result = SkillScanResult(
                skill_id=slugify_path(skill_root),
                skill_root=str(skill_root),
                skill_file=definition.skill_file,
                name=definition.name,
                runtime=definition.runtime,
                llm_enabled=llm_config.enabled,
                status="skipped",
                skip_reason=skip_reason,
                external_dependencies=missing or None,
                capability_profile=capability_profile.to_dict(),
                capability_tags=capability_profile.capability_tags,
                recommended_execution_profile=capability_profile.recommended_profile,
                recommended_trigger_mode=capability_profile.recommended_trigger_mode,
                estimated_budget_class=capability_profile.estimated_budget_class,
                execution_feasibility=capability_profile.execution_feasibility,
                blocking_requirements=capability_profile.blocking_requirements,
                selected_execution_profile=execution_plan.effective_profile,
                execution_profile_config=execution_plan.profile_config.to_dict(),
                execution_plan=execution_plan.to_dict(),
                first_attempt_profile=execution_plan.first_attempt_profile,
                promoted_profile=execution_plan.promoted_profile or None,
                promotion_reason=execution_plan.promotion_reason or None,
                budget_exceeded=execution_plan.budget_exceeded,
                profile_selection_source=execution_plan.selection_source,
                enabled_adapters=[],
                adapter_events_summary={},
                synthetic_artifact_summary={},
                trigger_plan=trigger_plan.to_dict(),
                trigger_depth=trigger_plan.trigger_depth,
                trigger_budget_class=trigger_plan.budget_class,
                trigger_generation_rationale=trigger_plan.generation_rationale,
                trigger_used=[],
                trigger_hits=[],
                trigger_unexecuted=[],
                trigger_events_summary={},
                execution_outcome=skip_bundle.execution_outcome,
                skip_category=skip_bundle.skip_category,
                skip_explanation=skip_bundle.skip_explanation,
                partial_evidence=skip_bundle.partial_evidence,
                profile_promotion_recommended=skip_bundle.profile_promotion_recommended,
                severity_label=dual_axis.get("severity_label"),
                evidence_strength=dual_axis.get("evidence_strength"),
                decision_rationale=dual_axis.get("decision_rationale"),
                dynamic_chain_observed=static_report.get("dynamic_chain_observed"),
                instruction_chain_recovered=static_report.get("instruction_chain_recovered"),
                chain_evidence_type=static_report.get("chain_evidence_type"),
                instruction_chain=static_report.get("instruction_chain", []),
                instruction_indicators=static_report.get("instruction_indicators", []),
                static_supply_chain_risk=static_report.get("static_supply_chain_risk", {}),
                instruction_document_scan=static_report.get("instruction_document_scan", {}),
                final_risk_level=static_report.get("final_risk_level"),
                final_label_reason=static_report.get("final_label_reason"),
                root_cause=static_report.get("root_cause"),
                root_cause_detail=static_report.get("root_cause_detail"),
                root_cause_v2=root_cause_v2,
                started_at=utc_now(),
                finished_at=utc_now(),
            )
        else:
            result = scan_one_skill(
                skill_root=skill_root,
                definition=definition,
                capability_profile=capability_profile,
                execution_plan=execution_plan.to_dict(),
                trigger_plan=trigger_plan.to_dict(),
                runner=runner,
                analysis_mode=args.analysis_mode,
                network_policy=args.network_policy,
                timeout_seconds=execution_plan.profile_config.timeout_seconds,
                provider=args.provider,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                force_llm_on_empty_actions=args.force_llm_on_empty_actions,
            )
        return result

    future_map: dict[concurrent.futures.Future[SkillScanResult], tuple[int, Path]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as executor:
        for index, skill_root in pending_skills:
            future = executor.submit(process_skill, index, skill_root)
            future_map[future] = (index, skill_root)

        for future in concurrent.futures.as_completed(future_map):
            _, skill_root = future_map[future]
            result = future.result()
            result_path = results_dir / f"{result.skill_id}.json"
            result_path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2), encoding="utf-8")
            generate_markdown_report_for_result(result_path)
            tracker.append_result(result, result_path)
            summary_rows.append(asdict(result))

    tracker.finish()
    progress_snapshot = tracker.snapshot()
    tracker.write_summary(
        {
            "generated_at": utc_now(),
            "skills_root": str(skills_root),
            "log_dir": str(log_dir),
            "progress": progress_snapshot,
            "distributions": build_summary_distributions(summary_rows),
            "results": summary_rows,
        }
    )
    print(
        json.dumps(
            {
                "status": "completed",
                "skills_root": str(skills_root),
                "log_dir": str(log_dir),
                "discovered": len(discovered),
                "skill_list_csv": str(skill_list_csv) if skill_list_csv else None,
                "skill_paths_file": str(skill_paths_file) if skill_paths_file else None,
                "requested_skill_count": len(requested_skill_ids),
                "missing_requested_skill_count": len(missing_requested_skill_ids),
                "resumed_existing_results": len(existing_results),
                "pending_skills": len(pending_skills),
                "progress_file": str(tracker.progress_path),
                "summary_file": str(tracker.summary_path),
                "results_jsonl": str(tracker.results_jsonl),
                "report_dir": str(report_dir) if args.generate_markdown_reports else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
