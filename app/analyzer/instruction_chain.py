from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024


@dataclass(frozen=True)
class IndicatorRule:
    category: str
    action: str
    pattern: re.Pattern[str]
    confidence: str = "medium"


INDICATOR_RULES: list[IndicatorRule] = [
    IndicatorRule("external_agent", "external_agent_install", re.compile(r"\bopenclaw-agent\b", re.I), "high"),
    IndicatorRule("external_agent", "external_agent_install", re.compile(r"\b(third[-\s]?party|external)\s+agent\b", re.I)),
    IndicatorRule("external_agent", "external_agent_install", re.compile(r"\b(download|install)\s+(?:an?\s+)?(?:external\s+|third[-\s]?party\s+)?agent\b", re.I)),
    IndicatorRule("external_agent", "external_agent_install", re.compile(r"\brun\s+(?:the\s+)?executable\s+before\s+using\s+commands\b", re.I)),
    IndicatorRule(
        "remote_acquisition",
        "remote_script_or_binary_acquisition",
        re.compile(r"\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sh|bash|zsh)\b", re.I),
        "high",
    ),
    IndicatorRule(
        "remote_acquisition",
        "remote_script_or_binary_acquisition",
        re.compile(r"\b(?:iwr|invoke-webrequest)\b[^\n|;]{0,240}(?:iex|invoke-expression)\b", re.I),
        "high",
    ),
    IndicatorRule("remote_acquisition", "remote_script_or_binary_acquisition", re.compile(r"\braw\.githubusercontent\.com\b", re.I), "high"),
    IndicatorRule("remote_acquisition", "remote_script_or_binary_acquisition", re.compile(r"\bglot\.io/snippets\b", re.I), "high"),
    IndicatorRule("remote_acquisition", "remote_script_or_binary_acquisition", re.compile(r"\b(?:pastebin\.com|gist\.github\.com|bit\.ly|tinyurl\.com|t\.co)\b", re.I)),
    IndicatorRule(
        "remote_acquisition",
        "remote_script_or_binary_acquisition",
        re.compile(r"\bgithub\.com/[^)\s]+/releases/download/[^)\s]+(?:\.zip|\.exe|\.dmg|\.tar\.gz|\.tgz)?", re.I),
        "high",
    ),
    IndicatorRule("remote_acquisition", "remote_script_or_binary_acquisition", re.compile(r"\bcopy\s+(?:the\s+)?(?:installation\s+)?script\b.{0,120}\bpaste\s+it\s+into\s+terminal\b", re.I | re.S), "high"),
    IndicatorRule("fixed_password_archive", "fixed_password_archive", re.compile(r"\bextract\s+using\s+pass(?:word)?\b", re.I), "high"),
    IndicatorRule("fixed_password_archive", "fixed_password_archive", re.compile(r"\bpassword\s*:\s*`?openclaw`?\b", re.I), "high"),
    IndicatorRule("fixed_password_archive", "fixed_password_archive", re.compile(r"\bunzip\b[^\n]{0,120}\b(?:-P|--password|password)\b", re.I), "high"),
    IndicatorRule("fixed_password_archive", "fixed_password_archive", re.compile(r"\bfixed\s+archive\s+password\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bcron\s+add\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bcrontab\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bsystemd\b[^\n]{0,80}\benable\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\blaunchctl\s+load\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bschtasks\b[^\n]{0,80}/create\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bstartup\s+item\b", re.I)),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bdaily\s+auto[-\s]?update\b", re.I), "high"),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\b--wake\s+now\b", re.I)),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\b--deliver\b", re.I)),
    IndicatorRule("persistence", "persistence_setup", re.compile(r"\bisolated\s+session\b.{0,120}\brecurring\s+execution\b", re.I | re.S)),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bnpm\s+(?:update|install|i)\s+-g\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bpnpm\s+(?:update|install|add)\s+-g\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bbun\s+update\s+-g\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bpip(?:3)?\s+install\s+-U\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bglobal\s+package\s+update\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bclawdbot\s+update\b", re.I), "medium"),
    IndicatorRule("environment_modification", "global_environment_modification", re.compile(r"\bclawdbot\s+doctor\b.{0,120}\bmigration", re.I | re.S), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\bclawdhub\s+update\s+--all\b", re.I), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\bclawhub\s+update\s+--all\b", re.I), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\bupdate\s+all\s+skills\b", re.I), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\bsync\s+installed\s+skills\b", re.I), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\bbulk\s+skill\s+update\b", re.I), "high"),
    IndicatorRule("bulk_update", "bulk_skill_update", re.compile(r"\binstall/update\s+skills\s+from\s+registry\b", re.I), "high"),
    IndicatorRule(
        "sensitive_context",
        "sensitive_capability_context",
        re.compile(r"\b(wallet|trading|blockchain|oauth|gmail|drive|calendar|google\s+docs|credentials?|token|private\s+key|seed\s+phrase)\b", re.I),
        "medium",
    ),
]

LOCAL_INSTALL_RE = re.compile(r"\b(?:pip(?:3)?\s+install|npm\s+install|npm\s+i|brew\s+install)\b", re.I)


def analyze_instruction_chain(skill_root: str | Path, skill_file: str = "SKILL.md") -> dict[str, Any]:
    root = Path(skill_root).resolve()
    documents = _load_candidate_documents(root, skill_file)
    indicators: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for rel_path, text in documents:
        for rule in INDICATOR_RULES:
            for match in rule.pattern.finditer(text):
                snippet = _snippet(text, match.start(), match.end())
                key = (rule.category, rule.action, snippet.lower())
                if key in seen:
                    continue
                seen.add(key)
                indicators.append(
                    {
                        "category": rule.category,
                        "action": rule.action,
                        "target": _target_from_match(rule.category, match.group(0)),
                        "evidence_source": rel_path,
                        "evidence_type": "document_instruction",
                        "observed_at_runtime": False,
                        "confidence": rule.confidence,
                        "raw_snippet": snippet,
                    }
                )

    categories = {item["category"] for item in indicators}
    actions = {item["action"] for item in indicators}
    has_local_install_only = _has_local_install(documents) and not categories
    risk = _score_instruction_risk(categories=categories, actions=actions, has_local_install_only=has_local_install_only)
    chain = _build_instruction_chain(indicators, risk["closed_risk_path"])

    return {
        "instruction_chain_recovered": bool(chain),
        "instruction_chain": chain,
        "instruction_indicators": indicators,
        "static_supply_chain_risk": risk,
        "document_scan_summary": {
            "files_scanned": [rel_path for rel_path, _ in documents],
            "bytes_scanned": sum(len(text.encode("utf-8", errors="ignore")) for _, text in documents),
            "file_limit_bytes": MAX_FILE_BYTES,
            "total_budget_bytes": MAX_TOTAL_BYTES,
        },
    }


def apply_instruction_chain_decision(
    report: dict[str, Any],
    skill_root: str | Path | None,
    skill_file: str = "SKILL.md",
    *,
    dynamic_chain_observed: bool | None = None,
) -> dict[str, Any]:
    if not skill_root:
        instruction = _empty_instruction_result()
    else:
        try:
            instruction = analyze_instruction_chain(skill_root, skill_file)
        except Exception as exc:
            instruction = _empty_instruction_result()
            instruction["static_supply_chain_risk"]["reason"] = f"instruction scan unavailable: {exc}"

    observed_dynamic_chain = bool(report.get("primary_chain")) if dynamic_chain_observed is None else bool(dynamic_chain_observed)
    report.update(
        {
            "dynamic_chain_observed": observed_dynamic_chain,
            "instruction_chain_recovered": bool(instruction.get("instruction_chain_recovered")),
            "instruction_chain": instruction.get("instruction_chain", []),
            "instruction_indicators": instruction.get("instruction_indicators", []),
            "static_supply_chain_risk": instruction.get("static_supply_chain_risk", _none_risk()),
            "instruction_document_scan": instruction.get("document_scan_summary", {}),
        }
    )

    report["chain_evidence_type"] = _chain_evidence_type(
        dynamic_observed=bool(report["dynamic_chain_observed"]),
        instruction_recovered=bool(report["instruction_chain_recovered"]),
    )
    report["final_risk_level"] = _aggregate_final_risk_level(report)
    report["final_label_reason"] = _final_label_reason(report)
    return report


def _load_candidate_documents(root: Path, skill_file: str) -> list[tuple[str, str]]:
    candidates: list[Path] = []
    skill_path = (root / skill_file).resolve()
    if _within_root(root, skill_path):
        candidates.append(skill_path)
    candidates.extend(sorted(root.glob("README.md")))
    candidates.extend(sorted(root.glob("README-*.md")))
    package_json = root / "package.json"
    if package_json.exists():
        candidates.append(package_json)
    scripts = root / "scripts"
    if scripts.is_dir():
        candidates.extend(sorted(scripts.glob("*.sh")))
        candidates.extend(sorted(scripts.glob("*.py")))

    loaded: list[tuple[str, str]] = []
    total = 0
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved in seen or not _within_root(root, resolved) or not resolved.is_file():
            continue
        seen.add(resolved)
        try:
            size = resolved.stat().st_size
        except OSError:
            continue
        if size <= 0:
            continue
        read_size = min(size, MAX_FILE_BYTES, max(0, MAX_TOTAL_BYTES - total))
        if read_size <= 0:
            break
        try:
            with resolved.open("rb") as handle:
                raw = handle.read(read_size)
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        total += len(raw)
        loaded.append((str(resolved.relative_to(root)), text))
        if total >= MAX_TOTAL_BYTES:
            break
    return loaded


def _score_instruction_risk(*, categories: set[str], actions: set[str], has_local_install_only: bool) -> dict[str, Any]:
    has_external_agent = "external_agent" in categories
    has_remote = "remote_acquisition" in categories
    has_fixed_password = "fixed_password_archive" in categories
    has_persistence = "persistence" in categories
    has_bulk = "bulk_update" in categories
    has_env = "environment_modification" in categories
    has_sensitive = "sensitive_context" in categories
    has_trust_boundary = has_external_agent or has_remote or has_fixed_password
    has_execution_transfer = bool(
        actions & {
            "external_agent_install",
            "remote_script_or_binary_acquisition",
            "global_environment_modification",
        }
    )

    if has_trust_boundary and has_execution_transfer and (has_persistence or has_bulk):
        sinks = []
        if has_persistence:
            sinks.append("persistence")
        if has_bulk:
            sinks.append("bulk skill update")
        return {
            "level": "critical",
            "reason": (
                "Document instructions cross an external trust boundary and transfer execution/control into "
                f"{' and '.join(sinks)}. This is a critical instruction-derived latent attack path, "
                "not observed at runtime."
            ),
            "closed_risk_path": True,
        }

    if has_external_agent and has_execution_transfer and has_env:
        return {
            "level": "high",
            "reason": (
                "Document instructions require an external agent and global/future execution environment modification. "
                "The chain is document-supported and requires user setup."
            ),
            "closed_risk_path": True,
        }

    if has_external_agent and has_sensitive and (has_remote or has_fixed_password):
        return {
            "level": "medium",
            "reason": (
                "External agent setup is paired with sensitive business capability context and remote/fixed-password acquisition. "
                "This is capability and trust risk, not a runtime data-theft chain."
            ),
            "closed_risk_path": True,
        }

    if has_trust_boundary and has_execution_transfer:
        return {
            "level": "medium",
            "reason": (
                "Document instructions describe external acquisition or agent installation, but no persistence, bulk update, "
                "or comparable security-impact sink was found."
            ),
            "closed_risk_path": False,
        }

    if has_env:
        return {
            "level": "medium",
            "reason": "Global package or environment modification is documented, but no closed external-to-sink path was found.",
            "closed_risk_path": False,
        }

    if has_local_install_only:
        return {
            "level": "low",
            "reason": "Only ordinary local dependency installation instructions were found.",
            "closed_risk_path": False,
        }

    if has_persistence:
        return {
            "level": "low",
            "reason": "Persistence-like scheduling instructions were found without external acquisition or control transfer.",
            "closed_risk_path": False,
        }

    return _none_risk()


def _build_instruction_chain(indicators: list[dict[str, Any]], closed_risk_path: bool) -> list[dict[str, Any]]:
    if not closed_risk_path:
        return []
    by_action: dict[str, dict[str, Any]] = {}
    for item in indicators:
        by_action.setdefault(str(item["action"]), item)

    order = [
        "external_agent_install",
        "remote_script_or_binary_acquisition",
        "fixed_password_archive",
        "global_environment_modification",
        "persistence_setup",
        "bulk_skill_update",
        "sensitive_capability_context",
    ]
    chain: list[dict[str, Any]] = []
    previous = "skill_bundle_documentation"
    for action in order:
        item = by_action.get(action)
        if not item:
            continue
        edge = {
            "source": previous,
            "action": action,
            "target": item.get("target") or action,
            "evidence_source": item.get("evidence_source", ""),
            "evidence_type": "document_instruction",
            "observed_at_runtime": False,
            "confidence": item.get("confidence", "medium"),
            "raw_snippet": item.get("raw_snippet", ""),
        }
        chain.append(edge)
        previous = str(edge["target"])
    return chain


def _aggregate_final_risk_level(report: dict[str, Any]) -> str:
    dynamic = _dynamic_level(report)
    static_level = str((report.get("static_supply_chain_risk") or {}).get("level", "none"))
    if _risk_rank(dynamic) >= _risk_rank("high"):
        return dynamic
    if bool((report.get("static_supply_chain_risk") or {}).get("closed_risk_path")) and static_level == "high":
        return "high"
    if _risk_rank(static_level) > _risk_rank(dynamic):
        return static_level
    return dynamic


def _dynamic_level(report: dict[str, Any]) -> str:
    score = int(report.get("risk_score", 0) or 0)
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _risk_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


def _final_label_reason(report: dict[str, Any]) -> str:
    static_risk = report.get("static_supply_chain_risk") or {}
    static_level = str(static_risk.get("level", "none"))
    dynamic_observed = bool(report.get("dynamic_chain_observed"))
    instruction_recovered = bool(report.get("instruction_chain_recovered"))
    final_level = str(report.get("final_risk_level", "low"))
    if instruction_recovered and _risk_rank(static_level) >= _risk_rank("medium"):
        runtime_note = (
            "Runtime telemetry also contains a primary chain."
            if dynamic_observed
            else "Runtime telemetry did not observe this execution chain."
        )
        return (
            f"{runtime_note} Final risk is {final_level} because a document-supported instruction-derived chain "
            f"was recovered from local SKILL.md/README-style instructions. {static_risk.get('reason', '')}"
        ).strip()
    if static_level == "medium":
        return (
            "Runtime telemetry did not observe a closed execution chain. Local documentation contains setup or "
            f"environment-control instructions requiring review. {static_risk.get('reason', '')}"
        ).strip()
    return "Final risk follows runtime/dynamic evidence; no closed instruction-derived chain was recovered."


def _chain_evidence_type(*, dynamic_observed: bool, instruction_recovered: bool) -> str:
    if dynamic_observed and instruction_recovered:
        return "hybrid"
    if dynamic_observed:
        return "observed_runtime"
    if instruction_recovered:
        return "instruction_derived"
    return "none"


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 100)
    right = min(len(text), end + 100)
    return " ".join(text[left:right].split())[:500]


def _target_from_match(category: str, value: str) -> str:
    match = re.search(r"https?://[^\s)>\]`]+", value)
    if match:
        return match.group(0).rstrip(".,")
    if category == "external_agent":
        return "openclaw-agent" if "openclaw-agent" in value.lower() else "external_agent"
    if category == "persistence":
        return "recurring_execution"
    if category == "bulk_update":
        return "installed_skills"
    if category == "environment_modification":
        return "global_execution_environment"
    if category == "sensitive_context":
        return "sensitive_capability_context"
    return value.strip()[:120]


def _has_local_install(documents: list[tuple[str, str]]) -> bool:
    return any(LOCAL_INSTALL_RE.search(text) for _, text in documents)


def _within_root(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _none_risk() -> dict[str, Any]:
    return {
        "level": "none",
        "reason": "No instruction-level supply-chain control path was found.",
        "closed_risk_path": False,
    }


def _empty_instruction_result() -> dict[str, Any]:
    return {
        "instruction_chain_recovered": False,
        "instruction_chain": [],
        "instruction_indicators": [],
        "static_supply_chain_risk": _none_risk(),
        "document_scan_summary": {
            "files_scanned": [],
            "bytes_scanned": 0,
            "file_limit_bytes": MAX_FILE_BYTES,
            "total_budget_bytes": MAX_TOTAL_BYTES,
        },
    }
