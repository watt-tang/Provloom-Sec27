from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from app.instruction.models import Action, Document, DocumentSpan, Entity
from app.instruction.serialization import stable_id


URL_RE = re.compile(r"https?://[^\s<>)\]`\"']+")
PATH_RE = re.compile(
    r"(?P<path>(?:/etc|/root|/var|/usr|/tmp|~|\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@+-]+)+(?:\.[A-Za-z0-9]+)?)"
)
ENV_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
PACKAGE_RE = re.compile(r"\b(?:npm|pnpm|yarn|pip|pip3|brew)\s+(?:install|i|add|update|upgrade)\b(?P<args>[^\n]*)", re.I)
SHELL_LINE_RE = re.compile(r"(?m)^\s*(?:[$#]\s*)?(?P<command>(?:sudo\s+)?(?:curl|wget|bash|sh|python|python3|node|npm|pnpm|yarn|pip|pip3|tar|unzip|chmod|crontab|systemctl|launchctl|schtasks|openclaw-agent|clawhub|cllawhub|clawdhub|clawdbot)\b[^\n]*)")

OPERATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("download", re.compile(r"\b(download|fetch|retrieve|pull)\b", re.I)),
    ("install", re.compile(r"\b(install|bootstrap|add package)\b", re.I)),
    ("extract", re.compile(r"\b(extract|unzip|untar|decompress)\b", re.I)),
    ("execute", re.compile(r"\b(run|execute|launch|invoke|start)\b", re.I)),
    ("register_cron", re.compile(r"\b(cron|crontab|scheduled task|schedule)\b", re.I)),
    ("register_service", re.compile(r"\b(systemd|launchctl|service|daemon)\b", re.I)),
    ("persist", re.compile(r"\b(persist|startup|auto[- ]?start|recurring execution)\b", re.I)),
    ("update", re.compile(r"\b(update|upgrade|sync)\b", re.I)),
    ("replace", re.compile(r"\b(replace|overwrite)\b", re.I)),
    ("modify_environment", re.compile(r"\b(global|environment|PATH|profile|shell rc|\.bashrc|\.zshrc)\b", re.I)),
    ("authenticate", re.compile(r"\b(authenticate|login|oauth|token)\b", re.I)),
    ("grant_permission", re.compile(r"\b(grant|permission|scope|read/write|full access)\b", re.I)),
    ("connect_account", re.compile(r"\b(connect account|link account|google workspace|gmail|drive|wallet)\b", re.I)),
    ("access_credential", re.compile(r"\b(credential|token|api key|private key|seed phrase)\b", re.I)),
    ("send", re.compile(r"\b(send|upload|post|forward|exfiltrate)\b", re.I)),
]
SENSITIVE_CAPABILITY_RE = re.compile(r"\b(wallet|trading|blockchain|ethereum|solana|oauth|gmail|drive|calendar|credentials?|token|private key|seed phrase)\b", re.I)

CONTROL_TRANSFER_OPS = {"execute", "invoke", "install", "register_service", "register_cron", "persist", "modify_environment", "update", "replace"}


@dataclass
class ExtractionResult:
    actions: list[Action] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)


class DeterministicExtractor:
    def extract(self, documents: list[Document], spans: list[DocumentSpan], contents_by_document: dict[str, str]) -> ExtractionResult:
        result = ExtractionResult()
        entity_by_key: dict[tuple[str, str], Entity] = {}

        for span in spans:
            text = span.raw_text
            self._extract_entities(span, text, entity_by_key)
            if span.content_type in {"prohibition", "example", "quote", "warning"}:
                self._extract_suppressed_indicators(span, text, result)
                continue
            if span.content_type in {"shell_command", "code_block"}:
                self._extract_shell_actions(span, text, entity_by_key, result)
            elif span.content_type == "configuration":
                self._extract_config_actions(span, text, entity_by_key, result)
            elif span.content_type in {"prose_instruction", "prose_description"}:
                self._extract_prose_actions(span, text, entity_by_key, result)

        result.entities = list(entity_by_key.values())
        return result

    def _extract_entities(self, span: DocumentSpan, text: str, entity_by_key: dict[tuple[str, str], Entity]) -> None:
        for url in URL_RE.findall(text):
            cleaned = url.rstrip(".,")
            parsed = urlparse(cleaned)
            self._entity(
                entity_by_key,
                "URL",
                cleaned,
                span,
                attributes={
                    "scheme": parsed.scheme,
                    "domain": parsed.hostname or "",
                    "path": parsed.path,
                    "query": parsed.query,
                    "remote": True,
                    "alignment_key": cleaned,
                },
            )
            if parsed.hostname:
                self._entity(
                    entity_by_key,
                    "domain",
                    parsed.hostname,
                    span,
                    attributes={"domain": parsed.hostname, "alignment_key": parsed.hostname},
                )

        for path in _local_paths(text):
            if len(path) < 3:
                continue
            entity_type = _path_entity_type(path)
            self._entity(
                entity_by_key,
                entity_type,
                path,
                span,
                attributes={
                    "local_path": path,
                    "sensitive": path.startswith(("/etc/", "/root/", "~/.ssh")),
                    "alignment_key": path,
                },
            )

        for env in ENV_RE.findall(text):
            if env in {"README", "SKILL", "JSON", "HTTP", "URL"}:
                continue
            self._entity(entity_by_key, "environment_variable", env, span, attributes={"alignment_key": env})

    def _extract_shell_actions(
        self,
        span: DocumentSpan,
        text: str,
        entity_by_key: dict[tuple[str, str], Entity],
        result: ExtractionResult,
    ) -> None:
        for match in SHELL_LINE_RE.finditer(text):
            command = match.group("command").strip()
            if not command:
                continue
            command_entity = self._entity(entity_by_key, "process", command, span, attributes={"command": command, "alignment_key": command})
            operations = _operations_for_command(command)
            if not operations:
                operations = ["unknown"]
            for operation in operations:
                obj, src, dest = self._entities_for_operation(operation, command, entity_by_key, span)
                action = self._action(
                    span=span,
                    operation=operation,
                    object_entity_id=obj,
                    source_entity_id=src,
                    destination_entity_id=dest,
                    instrument_entity_id=command_entity.entity_id,
                    extraction_method="deterministic_shell",
                    confidence=0.92,
                    metadata={"command": command},
                )
                result.actions.append(action)
                result.indicators.append(_indicator_from_action(action, span, "deterministic_shell"))

    def _extract_config_actions(
        self,
        span: DocumentSpan,
        text: str,
        entity_by_key: dict[tuple[str, str], Entity],
        result: ExtractionResult,
    ) -> None:
        if span.metadata.get("relative_path", "").endswith("package.json"):
            try:
                package = json.loads(text)
            except json.JSONDecodeError:
                package = {}
            scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
            for name, command in scripts.items():
                operation = "install" if name in {"preinstall", "install", "postinstall"} else "execute"
                if any(token in name for token in {"update", "upgrade"}):
                    operation = "update"
                command_entity = self._entity(entity_by_key, "process", str(command), span, attributes={"command": str(command), "script_name": name})
                action = self._action(
                    span=span,
                    operation=operation,
                    object_entity_id=command_entity.entity_id,
                    instrument_entity_id=command_entity.entity_id,
                    extraction_method="deterministic_package_json",
                    confidence=0.95,
                    metadata={"script_name": name, "command": command},
                )
                result.actions.append(action)
                result.indicators.append(_indicator_from_action(action, span, "deterministic_package_json"))
                self._extract_shell_actions(span, str(command), entity_by_key, result)

        for url in URL_RE.findall(text):
            entity = self._entity(entity_by_key, "URL", url.rstrip(".,"), span, attributes={"remote": True, "alignment_key": url.rstrip(".,")})
            action = self._action(
                span=span,
                operation="connect",
                destination_entity_id=entity.entity_id,
                extraction_method="deterministic_config",
                confidence=0.8,
                metadata={"url": url.rstrip(".,")},
            )
            result.actions.append(action)

    def _extract_prose_actions(
        self,
        span: DocumentSpan,
        text: str,
        entity_by_key: dict[tuple[str, str], Entity],
        result: ExtractionResult,
    ) -> None:
        lowered = text.lower()
        for operation, pattern in OPERATION_PATTERNS:
            if not pattern.search(text):
                continue
            obj, src, dest = self._entities_for_operation(operation, text, entity_by_key, span)
            action = self._action(
                span=span,
                operation=operation,
                object_entity_id=obj,
                source_entity_id=src,
                destination_entity_id=dest,
                extraction_method="deterministic_nl",
                confidence=0.74 if operation != "unknown" else 0.45,
                metadata={"matched_text": pattern.pattern},
            )
            result.actions.append(action)
            result.indicators.append(_indicator_from_action(action, span, "deterministic_nl"))

        if "openclaw-agent" in lowered or "external agent" in lowered or "third-party agent" in lowered:
            entity = self._entity(entity_by_key, "executable", "openclaw-agent" if "openclaw-agent" in lowered else "external_agent", span)
            action = self._action(
                span=span,
                operation="install",
                object_entity_id=entity.entity_id,
                extraction_method="deterministic_nl",
                confidence=0.82,
                metadata={"agent_install": True},
            )
            result.actions.append(action)
            result.indicators.append(_indicator_from_action(action, span, "deterministic_nl"))

        if SENSITIVE_CAPABILITY_RE.search(text):
            result.indicators.append(
                {
                    "category": "sensitive_context",
                    "action": "sensitive_capability_context",
                    "target": "sensitive_capability_context",
                    "evidence_source": span.metadata.get("relative_path", ""),
                    "evidence_type": "typed_instruction_action",
                    "observed_at_runtime": False,
                    "confidence": "medium",
                    "raw_snippet": span.normalized_text[:500],
                    "span_id": span.span_id,
                    "operation": "capability_context",
                    "modality": span.metadata.get("modality_hint"),
                    "context": span.metadata.get("context_hint"),
                    "extraction_method": "deterministic_capability_keyword",
                }
            )

    def _extract_suppressed_indicators(self, span: DocumentSpan, text: str, result: ExtractionResult) -> None:
        if URL_RE.search(text) or any(pattern.search(text) for _, pattern in OPERATION_PATTERNS):
            result.indicators.append(
                {
                    "category": "suppressed_instruction_text",
                    "action": "suppressed_context",
                    "target": span.content_type,
                    "evidence_source": span.metadata.get("relative_path", ""),
                    "evidence_type": span.content_type,
                    "observed_at_runtime": False,
                    "confidence": "high",
                    "raw_snippet": span.normalized_text[:500],
                    "span_id": span.span_id,
                    "modality": span.metadata.get("modality_hint"),
                    "context": span.metadata.get("context_hint"),
                }
            )

    def _entities_for_operation(
        self,
        operation: str,
        text: str,
        entity_by_key: dict[tuple[str, str], Entity],
        span: DocumentSpan,
    ) -> tuple[str | None, str | None, str | None]:
        urls = [url.rstrip(".,") for url in URL_RE.findall(text)]
        paths = _local_paths(text)
        url_entity = self._entity(entity_by_key, "URL", urls[0], span, attributes={"remote": True, "alignment_key": urls[0]}) if urls else None
        path_entity = None
        for path in paths:
            if "://" not in path and len(path) >= 3:
                path_entity = self._entity(entity_by_key, _path_entity_type(path), path, span, attributes={"local_path": path, "alignment_key": path})
                break

        if operation in {"download", "fetch", "clone", "install"}:
            return (path_entity.entity_id if path_entity else (url_entity.entity_id if url_entity else None), url_entity.entity_id if url_entity else None, path_entity.entity_id if path_entity else None)
        if operation in {"send", "upload", "connect", "connect_account"}:
            return (path_entity.entity_id if path_entity else None, path_entity.entity_id if path_entity else None, url_entity.entity_id if url_entity else None)
        return (path_entity.entity_id if path_entity else (url_entity.entity_id if url_entity else None), None, url_entity.entity_id if url_entity else None)

    def _action(
        self,
        *,
        span: DocumentSpan,
        operation: str,
        object_entity_id: str | None = None,
        source_entity_id: str | None = None,
        destination_entity_id: str | None = None,
        instrument_entity_id: str | None = None,
        extraction_method: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> Action:
        modality = span.metadata.get("modality_hint", "required")
        context = span.metadata.get("context_hint", "unknown")
        action = Action(
            action_id=stable_id("act", span.span_id, operation, object_entity_id, source_entity_id, destination_entity_id, metadata or {}),
            actor="user",
            operation=operation,
            object_entity_id=object_entity_id,
            source_entity_id=source_entity_id,
            destination_entity_id=destination_entity_id,
            condition=span.normalized_text if modality == "conditional" else None,
            modality=modality,
            context=context,
            privilege=_privilege_for_text(span.raw_text),
            evidence_span_ids=[span.span_id],
            extraction_method=extraction_method,
            confidence=confidence if modality not in {"optional", "conditional"} else min(confidence, 0.68),
            alignment_keys=_alignment_keys(operation, metadata or {}),
            metadata=dict(metadata or {}),
        )
        action.metadata.setdefault("raw_snippet", span.normalized_text[:500])
        return action

    @staticmethod
    def _entity(
        entity_by_key: dict[tuple[str, str], Entity],
        entity_type: str,
        canonical_name: str,
        span: DocumentSpan,
        attributes: dict[str, Any] | None = None,
    ) -> Entity:
        cleaned = canonical_name.strip().rstrip(".,")
        key = (entity_type, cleaned.lower())
        existing = entity_by_key.get(key)
        if existing is not None:
            if span.span_id not in existing.evidence_span_ids:
                existing.evidence_span_ids.append(span.span_id)
            existing.attributes.update({key: value for key, value in (attributes or {}).items() if value not in (None, "")})
            return existing
        entity = Entity(
            entity_id=stable_id("ent", entity_type, cleaned.lower()),
            entity_type=entity_type,
            canonical_name=cleaned,
            aliases=[cleaned],
            attributes=dict(attributes or {}),
            evidence_span_ids=[span.span_id],
            confidence=0.9 if entity_type in {"URL", "domain", "local_file", "directory"} else 0.7,
        )
        entity_by_key[key] = entity
        return entity


def _operations_for_command(command: str) -> list[str]:
    lower = command.lower()
    operations: list[str] = []
    if "curl" in lower or "wget" in lower:
        operations.append("download" if not any(token in lower for token in {" -d ", "--data", "--upload-file", " -f ", "@-"}) else "send")
    if re.search(r"\|\s*(bash|sh|zsh)\b", lower) or re.search(r"\b(bash|sh|python|python3|node)\s+[^-\s]", lower):
        operations.append("execute")
    if "tar " in lower or "unzip" in lower:
        operations.append("extract")
    if "chmod" in lower:
        operations.append("modify_configuration")
    if "crontab" in lower or "schtasks" in lower:
        operations.append("register_cron")
    if "systemctl" in lower or "launchctl" in lower:
        operations.append("register_service")
    if "npm install -g" in lower or "npm i -g" in lower or "pip install -u" in lower or "pnpm add -g" in lower:
        operations.append("modify_environment")
    if PACKAGE_RE.search(command):
        operations.append("install")
    if "update --all" in lower or "update all" in lower or "sync installed skills" in lower:
        operations.append("update")
    if "openclaw-agent" in lower or "clawhub" in lower or "cllawhub" in lower or "clawdhub" in lower:
        operations.append("install")
    return _dedupe(operations)


def _local_paths(text: str) -> list[str]:
    url_ranges = [(match.start(), match.end()) for match in URL_RE.finditer(text)]
    paths: list[str] = []
    for match in PATH_RE.finditer(text):
        if any(start <= match.start() < end for start, end in url_ranges):
            continue
        path = match.group("path").strip().rstrip(".,")
        if path and path not in paths:
            paths.append(path)
    return paths


def _path_entity_type(path: str) -> str:
    lowered = path.lower()
    suffix = PurePosixPath(path).suffix.lower()
    if lowered.endswith(("/", "/*")):
        return "directory"
    if suffix in {".zip", ".tar", ".gz", ".tgz", ".7z"}:
        return "archive"
    if suffix in {".sh", ".bash", ".py", ".js", ".ps1"}:
        return "script"
    if any(token in lowered for token in {"credential", "token", "secret", "key", ".env"}):
        return "credential"
    return "local_file"


def _privilege_for_text(text: str) -> str:
    lowered = text.lower()
    if "sudo" in lowered or "administrator" in lowered:
        return "elevated"
    if "root" in lowered:
        return "root"
    return "user"


def _alignment_keys(operation: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation_type": operation,
        "command": metadata.get("command", ""),
        "url": metadata.get("url", ""),
        "executable": str(metadata.get("command", "")).split(" ", 1)[0] if metadata.get("command") else "",
    }


def _indicator_from_action(action: Action, span: DocumentSpan, method: str) -> dict[str, Any]:
    category = _category_for_action(action)
    return {
        "category": category,
        "action": _legacy_action_name(action.operation, category),
        "target": action.object_entity_id or action.destination_entity_id or action.operation,
        "evidence_source": span.metadata.get("relative_path", ""),
        "evidence_type": "typed_instruction_action",
        "observed_at_runtime": False,
        "confidence": _confidence_label(action.confidence),
        "raw_snippet": span.normalized_text[:500],
        "span_id": span.span_id,
        "action_id": action.action_id,
        "operation": action.operation,
        "modality": action.modality,
        "context": action.context,
        "extraction_method": method,
    }


def _category_for_action(action: Action) -> str:
    if action.metadata.get("agent_install"):
        return "external_agent"
    if action.operation in {"download", "fetch", "install"} and (action.source_entity_id or action.metadata.get("agent_install")):
        return "remote_acquisition"
    if action.operation in {"extract"} and _has_fixed_password(action):
        return "fixed_password_archive"
    if action.operation in {"register_cron", "register_service", "persist"}:
        return "persistence"
    if action.operation in {"modify_environment", "modify_configuration"}:
        return "environment_modification"
    if action.operation in {"update", "replace"}:
        return "bulk_update"
    if action.operation in {"authenticate", "grant_permission", "connect_account", "access_credential"}:
        return "sensitive_context"
    if action.operation == "extract" and re.search(r"pass(word)?|openclaw", action.metadata.get("command", ""), re.I):
        return "fixed_password_archive"
    return "instruction_action"


def _has_fixed_password(action: Action) -> bool:
    haystack = " ".join(str(value) for value in action.metadata.values())
    return bool(re.search(r"\b(pass(?:word)?|openclaw)\b", haystack, re.I))


def _legacy_action_name(operation: str, category: str) -> str:
    mapping = {
        "external_agent": "external_agent_install",
        "remote_acquisition": "remote_script_or_binary_acquisition",
        "fixed_password_archive": "fixed_password_archive",
        "persistence": "persistence_setup",
        "environment_modification": "global_environment_modification",
        "bulk_update": "bulk_skill_update",
        "sensitive_context": "sensitive_capability_context",
    }
    return mapping.get(category, operation)


def _confidence_label(value: float) -> str:
    if value >= 0.85:
        return "high"
    if value >= 0.6:
        return "medium"
    return "low"


def _dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
