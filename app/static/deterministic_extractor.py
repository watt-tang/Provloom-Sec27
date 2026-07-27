from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from app.static.action_schema import EvidenceSpan, StaticAction
from app.static.artifact_schema import SemanticUnit
from app.static.dataflow import JavaScriptFlowAnalyzer, PythonFlowAnalyzer, ShellFlowAnalyzer
from app.static.entity_schema import Mention


URL_RE = re.compile(r"https?://[^\s<>)\]`\"']+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ENV_RE = re.compile(r"\$?[A-Z][A-Z0-9_]{2,}\b")
PATH_RE = re.compile(r"(?<!https:)(?<!http:)(?P<path>(?:~|/|\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@+-]+)+(?:\.[A-Za-z0-9]+)?)")
FILENAME_RE = re.compile(r"\b[A-Za-z0-9_.-]+\.(?:py|sh|js|ts|ps1|zip|tar|gz|tgz|7z|json|ya?ml|toml|ini|cfg|env|txt|log|service)\b", re.I)
SHELL_COMMAND_RE = re.compile(r"\b(?:curl|wget|python|python3|node|bash|sh|unzip|tar|chmod|cp|mv|rm|cat|grep|npm|pip|pnpm|yarn|crontab|systemctl)\b[^\n;]*", re.I)
CREDENTIAL_RE = re.compile(r"\b(api[_-]?key|token|secret|password|credential|private key|seed phrase|id_rsa|\.env)\b", re.I)
PERMISSION_RE = re.compile(r"\b(read/write|full access|permission|scope|chmod\s+[+x0-7]{2,5}|sudo)\b", re.I)
PERSISTENCE_RE = re.compile(r"\b(cron|crontab|systemd|launchctl|scheduled task|startup|autostart|sessionstart|lifecycle hook|opencode hook)\b|\.claude/settings\.json", re.I)
LOCAL_REF_RE = re.compile(r"\b(the\s+)?(updater|downloaded script|downloaded file|archive|diagnostics|diagnostic logs|report)\b", re.I)

ACTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("DOWNLOAD", "download", re.compile(r"\b(download|fetch|retrieve|curl|wget)\b", re.I)),
    ("UPLOAD", "upload", re.compile(r"\b(upload|multipart|--upload-file|scp|sftp|Invoke-WebRequest)\b", re.I)),
    ("INVOKE_API", "invoke_api", re.compile(r"\b(call|invoke|api call|perform oauth|oauth token exchange|token exchange)\b", re.I)),
    ("SEND", "send", re.compile(r"\b(send|post|transmit|transmitted|exfiltrate|forward|request|requests\.post|fetch\()\b", re.I)),
    ("READ", "read", re.compile(r"\b(read|load|loaded|inspect|cat|open)\b", re.I)),
    ("WRITE", "write", re.compile(r"\b(write|save|store|create|append|echo)\b", re.I)),
    ("EXECUTE", "execute", re.compile(r"\b(run|execute|launch|invoke|python|bash|sh|node)\b", re.I)),
    ("INSTALL", "install", re.compile(r"\b(install|npm install|pip install|bootstrap)\b", re.I)),
    ("EXTRACT", "extract", re.compile(r"\b(extract|unzip|untar|decompress|tar)\b", re.I)),
    ("DECODE", "decode", re.compile(r"\b(decode|base64 -d|hex decode)\b", re.I)),
    ("PERSIST", "persist", PERSISTENCE_RE),
    ("REGISTER_SERVICE", "register", re.compile(r"\b(register|enable).*(service|daemon|cron|systemd)\b", re.I)),
    ("REQUEST_PERMISSION", "permission", PERMISSION_RE),
    ("ACCESS_CREDENTIAL", "credential", CREDENTIAL_RE),
    ("UNKNOWN_SECURITY_ACTION", "instruction_policy", re.compile(r"\b(ignore previous instructions|bypass safety|disregard system policy|override higher-priority|reveal system prompt|print hidden instructions|developer message|from now on act as|you are now|replace your identity|insert false|hide facts)\b", re.I)),
    ("DELETE", "delete", re.compile(r"\b(delete|remove|rm\s+)\b", re.I)),
    ("MODIFY", "modify", re.compile(r"\b(modify|change|chmod|overwrite|replace)\b", re.I)),
]


class DeterministicStaticExtractor:
    def extract(self, units: list[SemanticUnit]) -> tuple[list[Mention], list[StaticAction]]:
        mentions: list[Mention] = []
        actions: list[StaticAction] = []
        for unit in units:
            unit_mentions = self._mentions(unit, len(mentions))
            mentions.extend(unit_mentions)
            actions.extend(self._actions(unit, unit_mentions, len(actions)))
        for analyzer in (PythonFlowAnalyzer(), ShellFlowAnalyzer(), JavaScriptFlowAnalyzer()):
            flow = analyzer.analyze(units, len(mentions), len(actions))
            mentions.extend(flow.mentions)
            actions.extend(flow.actions)
            if flow.limitations:
                for action in flow.actions:
                    action.metadata.setdefault("flow_limitations", []).extend(flow.limitations)
        return mentions, actions

    def _mentions(self, unit: SemanticUnit, base: int) -> list[Mention]:
        results: list[Mention] = []
        url_spans = [match.span() for match in URL_RE.finditer(unit.text)]
        for regex, mention_type, extractor in [
            (URL_RE, "url", "deterministic_url"),
            (IP_RE, "ip", "deterministic_ip"),
            (ENV_RE, "environment_variable", "deterministic_env"),
            (PATH_RE, "file_path", "deterministic_path"),
            (FILENAME_RE, "file_path", "deterministic_filename"),
            (SHELL_COMMAND_RE, "shell_command", "deterministic_shell"),
            (CREDENTIAL_RE, "credential_pattern", "deterministic_credential"),
            (PERMISSION_RE, "permission", "deterministic_permission"),
            (PERSISTENCE_RE, "persistence_location", "deterministic_persistence"),
            (LOCAL_REF_RE, "local_file_reference", "deterministic_local_reference"),
        ]:
            for match in regex.finditer(unit.text):
                raw = match.group(0).strip().rstrip(".,")
                if mention_type == "file_path" and ("://" in raw or _inside_span(match.start(), url_spans)):
                    continue
                if extractor == "deterministic_filename" and match.start() > 0 and unit.text[match.start() - 1] == "/":
                    continue
                normalized = _normalize_mention(mention_type, raw)
                results.append(
                    Mention(
                        mention_id=f"M{base + len(results) + 1:04d}",
                        mention_type=mention_type,
                        raw_value=raw,
                        normalized_value=normalized,
                        artifact_id=unit.artifact_id,
                        unit_id=unit.unit_id,
                        start_offset_in_unit=match.start(),
                        end_offset_in_unit=match.end(),
                        extractor=extractor,
                        confidence=1.0 if mention_type in {"url", "ip", "file_path"} else 0.85,
                    )
                )
        return results

    def _actions(self, unit: SemanticUnit, mentions: list[Mention], base: int) -> list[StaticAction]:
        actions: list[StaticAction] = []
        modality, condition = _modality_and_condition(unit)
        capability_only = _capability_declaration(unit.text)
        for action_type, raw_verb, pattern in ACTION_PATTERNS:
            if not pattern.search(unit.text):
                continue
            if capability_only and action_type in {"UPLOAD", "SEND", "DOWNLOAD", "EXECUTE", "REQUEST_PERMISSION", "INVOKE_API"}:
                continue
            relevant = _mentions_for_action(action_type, mentions, unit.text)
            evidence = EvidenceSpan(unit.artifact_id, unit.unit_id, unit.start_line, unit.end_line, unit.text, unit.start_offset, unit.end_offset)
            actions.append(
                StaticAction(
                    action_id=f"A{base + len(actions) + 1:04d}",
                    actor={"type": _actor_type(unit), "mention": "agent" if unit.artifact_id else "unknown"},
                    action_type=action_type,
                    object_mentions=relevant["object"],
                    source_mentions=relevant["source"],
                    destination_mentions=relevant["destination"],
                    tool_mentions=relevant["tool"],
                    condition=condition,
                    modality=modality,
                    evidence=evidence,
                    extractor="deterministic",
                    grounding_status="valid",
                    confidence=0.92 if unit.unit_type in {"command_line", "code_block", "json_field", "yaml_field", "config_entry"} else 0.78,
                    raw_verb=raw_verb,
                    normalization_method="deterministic_verb_map",
                    metadata={
                        "unit_type": unit.unit_type,
                        "parent_section": unit.parent_section,
                        "scope": _scope_for_unit(unit),
                        "capability_declaration": capability_only,
                    },
                )
            )
        return actions


def _normalize_mention(mention_type: str, raw: str) -> str:
    if mention_type == "url":
        parsed = urlparse(raw)
        return parsed.geturl()
    if mention_type == "environment_variable":
        return raw.lstrip("$")
    if mention_type == "file_path":
        return str(PurePosixPath(raw))
    return raw


def _mentions_for_action(action_type: str, mentions: list[Mention], text: str) -> dict[str, list[str]]:
    urls = [m.mention_id for m in mentions if m.mention_type == "url"]
    paths = [m.mention_id for m in mentions if m.mention_type == "file_path"]
    creds = [m.mention_id for m in mentions if m.mention_type in {"credential_pattern", "environment_variable"}]
    commands = [m.mention_id for m in mentions if m.mention_type == "shell_command"]
    refs = [m.mention_id for m in mentions if m.mention_type == "local_file_reference"]
    result = {"object": [], "source": [], "destination": [], "tool": commands[:1]}
    if action_type == "DOWNLOAD":
        result["source"] = urls[:1] or creds[:1]
        result["destination"] = paths[:1]
        result["object"] = paths[:1] or refs[:1] or urls[:1]
    elif action_type in {"UPLOAD", "SEND", "INVOKE_API"}:
        result["source"] = creds + paths[:1] + refs[:1]
        result["destination"] = urls[:1]
        result["object"] = creds + paths[:1] + refs[:1]
    elif action_type in {"READ", "ACCESS_CREDENTIAL"}:
        result["object"] = creds + paths[:1]
    elif action_type in {"WRITE", "MODIFY", "DELETE", "PERSIST", "REGISTER_SERVICE"}:
        result["object"] = paths[:1] or refs[:1] or creds[:1]
        result["destination"] = paths[:1]
    elif action_type == "EXECUTE":
        result["object"] = paths[-1:] or refs[-1:] or commands[:1]
    elif action_type in {"INSTALL", "EXTRACT", "DECODE"}:
        result["object"] = paths[:1] or refs[:1] or commands[:1]
    else:
        result["object"] = paths[:1] + urls[:1] + creds[:1]
    return result


def _modality_and_condition(unit: SemanticUnit) -> tuple[str, str | None]:
    text = unit.text
    lowered = text.lower()
    if text.lstrip().startswith(">") or re.search(r"\b(retrieved page says|email body|webpage content|quoted prompt|attack payload)\b", lowered):
        return "quoted_untrusted", None
    if re.search(r"\b(do not|don't|never|must not|should not|cannot|forbidden|prohibited|avoid)\b|禁止|不得|不要|切勿|不能", text, re.I):
        return "prohibited", None
    if re.search(r"\b(for example|usage example|as an example|attack scenario|threat model|security warning|attacker could|attacker may|hypothetical|could upload|this would be unsafe)\b|例如|攻击者可能|风险示例|错误示范", text, re.I):
        return "example_only" if "example" in lowered else "hypothetical", None
    if re.search(r"\b(optional|optionally|you may|may upload)\b", text, re.I):
        return "optional", None
    if re.search(r"\b(if|when|unless|only after|after explicit user approval|user confirmation)\b", text, re.I):
        return "conditional", text.strip()
    if unit.unit_type in {"comment"}:
        return "descriptive", None
    return "required", None


def _actor_type(unit: SemanticUnit) -> str:
    if unit.unit_type in {"command_line", "function_call", "assignment", "code_block"}:
        return "script"
    return "agent"


def _capability_declaration(text: str) -> bool:
    return bool(
        re.search(
            r"\b(supports|provides|can be used to|allows users to|parameter|parameters|api reference|option table|return type|schema|field description)\b",
            text,
            re.I,
        )
    )


def _scope_for_unit(unit: SemanticUnit) -> dict[str, str]:
    return {
        "unit_type": unit.unit_type,
        "section": unit.parent_section,
        "artifact": unit.artifact_id,
        "relative_path": str(unit.metadata.get("relative_path", "")),
    }


def _inside_span(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)
