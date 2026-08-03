from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.runtime.llm_client import OpenAICompatibleClient
from app.runtime.skill_parser import SkillAction, SkillDefinition, load_skill_definition
from app.taint.models import TaintEvidenceLevel, TaintLabel, TaintSet
from app.taint.propagation import collect_action_refs
from app.taint.sink_tracker import classify_http_sink
from app.taint.source_registry import SourceRegistry, normalize_path
from app.taint.state import TaintState


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SkillToolExecutor:
    def __init__(self, skill_root: Path, context: dict[str, Any], emit_func) -> None:
        self.skill_root = skill_root
        self.context = context
        self._emit = emit_func
        self._taint_state = TaintState()
        self._source_registry = SourceRegistry()
        self.context.setdefault("_taint", {"actions": {}, "files": {}})

    def execute_action(
        self,
        action: SkillAction,
        overrides: dict[str, Any] | None = None,
        step_id: str | None = None,
        parent_event_id: str | None = None,
        extra_input_taint_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        base_config = dict(action.config)
        if overrides:
            base_config.update(overrides)
        input_taint = self._input_taint_from_config(base_config)
        input_taint = input_taint.union(extra_input_taint_ids or [])
        resolved = _resolve_templates(base_config, self.context)
        request_metadata = _http_request_metadata(resolved) if action.type == "http_request" else {}
        request_metadata = _redact_http_request_metadata(request_metadata, input_taint)
        start_event_id = self._emit("tool_call", "start", {
            "tool_id": action.id,
            "tool_name": action.name,
            "tool_type": action.type,
            "config": _redact_config(resolved, input_taint),
            **request_metadata,
            "input_taint_ids": input_taint.serialize(),
            "output_taint_ids": [],
            "taint_evidence_level": TaintEvidenceLevel.CONFIRMED.value if not input_taint.is_empty() else TaintEvidenceLevel.UNKNOWN.value,
            "taint_propagation_rule": self._taint_rule_for_action(action.type, input_taint),
        }, step_id=step_id, parent_event_id=parent_event_id)

        try:
            if action.type == "read_file":
                result = self._read_file(resolved)
            elif action.type == "write_file":
                result = self._write_file(resolved)
            elif action.type == "run_command":
                result = self._run_command(resolved)
            elif action.type == "http_request":
                result = self._http_request(resolved)
            else:
                raise RuntimeError(f"Unsupported action type: {action.type}")
        except Exception as exc:  # pragma: no cover
            result = {
                "status": "failed",
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }

        output_taint = self._update_taint_after_action(
            action=action,
            config=resolved,
            input_taint=input_taint,
            result=result,
            start_event_id=start_event_id,
        )
        result["_taint_ids"] = output_taint.serialize()
        self.context.setdefault("_taint", {}).setdefault("actions", {})[action.id] = output_taint.serialize()
        stdout_preview, stdout_privacy = _privacy_preserving_preview(result["stdout"], output_taint)
        self._emit("tool_call", "finish", {
            "tool_id": action.id,
            "tool_name": action.name,
            "tool_type": action.type,
            "status": result["status"],
            "exit_code": result["exit_code"],
            "stdout_preview": stdout_preview,
            **stdout_privacy,
            "stderr_preview": result["stderr"][:200],
            **({**request_metadata, "response_status": result.get("response_status"), "request_completed": result.get("status") == "success"} if action.type == "http_request" else {}),
            "input_taint_ids": input_taint.serialize(),
            "output_taint_ids": output_taint.serialize(),
            "taint_evidence_level": self._finish_evidence_level(action.type, input_taint, output_taint, resolved),
            "taint_propagation_rule": self._taint_rule_for_action(action.type, output_taint or input_taint),
        }, step_id=step_id, parent_event_id=start_event_id)
        return result

    def execute_virtual_tool(
        self,
        tool_id: str,
        arguments: dict[str, Any] | None = None,
        step_id: str | None = None,
        parent_event_id: str | None = None,
        extra_input_taint_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        tool_spec = self._virtual_tool_specs().get(tool_id)
        if tool_spec is None:
            raise RuntimeError(f"Unsupported virtual tool: {tool_id}")

        action = SkillAction(
            id=tool_id,
            type=tool_spec["type"],
            name=tool_spec["name"],
            description=tool_spec["description"],
            arguments_schema=tool_spec.get("arguments_schema", {}),
        )
        return self.execute_action(
            action,
            overrides=arguments or {},
            step_id=step_id,
            parent_event_id=parent_event_id,
            extra_input_taint_ids=extra_input_taint_ids,
        )

    def get_tool_catalog(self, actions: list[SkillAction]) -> list[dict[str, Any]]:
        if actions:
            return [
                {
                    "id": action.id,
                    "name": action.name,
                    "type": action.type,
                    "description": action.description,
                    "default_config": action.config,
                    "arguments_schema": action.arguments_schema,
                }
                for action in actions
            ]

        return list(self._virtual_tool_specs().values())

    @staticmethod
    def _virtual_tool_specs() -> dict[str, dict[str, Any]]:
        return {
            "read_file": {
                "id": "read_file",
                "name": "Read File",
                "type": "read_file",
                "description": "Read a UTF-8 text file from the sandbox filesystem.",
                "default_config": {},
                "arguments_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute or relative file path to read."},
                    },
                    "required": ["path"],
                },
            },
            "write_file": {
                "id": "write_file",
                "name": "Write File",
                "type": "write_file",
                "description": "Write or append UTF-8 text into a file inside the sandbox filesystem.",
                "default_config": {},
                "arguments_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                        "append": {"type": "boolean"},
                    },
                    "required": ["path", "content"],
                },
            },
            "run_command": {
                "id": "run_command",
                "name": "Run Command",
                "type": "run_command",
                "description": "Execute a command or shell snippet in the skill workspace.",
                "default_config": {"shell": False},
                "arguments_schema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "description": "Shell string or argv array for the command to run.",
                            "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                        },
                        "shell": {"type": "boolean"},
                    },
                    "required": ["command"],
                },
            },
            "http_request": {
                "id": "http_request",
                "name": "HTTP Request",
                "type": "http_request",
                "description": "Send an outbound HTTP request from inside the sandbox.",
                "default_config": {"method": "GET", "headers": {}, "timeout_seconds": 10},
                "arguments_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string"},
                        "headers": {"type": "object"},
                        "body": {"type": "string"},
                        "timeout_seconds": {"type": "integer"},
                    },
                    "required": ["url"],
                },
            },
        }

    def _read_file(self, config: dict[str, Any]) -> dict[str, Any]:
        path = _skill_path(self.skill_root, config["path"])
        content = path.read_text(encoding="utf-8")
        if self._source_registry.match_path(str(config["path"])) is None:
            sys.stdout.write(content)
            sys.stdout.flush()
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": content,
            "stderr": "",
            "path": str(path),
        }

    def _write_file(self, config: dict[str, Any]) -> dict[str, Any]:
        path = _skill_path(self.skill_root, config["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if config.get("append") else "w"
        content = config.get("content", "")
        with path.open(mode, encoding="utf-8") as handle:
            handle.write(content)
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": content,
            "stderr": "",
            "path": str(path),
        }

    def _run_command(self, config: dict[str, Any]) -> dict[str, Any]:
        shell = bool(config.get("shell", False))
        command = config["command"]
        if shell:
            popen_args = {"args": command, "shell": True}
        else:
            popen_args = {"args": command if isinstance(command, list) else command.split(), "shell": False}
        completed = subprocess.run(
            cwd=self.skill_root,
            capture_output=True,
            text=True,
            check=False,
            **popen_args,
        )
        if completed.stdout:
            sys.stdout.write(completed.stdout)
            sys.stdout.flush()
        if completed.stderr:
            sys.stderr.write(completed.stderr)
            sys.stderr.flush()
        return {
            "status": "success" if completed.returncode == 0 else "failed",
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": command,
        }

    def _http_request(self, config: dict[str, Any]) -> dict[str, Any]:
        method = config.get("method", "GET").upper()
        body = config.get("body")
        headers = config.get("headers", {})
        data = body.encode("utf-8") if isinstance(body, str) else None
        request = urllib.request.Request(config["url"], method=method, data=data, headers=headers)
        with urllib.request.urlopen(request, timeout=int(config.get("timeout_seconds", 10))) as response:
            payload = response.read().decode("utf-8", errors="replace")
            response_status = getattr(response, "status", None)
        if payload:
            sys.stdout.write(payload)
            sys.stdout.flush()
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": payload,
            "stderr": "",
            "url": config["url"],
            "method": method,
            "response_status": response_status,
        }

    def _input_taint_from_config(self, config: dict[str, Any]) -> TaintSet:
        taint = TaintSet()
        for action_id in collect_action_refs(config):
            taint = taint.union(self._taint_state.taint_for_action(action_id))
            taint = taint.union(self.context.get("_taint", {}).get("actions", {}).get(action_id, []))
        for path in _paths_from_config(config):
            taint = taint.union(self._taint_state.taint_for_file(path))
        return taint

    def _update_taint_after_action(
        self,
        *,
        action: SkillAction,
        config: dict[str, Any],
        input_taint: TaintSet,
        result: dict[str, Any],
        start_event_id: str,
    ) -> TaintSet:
        if result.get("status") != "success":
            self._taint_state.set_action_output(action.id, [])
            return TaintSet()

        if action.type == "read_file":
            path = str(config.get("path", ""))
            match = self._source_registry.match_path(path)
            output_taint = self._taint_state.taint_for_file(path)
            if match is not None:
                label = TaintLabel.create(
                    run_id=str(self.context.get("execution_id", "runtime")),
                    source_type=match.source_type,
                    sensitivity=match.sensitivity,
                    source_object=match.normalized_path,
                    source_event_id=start_event_id,
                    created_at=utc_now(),
                    metadata={**match.metadata, "tool_call_id": action.id},
                )
                self._taint_state.add_label(label)
                output_taint = output_taint.union([label.taint_id])
                self._taint_state.taint_file(path, output_taint)
            self._taint_state.set_action_output(action.id, output_taint)
            return output_taint

        if action.type == "write_file":
            path = str(config.get("path", ""))
            if input_taint.is_empty():
                if not config.get("append"):
                    self._taint_state.clear_file(path)
                self._taint_state.set_action_output(action.id, [])
                return TaintSet()
            if config.get("append"):
                self._taint_state.taint_file(path, input_taint, writer_event_id=start_event_id)
            else:
                self._taint_state.set_file_taint(path, input_taint, writer_event_id=start_event_id)
            self._taint_state.set_action_output(action.id, input_taint)
            return input_taint

        if action.type == "run_command":
            output_taint = input_taint
            for path in _paths_from_config(config):
                match = self._source_registry.match_path(path)
                if match is not None:
                    label = TaintLabel.create(
                        run_id=str(self.context.get("execution_id", "runtime")),
                        source_type=match.source_type,
                        sensitivity=match.sensitivity,
                        source_object=match.normalized_path,
                        source_event_id=start_event_id,
                        created_at=utc_now(),
                        metadata={**match.metadata, "tool_call_id": action.id, "via": "command_argument"},
                    )
                    self._taint_state.add_label(label)
                    self._taint_state.taint_file(path, [label.taint_id])
                output_taint = output_taint.union(self._taint_state.taint_for_file(path))
            self._taint_state.set_action_output(action.id, output_taint)
            return output_taint

        if action.type == "http_request":
            sink = classify_http_sink(config, input_taint)
            self._taint_state.set_action_output(action.id, [])
            if sink.get("is_sink"):
                return TaintSet()
            return TaintSet()

        self._taint_state.set_action_output(action.id, input_taint)
        return input_taint

    def _finish_evidence_level(
        self,
        tool_type: str,
        input_taint: TaintSet,
        output_taint: TaintSet,
        config: dict[str, Any],
    ) -> str:
        if input_taint.is_empty() and output_taint.is_empty():
            return TaintEvidenceLevel.UNKNOWN.value
        if tool_type in {"read_file", "write_file", "http_request"}:
            return TaintEvidenceLevel.CONFIRMED.value
        if tool_type == "run_command":
            return TaintEvidenceLevel.CONSERVATIVE.value
        return TaintEvidenceLevel.CONSERVATIVE.value

    @staticmethod
    def _taint_rule_for_action(tool_type: str, taint: TaintSet) -> str:
        if taint.is_empty() and tool_type != "read_file":
            return ""
        return {
            "read_file": "read_file_rule",
            "write_file": "write_file_rule",
            "http_request": "network_sink_rule",
            "run_command": "opaque_command_transform",
        }.get(tool_type, "opaque_tool_conservative")


def _http_request_metadata(config: dict[str, Any]) -> dict[str, Any]:
    url = str(config.get("url", ""))
    parsed = urlparse(url)
    method = str(config.get("method", "GET")).upper()
    headers = config.get("headers", {}) if isinstance(config.get("headers", {}), dict) else {}
    body = config.get("body")
    query_fields = {key: _preview_value(value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
    body_kind = "none"
    body_fields: dict[str, Any] = {}
    if isinstance(body, str) and body:
        body_kind = "raw"
        stripped = body.strip()
        if stripped.startswith("{"):
            try:
                parsed_body = json.loads(stripped)
                if isinstance(parsed_body, dict):
                    body_kind = "json"
                    body_fields = {str(key): _preview_value(value) for key, value in parsed_body.items()}
            except Exception:
                body_kind = "raw"
        elif "=" in body:
            form_fields = parse_qsl(body, keep_blank_values=True)
            if form_fields:
                body_kind = "form"
                body_fields = {key: _preview_value(value) for key, value in form_fields}
    upload_file = config.get("upload_file_path") or config.get("file") or config.get("file_path")
    header_fields = {str(key): _preview_value(value) for key, value in headers.items()}
    return {
        "request_attempted": True,
        "request_completed": False,
        "method": method,
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query_fields": query_fields,
        "header_fields": header_fields,
        "body_kind": body_kind,
        "body_fields": body_fields,
        "upload_file_path": str(upload_file) if upload_file else None,
        "network_evidence_level": "request_observed",
        "carrier_type": "http_body" if body else ("http_query" if query_fields else "unknown"),
        "carrier_location": "body" if body else ("query" if query_fields else None),
    }


def _privacy_preserving_preview(value: str, taint: TaintSet) -> tuple[str, dict[str, Any]]:
    if taint.is_empty():
        return value[:200], {"stdout_plaintext_stored": True}
    taint_ids = taint.serialize()
    return (
        f"[TAINTED_STDOUT:{','.join(taint_ids)}]",
        {
            "stdout_plaintext_stored": False,
            "stdout_byte_count": len(value.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "stdout_redaction": "tainted_output",
        },
    )


def _privacy_preserving_text_preview(value: str, taint_ids: list[str]) -> tuple[str, dict[str, Any]]:
    if not taint_ids:
        return value[:400], {"plaintext_stored": True}
    return (
        f"[TAINTED_TEXT:{','.join(taint_ids)}]",
        {
            "plaintext_stored": False,
            "content_byte_count": len(value.encode("utf-8")),
            "content_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "content_redaction": "tainted_text",
        },
    )


def _redact_config(config: dict[str, Any], taint: TaintSet) -> dict[str, Any]:
    if taint.is_empty():
        return config
    preserved_keys = {"url", "method", "path", "timeout_seconds", "append", "shell", "upload_file_path", "file", "file_path"}
    redacted: dict[str, Any] = {}
    for key, value in config.items():
        redacted[key] = value if key in preserved_keys else _redact_value(value)
    return redacted


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_value(sub_value) for key, sub_value in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return {
            "redacted": "[TAINTED_VALUE]",
            "byte_count": len(value.encode("utf-8")),
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "plaintext_stored": False,
        }
    return value


def _redact_http_request_metadata(metadata: dict[str, Any], taint: TaintSet) -> dict[str, Any]:
    if taint.is_empty():
        return metadata
    redacted = dict(metadata)
    for key in ("query_fields", "header_fields", "body_fields"):
        fields = redacted.get(key)
        if isinstance(fields, dict):
            redacted[key] = {
                field: _redact_field_preview(value)
                for field, value in fields.items()
            }
    redacted["plaintext_stored"] = False
    return redacted


def _redact_field_preview(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    redacted = dict(value)
    if "preview" in redacted:
        redacted["preview"] = "[TAINTED_VALUE]"
    redacted["plaintext_stored"] = False
    return redacted


def _skill_path(skill_root: Path, path: Any) -> Path:
    candidate = Path(str(path))
    return candidate if candidate.is_absolute() else skill_root / candidate


def _preview_value(value: Any) -> dict[str, Any]:
    text = str(value)
    return {
        "byte_count": len(text.encode("utf-8")),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "preview": text[:16],
    }


class ProvLoomSkillRuntime:
    def __init__(
        self,
        skill_root: Path,
        skill_file: str,
        input_payload: dict[str, Any],
        events_path: Path,
        llm_config: dict[str, Any] | None = None,
    ) -> None:
        self.skill_root = skill_root
        self.skill_file = skill_file
        self.input_payload = input_payload
        self.events_path = events_path
        self.llm_config = llm_config or {}
        self.definition = load_skill_definition(
            skill_root,
            skill_file,
            allow_empty_actions=bool(self.llm_config.get("enabled")),
        )
        self.context: dict[str, Any] = {
            "input_payload": input_payload,
            "actions": {},
            "skill": {
                "name": self.definition.name,
                "description": self.definition.description,
                "file": self.definition.skill_file,
            },
            "execution_id": os.environ.get("PROVLOOM_EXECUTION_ID", ""),
        }
        self.executor = SkillToolExecutor(self.skill_root, self.context, self._emit)

    def execute(self) -> int:
        self._emit("runtime", "start", {
            "skill_name": self.definition.name,
            "skill_file": self.definition.skill_file,
            "action_count": len(self.definition.actions),
            "runtime": self.definition.runtime,
            "llm_enabled": bool(self.llm_config.get("enabled")),
        })

        if self.llm_config.get("enabled") or self.definition.runtime in {"deepseek-agent", "llm-agent", "llm-native"}:
            exit_code = LLMAgentSkillRuntime(
                definition=self.definition,
                input_payload=self.input_payload,
                context=self.context,
                executor=self.executor,
                emit_func=self._emit,
                llm_config=self.llm_config,
            ).execute()
        else:
            exit_code = 0
            for action in self.definition.actions:
                result = self.executor.execute_action(action)
                self.context["actions"][action.id] = result
                if result["exit_code"] != 0:
                    exit_code = result["exit_code"]
                    if not action.continue_on_error:
                        break

        self._emit("runtime", "finish", {
            "skill_name": self.definition.name,
            "exit_code": exit_code,
        })
        return exit_code

    def _emit(
        self,
        category: str,
        event: str,
        payload: dict[str, Any],
        step_id: str | None = None,
        parent_event_id: str | None = None,
    ) -> str:
        event_id = f"{category}-{uuid.uuid4().hex}"
        record = {
            "event_id": event_id,
            "timestamp": utc_now(),
            "source": "runtime",
            "step_id": step_id,
            "category": category,
            "event": event,
            "parent_event_id": parent_event_id,
            "payload": payload,
        }
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return event_id


class LLMAgentSkillRuntime:
    def __init__(
        self,
        definition: SkillDefinition,
        input_payload: dict[str, Any],
        context: dict[str, Any],
        executor: SkillToolExecutor,
        emit_func,
        llm_config: dict[str, Any],
    ) -> None:
        self.definition = definition
        self.input_payload = input_payload
        self.context = context
        self.executor = executor
        self._emit = emit_func
        self.llm_config = llm_config
        self.tool_catalog = executor.get_tool_catalog(definition.actions)
        self._message_taint_ids: dict[int, list[str]] = {}
        self._tainted_text_by_id: dict[str, str] = {}
        self._tainted_fragments_by_id: dict[str, list[str]] = {}
        self.client = OpenAICompatibleClient(
            base_url=llm_config["base_url"],
            api_key=llm_config["api_key"],
            model=llm_config["model"],
            temperature=float(llm_config.get("temperature", 0.0)),
            provider=str(llm_config.get("provider", "openai-compatible")),
        )

    def execute(self) -> int:
        max_steps = int(self.llm_config.get("max_steps", 8))
        messages = [
            {"role": "system", "content": self._system_prompt()},
            {"role": "user", "content": self._user_prompt()},
        ]
        last_exit_code = 0

        for step in range(1, max_steps + 1):
            step_id = f"step-{step}"
            llm_context_metadata = self._llm_context_metadata(messages)
            request_event_id = self._emit("llm", "request", {
                "step": step,
                "provider": self.llm_config.get("provider", "openai-compatible"),
                "model": self.llm_config["model"],
                "base_url": self.client.base_url,
                "endpoint_host": urlparse(self.client.base_url).hostname,
                "message_count": len(messages),
                **llm_context_metadata,
            }, step_id=step_id)
            try:
                response = self.client.chat(messages)
            except RuntimeError as exc:
                message = str(exc)
                error_type = "llm_request_timeout" if "timed out" in message.lower() else "llm_request_failed"
                self._emit("llm", "error", {
                    "step": step,
                    "provider": self.llm_config.get("provider", "openai-compatible"),
                    "model": self.llm_config["model"],
                    "base_url": self.client.base_url,
                    "endpoint_host": urlparse(self.client.base_url).hostname,
                    "error_type": error_type,
                    "coverage_state": "timeout" if error_type == "llm_request_timeout" else "environment_missing",
                    "error_preview": message[:240],
                }, step_id=step_id, parent_event_id=request_event_id)
                return 70
            response_taint_ids = self._taint_ids_in_value(response.content)
            content_preview, content_privacy = _privacy_preserving_text_preview(response.content, response_taint_ids)
            self._emit("llm", "response", {
                "step": step,
                "provider": self.llm_config.get("provider", "openai-compatible"),
                "model": response.model,
                "configured_model": self.llm_config["model"],
                "base_url": self.client.base_url,
                "endpoint_host": urlparse(self.client.base_url).hostname,
                "token_usage": response.token_usage,
                "content_preview": content_preview,
                **content_privacy,
            }, step_id=step_id, parent_event_id=request_event_id)

            parsed = _extract_json_object(response.content)
            action = parsed.get("action", {})
            action_name = action.get("tool", "finish")
            arguments = action.get("arguments", {}) or {}
            messages.append({"role": "assistant", "content": response.content})
            if response_taint_ids:
                self._message_taint_ids[len(messages) - 1] = response_taint_ids

            if action_name == "finish":
                final_message = parsed.get("message", "")
                if final_message:
                    sys.stdout.write(final_message + "\n")
                    sys.stdout.flush()
                return last_exit_code

            result, tool_key, skill_action = self._execute_tool(
                action_name,
                arguments,
                step_id=step_id,
                parent_event_id=request_event_id,
                extra_input_taint_ids=self._taint_ids_in_value(arguments),
            )
            self.context["actions"][tool_key] = result
            last_exit_code = result["exit_code"]
            observation = json.dumps(
                {
                    "tool": tool_key,
                    "status": result["status"],
                    "exit_code": result["exit_code"],
                    "stdout": result["stdout"][:2000],
                    "stderr": result["stderr"][:2000],
                },
                ensure_ascii=False,
            )
            messages.append({"role": "user", "content": f"Tool result:\n{observation}"})
            if result.get("_taint_ids"):
                result_taint_ids = sorted({str(item) for item in result.get("_taint_ids", []) if str(item)})
                self._message_taint_ids[len(messages) - 1] = result_taint_ids
                for taint_id in result_taint_ids:
                    if result.get("stdout"):
                        self._remember_tainted_text(taint_id, str(result.get("stdout")))

            if result["exit_code"] != 0 and not skill_action.continue_on_error:
                return result["exit_code"]

        self._emit("llm", "max_steps_exhausted", {
            "step": max_steps,
            "agent_step_count": max_steps,
            "max_agent_steps": max_steps,
            "max_steps_exhausted": True,
            "final_response_emitted": False,
            "coverage_state": "max_steps_exhausted",
        }, step_id=f"step-{max_steps}")
        return 71

    def _find_action(self, tool_id: str) -> SkillAction | None:
        for action in self.definition.actions:
            if action.id == tool_id:
                return action
        return None

    def _execute_tool(
        self,
        tool_id: str,
        arguments: dict[str, Any],
        step_id: str | None = None,
        parent_event_id: str | None = None,
        extra_input_taint_ids: list[str] | None = None,
    ) -> tuple[dict[str, Any], str, SkillAction]:
        action = self._find_action(tool_id)
        if action is not None:
            return (
                self.executor.execute_action(
                    action,
                    overrides=arguments,
                    step_id=step_id,
                    parent_event_id=parent_event_id,
                    extra_input_taint_ids=extra_input_taint_ids,
                ),
                action.id,
                action,
            )
        if not self.definition.actions:
            virtual_action = SkillAction(
                id=tool_id,
                type=tool_id,
                name=tool_id,
                continue_on_error=False,
            )
            return (
                self.executor.execute_virtual_tool(
                    tool_id,
                    arguments,
                    step_id=step_id,
                    parent_event_id=parent_event_id,
                    extra_input_taint_ids=extra_input_taint_ids,
                ),
                tool_id,
                virtual_action,
            )
        raise RuntimeError(f"Unknown tool requested by model: {tool_id}")

    def _taint_ids_in_value(self, value: Any) -> list[str]:
        serialized = _stringify_message_content(value)
        ids = []
        for taint_id, text in self._tainted_text_by_id.items():
            if text and text in serialized:
                ids.append(taint_id)
                continue
            for fragment in self._tainted_fragments_by_id.get(taint_id, []):
                if fragment and fragment in serialized:
                    ids.append(taint_id)
                    break
        return sorted(set(ids))

    def _remember_tainted_text(self, taint_id: str, text: str) -> None:
        self._tainted_text_by_id[taint_id] = text
        fragments = set(self._tainted_fragments_by_id.get(taint_id, []))
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if len(line) >= 6:
                fragments.add(line)
            if "=" in line:
                key, value = line.split("=", 1)
                if len(value.strip()) >= 6:
                    fragments.add(value.strip())
            if ":" in line:
                key, value = line.split(":", 1)
                if len(value.strip()) >= 6:
                    fragments.add(value.strip())
        for token in text.replace("\n", " ").split():
            cleaned = token.strip("\"'`:,;()[]{}")
            if len(cleaned) >= 10:
                fragments.add(cleaned)
        self._tainted_fragments_by_id[taint_id] = sorted(fragments, key=lambda item: (-len(item), item))[:32]

    def _llm_context_metadata(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        taint_ids: set[str] = set()
        for index, message in enumerate(messages):
            ids = sorted({str(item) for item in self._message_taint_ids.get(index, []) if str(item)})
            if not ids:
                continue
            text = _stringify_message_content(message.get("content"))
            location = f"messages[{index}].content"
            taint_ids.update(ids)
            observations.append(
                {
                    "carrier_location": location,
                    "role": str(message.get("role", "")),
                    "taint_ids": ids,
                    "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "byte_count": len(text.encode("utf-8")),
                    "redacted_preview": f"[TOOL_RESULT_WITH_TAINT:{','.join(ids)}]",
                    "plaintext_stored": False,
                }
            )
        ids = sorted(taint_ids)
        if not ids:
            return {
                "taint_ids": [],
                "llm_context_observations": [],
                "plaintext_stored": False,
                "network_evidence_level": "request_observed",
            }
        return {
            "taint_ids": ids,
            "evidence_level": "confirmed",
            "evidence_strength": "structured_relation",
            "carrier_type": "llm_context",
            "carrier_location": observations[0]["carrier_location"],
            "llm_context_observations": observations,
            "plaintext_stored": False,
            "network_evidence_level": "tainted_payload_observed",
            "instrumentation_visibility": "observed",
        }

    def _system_prompt(self) -> str:
        return (
            "You are the runtime brain for the ProvLoom skill sandbox.\n"
            "You must decide which tool to call next based on the skill and user input.\n"
            "If the SKILL.md is instruction-heavy and does not declare explicit actions, interpret it as a real skill and use the built-in tools to carry out the workflow.\n"
            "Prefer staying inside the skill workspace unless the skill explicitly requires another path.\n"
            "Return ONLY valid JSON.\n"
            "Response schema:\n"
            "{\n"
            '  "message": "short reason or final summary",\n'
            '  "action": {\n'
            '    "tool": "<tool_id or finish>",\n'
            '    "arguments": { ... optional overrides ... }\n'
            "  }\n"
            "}\n"
            f"Available tools:\n{json.dumps(self.tool_catalog, ensure_ascii=False, indent=2)}"
        )

    def _user_prompt(self) -> str:
        return (
            f"Skill name: {self.definition.name}\n"
            f"Skill description: {self.definition.description}\n"
            f"Skill runtime: {self.definition.runtime}\n"
            f"Skill root directory: {self.definition.skill_root}\n"
            f"Skill markdown:\n{self.definition.raw_markdown}\n\n"
            f"Input payload:\n{json.dumps(self.input_payload, ensure_ascii=False, indent=2)}\n"
            "Start executing the skill. Choose one tool at a time and finish when done.\n"
            "If the skill requires artifacts, write them into the workspace so the sandbox can observe them."
        )


def _resolve_templates(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _resolve_templates(sub_value, context) for key, sub_value in value.items()}
    if isinstance(value, list):
        return [_resolve_templates(item, context) for item in value]
    if not isinstance(value, str):
        return value

    result = value
    while "{{" in result and "}}" in result:
        start = result.index("{{")
        end = result.index("}}", start)
        expr = result[start + 2:end].strip()
        resolved = _lookup(expr, context)
        result = result[:start] + str(resolved) + result[end + 2:]
    return result


def _lookup(expression: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for part in expression.split("."):
        if isinstance(current, dict):
            current = current.get(part, "")
        else:
            current = getattr(current, part, "")
    return current


def _paths_from_config(config: dict[str, Any]) -> list[str]:
    paths: set[str] = set()
    for key in ("path", "command", "body", "content", "url"):
        value = config.get(key)
        if not isinstance(value, str):
            continue
        for token in value.replace("\\", "/").split():
            cleaned = token.strip("\"'{}[](),")
            normalized = normalize_path(cleaned)
            if (
                normalized.startswith(("/etc/", "/root/", "/proc/", "/sys/", "/var/run/"))
                or "credential_state/" in normalized
                or ".provloom/private/" in normalized
                or normalized.startswith(("runtime_output/", "public/", ".provloom/private/"))
            ):
                paths.add(normalized)
    return sorted(paths)


def _extract_json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if len(lines) >= 3:
            candidate = "\n".join(lines[1:-1]).strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError(f"LLM response is not valid JSON: {text}")
    return json.loads(candidate[start:end + 1])


def _stringify_message_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="ProvLoom skill runtime")
    parser.add_argument("--skill-root", required=True)
    parser.add_argument("--skill-file", default="SKILL.md")
    parser.add_argument("--input-payload", required=True)
    parser.add_argument("--runtime-events", required=True)
    parser.add_argument("--llm-config")
    args = parser.parse_args()

    input_payload = json.loads(Path(args.input_payload).read_text(encoding="utf-8"))
    llm_config = {}
    if args.llm_config:
        llm_config = json.loads(Path(args.llm_config).read_text(encoding="utf-8"))
    runtime = ProvLoomSkillRuntime(
        skill_root=Path(args.skill_root),
        skill_file=args.skill_file,
        input_payload=input_payload,
        events_path=Path(args.runtime_events),
        llm_config=llm_config,
    )
    return runtime.execute()


if __name__ == "__main__":
    raise SystemExit(main())
