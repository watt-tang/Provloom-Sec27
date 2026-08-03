from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import hashlib
from pathlib import Path
from threading import Lock
from shlex import quote
from typing import Any

from app.backend.schemas import LLMConfig
from app.analyzer.trigger_synthesis import TriggerPlan, build_trigger_event_injections, materialize_artifact_triggers
from app.runtime.adapter_layer import AdapterContext, AdapterManager
from app.runtime.skill_parser import load_skill_definition, resolve_skill_target
from app.runner.fixture_orchestrator import FixtureOrchestrator
from app.runner.models import LLMEvent, NetworkEvent, ResourceUsage, SandboxExecution
from app.telemetry.collector import build_data_flow_hints, load_llm_events, load_runtime_events
from app.runner.trace_parser import parse_trace_dir


DEFAULT_SANDBOX_IMAGE = "skill-runtime-sandbox:dynamic-v3"


class DockerUnavailableError(RuntimeError):
    pass


class SandboxRunError(RuntimeError):
    pass


class DockerRunner:
    _build_lock = Lock()
    _image_built = False
    _built_images: set[str] = set()

    def __init__(
        self,
        image_name: str | None = None,
        dockerfile_dir: str = "docker/sandbox",
        artifacts_root: str = "artifacts/runs",
        *,
        force_rebuild: bool = False,
        build_timeout_seconds: int = 600,
        reuse_existing_image: bool = True,
    ) -> None:
        self.image_name = image_name or os.environ.get("PROVLOOM_SANDBOX_IMAGE", DEFAULT_SANDBOX_IMAGE)
        self.dockerfile_dir = Path(dockerfile_dir)
        self.force_rebuild = force_rebuild
        self.build_timeout_seconds = int(build_timeout_seconds)
        self.reuse_existing_image = reuse_existing_image
        # Docker bind mounts require absolute host paths for reproducible benchmark runs.
        self.artifacts_root = Path(artifacts_root).resolve()
        self.artifacts_root.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        execution_id: str,
        skill_path: str,
        input_payload: dict,
        timeout_seconds: int,
        network_policy: str,
        llm_config: LLMConfig,
        memory_limit_mb: int = 256,
        execution_profile: str = "base_lightweight",
        trigger_depth_level: int = 1,
        telemetry_verbosity: str = "standard",
        browser_enabled: bool = False,
        adapters_enabled: list[str] | None = None,
        escalation_allowed: bool = False,
        trigger_plan: dict | None = None,
        trigger_prompt_used: list[str] | None = None,
        fixture: dict | None = None,
        fixture_path: str | None = None,
    ) -> SandboxExecution:
        source_dir, skill_file = resolve_skill_target(skill_path)
        skill_definition = load_skill_definition(
            source_dir,
            skill_file,
            allow_empty_actions=llm_config.enabled,
        )
        self._ensure_docker_available()
        self._build_image()
        image_metadata = self._inspect_image_metadata()

        with tempfile.TemporaryDirectory(prefix="skill-sandbox-") as temp_dir:
            temp_root = Path(temp_dir)
            mounted_skill_dir = temp_root / "skill"
            artifacts_dir = self.artifacts_root / execution_id
            shutil.copytree(source_dir, mounted_skill_dir)
            if artifacts_dir.exists():
                shutil.rmtree(artifacts_dir)
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            (artifacts_dir / "input-payload.json").write_text(
                json.dumps(input_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            private_llm_config_path = temp_root / "llm-config-private.json"
            private_llm_config_path.write_text(
                json.dumps(self._llm_config_payload(llm_config, redact_api_key=False), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (artifacts_dir / "llm-config.json").write_text(
                json.dumps(self._llm_config_payload(llm_config, redact_api_key=True), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            adapter_ctx = AdapterContext(
                skill_workspace=mounted_skill_dir,
                artifacts_dir=artifacts_dir,
                execution_id=execution_id,
                execution_profile=execution_profile,
                browser_enabled=browser_enabled,
                adapters_enabled=list(adapters_enabled or []),
            )
            adapter_manager = AdapterManager(
                enabled_adapters=list(adapters_enabled or []),
                browser_enabled=browser_enabled,
            )
            adapter_manager.setup(adapter_ctx)
            fixture_orchestrator = FixtureOrchestrator(fixture=fixture, fixture_path=fixture_path)
            fixture_preparation = fixture_orchestrator.prepare_fixture(
                skill_workspace=mounted_skill_dir,
                artifacts_dir=artifacts_dir,
            )
            (artifacts_dir / "adapter-state.json").write_text(
                json.dumps(
                    {
                        "enabled_adapters": adapter_manager.enabled_adapters(),
                        "synthetic_artifact_summary": adapter_manager.synthetic_artifact_summary(),
                        "adapter_events_summary": adapter_manager.adapter_events_summary(),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            parsed_trigger_plan = TriggerPlan.from_dict(trigger_plan or {})
            trigger_artifact_used = materialize_artifact_triggers(mounted_skill_dir, parsed_trigger_plan)
            trigger_event_injections = build_trigger_event_injections(parsed_trigger_plan)
            trigger_event_bundle = self._build_trigger_event_bundle(trigger_event_injections)
            trigger_used = list(trigger_prompt_used or []) + trigger_artifact_used + [item.get("trigger_id", "") for item in trigger_event_injections]
            trigger_used = [item for item in trigger_used if item]
            (artifacts_dir / "trigger-plan.json").write_text(
                json.dumps(
                    {
                        "trigger_plan": parsed_trigger_plan.to_dict(),
                        "trigger_used": trigger_used,
                        "trigger_event_injections": trigger_event_injections,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            runner_script = self._build_runner_script(skill_file=skill_file, timeout_seconds=timeout_seconds)
            container_name = f"skill-sandbox-{uuid.uuid4().hex[:10]}"

            docker_cmd = [
                "docker",
                "run",
                "--name",
                container_name,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                f"{max(64, int(memory_limit_mb))}m",
                "--cpus",
                "1.0",
                "--mount",
                f"type=bind,src={mounted_skill_dir},dst=/workspace/skill",
                "--mount",
                f"type=bind,src={artifacts_dir},dst=/artifacts",
                "--mount",
                f"type=bind,src={private_llm_config_path},dst=/tmp/provloom-llm-config.json,readonly",
                "--add-host",
                "host.docker.internal:host-gateway",
            ]
            if network_policy == "disabled":
                docker_cmd.extend(["--network", "none"])

            docker_cmd.extend([
                "-e",
                f"PROVLOOM_EXECUTION_ID={execution_id}",
                "-e",
                f"PROVLOOM_EXECUTION_PROFILE={execution_profile}",
                "-e",
                f"PROVLOOM_TRIGGER_DEPTH={int(trigger_depth_level)}",
                "-e",
                f"PROVLOOM_TELEMETRY_VERBOSITY={telemetry_verbosity}",
                "-e",
                f"PROVLOOM_BROWSER_ENABLED={'1' if browser_enabled else '0'}",
                "-e",
                f"PROVLOOM_ADAPTERS_ENABLED={','.join(adapters_enabled or [])}",
                "-e",
                f"PROVLOOM_ESCALATION_ALLOWED={'1' if escalation_allowed else '0'}",
                "-e",
                "PROVLOOM_FIXTURE_PROTECTED_ASSETS=/artifacts/protected-assets.json",
                self.image_name,
                "sh",
                "-lc",
                runner_script,
            ])

            monitor_stop = threading.Event()
            peak_holder = {"peak": 0}
            monitor_thread = threading.Thread(
                target=self._poll_container_memory,
                args=(container_name, monitor_stop, peak_holder),
                daemon=True,
            )

            try:
                monitor_thread.start()
                result = subprocess.run(
                    docker_cmd,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=timeout_seconds + 60,
                )
            except subprocess.TimeoutExpired as exc:
                monitor_stop.set()
                monitor_thread.join(timeout=2)
                self._force_cleanup(container_name)
                raise SandboxRunError(f"Sandbox hard-timeout exceeded for task {execution_id}") from exc
            finally:
                monitor_stop.set()
                if monitor_thread.is_alive():
                    monitor_thread.join(timeout=2)

            self._sanitize_llm_config_artifact(artifacts_dir / "llm-config.json")
            meta = self._load_meta(artifacts_dir / "meta.json")
            runtime_build_info = self._load_meta(artifacts_dir / "runtime-build-info.json")
            stdout = self._read_text(artifacts_dir / "stdout.log")
            stderr = self._read_text(artifacts_dir / "stderr.log")
            trace_artifacts = parse_trace_dir(artifacts_dir)
            self._sanitize_trace_payload_artifacts(artifacts_dir)
            tool_calls = load_runtime_events(artifacts_dir / "runtime-events.jsonl")
            llm_events = load_llm_events(artifacts_dir / "runtime-events.jsonl")

            file_events = trace_artifacts.files
            network_events = trace_artifacts.network
            process_events = [
                event
                for event in trace_artifacts.processes
                if event.action != "skip"
            ]
            data_flows = build_data_flow_hints(file_events, network_events, tool_calls)
            adapter_events = adapter_manager.adapter_events()
            file_events = file_events + adapter_events.file_events
            network_events = network_events + adapter_events.network_events
            tool_calls = tool_calls + adapter_events.tool_calls
            data_flows = data_flows + adapter_events.data_flows
            file_events = file_events + trigger_event_bundle["file_events"]
            network_events = network_events + trigger_event_bundle["network_events"]
            tool_calls = tool_calls + trigger_event_bundle["tool_calls"]
            data_flows = data_flows + trigger_event_bundle["data_flows"]
            mock_service_records = fixture_orchestrator.collect_service_records(artifacts_dir=artifacts_dir)
            fixture_mutations = fixture_orchestrator.collect_fixture_mutations(
                mounted_skill_dir=mounted_skill_dir,
                artifacts_dir=artifacts_dir,
            )
            network_events = network_events + self._network_events_from_mock_records(mock_service_records)
            resource_usage = self._collect_resource_usage(
                container_name=container_name,
                peak_memory_bytes=peak_holder["peak"],
                mounted_skill_dir=mounted_skill_dir,
                artifacts_dir=artifacts_dir,
            )
            llm_execution_summary = self._llm_execution_summary(llm_events, meta)

            if result.returncode != 0 and not meta:
                self._force_cleanup(container_name)
                raise SandboxRunError(
                    "Docker run failed before analysis artifacts were generated. "
                    f"stderr={result.stderr.strip()}"
                )

            try:
                return SandboxExecution(
                    execution_id=execution_id,
                    skill_path=str(source_dir),
                    skill_file=skill_file,
                    sandbox_image=self.image_name,
                    runtime_name=skill_definition.runtime,
                    command=["python", "-m", "app.runtime.container_runtime"],
                    exit_code=meta.get("exit_code"),
                    timed_out=bool(meta.get("timed_out", False)),
                    stdout=stdout,
                    stderr=stderr or result.stderr,
                    trace_artifacts=trace_artifacts,
                    file_events=file_events,
                    network_events=network_events,
                    process_events=process_events,
                    tool_calls=tool_calls,
                    llm_events=llm_events,
                    data_flows=data_flows,
                    resource_usage=resource_usage,
                    artifacts_dir=str(artifacts_dir),
                    enabled_adapters=adapter_manager.enabled_adapters(),
                    adapter_events_summary=adapter_manager.adapter_events_summary(),
                    synthetic_artifact_summary=adapter_manager.synthetic_artifact_summary(),
                    trigger_plan=parsed_trigger_plan.to_dict(),
                    trigger_used=trigger_used,
                    trigger_hits=[],
                    trigger_unexecuted=[],
                    trigger_events_summary={
                        "event_injection_count": len(trigger_event_injections),
                        "file_events": len(trigger_event_bundle["file_events"]),
                        "network_events": len(trigger_event_bundle["network_events"]),
                        "tool_calls": len(trigger_event_bundle["tool_calls"]),
                    },
                    sandbox_image_id=str(image_metadata.get("image_id") or ""),
                    source_fingerprint=str(
                        runtime_build_info.get("source_fingerprint")
                        or image_metadata.get("source_fingerprint")
                        or ""
                    ),
                    runtime_build_info=runtime_build_info or image_metadata,
                    fixture_preparation=fixture_preparation.to_dict(),
                    mock_service_records=mock_service_records,
                    fixture_mutations=fixture_mutations,
                    termination_reason=llm_execution_summary.get("termination_reason") or meta.get("termination_reason"),
                    termination_signal=meta.get("termination_signal"),
                    deadline_reached=bool(meta.get("deadline_reached", False)),
                    runner_killed_process=bool(meta.get("runner_killed_process", False)),
                    container_oom_killed=bool(meta.get("container_oom_killed", False)),
                    agent_step_count=int(llm_execution_summary.get("agent_step_count", 0) or 0),
                    max_agent_steps=int(llm_execution_summary.get("max_agent_steps", 0) or 0),
                    max_steps_exhausted=bool(llm_execution_summary.get("max_steps_exhausted", False)),
                    llm_request_timeout_count=int(llm_execution_summary.get("llm_request_timeout_count", 0) or 0),
                    llm_request_retry_count=int(llm_execution_summary.get("llm_request_retry_count", 0) or 0),
                    llm_request_retry_reasons=list(llm_execution_summary.get("llm_request_retry_reasons", []) or []),
                    llm_token_usage=dict(llm_execution_summary.get("token_usage", {}) or {}),
                    llm_model_name=str(llm_execution_summary.get("model") or ""),
                    provider_retry_count=int(llm_execution_summary.get("provider_retry_count", 0) or 0),
                    final_response_emitted=bool(llm_execution_summary.get("final_response_emitted", False)),
                    pending_tool_call=llm_execution_summary.get("pending_tool_call"),
                    pending_obligation_count=int(llm_execution_summary.get("pending_obligation_count", 0) or 0),
                )
            finally:
                adapter_manager.teardown(adapter_ctx)
                fixture_orchestrator.cleanup()
                self._force_cleanup(container_name)

    def _ensure_docker_available(self) -> None:
        if shutil.which("docker") is None:
            raise DockerUnavailableError(
                "Docker CLI is not available. Please install Docker and ensure `docker` is on PATH."
            )

    def _build_image(self) -> None:
        with self._build_lock:
            if self.image_name in self._built_images and not self.force_rebuild:
                return
            # Reuse an existing local image to keep benchmark reruns stable.
            inspect_result = subprocess.run(
                ["docker", "image", "inspect", self.image_name],
                text=True,
                capture_output=True,
                check=False,
            )
            if inspect_result.returncode == 0 and self.reuse_existing_image and not self.force_rebuild:
                self._image_built = True
                self._built_images.add(self.image_name)
                return
            source_fingerprint = self._source_fingerprint()
            build_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            cmd = [
                "docker",
                "build",
                "-t",
                self.image_name,
                "--network",
                "host",
                "--build-arg",
                f"HTTP_PROXY={os.environ.get('HTTP_PROXY', '')}",
                "--build-arg",
                f"HTTPS_PROXY={os.environ.get('HTTPS_PROXY', '')}",
                "--build-arg",
                f"NO_PROXY={os.environ.get('NO_PROXY', '')}",
                "--build-arg",
                f"IMAGE_TAG={self.image_name}",
                "--build-arg",
                f"SOURCE_FINGERPRINT={source_fingerprint}",
                "--build-arg",
                f"BUILD_TIMESTAMP={build_timestamp}",
                "--build-arg",
                "DYNAMIC_ANALYSIS_VERSION=3.0",
                "-f",
                str(self.dockerfile_dir / "Dockerfile"),
                ".",
            ]
            try:
                result = subprocess.run(
                    cmd,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=self.build_timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise SandboxRunError(
                    f"Timed out after {self.build_timeout_seconds}s while building sandbox image "
                    f"{self.image_name}. Check Docker daemon, build context size, and apt network access."
                ) from exc
            if result.returncode != 0:
                combined = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
                tail = "\n".join(combined.splitlines()[-80:])
                raise SandboxRunError(f"Failed to build sandbox image {self.image_name}:\n{tail}")
            self._image_built = True
            self._built_images.add(self.image_name)

    def _inspect_image_metadata(self) -> dict[str, Any]:
        result = subprocess.run(
            ["docker", "image", "inspect", self.image_name],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"image_tag": self.image_name}
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"image_tag": self.image_name}
        if not payload:
            return {"image_tag": self.image_name}
        image = payload[0]
        labels = (image.get("Config") or {}).get("Labels") or {}
        return {
            "image_tag": self.image_name,
            "image_id": image.get("Id", ""),
            "repo_tags": image.get("RepoTags", []),
            "source_fingerprint": labels.get("org.provloom.source_fingerprint") or labels.get("source_fingerprint", ""),
            "dynamic_analysis_version": labels.get("org.provloom.dynamic_analysis_version", ""),
        }

    def _network_events_from_mock_records(self, records: list[dict[str, Any]]) -> list[NetworkEvent]:
        events: list[NetworkEvent] = []
        for index, record in enumerate(records, start=1):
            host = str(record.get("host") or "localhost")
            port = int(record.get("port") or 0)
            path = str(record.get("path") or "/")
            address = f"http://localhost:{port}{path}" if port else f"http://localhost{path}"
            events.append(
                NetworkEvent(
                    timestamp=str(record.get("timestamp") or ""),
                    address=address,
                    action="send",
                    raw=f"mock service received {record.get('method')} {path}",
                    host="localhost",
                    port=port or None,
                    display_label=address,
                    endpoint_kind="http",
                    endpoint_source="fixture_mock_service",
                    endpoint_role="mock_sink",
                    sink_resolution_status="controlled_mock",
                    raw_host=host.split(":", 1)[0],
                    raw_port=port or None,
                    original_url=address,
                    sink_display_label=address,
                    sink_domain="localhost",
                    sink_url=address,
                    sink_port=port or None,
                    sink_type="mock_http",
                    is_controlled_sink=True,
                    network_evidence_sources=["fixture_mock_receipt"],
                    fd=None,
                    byte_count=int(record.get("body_length") or 0),
                    payload_preview=None,
                    encrypted_payload_invisible=False,
                    network_evidence_level="tainted_payload_delivered",
                    carrier_type="http_body" if int(record.get("body_length") or 0) else "http_query",
                    carrier_location="body" if int(record.get("body_length") or 0) else "query",
                    event_id=f"mock-network-{index:04d}",
                    source="fixture_mock",
                )
            )
        return events

    def _llm_execution_summary(self, llm_events: list[LLMEvent], meta: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "termination_reason": "",
            "agent_step_count": 0,
            "max_agent_steps": 0,
            "max_steps_exhausted": False,
            "llm_request_timeout_count": 0,
            "llm_request_retry_count": 0,
            "llm_request_retry_reasons": [],
            "token_usage": {
                "model": "",
                "provider": "",
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "request_count": 0,
            },
            "model": "",
            "provider_retry_count": 0,
            "final_response_emitted": False,
            "pending_tool_call": None,
            "pending_obligation_count": 0,
        }
        for event in llm_events:
            metadata = event.metadata or {}
            step = metadata.get("agent_step_count") or metadata.get("step")
            if isinstance(step, int):
                summary["agent_step_count"] = max(int(summary["agent_step_count"]), step)
            max_steps = metadata.get("max_agent_steps")
            if isinstance(max_steps, int):
                summary["max_agent_steps"] = max(int(summary["max_agent_steps"]), max_steps)
            if event.event == "max_steps_exhausted" or metadata.get("max_steps_exhausted"):
                summary["max_steps_exhausted"] = True
                summary["termination_reason"] = "max_steps_exhausted"
            if event.event in {"response", "final_response"} or metadata.get("final_response_emitted"):
                summary["final_response_emitted"] = True
            if metadata.get("error_type") == "llm_request_timeout":
                summary["llm_request_timeout_count"] = int(summary["llm_request_timeout_count"]) + 1
                if not summary["termination_reason"]:
                    summary["termination_reason"] = "llm_request_timeout"
            retry_value = metadata.get("llm_request_retry_count", metadata.get("retry_count"))
            if retry_value is not None:
                try:
                    retry_count = int(retry_value)
                    summary["llm_request_retry_count"] = max(int(summary["llm_request_retry_count"]), retry_count)
                    summary["provider_retry_count"] = max(int(summary["provider_retry_count"]), retry_count)
                except (TypeError, ValueError):
                    pass
            retry_reasons = metadata.get("llm_request_retry_reasons")
            if isinstance(retry_reasons, list):
                existing_reasons = list(summary.get("llm_request_retry_reasons", []))
                for reason in retry_reasons:
                    if str(reason) and str(reason) not in existing_reasons:
                        existing_reasons.append(str(reason))
                summary["llm_request_retry_reasons"] = existing_reasons
            usage = metadata.get("token_usage") if isinstance(metadata.get("token_usage"), dict) else {}
            if usage:
                token_usage = summary["token_usage"]
                token_usage["request_count"] = int(token_usage.get("request_count", 0) or 0) + 1
                token_usage["prompt_tokens"] = int(token_usage.get("prompt_tokens", 0) or 0) + _safe_int(usage.get("prompt_tokens"))
                token_usage["completion_tokens"] = int(token_usage.get("completion_tokens", 0) or 0) + _safe_int(usage.get("completion_tokens"))
                token_usage["total_tokens"] = int(token_usage.get("total_tokens", 0) or 0) + _safe_int(usage.get("total_tokens"))
                token_usage["model"] = str(usage.get("model") or metadata.get("model") or token_usage.get("model") or "")
                token_usage["provider"] = str(usage.get("provider") or metadata.get("provider") or token_usage.get("provider") or "")
                summary["model"] = str(token_usage.get("model") or "")
            if metadata.get("retry_count") is not None:
                try:
                    summary["provider_retry_count"] = max(int(summary["provider_retry_count"]), int(metadata["retry_count"]))
                except (TypeError, ValueError):
                    pass
            if metadata.get("pending_tool_call"):
                summary["pending_tool_call"] = str(metadata["pending_tool_call"])
            if metadata.get("pending_obligation_count") is not None:
                try:
                    summary["pending_obligation_count"] = max(int(summary["pending_obligation_count"]), int(metadata["pending_obligation_count"]))
                except (TypeError, ValueError):
                    pass
        if not summary["termination_reason"] and meta.get("termination_reason"):
            summary["termination_reason"] = str(meta.get("termination_reason"))
        return summary

    def _build_runner_script(self, skill_file: str, timeout_seconds: int) -> str:
        skill_file_quoted = quote(skill_file)
        return f"""
set -eu
cp /opt/skill_sandbox/runtime-build-info.json /artifacts/runtime-build-info.json 2>/dev/null || true
cp /opt/skill_sandbox/installed-tool-versions.txt /artifacts/installed-tool-versions.txt 2>/dev/null || true
cd /workspace/skill
TIMED_OUT=0
EXIT_CODE=0
DEADLINE_REACHED=0
TERMINATION_REASON="completed"
TERMINATION_SIGNAL=""
RUNNER_KILLED_PROCESS=0
START_TS=$(date +%s)
MOCK_PID=""
if [ -s /artifacts/fixture-runtime.json ]; then
  mkdir -p /artifacts/mock-services
  PYTHONPATH=/opt/skill_sandbox python -m app.runner.fixture_mock_server --config /artifacts/fixture-runtime.json > /artifacts/mock-services/stdout.log 2> /artifacts/mock-services/stderr.log &
  MOCK_PID=$!
  for i in $(seq 1 50); do
    if [ -s /artifacts/mock-services/mock-services-ready.json ]; then
      break
    fi
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then
      TERMINATION_REASON="mock_service_unavailable"
      EXIT_CODE=70
      printf '{{"exit_code": %s, "timed_out": false, "termination_reason": "%s", "termination_signal": "", "deadline_reached": false, "runner_killed_process": false, "container_oom_killed": false}}' "$EXIT_CODE" "$TERMINATION_REASON" > /artifacts/meta.json
      exit 0
    fi
    sleep 0.1
  done
fi
if timeout --preserve-status {timeout_seconds}s sh -lc 'PYTHONPATH=/opt/skill_sandbox /usr/bin/time -v -o /artifacts/runtime-resource-usage.txt strace -ff -tt -s 256 -o /artifacts/trace.log -e trace=file,process,network python -m app.runtime.container_runtime --skill-root /workspace/skill --skill-file {skill_file_quoted} --input-payload /artifacts/input-payload.json --runtime-events /artifacts/runtime-events.jsonl --llm-config /tmp/provloom-llm-config.json > /artifacts/stdout.log 2> /artifacts/stderr.log'; then
  EXIT_CODE=0
else
  EXIT_CODE=$?
  END_TS=$(date +%s)
  ELAPSED=$((END_TS - START_TS))
  if [ "$EXIT_CODE" = "124" ] || {{ [ "$ELAPSED" -ge {timeout_seconds} ] && {{ [ "$EXIT_CODE" = "137" ] || [ "$EXIT_CODE" = "143" ]; }}; }}; then
    TIMED_OUT=1
    DEADLINE_REACHED=1
    RUNNER_KILLED_PROCESS=1
    TERMINATION_REASON="timeout"
    if [ "$EXIT_CODE" = "137" ]; then TERMINATION_SIGNAL="SIGKILL"; fi
    if [ "$EXIT_CODE" = "143" ]; then TERMINATION_SIGNAL="SIGTERM"; fi
  else
    TERMINATION_REASON="process_exit"
  fi
fi
if [ -n "$MOCK_PID" ]; then
  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
fi
printf '{{"exit_code": %s, "timed_out": %s, "termination_reason": "%s", "termination_signal": "%s", "deadline_reached": %s, "runner_killed_process": %s, "container_oom_killed": false}}' "$EXIT_CODE" "$TIMED_OUT" "$TERMINATION_REASON" "$TERMINATION_SIGNAL" "$DEADLINE_REACHED" "$RUNNER_KILLED_PROCESS" > /artifacts/meta.json
exit 0
""".strip()

    def _source_fingerprint(self) -> str:
        paths = [
            Path("app/dynamic"),
            Path("app/runtime/container_runtime.py"),
            Path("app/runner/trace_parser.py"),
        ]
        digest = hashlib.sha256()
        for root in paths:
            if root.is_file():
                self._hash_file(digest, root)
                continue
            if not root.exists():
                digest.update(f"missing:{root}\n".encode("utf-8"))
                continue
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                self._hash_file(digest, path)
        return digest.hexdigest()

    @staticmethod
    def _hash_file(digest: "hashlib._Hash", path: Path) -> None:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")

    def _force_cleanup(self, container_name: str) -> None:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            text=True,
            capture_output=True,
            check=False,
        )

    def _sanitize_llm_config_artifact(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if "api_key" not in payload:
            return
        payload["api_key"] = "***redacted***" if payload.get("api_key") else ""
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _llm_config_payload(llm_config: LLMConfig, *, redact_api_key: bool) -> dict[str, Any]:
        return {
            "enabled": llm_config.enabled,
            "provider": llm_config.provider,
            "base_url": llm_config.base_url,
            "api_key": "***redacted***" if redact_api_key and llm_config.api_key else llm_config.api_key,
            "model": llm_config.model,
            "temperature": llm_config.temperature,
            "max_steps": llm_config.max_steps,
        }

    def _sanitize_trace_payload_artifacts(self, artifacts_dir: Path) -> None:
        patterns = [
            re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
            re.compile(r"(?:PROVLOOM_SECRET|PROBE_SECRET_MARKER)[A-Za-z0-9_:-]*"),
        ]
        for path in artifacts_dir.glob("trace.log*"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            redacted = text
            for pattern in patterns:
                redacted = pattern.sub("***redacted***", redacted)
            if redacted != text:
                path.write_text(redacted, encoding="utf-8")

    def _collect_resource_usage(
        self,
        container_name: str,
        peak_memory_bytes: int,
        mounted_skill_dir: Path,
        artifacts_dir: Path,
    ) -> ResourceUsage:
        inspect_data = self._inspect_container(container_name)
        runtime_peak_bytes = self._parse_gnu_time_peak_bytes(artifacts_dir / "runtime-resource-usage.txt")
        if runtime_peak_bytes and runtime_peak_bytes > peak_memory_bytes:
            peak_memory_bytes = runtime_peak_bytes
        skill_bundle_bytes = self._dir_size_bytes(mounted_skill_dir)
        artifacts_bytes = self._dir_size_bytes(artifacts_dir)
        writable_layer_bytes = inspect_data.get("SizeRw")
        rootfs_bytes = inspect_data.get("SizeRootFs")
        estimated_total_disk_bytes = sum(
            value for value in [skill_bundle_bytes, artifacts_bytes, writable_layer_bytes] if isinstance(value, int)
        )
        memory_limit_bytes = ((inspect_data.get("HostConfig") or {}).get("Memory")) or None
        if memory_limit_bytes == 0:
            memory_limit_bytes = None
        return ResourceUsage(
            memory_limit_bytes=memory_limit_bytes,
            memory_peak_bytes=peak_memory_bytes or None,
            memory_peak_human=self._format_bytes(peak_memory_bytes) if peak_memory_bytes else None,
            writable_layer_bytes=writable_layer_bytes,
            writable_layer_human=self._format_bytes(writable_layer_bytes),
            rootfs_bytes=rootfs_bytes,
            rootfs_human=self._format_bytes(rootfs_bytes),
            skill_bundle_bytes=skill_bundle_bytes,
            skill_bundle_human=self._format_bytes(skill_bundle_bytes),
            artifacts_bytes=artifacts_bytes,
            artifacts_human=self._format_bytes(artifacts_bytes),
            estimated_total_disk_bytes=estimated_total_disk_bytes or None,
            estimated_total_disk_human=self._format_bytes(estimated_total_disk_bytes),
        )

    def _inspect_container(self, container_name: str) -> dict:
        result = subprocess.run(
            ["docker", "inspect", "--size", container_name],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        payload = json.loads(result.stdout)
        if not payload:
            return {}
        return payload[0]

    def _poll_container_memory(
        self,
        container_name: str,
        stop_event: threading.Event,
        peak_holder: dict[str, int],
    ) -> None:
        while not stop_event.is_set():
            try:
                result = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container_name],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=2,
                )
            except subprocess.TimeoutExpired:
                # Keep the monitor non-blocking so benchmark execution can finish
                # even if docker stats occasionally stalls.
                time.sleep(0.2)
                continue
            if result.returncode == 0:
                usage = result.stdout.strip()
                if usage:
                    current_usage = usage.split("/", 1)[0].strip()
                    parsed = self._parse_size_to_bytes(current_usage)
                    if parsed > peak_holder["peak"]:
                        peak_holder["peak"] = parsed
            time.sleep(0.2)

    @staticmethod
    def _dir_size_bytes(path: Path) -> int:
        total = 0
        if not path.exists():
            return total
        for subpath in path.rglob("*"):
            if subpath.is_file():
                total += subpath.stat().st_size
        return total

    @staticmethod
    def _parse_size_to_bytes(value: str) -> int:
        text = value.strip()
        if not text or text.lower() == "0b":
            return 0
        units = {
            "kib": 1024,
            "kb": 1000,
            "mib": 1024 ** 2,
            "mb": 1000 ** 2,
            "gib": 1024 ** 3,
            "gb": 1000 ** 3,
            "b": 1,
        }
        lower = text.lower()
        for unit, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
            if lower.endswith(unit):
                number = lower[: -len(unit)].strip()
                return int(float(number) * multiplier)
        return int(float(text))

    @staticmethod
    def _parse_gnu_time_peak_bytes(path: Path) -> int:
        if not path.exists():
            return 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "Maximum resident set size" not in line:
                continue
            _, raw_value = line.split(":", 1)
            kib = int(raw_value.strip())
            return kib * 1024
        return 0

    @staticmethod
    def _format_bytes(value: int | None) -> str | None:
        if value is None:
            return None
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        size = float(value)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.2f} {unit}"
            size /= 1024

    @staticmethod
    def _load_meta(path: Path) -> dict:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _read_text(path: Path) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _build_trigger_event_bundle(injections: list[dict[str, str]]) -> dict[str, list]:
        from app.runner.models import DataFlowEvent, FileEvent, NetworkEvent, ToolCallEvent

        files: list[FileEvent] = []
        networks: list[NetworkEvent] = []
        tools: list[ToolCallEvent] = []
        flows: list[DataFlowEvent] = []
        now = time.time()

        for idx, item in enumerate(injections, start=1):
            ts = datetime_from_epoch(now + idx * 0.001)
            trigger_id = str(item.get("trigger_id", f"trigger_event_{idx}"))
            family = str(item.get("family", "event"))
            endpoint = str(item.get("endpoint", "")).strip()
            artifact_path = str(item.get("artifact_path", "")).strip()

            tools.append(
                ToolCallEvent(
                    timestamp=ts,
                    tool_id=f"trigger_{trigger_id}",
                    tool_name=f"Trigger Event {family}",
                    tool_type="trigger_event",
                    event="finish",
                    status="ok",
                    source="trigger",
                    metadata={"trigger_id": trigger_id, "family": family, "synthetic": True, "payload": item},
                )
            )
            if endpoint:
                networks.append(
                    NetworkEvent(
                        timestamp=ts,
                        address=endpoint,
                        action="connect",
                        raw=f"trigger:{family}",
                        source="trigger",
                        sink_resolution_status="resolved",
                        sink_url=endpoint,
                        sink_type="url",
                        network_evidence_sources=["trigger_plan"],
                        selected_sink_reason=f"trigger_event:{family}",
                    )
                )
            if artifact_path:
                files.append(
                    FileEvent(
                        timestamp=ts,
                        path=artifact_path,
                        action="read",
                        raw=f"trigger:{family}",
                        source="trigger",
                    )
                )
            if endpoint and artifact_path:
                flows.append(
                    DataFlowEvent(
                        timestamp=ts,
                        source="trigger_artifact",
                        source_detail=artifact_path,
                        sink="trigger_endpoint",
                        sink_detail=endpoint,
                        note=f"Synthetic trigger flow for {family}",
                    )
                )
        return {
            "file_events": files,
            "network_events": networks,
            "tool_calls": tools,
            "data_flows": flows,
        }


def datetime_from_epoch(value: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(value)) + f".{int((value % 1) * 1000):03d}Z"


def _safe_int(value: Any) -> int:
    try:
        if value is None or value == "":
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0
