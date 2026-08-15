from __future__ import annotations

import io
import os
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import urllib.error

from app.analyzer.endpoint_semantics import llm_provider_name
from app.backend.schemas import (
    DEFAULT_LLM_API_KEY,
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    LLMConfig,
)
from app.runtime.container_runtime import LLMAgentSkillRuntime
from app.runtime.llm_client import LLMResponse, OpenAICompatibleClient
from app.runtime.skill_parser import SkillDefinition
from app.runner.docker_runner import DockerRunner
from app.runner.models import LLMEvent


class _FakeHTTPResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self.body


class SiliconFlowProviderTests(unittest.TestCase):
    def test_llm_config_defaults_to_siliconflow(self) -> None:
        with patch.dict(os.environ, {"PROVLOOM_SCAN_API_KEY": "unit-api-key"}, clear=False):
            config = LLMConfig.from_dict({"enabled": True})

        self.assertTrue(config.enabled)
        self.assertEqual(config.provider, "siliconflow")
        self.assertEqual(config.base_url, DEFAULT_LLM_BASE_URL)
        self.assertEqual(config.model, DEFAULT_LLM_MODEL)
        self.assertEqual(config.api_key, "unit-api-key")

    def test_llm_config_requires_api_key_when_enabled_without_env(self) -> None:
        with patch.dict(os.environ, {"PROVLOOM_SCAN_API_KEY": "", "PROVLOOM_LLM_API_KEY": ""}, clear=False):
            with self.assertRaisesRegex(ValueError, "api_key"):
                LLMConfig.from_dict({"enabled": True})

    def test_endpoint_semantics_recognizes_siliconflow_hosts(self) -> None:
        provider = llm_provider_name(
            label="https://api.siliconflow.cn/v1/chat/completions",
            host=None,
        )

        self.assertEqual(provider, "siliconflow")

    def test_llm_client_surfaces_http_error_details(self) -> None:
        client = OpenAICompatibleClient(
            provider="siliconflow",
            base_url=DEFAULT_LLM_BASE_URL,
            api_key="unit-api-key",
            model=DEFAULT_LLM_MODEL,
        )
        error = urllib.error.HTTPError(
            url=f"{DEFAULT_LLM_BASE_URL}/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(b'{"error":{"message":"bad key"}}'),
        )

        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
                client.chat([{"role": "user", "content": "hello"}])

    def test_llm_client_uses_chat_completions_endpoint_and_extracts_token_usage(self) -> None:
        client = OpenAICompatibleClient(
            provider="autos",
            base_url="https://llm-provider.example/v1/chat/completions",
            api_key="unit-api-key",
            model="glm-5.2",
        )
        body = (
            b'{"model":"glm-5.2","choices":[{"message":{"content":"{\\\\\\"action\\\\\\":{\\\\\\"tool\\\\\\":\\\\\\"finish\\\\\\"}}"}}],'
            b'"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}'
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            return _FakeHTTPResponse(body)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            response = client.chat([{"role": "user", "content": "hello"}])

        self.assertEqual(captured["url"], "https://llm-provider.example/v1/chat/completions")
        self.assertEqual(response.model, "glm-5.2")
        self.assertEqual(response.token_usage["prompt_tokens"], 11)
        self.assertEqual(response.token_usage["completion_tokens"], 7)
        self.assertEqual(response.token_usage["total_tokens"], 18)

    def test_llm_client_retries_timeout_and_reports_retry_metadata(self) -> None:
        client = OpenAICompatibleClient(
            provider="autos",
            base_url="https://llm-provider.example/v1/chat/completions",
            api_key="unit-api-key",
            model="glm-5.2",
        )
        body = (
            b'{"model":"glm-5.2","choices":[{"message":{"content":"{\\\\\\"action\\\\\\":{\\\\\\"tool\\\\\\":\\\\\\"finish\\\\\\"}}"}}],'
            b'"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}'
        )
        calls = {"count": 0}

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise socket.timeout("slow provider")
            return _FakeHTTPResponse(body)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen), patch("time.sleep") as sleep:
            response = client.chat([{"role": "user", "content": "hello"}])

        self.assertEqual(calls["count"], 2)
        sleep.assert_called_once_with(5)
        self.assertEqual(response.retry_count, 1)
        self.assertEqual(response.retry_reasons, ["timeout"])
        self.assertEqual(response.initial_failure, "llm_request_timeout")

    def test_llm_client_does_not_retry_http_400(self) -> None:
        client = OpenAICompatibleClient(
            provider="autos",
            base_url="https://llm-provider.example/v1/chat/completions",
            api_key="unit-api-key",
            model="glm-5.2",
        )
        error = urllib.error.HTTPError(
            url="https://llm-provider.example/v1/chat/completions",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b'{"error":{"message":"bad schema"}}'),
        )

        with patch("urllib.request.urlopen", side_effect=error) as urlopen, patch("time.sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
                client.chat([{"role": "user", "content": "hello"}])

        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()

    def test_runner_summarizes_llm_token_usage(self) -> None:
        runner = DockerRunner(image_name="unit-image")
        summary = runner._llm_execution_summary(
            [
                LLMEvent(
                    timestamp="t1",
                    event="response",
                    metadata={
                        "model": "glm-5.2",
                        "provider": "autos",
                        "token_usage": {"model": "glm-5.2", "provider": "autos", "prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
                        "llm_request_retry_count": 1,
                        "llm_request_retry_reasons": ["timeout"],
                    },
                ),
                LLMEvent(
                    timestamp="t2",
                    event="response",
                    metadata={
                        "model": "glm-5.2",
                        "provider": "autos",
                        "token_usage": {"model": "glm-5.2", "provider": "autos", "prompt_tokens": 5, "completion_tokens": 6, "total_tokens": 11},
                    },
                ),
            ],
            {},
        )

        self.assertEqual(summary["model"], "glm-5.2")
        self.assertEqual(summary["token_usage"]["request_count"], 2)
        self.assertEqual(summary["token_usage"]["prompt_tokens"], 8)
        self.assertEqual(summary["token_usage"]["completion_tokens"], 10)
        self.assertEqual(summary["token_usage"]["total_tokens"], 18)
        self.assertEqual(summary["llm_request_retry_count"], 1)
        self.assertEqual(summary["llm_request_retry_reasons"], ["timeout"])

    def test_llm_agent_repairs_non_json_action_once(self) -> None:
        events = []
        definition = SkillDefinition(
            skill_root="/tmp/unit-skill",
            skill_file="SKILL.md",
            name="unit",
            description="unit",
            runtime="llm-agent",
            actions=[],
            raw_markdown="# Unit\n",
        )
        executor = _FakeExecutor()
        runtime = LLMAgentSkillRuntime(
            definition=definition,
            input_payload={"trigger": "run"},
            context={"skill_root": "/tmp/unit-skill", "actions": {}},
            executor=executor,
            emit_func=lambda category, event, payload, step_id=None, parent_event_id=None: _capture_event(events, category, event, payload, step_id, parent_event_id),
            llm_config={
                "provider": "autos",
                "base_url": "https://llm-provider.example/v1/chat/completions",
                "api_key": "unit-api-key",
                "model": "glm-5.2",
                "temperature": 0.0,
                "max_steps": 1,
            },
        )
        runtime.client = _FakeRepairClient(
            [
                LLMResponse(
                    content="I'll start by reading the request file.",
                    raw={"model": "glm-5.2"},
                    model="glm-5.2",
                    token_usage={"model": "glm-5.2", "provider": "autos", "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                ),
                LLMResponse(
                    content='{"action":{"tool":"finish"},"message":"done"}',
                    raw={"model": "glm-5.2"},
                    model="glm-5.2",
                    token_usage={"model": "glm-5.2", "provider": "autos", "prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
                ),
            ]
        )

        with redirect_stdout(io.StringIO()):
            exit_code = runtime.execute()

        self.assertEqual(exit_code, 0)
        self.assertEqual(runtime.client.call_count, 2)
        repair_events = [item for item in events if item["event"] == "json_repair"]
        self.assertTrue(any(item["payload"].get("llm_json_repair_success") is True for item in repair_events))
        repair_requests = [item for item in events if item["event"] == "request" and item["payload"].get("llm_json_repair_attempted")]
        self.assertEqual(len(repair_requests), 1)

class _FakeRepairClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.call_count = 0
        self.base_url = "https://llm-provider.example/v1/chat/completions"

    def chat(self, messages):
        self.call_count += 1
        return self.responses.pop(0)


class _FakeExecutor:
    def get_tool_catalog(self, actions):
        return []


def _capture_event(events, category, event, payload, step_id=None, parent_event_id=None):
    event_id = f"{category}-{event}-{len(events)}"
    events.append(
        {
            "event_id": event_id,
            "category": category,
            "event": event,
            "payload": payload,
            "step_id": step_id,
            "parent_event_id": parent_event_id,
        }
    )
    return event_id


if __name__ == "__main__":
    unittest.main()
