from __future__ import annotations

import io
import os
import unittest
from unittest.mock import patch
import urllib.error

from app.analyzer.endpoint_semantics import llm_provider_name
from app.backend.schemas import (
    DEFAULT_LLM_API_KEY,
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    LLMConfig,
)
from app.runtime.llm_client import OpenAICompatibleClient
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
            base_url="https://sec.llm.autos/v1/chat/completions",
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

        self.assertEqual(captured["url"], "https://sec.llm.autos/v1/chat/completions")
        self.assertEqual(response.model, "glm-5.2")
        self.assertEqual(response.token_usage["prompt_tokens"], 11)
        self.assertEqual(response.token_usage["completion_tokens"], 7)
        self.assertEqual(response.token_usage["total_tokens"], 18)

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


if __name__ == "__main__":
    unittest.main()
