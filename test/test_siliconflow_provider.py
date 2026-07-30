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


if __name__ == "__main__":
    unittest.main()
