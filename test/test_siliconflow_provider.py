from __future__ import annotations

import io
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
        config = LLMConfig.from_dict({"enabled": True})

        self.assertTrue(config.enabled)
        self.assertEqual(config.provider, "siliconflow")
        self.assertEqual(config.base_url, DEFAULT_LLM_BASE_URL)
        self.assertEqual(config.model, DEFAULT_LLM_MODEL)
        self.assertEqual(config.api_key, DEFAULT_LLM_API_KEY)

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
            api_key=DEFAULT_LLM_API_KEY,
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
