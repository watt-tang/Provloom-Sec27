from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass
class LLMResponse:
    content: str
    raw: dict[str, Any]
    model: str
    token_usage: dict[str, Any]


class OpenAICompatibleClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float = 0.0,
        provider: str = "openai-compatible",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.provider = provider

    def chat(self, messages: list[dict[str, str]]) -> LLMResponse:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": messages,
        }
        request = urllib.request.Request(
            self._request_url(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            data=json.dumps(payload).encode("utf-8"),
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw_body = response.read().decode("utf-8")
        except TimeoutError as exc:
            raise RuntimeError(
                f"LLM request timed out for provider={self.provider} model={self.model} "
                f"base_url={self.base_url}"
            ) from exc
        except socket.timeout as exc:
            raise RuntimeError(
                f"LLM request timed out for provider={self.provider} model={self.model} "
                f"base_url={self.base_url}"
            ) from exc
        except urllib.error.HTTPError as exc:
            raise RuntimeError(self._format_http_error(exc)) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(
                f"LLM request failed for provider={self.provider} model={self.model} "
                f"base_url={self.base_url}: {reason}"
            ) from exc

        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            preview = raw_body[:400].replace("\n", " ")
            raise RuntimeError(
                f"LLM returned non-JSON response for provider={self.provider} model={self.model} "
                f"base_url={self.base_url}: {preview}"
            ) from exc

        try:
            content = self._extract_content(data)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            preview = json.dumps(data, ensure_ascii=False)[:400]
            raise RuntimeError(
                f"LLM response format was unexpected for provider={self.provider} "
                f"model={self.model}: {preview}"
            ) from exc
        return LLMResponse(
            content=content,
            raw=data,
            model=str(data.get("model") or self.model),
            token_usage=self._extract_token_usage(data),
        )

    def _request_url(self) -> str:
        parsed = urlparse(self.base_url)
        path = parsed.path.rstrip("/")
        if path.endswith("/messages") or path.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def _extract_content(self, data: dict[str, Any]) -> str:
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "".join(str(item.get("text") or "") if isinstance(item, dict) else str(item) for item in content)
        content = data.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(str(item.get("text") or "") if isinstance(item, dict) else str(item) for item in content)
        output_text = data.get("output_text")
        if isinstance(output_text, str):
            return output_text
        raise ValueError("missing assistant content")

    def _extract_token_usage(self, data: dict[str, Any]) -> dict[str, Any]:
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        prompt_tokens = _int_or_none(usage.get("prompt_tokens", usage.get("input_tokens")))
        completion_tokens = _int_or_none(usage.get("completion_tokens", usage.get("output_tokens")))
        total_tokens = _int_or_none(usage.get("total_tokens"))
        if total_tokens is None and (prompt_tokens is not None or completion_tokens is not None):
            total_tokens = int(prompt_tokens or 0) + int(completion_tokens or 0)
        return {
            "model": str(data.get("model") or self.model),
            "provider": self.provider,
            "prompt_tokens": int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "total_tokens": int(total_tokens or 0),
            "raw_usage_keys": sorted(str(key) for key in usage.keys()),
        }

    def _format_http_error(self, error: urllib.error.HTTPError) -> str:
        body = ""
        if error.fp is not None:
            body = error.read().decode("utf-8", errors="replace")
        detail = body.strip()
        if detail:
            try:
                parsed = json.loads(detail)
                detail = json.dumps(parsed, ensure_ascii=False)
            except json.JSONDecodeError:
                detail = detail.replace("\n", " ")
            detail = detail[:400]
        else:
            detail = error.reason if getattr(error, "reason", None) else "empty response body"
        return (
            f"LLM request returned HTTP {error.code} for provider={self.provider} "
            f"model={self.model} base_url={self.base_url}: {detail}"
        )


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
