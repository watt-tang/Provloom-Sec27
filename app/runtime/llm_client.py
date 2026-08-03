from __future__ import annotations

import json
import socket
import time
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
    retry_count: int = 0
    retry_reasons: list[str] | None = None
    initial_failure: str = ""


class LLMRequestError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        error_type: str,
        retry_count: int = 0,
        retry_reasons: list[str] | None = None,
        initial_failure: str = "",
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.retry_count = retry_count
        self.retry_reasons = list(retry_reasons or [])
        self.initial_failure = initial_failure


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
        raw_body, retry_count, retry_reasons, initial_failure = self._post_with_retries(payload)

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
            retry_count=retry_count,
            retry_reasons=retry_reasons,
            initial_failure=initial_failure,
        )

    def _post_with_retries(self, payload: dict[str, Any]) -> tuple[str, int, list[str], str]:
        retry_reasons: list[str] = []
        initial_failure = ""
        delays = [5, 15]
        last_exc: BaseException | None = None
        last_error_type = "llm_request_failed"
        last_message = ""

        for attempt in range(0, len(delays) + 1):
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
                    return response.read().decode("utf-8"), attempt, retry_reasons, initial_failure
            except urllib.error.HTTPError as exc:
                last_exc = exc
                last_error_type = "llm_request_failed"
                last_message = self._format_http_error(exc)
                retry_reason = "http_5xx" if 500 <= int(exc.code) <= 599 else ""
                if not retry_reason:
                    break
            except (TimeoutError, socket.timeout) as exc:
                last_exc = exc
                last_error_type = "llm_request_timeout"
                retry_reason = "timeout"
                last_message = (
                    f"LLM request timed out for provider={self.provider} model={self.model} "
                    f"base_url={self.base_url}"
                )
            except urllib.error.URLError as exc:
                last_exc = exc
                retry_reason, last_error_type = self._classify_url_error(exc)
                reason = getattr(exc, "reason", exc)
                if last_error_type == "llm_request_timeout":
                    last_message = (
                        f"LLM request timed out for provider={self.provider} model={self.model} "
                        f"base_url={self.base_url}"
                    )
                else:
                    last_message = (
                        f"LLM request failed for provider={self.provider} model={self.model} "
                        f"base_url={self.base_url}: {reason}"
                    )
                if not retry_reason:
                    break
            except ConnectionResetError as exc:
                last_exc = exc
                last_error_type = "llm_request_failed"
                retry_reason = "connection_reset"
                last_message = (
                    f"LLM request failed for provider={self.provider} model={self.model} "
                    f"base_url={self.base_url}: connection reset"
                )

            if retry_reason and not initial_failure:
                initial_failure = last_error_type
            if retry_reason and attempt < len(delays):
                retry_reasons.append(retry_reason)
                time.sleep(delays[attempt])
                continue
            break

        raise LLMRequestError(
            last_message or f"LLM request failed for provider={self.provider} model={self.model} base_url={self.base_url}",
            error_type=last_error_type,
            retry_count=len(retry_reasons),
            retry_reasons=retry_reasons,
            initial_failure=initial_failure,
        ) from last_exc

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

    def _classify_url_error(self, error: urllib.error.URLError) -> tuple[str, str]:
        reason = getattr(error, "reason", error)
        if isinstance(reason, socket.timeout):
            return "timeout", "llm_request_timeout"
        if isinstance(reason, ConnectionResetError):
            return "connection_reset", "llm_request_failed"
        if isinstance(reason, OSError):
            message = str(reason).lower()
            if "timed out" in message or "timeout" in message:
                return "timeout", "llm_request_timeout"
            if "connection reset" in message:
                return "connection_reset", "llm_request_failed"
            if "temporarily unavailable" in message or "temporary failure" in message:
                return "temporary_network_error", "llm_request_failed"
        return "", "llm_request_failed"


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
