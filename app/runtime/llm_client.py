from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class LLMResponse:
    content: str
    raw: dict[str, Any]


class OpenAICompatibleClient:
    def __init__(self, base_url: str, api_key: str, model: str, temperature: float = 0.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = temperature

    def chat(self, messages: list[dict[str, str]]) -> LLMResponse:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": messages,
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            data=json.dumps(payload).encode("utf-8"),
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return LLMResponse(content=content, raw=data)
