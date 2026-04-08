from __future__ import annotations

import os
import time
from typing import Literal, Protocol, TypedDict

from socketai_reproduce.analysis.models import UsageStats
from socketai_reproduce.env import load_project_dotenv


class ChatMessage(TypedDict):
    role: Literal["system", "user", "assistant"]
    content: str


class LLMResponse(TypedDict):
    texts: list[str]
    usage: UsageStats
    latency_ms: int


class LLMClient(Protocol):
    model_name: str
    provider_name: str

    def generate(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float,
        n: int = 1,
    ) -> LLMResponse: ...


class LiteLLMClient:
    def __init__(
        self,
        *,
        model_name: str,
        provider_name: str,
        temperature: float = 0.0,
        api_key: str | None = None,
        api_base: str | None = None,
        timeout: int = 120,
    ) -> None:
        load_project_dotenv()
        self.model_name = model_name
        self.provider_name = provider_name
        self.temperature = temperature
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        self.api_base = api_base if api_base is not None else os.getenv("OPENAI_BASE_URL")
        self.timeout = timeout

    def generate(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float,
        n: int = 1,
    ) -> LLMResponse:
        try:
            from litellm import completion
        except ImportError as exc:
            raise RuntimeError(
                "LiteLLM is not installed. Install project dependencies before running detection."
            ) from exc

        kwargs: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "n": n,
            "timeout": self.timeout,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base

        started_at = time.perf_counter()
        response = completion(**kwargs)
        latency_ms = int((time.perf_counter() - started_at) * 1000)

        texts: list[str] = []
        for choice in getattr(response, "choices", []):
            message = getattr(choice, "message", None)
            content = getattr(message, "content", "")
            if isinstance(content, list):
                joined = "\n".join(
                    item.get("text", "") for item in content if isinstance(item, dict)
                )
                texts.append(joined)
            else:
                texts.append(str(content))

        usage_raw = getattr(response, "usage", None)
        usage = UsageStats(
            prompt_tokens=int(getattr(usage_raw, "prompt_tokens", 0) or 0),
            completion_tokens=int(getattr(usage_raw, "completion_tokens", 0) or 0),
            total_tokens=int(getattr(usage_raw, "total_tokens", 0) or 0),
        )

        return {
            "texts": texts,
            "usage": usage,
            "latency_ms": latency_ms,
        }
