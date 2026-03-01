"""
LLM Adapter Layer — Unified Interface for Live Model Interrogation
===================================================================
Provides a provider-agnostic interface for sending prompts to LLMs
and receiving responses, enabling AIntegrity to actively interrogate
models under audit.

Supported backends:
  - OpenAI  (GPT-4, GPT-3.5, etc.)
  - Anthropic (Claude family)
  - Echo   (deterministic mock for testing)

Usage::

    adapter = LLMAdapter.create("openai", api_key="sk-...")
    response = adapter.query("What is 2+2?")
    print(response.text)  # "4"
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import time


@dataclass
class LLMResponse:
    """Standardized response from any LLM backend."""
    text: str
    model: str
    provider: str
    latency_ms: float = 0.0
    usage: Dict[str, int] = field(default_factory=dict)
    raw: Optional[Any] = None


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    provider: str = "unknown"

    @abstractmethod
    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Send a prompt and return a standardized response."""

    @abstractmethod
    def query_multi_turn(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Send a multi-turn conversation and return a standardized response."""


class OpenAIBackend(LLMBackend):
    """OpenAI API backend (GPT-4, GPT-3.5, etc.)."""

    provider = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.model = model
        self._client = None
        self._api_key = api_key

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self._api_key)
            except ImportError:
                raise ImportError(
                    "openai package required: pip install 'aintegrity[llm]'"
                )
        return self._client

    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self.query_multi_turn(messages, temperature=temperature, max_tokens=max_tokens)

    def query_multi_turn(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
        client = self._get_client()
        start = time.monotonic()
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        latency = (time.monotonic() - start) * 1000
        choice = response.choices[0]
        return LLMResponse(
            text=choice.message.content or "",
            model=self.model,
            provider=self.provider,
            latency_ms=round(latency, 2),
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            },
            raw=response,
        )


class AnthropicBackend(LLMBackend):
    """Anthropic API backend (Claude family)."""

    provider = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.model = model
        self._client = None
        self._api_key = api_key

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise ImportError(
                    "anthropic package required: pip install 'aintegrity[llm]'"
                )
        return self._client

    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        messages = [{"role": "user", "content": prompt}]
        return self.query_multi_turn(messages, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)

    def query_multi_turn(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        client = self._get_client()
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        start = time.monotonic()
        response = client.messages.create(**kwargs)
        latency = (time.monotonic() - start) * 1000
        text = response.content[0].text if response.content else ""
        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider,
            latency_ms=round(latency, 2),
            usage={
                "input_tokens": response.usage.input_tokens if response.usage else 0,
                "output_tokens": response.usage.output_tokens if response.usage else 0,
            },
            raw=response,
        )


class EchoBackend(LLMBackend):
    """Deterministic mock backend for testing.

    Returns a configurable response or echoes the prompt.
    """

    provider = "echo"

    def __init__(self, default_response: str = "", responses: Optional[List[str]] = None):
        self.default_response = default_response
        self._responses = list(responses) if responses else []
        self._call_count = 0

    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        return self._make_response(prompt)

    def query_multi_turn(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        last_prompt = messages[-1]["content"] if messages else ""
        return self._make_response(last_prompt)

    def _make_response(self, prompt: str) -> LLMResponse:
        if self._responses:
            text = self._responses[self._call_count % len(self._responses)]
        elif self.default_response:
            text = self.default_response
        else:
            text = f"Echo: {prompt}"
        self._call_count += 1
        return LLMResponse(
            text=text,
            model="echo-v1",
            provider=self.provider,
            latency_ms=0.0,
            usage={"prompt_tokens": len(prompt.split()), "completion_tokens": len(text.split())},
        )


class LLMAdapter:
    """Factory + wrapper that adds audit-friendly metadata to every call."""

    BACKENDS = {
        "openai": OpenAIBackend,
        "anthropic": AnthropicBackend,
        "echo": EchoBackend,
    }

    def __init__(self, backend: LLMBackend):
        self.backend = backend
        self.call_log: List[Dict[str, Any]] = []

    @classmethod
    def create(cls, provider: str, **kwargs) -> "LLMAdapter":
        """Create an adapter for a given provider.

        Args:
            provider: One of "openai", "anthropic", "echo"
            **kwargs: Passed to the backend constructor

        Returns:
            Configured LLMAdapter instance
        """
        if provider not in cls.BACKENDS:
            raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(cls.BACKENDS.keys())}")
        backend = cls.BACKENDS[provider](**kwargs)
        return cls(backend)

    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Send a single prompt and return a standardized response."""
        response = self.backend.query(prompt, system_prompt, temperature, max_tokens)
        self._log(prompt, response)
        return response

    def query_multi_turn(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Send a multi-turn conversation and return a standardized response."""
        response = self.backend.query_multi_turn(messages, system_prompt, temperature, max_tokens)
        prompt_summary = messages[-1]["content"] if messages else ""
        self._log(prompt_summary, response)
        return response

    def _log(self, prompt: str, response: LLMResponse):
        self.call_log.append({
            "prompt_preview": prompt[:200],
            "response_preview": response.text[:200],
            "model": response.model,
            "provider": response.provider,
            "latency_ms": response.latency_ms,
            "usage": response.usage,
        })

    def get_call_log(self) -> List[Dict[str, Any]]:
        """Return the full call log for audit purposes."""
        return self.call_log
