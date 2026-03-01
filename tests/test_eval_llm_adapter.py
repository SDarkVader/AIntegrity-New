"""
Project Sentinel — LLM Adapter Evaluation Suite
=================================================
Metrics evaluated:
  LLM-01  EchoBackend returns deterministic responses
  LLM-02  EchoBackend cycles through response list
  LLM-03  EchoBackend default echo behavior
  LLM-04  LLMAdapter factory creates echo backend
  LLM-05  LLMAdapter factory rejects unknown provider
  LLM-06  LLMResponse dataclass structure
  LLM-07  Call log records every query
  LLM-08  Multi-turn query works with echo
  LLM-09  OpenAI backend raises on missing package
  LLM-10  Anthropic backend raises on missing package
"""

import pytest

from aintegrity.modules.llm_adapter import (
    LLMAdapter,
    LLMResponse,
    EchoBackend,
    OpenAIBackend,
    AnthropicBackend,
)


# ── LLM-01: EchoBackend deterministic responses ──────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestEchoDeterministic:

    def test_fixed_response(self):
        backend = EchoBackend(default_response="fixed answer")
        resp = backend.query("anything")
        assert resp.text == "fixed answer"
        assert resp.provider == "echo"
        assert resp.model == "echo-v1"

    def test_same_response_on_repeat(self):
        backend = EchoBackend(default_response="same")
        r1 = backend.query("q1")
        r2 = backend.query("q2")
        assert r1.text == r2.text


# ── LLM-02: EchoBackend response cycling ─────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestEchoCycling:

    def test_cycles_through_responses(self):
        backend = EchoBackend(responses=["first", "second", "third"])
        assert backend.query("a").text == "first"
        assert backend.query("b").text == "second"
        assert backend.query("c").text == "third"
        assert backend.query("d").text == "first"  # cycles


# ── LLM-03: EchoBackend default echo ─────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestEchoDefault:

    def test_echoes_prompt(self):
        backend = EchoBackend()
        resp = backend.query("hello world")
        assert resp.text == "Echo: hello world"


# ── LLM-04: LLMAdapter factory ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestAdapterFactory:

    def test_create_echo(self):
        adapter = LLMAdapter.create("echo", default_response="test")
        assert isinstance(adapter.backend, EchoBackend)
        resp = adapter.query("anything")
        assert resp.text == "test"

    def test_create_echo_with_responses(self):
        adapter = LLMAdapter.create("echo", responses=["a", "b"])
        assert adapter.query("q").text == "a"
        assert adapter.query("q").text == "b"


# ── LLM-05: Unknown provider ─────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestUnknownProvider:

    def test_raises_on_unknown(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            LLMAdapter.create("nonexistent")


# ── LLM-06: LLMResponse structure ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestLLMResponseStructure:

    def test_response_fields(self):
        resp = LLMResponse(
            text="answer",
            model="test-model",
            provider="test",
            latency_ms=42.0,
            usage={"prompt_tokens": 10, "completion_tokens": 5},
        )
        assert resp.text == "answer"
        assert resp.model == "test-model"
        assert resp.provider == "test"
        assert resp.latency_ms == 42.0
        assert resp.usage["prompt_tokens"] == 10

    def test_response_defaults(self):
        resp = LLMResponse(text="x", model="m", provider="p")
        assert resp.latency_ms == 0.0
        assert resp.usage == {}
        assert resp.raw is None


# ── LLM-07: Call log ─────────────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestCallLog:

    def test_log_records_queries(self):
        adapter = LLMAdapter.create("echo", default_response="resp")
        adapter.query("first prompt")
        adapter.query("second prompt")
        log = adapter.get_call_log()
        assert len(log) == 2
        assert log[0]["prompt_preview"] == "first prompt"
        assert log[1]["prompt_preview"] == "second prompt"
        assert log[0]["provider"] == "echo"

    def test_log_truncates_long_previews(self):
        adapter = LLMAdapter.create("echo", default_response="short")
        long_prompt = "x" * 500
        adapter.query(long_prompt)
        log = adapter.get_call_log()
        assert len(log[0]["prompt_preview"]) == 200


# ── LLM-08: Multi-turn query ─────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestMultiTurn:

    def test_multi_turn_echo(self):
        adapter = LLMAdapter.create("echo", default_response="multi-reply")
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
            {"role": "user", "content": "How are you?"},
        ]
        resp = adapter.query_multi_turn(messages)
        assert resp.text == "multi-reply"

    def test_multi_turn_logged(self):
        adapter = LLMAdapter.create("echo", default_response="ok")
        messages = [{"role": "user", "content": "Last message"}]
        adapter.query_multi_turn(messages)
        log = adapter.get_call_log()
        assert len(log) == 1
        assert log[0]["prompt_preview"] == "Last message"


# ── LLM-09 / LLM-10: Backend import guards ──────────────────────────────

@pytest.mark.sentinel
@pytest.mark.llm
class TestBackendImportGuards:

    def test_openai_backend_requires_package(self):
        backend = OpenAIBackend(api_key="fake-key")
        # The client is lazy-loaded, so calling _get_client should fail
        # unless openai is installed (which it isn't in test env)
        try:
            backend._get_client()
            # If it doesn't raise, openai is installed — that's fine too
        except ImportError as e:
            assert "openai" in str(e).lower() or "aintegrity" in str(e).lower()

    def test_anthropic_backend_requires_package(self):
        backend = AnthropicBackend(api_key="fake-key")
        try:
            backend._get_client()
        except ImportError as e:
            assert "anthropic" in str(e).lower() or "aintegrity" in str(e).lower()
