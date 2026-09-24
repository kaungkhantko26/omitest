import asyncio

import httpx
import pytest

from ai.connector import KMN_AI_Connector, _chat_completions_url


def test_cloud_provider_aliases_and_endpoints(monkeypatch):
    key = "provider-test-key-123456"
    deepseek = KMN_AI_Connector(provider="api", api_key=key, api_model="deepseek-chat")
    assert deepseek.provider == "deepseek"
    assert "deepseek.com" in deepseek.api_urls["deepseek"]

    openai = KMN_AI_Connector(provider="openai", api_key=key, api_model="gpt-4o-mini")
    assert openai.provider == "openai"
    assert openai.api_model == "gpt-4o-mini"
    assert "openai.com" in openai.api_urls["openai"]

    claude = KMN_AI_Connector(provider="claude", api_key=key)
    assert claude.provider == "anthropic"
    assert "anthropic.com" in claude.api_urls["anthropic"]

    router = KMN_AI_Connector(provider="openrouter", api_key=key)
    assert router.provider == "openrouter"
    assert router.api_model == "openai/gpt-4o-mini"
    assert "openrouter.ai" in router.api_urls["openrouter"]


def test_none_provider_does_not_make_network_calls():
    connector = KMN_AI_Connector(provider="none")
    assert connector.provider == "none"


def test_openai_compatible_provider_normalizes_base_url(monkeypatch):
    monkeypatch.setenv("COMPATIBLE_BASE_URL", "https://example.test/v1/")
    connector = KMN_AI_Connector(
        provider="compatible", api_key="compatible-test-key-123456", api_model="gpt-5.4"
    )
    assert connector.provider == "compatible"
    assert connector.api_urls["compatible"] == "https://example.test/v1/chat/completions"
    assert connector.api_model == "gpt-5.4"


def test_openai_compatible_url_validation():
    assert _chat_completions_url("https://example.test/v1/chat/completions") == (
        "https://example.test/v1/chat/completions"
    )
    with pytest.raises(ValueError):
        _chat_completions_url("example.test/v1")
    with pytest.raises(ValueError):
        _chat_completions_url("https://user:secret@example.test/v1")


def test_compatible_request_falls_back_to_minimal_payload():
    seen = []

    def handler(request):
        body = __import__("json").loads(request.content)
        seen.append(body)
        if "temperature" in body:
            return httpx.Response(400, json={"error": {"message": "unsupported temperature"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "OK"}}]})

    connector = KMN_AI_Connector(
        provider="compatible", api_key="compatible-test-key-123456",
        api_model="gpt-5.4", api_base_url="https://example.test/v1",
    )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await connector._post_api(
                client,
                {"model": "gpt-5.4", "messages": [], "temperature": 0.2, "max_tokens": 20},
                {"Authorization": "Bearer test"},
            )

    response = asyncio.run(run())
    assert response.status_code == 200
    assert len(seen) == 2
    assert "temperature" not in seen[1]
    assert "max_tokens" not in seen[1]
