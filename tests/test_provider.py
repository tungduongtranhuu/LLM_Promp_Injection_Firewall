"""Tests for app/llm/provider.py. Ollama is replaced by httpx.MockTransport."""

import json

import httpx
import pytest

from app.llm.provider import LLMUnavailableError, OllamaProvider, load_system_prompt


def make_provider(handler):
    client = httpx.Client(base_url="http://ollama.test", transport=httpx.MockTransport(handler))
    return OllamaProvider(base_url="http://ollama.test", model="m", embed_model="e", client=client)


def test_chat_payload_and_answer():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "Bonjour"}})

    answer = make_provider(handler).chat([{"role": "user", "content": "Salut"}])
    assert answer == "Bonjour"
    assert seen["path"] == "/api/chat"
    assert seen["body"]["model"] == "m" and seen["body"]["stream"] is False
    assert seen["body"]["options"]["temperature"] == 0
    assert seen["body"]["messages"] == [{"role": "user", "content": "Salut"}]


def test_embed_uses_nomic_task_prefixes():
    inputs = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.url.path == "/api/embed" and body["model"] == "e"
        inputs.append(body["input"])
        return httpx.Response(200, json={"embeddings": [[0.1, 0.2]] * len(body["input"])})

    provider = make_provider(handler)
    assert provider.embed_documents(["a", "b"]) == [[0.1, 0.2], [0.1, 0.2]]
    assert provider.embed_query("q") == [0.1, 0.2]
    assert inputs == [["search_document: a", "search_document: b"], ["search_query: q"]]


def test_embed_empty_list_does_not_call_ollama():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    assert make_provider(handler).embed_documents([]) == []


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)),
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("timeout", request=r)),
        lambda r: httpx.Response(500, json={"error": "boom"}),
        lambda r: httpx.Response(200, content=b"not json"),
        lambda r: httpx.Response(200, json={"message": {}}),
    ],
    ids=["connect", "timeout", "http_500", "bad_json", "no_content"],
)
def test_chat_errors_become_llm_unavailable(handler):
    with pytest.raises(LLMUnavailableError):
        make_provider(handler).chat([{"role": "user", "content": "x"}])


def test_embed_count_mismatch_is_an_error():
    provider = make_provider(lambda r: httpx.Response(200, json={"embeddings": [[1.0]]}))
    with pytest.raises(LLMUnavailableError):
        provider.embed_documents(["a", "b"])


def test_ping():
    assert make_provider(lambda r: httpx.Response(200, json={"models": []})).ping() is True
    down = make_provider(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x", request=r)))
    assert down.ping() is False


def test_system_prompt_treats_documents_as_data():
    prompt = load_system_prompt()
    assert "donnée" in prompt and "acme.fr" in prompt
