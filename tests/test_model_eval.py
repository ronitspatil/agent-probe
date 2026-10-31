import json

import httpx
import pytest
from typer.testing import CliRunner

from agentprobe.cli import app
from agentprobe.model_eval import (
    ModelAgent,
    ModelSettings,
    model_corpus,
    preview_request_budget,
    sample_case,
)
from agentprobe.models import ScanConfig
from agentprobe.sandbox import Sandbox, SandboxMode
from agentprobe.scanners import AgentScanner


def settings() -> ModelSettings:
    return ModelSettings(
        endpoint="https://provider.test/v1/chat/completions",
        model="mock-model",
        temperature=0.25,
        top_p=0.8,
        max_tokens=73,
        max_tool_rounds=1,
    )


def completion(*, tool: bool, text: str = "safe final") -> dict[str, object]:
    message: dict[str, object] = {"role": "assistant", "content": text}
    if tool:
        message["tool_calls"] = [
            {
                "id": "call-local-1",
                "type": "function",
                "function": {
                    "name": "agentprobe_canary_sink",
                    "arguments": json.dumps({"marker": "CANARY_EXFIL_TEST_1234567890"}),
                },
            }
        ]
    return {
        "id": "mock-request-id",
        "model": "mock-model-version",
        "choices": [{"message": message, "finish_reason": "tool_calls" if tool else "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3},
    }


@pytest.mark.parametrize("mode", [SandboxMode.PROTECTED, SandboxMode.VULNERABLE])
@pytest.mark.asyncio
async def test_loopback_harness_separates_model_calls_and_dispatcher_truth(mode) -> None:
    case = sample_case("direct_call", dict(model_corpus())["direct_call"], 1, mode)
    calls: list[httpx.Request] = []

    async def provider(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = json.loads(request.content)
        assert body["model"] == "mock-model"
        assert body["temperature"] == 0.25
        assert body["top_p"] == 0.8
        assert body["max_tokens"] == 73
        assert [row["function"]["name"] for row in body["tools"]] == ["agentprobe_canary_sink"]
        assert request.headers["authorization"] == "Bearer mock-secret"
        if len(calls) == 1:
            payload = completion(tool=True)
            payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json.dumps(
                {"marker": case.canary}
            )
        else:
            payload = completion(tool=False)
            assert body["messages"][-1]["role"] == "tool"
            assert body["messages"][-1]["content"] in {
                "Synthetic marker recorded in memory.",
                "Authorization denied by protected fixture.",
            }
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    model = ModelAgent(settings(), "mock-secret", cases={case.id: case.canary}, client=client)
    async with model:
        with Sandbox(mode, agent=model) as sandbox:
            async with AgentScanner(
                sandbox.url + "/agent",
                config=ScanConfig(timeout=5, trust_telemetry=True),
            ) as scanner:
                result = (await scanner.scan([case]))[0]
            snapshot = sandbox.dispatcher.snapshot()
        traces = model.traces[case.id]
    await client.aclose()

    assert len(calls) == len(traces) == 2
    assert traces[0].tool_names == ["agentprobe_canary_sink"]
    assert traces[1].tool_names == []
    assert len(snapshot.records) == 1
    assert snapshot.records[0].executed is (mode == SandboxMode.VULNERABLE)
    assert snapshot.sink == ([case.canary] if mode == SandboxMode.VULNERABLE else [])
    assert case.canary not in json.dumps([trace.model_dump() for trace in traces])
    assert "safe final" not in json.dumps(result.model_dump())


@pytest.mark.asyncio
async def test_unknown_tool_and_wrong_canary_are_attempts_not_dispatches() -> None:
    case = sample_case(
        "direct_call", dict(model_corpus())["direct_call"], 1, SandboxMode.VULNERABLE
    )
    replies = iter(
        [
            {
                "id": "attempt-1",
                "model": "mock",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "one",
                                    "function": {"name": "arbitrary_tool", "arguments": "{}"},
                                },
                                {
                                    "id": "two",
                                    "function": {
                                        "name": "agentprobe_canary_sink",
                                        "arguments": '{"marker":"CANARY_EXFIL_TEST_WRONG0000"}',
                                    },
                                },
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            },
            {
                "choices": [
                    {"message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}
                ]
            },
        ]
    )

    async def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(replies))

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    model = ModelAgent(settings(), "token", cases={case.id: case.canary}, client=client)
    async with model:
        with Sandbox(SandboxMode.VULNERABLE, agent=model) as sandbox:
            async with AgentScanner(
                sandbox.url + "/agent", config=ScanConfig(timeout=5)
            ) as scanner:
                await scanner.scan([case])
            snapshot = sandbox.dispatcher.snapshot()
        trace = model.traces[case.id][0]
    await client.aclose()
    assert trace.tool_names == ["arbitrary_tool", "agentprobe_canary_sink"]
    assert snapshot.records == []
    assert snapshot.sink == []


@pytest.mark.asyncio
async def test_provider_error_is_counted_once_without_leaking_response_or_credential() -> None:
    requests = 0

    async def provider(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        assert request.headers["authorization"] == "Bearer top-secret-value"
        return httpx.Response(503, text="private provider error body")

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    model = ModelAgent(
        settings(), "top-secret-value", cases={"sample": "CANARY_EXFIL_TEST_123456"}, client=client
    )
    async with model:
        with pytest.raises(httpx.HTTPStatusError):
            await model._complete("sample", [{"role": "user", "content": "test"}])
        trace = model.traces["sample"][0]
    await client.aclose()
    assert requests == 1
    assert trace.completed is False
    assert trace.request_id is None
    assert "top-secret-value" not in json.dumps(trace.model_dump())
    assert "private provider error body" not in json.dumps(trace.model_dump())


def test_case_ids_and_canaries_repeat_but_vary_by_repeat_and_mode() -> None:
    base = dict(model_corpus())["direct_call"]
    first = sample_case("direct_call", base, 1, SandboxMode.PROTECTED)
    assert first == sample_case("direct_call", base, 1, SandboxMode.PROTECTED)
    assert first.id != sample_case("direct_call", base, 2, SandboxMode.PROTECTED).id
    assert first.canary != sample_case("direct_call", base, 2, SandboxMode.PROTECTED).canary
    assert first.canary != sample_case("direct_call", base, 1, SandboxMode.VULNERABLE).canary
    assert preview_request_budget(4, 10, 2, 5) == 600


def test_provider_endpoint_requires_tls_except_for_loopback() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        ModelSettings(endpoint="http://provider.example/v1/chat/completions", model="m")
    assert ModelSettings(endpoint="http://127.0.0.1:9000/v1/chat/completions", model="m")
    assert ModelSettings(endpoint="http://localhost/v1/chat/completions", model="m")


def test_calibrate_model_is_preview_only_without_execute(monkeypatch, tmp_path) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("preview must not read credentials or contact a provider")

    monkeypatch.setattr("agentprobe.cli.load_token", unexpected)
    report = tmp_path / "must-not-exist.json"
    result = CliRunner().invoke(
        app,
        [
            "calibrate-model",
            "--endpoint",
            "https://provider.test/v1/chat/completions",
            "--model",
            "mock-model",
            "--scenario",
            "multiturn_drift",
            "--repetitions",
            "2",
            "--output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "maximum provider requests: 20" in result.output
    assert "maximum generated-token ceiling: 5120" in result.output
    assert "Preview only" in result.output
    assert not report.exists()
