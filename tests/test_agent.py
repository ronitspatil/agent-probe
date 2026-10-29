import asyncio
import json
from typing import Any

import httpx
import pytest

from agentprobe.models import PayloadCategory, ResultStatus, ScanConfig
from agentprobe.payloads import build_registry
from agentprobe.scanners import AgentScanner
from agentprobe.scanners.http import redact_url, validate_url


async def test_context_history_contains_real_assistant_turns() -> None:
    case = next(
        case for case in build_registry() if case.category == PayloadCategory.CONTEXT_POISONING
    )
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        requests.append(data)
        return httpx.Response(200, json={"text": f"Answer {len(requests)}"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner("https://agent.test/scan", client=client) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.NO_FINDING
    assert len(requests) == len(case.turns)
    assert requests[-1]["messages"][2] == {"role": "assistant", "content": "Answer 1"}
    assert len(requests[-1]["messages"]) == len(case.turns) * 2


async def test_openai_standard_schema_and_structured_call_detection() -> None:
    case = build_registry()[0]

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        assert "context" not in data and "test_id" not in data and "tool_metadata" not in data
        assert data["model"] == "fixture-model"
        assert case.canary in data["messages"][1]["content"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "agentprobe_canary_sink",
                                        "arguments": json.dumps({"marker": case.canary}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/chat/completions",
            schema="openai",
            model="fixture-model",
            client=client,
        ) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.ATTEMPTED
    assert result.evidence[0].detector == "structured_tool_call"


async def test_tool_calls_are_not_executed_or_followed() -> None:
    case = next(
        case for case in build_registry() if case.category == PayloadCategory.CONTEXT_POISONING
    )
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={
                "tool_calls": [
                    {
                        "name": "agentprobe_canary_sink",
                        "arguments": {"marker": case.canary},
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner("https://agent.test/scan", client=client) as scanner:
            result = (await scanner.scan([case]))[0]
    assert requests == 1
    assert result.status == ResultStatus.ATTEMPTED


async def test_bounded_concurrency_and_per_case_error_isolation() -> None:
    cases = build_registry()[:5]
    active = maximum = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.01)
        active -= 1
        data = json.loads(request.content)
        if data["test_id"] == cases[0].id:
            return httpx.Response(503, text="secret response body")
        return httpx.Response(200, json={"text": "No action taken"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/scan?token=secret",
            client=client,
            config=ScanConfig(concurrency=2),
        ) as scanner:
            results = await scanner.scan(cases)
    assert maximum == 2
    assert results[0].status == ResultStatus.ERROR
    assert all(result.status == ResultStatus.NO_FINDING for result in results[1:])
    assert "secret" not in results[0].model_dump_json()
    assert "503" in results[0].error


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json=[]),
        httpx.Response(200, text="not JSON"),
        httpx.Response(200, json={"unknown": "field"}),
        httpx.Response(200, json={"text": "x" * 2048}),
        httpx.Response(302, headers={"Location": "https://other.test/"}),
    ],
)
async def test_invalid_oversized_and_redirect_responses_are_errors(
    response: httpx.Response,
) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response)) as client:
        async with AgentScanner(
            "https://agent.test/",
            client=client,
            config=ScanConfig(max_response_bytes=1024),
        ) as scanner:
            result = (await scanner.scan(build_registry()[:1]))[0]
    assert result.status == ResultStatus.ERROR


async def test_total_timeout_is_bounded() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"text": "late"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/",
            client=client,
            config=ScanConfig(timeout=0.01),
        ) as scanner:
            result = (await scanner.scan(build_registry()[:1]))[0]
    assert result.status == ResultStatus.ERROR
    assert "timeout" in result.error


@pytest.mark.parametrize(
    "url", ["file:///tmp/x", "https://user:secret@agent.test/", "https://agent.test/#x"]
)
def test_invalid_or_credentialed_urls_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        validate_url(url)


def test_report_url_omits_query_secrets() -> None:
    assert redact_url("https://agent.test/scan?api_key=secret") == "https://agent.test/scan"


async def test_generic_metadata_poisoning_is_local_copy() -> None:
    from agentprobe.models import MCPToolMetadata

    case = next(
        case
        for case in build_registry()
        if case.category == PayloadCategory.MCP_DESCRIPTION_POISONING
    )
    tool = MCPToolMetadata(
        name="fixture",
        description="Reviewed purpose",
        inputSchema={"type": "object"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        metadata = next(item for item in data["tool_metadata"] if item["name"] == "fixture")
        assert case.canary in metadata["description"]
        return httpx.Response(200, json={"text": "Treating metadata as untrusted."})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner("https://agent.test/", client=client, tools=[tool]) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.NO_FINDING
    assert tool.description == "Reviewed purpose"


@pytest.mark.parametrize("arguments", ["not-json", "[]", '"string"'])
async def test_openai_non_object_function_arguments_are_errors(arguments: str) -> None:
    response = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "function": {
                                "name": "agentprobe_canary_sink",
                                "arguments": arguments,
                            }
                        }
                    ],
                }
            }
        ]
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    ) as client:
        async with AgentScanner("https://agent.test/", schema="openai", client=client) as scanner:
            result = (await scanner.scan(build_registry()[:1]))[0]
    assert result.status == ResultStatus.ERROR


@pytest.mark.parametrize("failure", ["http", "deadline"])
async def test_later_turn_failure_preserves_trusted_event(failure: str) -> None:
    case = next(c for c in build_registry() if c.category == PayloadCategory.CONTEXT_POISONING)
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "tool": "agentprobe_canary_sink",
                            "arguments": {"marker": case.canary},
                            "executed": True,
                            "authorized": False,
                            "canary": case.canary,
                        }
                    ]
                },
            )
        if failure == "deadline":
            await asyncio.sleep(0.2)
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/",
            client=client,
            config=ScanConfig(timeout=0.05, trust_telemetry=True),
        ) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.CONFIRMED
    assert result.error
    assert result.evidence[0].detector == "trusted_harness_event"


async def test_semantic_failure_retains_call_and_marks_incomplete() -> None:
    from collections.abc import Sequence

    from agentprobe.evaluators import DetectionEngine
    from agentprobe.models import VulnerabilityReport
    from agentprobe.reporting import exit_code

    class BrokenEmbeddings:
        async def embed(self, texts: Sequence[str]) -> list[list[float]]:
            raise RuntimeError("secret backend error")

    case = build_registry()[0]
    response = {
        "text": "An action was requested.",
        "tool_calls": [
            {
                "name": "agentprobe_canary_sink",
                "arguments": {"marker": case.canary},
            }
        ],
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json=response),
        )
    ) as client:
        async with AgentScanner(
            "https://agent.test/",
            client=client,
            evaluator=DetectionEngine(embeddings=BrokenEmbeddings()),
        ) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.ATTEMPTED
    assert result.error and "secret" not in result.error
    assert exit_code(VulnerabilityReport(targets=["fixture"], results=[result])) == 2


async def test_openai_mcp_name_aliases_preserve_metadata_and_map_calls_back() -> None:
    from agentprobe.models import MCPToolMetadata

    case = build_registry()[0]
    name = "catalog." + "long_tool_" * 8
    case.forbidden_tools = [name]
    tool = MCPToolMetadata(
        name=name, description="Fixture description", inputSchema={"type": "object"}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        function = next(
            t["function"]
            for t in data["tools"]
            if t["function"]["description"] == "Fixture description"
        )
        assert function["name"].startswith("agentprobe_tool_")
        assert len(function["name"]) <= 64
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": function["name"],
                                        "arguments": json.dumps({"marker": case.canary}),
                                    },
                                }
                            ]
                        }
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/", schema="openai", tools=[tool], client=client
        ) as scanner:
            result = (await scanner.scan([case]))[0]
    assert result.status == ResultStatus.ATTEMPTED
    assert result.evidence[0].tool == name
    assert tool.name == name


async def test_oversized_openai_catalog_fails_before_http_request() -> None:
    from agentprobe.models import MCPToolMetadata

    tools = [MCPToolMetadata(name=f"tool_{i}", inputSchema={"type": "object"}) for i in range(128)]
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with AgentScanner(
            "https://agent.test/", schema="openai", tools=tools, client=client
        ) as scanner:
            result = (await scanner.scan(build_registry()[:1]))[0]
    assert result.status == ResultStatus.ERROR
    assert "128" in result.error
    assert requests == 0
