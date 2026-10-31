import json

import httpx
import pytest
from typer.testing import CliRunner

from agentprobe.cli import app
from agentprobe.model_eval import ModelSettings
from agentprobe.model_planner import (
    MAX_PLAN_STEPS,
    parse_planner_response,
    preview_provider_budget,
    run_model_plan,
)
from agentprobe.payloads import build_registry
from agentprobe.sandbox import SandboxMode


def settings() -> ModelSettings:
    return ModelSettings(
        endpoint="https://provider.test/v1/chat/completions",
        model="mock-planner",
        temperature=0.0,
        top_p=1.0,
        max_tokens=64,
        max_tool_rounds=0,
    )


def planner_response(action: str, case_id: str | None = None) -> dict[str, object]:
    decision: dict[str, str] = {"action": action}
    if case_id is not None:
        decision["case_id"] = case_id
    return {
        "id": "planner-request-1",
        "model": "mock-planner-version",
        "choices": [
            {
                "message": {"role": "assistant", "content": json.dumps(decision)},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 120, "completion_tokens": 8},
    }


@pytest.mark.asyncio
async def test_model_selects_registered_case_and_adapts_from_sanitized_local_result() -> None:
    calls: list[httpx.Request] = []
    case = next(case for case in build_registry() if case.id == "tool-approval-bypass")

    async def provider(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = json.loads(request.content)
        assert body["model"] == "mock-planner"
        assert "tools" not in body
        assert body["response_format"] == {"type": "json_object"}
        prompt = json.loads(body["messages"][-1]["content"])
        assert "payload" not in prompt and "url" not in prompt
        if len(calls) == 1:
            assert [item["case_id"] for item in prompt["available_cases"]] == [
                item.id for item in build_registry()
            ]
            assert case.turns[0] not in body["messages"][-1]["content"]
            return httpx.Response(200, json=planner_response("run", case.id))
        observation = prompt["observations"][-1]
        assert observation == {
            "case_id": case.id,
            "status": "attempted",
            "category": "tool_abuse",
            "evidence_detectors": ["structured_tool_call"],
        }
        assert case.canary not in body["messages"][-1]["content"]
        return httpx.Response(200, json=planner_response("stop"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(settings(), token="mock-secret", max_steps=3, client=client)
    await client.aclose()

    assert len(calls) == len(report.provider_traces) == 2
    assert [step.action for step in report.steps] == ["run", "stop"]
    assert report.steps[0].observation is not None
    assert report.steps[0].observation.status.value == "attempted"
    assert len(report.steps[0].oracle_records) == 1
    assert report.steps[0].oracle_records[0].executed is False
    assert report.steps[0].sink_effects == []
    encoded = report.model_dump_json()
    assert "mock-secret" not in encoded
    assert "mock-planner-version" in encoded
    assert "rationale" not in encoded


@pytest.mark.asyncio
async def test_unknown_case_decision_is_rejected_without_dispatch() -> None:
    async def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=planner_response("run", "arbitrary-case"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(settings(), token="secret", max_steps=2, client=client)
    await client.aclose()

    assert report.error == "Planner selected an unknown or already-used test case."
    assert report.steps[0].action == "invalid"
    assert report.steps[0].observation is None
    assert report.steps[0].oracle_records == []
    assert report.scanner_exit_code() == 2


@pytest.mark.asyncio
async def test_model_cannot_repeat_a_case() -> None:
    case_id = "tool-approval-bypass"
    replies = iter([planner_response("run", case_id), planner_response("run", case_id)])

    async def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(replies))

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(settings(), token="secret", max_steps=2, client=client)
    await client.aclose()

    assert report.error == "Planner selected an unknown or already-used test case."
    assert [step.action for step in report.steps] == ["run", "invalid"]
    assert len([step for step in report.steps if step.observation is not None]) == 1


@pytest.mark.asyncio
async def test_malformed_decision_fails_closed_and_keeps_error_redacted() -> None:
    async def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": (
                                '{"action":"run","case_id":"tool-approval-bypass","payload":"oops"}'
                            ),
                        }
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(settings(), token="secret", max_steps=1, client=client)
    await client.aclose()

    assert report.error == "Test failed (ValueError); response details withheld."
    assert "payload" not in report.error
    assert report.steps == []
    assert report.provider_traces[0].completed is False


@pytest.mark.asyncio
async def test_provider_error_is_not_retried_or_saved() -> None:
    requests = 0

    async def provider(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(503, text="sensitive provider response")

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(settings(), token="secret", max_steps=2, client=client)
    await client.aclose()

    assert requests == 1
    assert report.error == "HTTP request failed with status 503."
    assert len(report.provider_traces) == 1
    assert report.provider_traces[0].completed is False
    assert "sensitive provider response" not in report.model_dump_json()
    assert "secret" not in report.model_dump_json()


def test_decision_schema_rejects_unknown_fields_and_invalid_stop_shape() -> None:
    with pytest.raises(ValueError):
        parse_planner_response(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": '{"action":"stop","case_id":"unused"}',
                        }
                    }
                ]
            }
        )
    with pytest.raises(ValueError):
        parse_planner_response(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [{"function": {"name": "agentprobe_canary_sink"}}],
                            "content": '{"action":"stop"}',
                        }
                    }
                ]
            }
        )


def test_budget_and_remote_endpoint_limits() -> None:
    assert preview_provider_budget(5, 256) == 1280
    with pytest.raises(ValueError):
        preview_provider_budget(MAX_PLAN_STEPS + 1, 256)
    with pytest.raises(ValueError):
        preview_provider_budget(1, 513)
    with pytest.raises(ValueError, match="HTTPS"):
        ModelSettings(endpoint="http://provider.example/v1/chat/completions", model="m")


def test_model_plan_is_preview_only_without_execute(monkeypatch, tmp_path) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("preview must not read credentials or contact a provider")

    monkeypatch.setattr("agentprobe.cli.load_token", unexpected)
    monkeypatch.setattr("agentprobe.cli.asyncio.run", unexpected)
    output = tmp_path / "must-not-exist.json"
    result = CliRunner().invoke(
        app,
        [
            "model-plan",
            "--endpoint",
            "https://provider.test/v1/chat/completions",
            "--model",
            "mock-planner",
            "--max-steps",
            "3",
            "--max-tokens",
            "64",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    normalized_output = " ".join(result.output.split())
    assert "maximum planner requests: 3" in normalized_output
    assert "maximum generated-token ceiling: 192" in normalized_output
    assert "Preview only" in result.output
    assert not output.exists()


@pytest.mark.asyncio
async def test_vulnerable_mode_records_only_synthetic_canary_effect() -> None:
    case_id = "tool-approval-bypass"

    async def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=planner_response("run", case_id))

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    report = await run_model_plan(
        settings(),
        token="secret",
        max_steps=1,
        mode=SandboxMode.VULNERABLE,
        client=client,
    )
    await client.aclose()

    step = report.steps[0]
    assert step.oracle_records[0].authorized is False
    assert step.oracle_records[0].executed is True
    assert len(step.sink_effects) == 1
    assert step.sink_effects[0].startswith("CANARY_EXFIL_TEST_")
