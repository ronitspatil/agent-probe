from collections.abc import Sequence

import pytest

from agentprobe.evaluators import DetectionEngine
from agentprobe.evaluators.engine import cosine
from agentprobe.models import AgentResponse, ExecutionEvent, ResultStatus, ToolCall
from agentprobe.payloads import build_registry


@pytest.mark.parametrize("prefix", ["Here is the marker: ", "I refuse to send "])
async def test_echo_or_refusal_is_never_execution(prefix: str) -> None:
    case = build_registry()[0]
    status, evidence = await DetectionEngine().evaluate(
        case, AgentResponse(text=prefix + case.canary)
    )
    assert status == ResultStatus.SUSPICIOUS
    assert evidence[0].confidence < 0.5


async def test_another_cases_marker_is_not_evidence() -> None:
    first, second = build_registry()[:2]
    status, evidence = await DetectionEngine().evaluate(first, AgentResponse(text=second.canary))
    assert status == ResultStatus.NO_FINDING
    assert not evidence


@pytest.mark.parametrize(
    "name,contains,expected",
    [
        ("agentprobe_canary_sink", True, ResultStatus.ATTEMPTED),
        ("approved_summary", True, ResultStatus.NO_FINDING),
        ("agentprobe_canary_sink", False, ResultStatus.NO_FINDING),
    ],
)
async def test_tool_call_requires_name_and_marker(
    name: str,
    contains: bool,
    expected: ResultStatus,
) -> None:
    case = build_registry()[0]
    response = AgentResponse(
        tool_calls=[
            ToolCall(
                name=name,
                arguments={"marker": case.canary if contains else "unrelated"},
            )
        ]
    )
    status, _ = await DetectionEngine().evaluate(case, response)
    assert status == expected


@pytest.mark.parametrize(
    "trusted,authorized,executed,expected",
    [
        (False, False, True, ResultStatus.SUSPICIOUS),
        (True, False, True, ResultStatus.CONFIRMED),
        (True, True, True, ResultStatus.NO_FINDING),
        (True, False, False, ResultStatus.NO_FINDING),
    ],
)
async def test_execution_requires_trusted_unauthorized_event(
    trusted: bool,
    authorized: bool,
    executed: bool,
    expected: ResultStatus,
) -> None:
    case = build_registry()[0]
    response = AgentResponse(
        events=[
            ExecutionEvent(
                tool="agentprobe_canary_sink",
                arguments={"marker": case.canary},
                canary=case.canary,
                executed=executed,
                authorized=authorized,
            )
        ]
    )
    status, _ = await DetectionEngine(trust_telemetry=trusted).evaluate(case, response)
    assert status == expected


class Embeddings:
    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        assert len(texts) == 2
        return [[0.4, 0.9], [0.4, 0.9]]


async def test_semantic_similarity_is_only_heuristic() -> None:
    status, evidence = await DetectionEngine(embeddings=Embeddings()).evaluate(
        build_registry()[0], AgentResponse(text="I completed the requested operation.")
    )
    assert status == ResultStatus.SUSPICIOUS
    assert evidence[0].detector == "semantic_similarity"


@pytest.mark.parametrize("a,b", [([], []), ([1.0], [1.0, 2.0]), ([float("nan")], [1.0])])
def test_invalid_embeddings_rejected(a: list[float], b: list[float]) -> None:
    with pytest.raises(ValueError):
        cosine(a, b)


@pytest.mark.parametrize("mode", ["key_only", "longer_token"])
async def test_argument_keys_and_longer_tokens_do_not_match_canary(mode: str) -> None:
    case = build_registry()[0]
    arguments = (
        {case.canary: "ordinary"} if mode == "key_only" else {"marker": case.canary + "_other"}
    )
    response = AgentResponse(
        tool_calls=[ToolCall(name="agentprobe_canary_sink", arguments=arguments)]
    )
    status, evidence = await DetectionEngine().evaluate(case, response)
    assert status == ResultStatus.NO_FINDING
    assert not evidence


async def test_canary_in_nested_string_value_is_matched() -> None:
    case = build_registry()[0]
    response = AgentResponse(
        tool_calls=[
            ToolCall(
                name="agentprobe_canary_sink",
                arguments={"nested": [{"path": f"agentprobe-fixture/{case.canary}.txt"}]},
            )
        ]
    )
    status, _ = await DetectionEngine().evaluate(case, response)
    assert status == ResultStatus.ATTEMPTED


async def test_execution_event_requires_canary_in_argument_value() -> None:
    case = build_registry()[0]
    response = AgentResponse(
        events=[
            ExecutionEvent(
                tool="agentprobe_canary_sink",
                arguments={case.canary: "ordinary"},
                canary=case.canary,
                executed=True,
                authorized=False,
            )
        ]
    )
    status, _ = await DetectionEngine(trust_telemetry=True).evaluate(case, response)
    assert status == ResultStatus.NO_FINDING
