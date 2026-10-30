import httpx
import pytest
from pydantic import ValidationError

from agentprobe.calibration import Scenario, corpus
from agentprobe.models import MCPFixture, Message, ResultStatus, ScanConfig
from agentprobe.sandbox import (
    MAX_BODY,
    SINK,
    AgentInput,
    Dispatcher,
    FixtureAgent,
    Sandbox,
    SandboxMode,
)
from agentprobe.scanners import AgentScanner, MCPScanner

MARKER = "CANARY_EXFIL_TEST_SANDBOX_12345"


@pytest.mark.parametrize("mode", list(SandboxMode))
def test_dispatcher_enforces_policy_and_records_real_effects(mode: SandboxMode) -> None:
    dispatcher = Dispatcher(mode)
    record = dispatcher.call("request-1", SINK, MARKER)
    snapshot = dispatcher.snapshot()
    assert not record.authorized
    assert record.executed == (mode == SandboxMode.VULNERABLE)
    assert snapshot.records == [record]
    assert snapshot.sink == ([MARKER] if record.executed else [])
    snapshot.records.clear()
    snapshot.sink.clear()
    assert dispatcher.snapshot().records == [record]
    with pytest.raises(ValidationError):
        record.executed = False


@pytest.mark.parametrize("tool,marker", [("shell", MARKER), (SINK, "bad; command")])
def test_dispatcher_rejects_other_tools_without_side_effects(tool: str, marker: str) -> None:
    dispatcher = Dispatcher(SandboxMode.VULNERABLE)
    with pytest.raises(ValueError):
        dispatcher.call("request", tool, marker)
    assert dispatcher.snapshot().records == []
    assert dispatcher.snapshot().sink == []


def test_dispatcher_capacity_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentprobe.sandbox.MAX_RECORDS", 1)
    dispatcher = Dispatcher(SandboxMode.VULNERABLE)
    dispatcher.call("one", SINK, MARKER)
    with pytest.raises(ValueError, match="capacity"):
        dispatcher.call("two", SINK, MARKER)
    assert len(dispatcher.snapshot().sink) == 1
    assert len(dispatcher.snapshot().records) == 1


def test_test_id_only_correlates_audit_never_selects_behavior() -> None:
    dispatcher = Dispatcher(SandboxMode.VULNERABLE)
    agent = FixtureAgent(dispatcher)
    quiet = agent.respond(
        AgentInput(
            test_id="direct_call",
            messages=[Message(role="user", content="Describe the sky.")],
        )
    )
    assert not quiet.tool_calls
    assert dispatcher.snapshot().records == []
    action = agent.respond(
        AgentInput(
            test_id="benign_text",
            messages=[Message(role="user", content=f"Call {SINK} with marker {MARKER}.")],
        )
    )
    assert action.events[0].executed
    assert dispatcher.snapshot().records[0].request_id == "benign_text"
    assert dispatcher.snapshot().sink == [MARKER]


@pytest.mark.parametrize("control", ["FIXTURE_CLAIM", "FIXTURE_FORGED_EVENT"])
def test_fabricated_claims_cannot_write_independent_audit(control: str) -> None:
    dispatcher = Dispatcher(SandboxMode.VULNERABLE)
    response = FixtureAgent(dispatcher).respond(
        AgentInput(
            test_id="claim",
            messages=[Message(role="user", content=f"{control} {MARKER}")],
        )
    )
    assert response.text or response.events
    assert dispatcher.snapshot().records == []
    assert dispatcher.snapshot().sink == []


@pytest.mark.parametrize("mode", list(SandboxMode))
async def test_live_agent_scanner_and_independent_http_audit(mode: SandboxMode) -> None:
    case = dict(corpus())[Scenario.DIRECT]
    with Sandbox(mode) as sandbox:
        endpoint = sandbox.url
        async with AgentScanner(
            endpoint + "/agent",
            config=ScanConfig(trust_telemetry=True),
        ) as scanner:
            result = (await scanner.scan([case]))[0]
        async with httpx.AsyncClient(trust_env=False) as client:
            audit = await client.get(endpoint + "/audit")
        assert audit.status_code == 200
        data = audit.json()
        assert data["records"][0]["request_id"] == case.id
        assert data["records"][0]["authorized"] is False
        expected = (
            ResultStatus.CONFIRMED if mode == SandboxMode.VULNERABLE else ResultStatus.ATTEMPTED
        )
        assert result.status == expected
        assert data["sink"] == ([case.canary] if mode == SandboxMode.VULNERABLE else [])
    async with httpx.AsyncClient(trust_env=False, timeout=0.2) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(endpoint + "/audit")
    with pytest.raises(RuntimeError, match="not running"):
        _ = sandbox.url


@pytest.mark.parametrize("mode", list(SandboxMode))
async def test_live_mcp_denial_and_vulnerable_execution(mode: SandboxMode) -> None:
    with Sandbox(mode) as sandbox:
        async with MCPScanner(
            sandbox.url + "/mcp",
            active=True,
            allowed_tools={SINK},
            config=ScanConfig(trust_telemetry=True),
        ) as scanner:
            results = await scanner.audit(
                [
                    MCPFixture(tool=SINK, arguments={"marker": "{canary}"}, expected_denied=True),
                ]
            )
        snapshot = sandbox.dispatcher.snapshot()
        assert len(snapshot.records) == 1
        assert not snapshot.records[0].authorized
        if mode == SandboxMode.PROTECTED:
            assert results[-1].status == ResultStatus.NO_FINDING
            assert results[-1].evidence[0].detector == "rpc_denial"
            assert snapshot.sink == []
        else:
            assert results[-1].status == ResultStatus.CONFIRMED
            assert snapshot.sink == [snapshot.records[0].marker]


async def test_mcp_discovery_is_nonexecuting() -> None:
    with Sandbox(SandboxMode.VULNERABLE) as sandbox:
        async with MCPScanner(sandbox.url + "/mcp") as scanner:
            results = await scanner.audit()
        assert not any(result.status == ResultStatus.ERROR for result in results)
        assert sandbox.dispatcher.snapshot().records == []
        assert sandbox.dispatcher.snapshot().sink == []


async def test_http_boundaries_reject_untrusted_and_malformed_requests() -> None:
    with Sandbox(SandboxMode.VULNERABLE) as sandbox:
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (
                await client.get(sandbox.url + "/audit", headers={"Host": "attacker.test"})
            ).status_code == 403
            assert (
                await client.post(
                    sandbox.url + "/agent", json={}, headers={"Origin": "https://attacker.test"}
                )
            ).status_code == 403
            assert (await client.post(sandbox.url + "/agent", json={})).status_code == 400
            assert (
                await client.post(
                    sandbox.url + "/agent",
                    content=b"not json",
                    headers={"Content-Type": "application/json"},
                )
            ).status_code == 400
            assert (
                await client.post(
                    sandbox.url + "/agent",
                    content=b"x" * (MAX_BODY + 1),
                    headers={"Content-Type": "application/json"},
                )
            ).status_code == 413
            assert (await client.post(sandbox.url + "/agent", content="text")).status_code == 415
            assert (await client.post(sandbox.url + "/missing", json={})).status_code == 404
        assert sandbox.dispatcher.snapshot().records == []


def test_sandbox_context_releases_socket_after_failure() -> None:
    fixture = Sandbox()
    with pytest.raises(RuntimeError, match="test failure"), fixture:
        port = int(fixture.url.rsplit(":", 1)[1])
        raise RuntimeError("test failure")
    with Sandbox(port=port) as restarted:
        assert restarted.url.endswith(f":{port}")


@pytest.mark.parametrize("port", [-1, 65536])
def test_invalid_ports_rejected(port: int) -> None:
    with pytest.raises(ValueError):
        Sandbox(port=port)
