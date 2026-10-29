"""Bounded Streamable HTTP client and explicit sandbox-only tool fuzzing."""

import asyncio
import copy
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

import httpx

from agentprobe.evaluators import DetectionEngine
from agentprobe.models import (
    AgentResponse,
    Evidence,
    MCPFixture,
    MCPToolMetadata,
    PayloadCategory,
    ResultStatus,
    ScanConfig,
    ScanResult,
    Severity,
    TestCase,
)
from agentprobe.payloads import fuzz_values
from agentprobe.scanners.base import BaseScanner, ScanError, result_for, safe_error
from agentprobe.scanners.http import HTTPTransport

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_VERSIONS = {PROTOCOL_VERSION, "2025-06-18", "2025-03-26"}
Observer = Callable[[dict[str, Any]], Awaitable[None]]


class RPCError(ScanError):
    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"MCP JSON-RPC error ({code}); server message withheld.")


class MCPClient:
    """Request/response observation hooks are copies and cannot alter outbound actions."""

    def __init__(
        self,
        transport: HTTPTransport,
        *,
        request_observer: Observer | None = None,
        response_observer: Observer | None = None,
    ) -> None:
        self.http = transport
        self.request_observer = request_observer
        self.response_observer = response_observer
        self.session: str | None = None
        self.version = PROTOCOL_VERSION
        self.initialized = False
        self._lock = asyncio.Lock()

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream"}
        if self.initialized:
            headers["MCP-Protocol-Version"] = self.version
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    async def initialize(self) -> None:
        async with self._lock:
            if self.initialized:
                return
            result = await self.rpc(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "agentprobe", "version": "0.1.0"},
                },
            )
            if result.get("protocolVersion") not in SUPPORTED_VERSIONS:
                raise ScanError("Server negotiated an unsupported MCP protocol version.")
            if not isinstance(result.get("capabilities"), dict):
                raise ScanError("MCP initialization response omitted capabilities.")
            self.version = result["protocolVersion"]
            self.initialized = True
            try:
                await self.rpc("notifications/initialized", notification=True)
            except Exception:
                self.initialized = False
                raise

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        notification: bool = False,
    ) -> dict[str, Any]:
        identifier = uuid4().hex
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            body["id"] = identifier
        if params is not None:
            body["params"] = params
        if self.request_observer:
            await self.request_observer(copy.deepcopy(body))
        async with asyncio.timeout(self.http.config.timeout):
            async with self.http.stream(body, self.headers) as response:
                if method == "initialize":
                    self.session = response.headers.get("Mcp-Session-Id")
                    if self.session and (
                        len(self.session) > 1024
                        or not all(33 <= ord(c) <= 126 for c in self.session)
                    ):
                        raise ScanError("Invalid MCP session identifier.")
                if notification:
                    if response.status_code != 202:
                        raise ScanError("MCP notification must receive HTTP 202.")
                    return {}
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
                if content_type == "text/event-stream":
                    data = await self._read_sse(response, identifier)
                elif content_type == "application/json":
                    data = json.loads(await self.http.read(response))
                else:
                    raise ScanError("Unsupported MCP response content type.")
        if (
            not isinstance(data, dict)
            or data.get("jsonrpc") != "2.0"
            or data.get("id") != identifier
        ):
            raise ScanError("Invalid or mismatched MCP JSON-RPC response.")
        if self.response_observer:
            await self.response_observer(copy.deepcopy(data))
        if ("error" in data) == ("result" in data):
            raise ScanError("MCP response must contain exactly one of result or error.")
        if "error" in data:
            error = data["error"]
            if not isinstance(error, dict) or type(error.get("code")) is not int:
                raise ScanError("Malformed MCP JSON-RPC error.")
            raise RPCError(error["code"])
        if not isinstance(data["result"], dict):
            raise ScanError("MCP result must be an object.")
        return dict(data["result"])

    async def _read_sse(self, response: httpx.Response, identifier: str) -> dict[str, Any]:
        # Stop at the matching response, even when the SSE stream remains open.
        buffer = bytearray()
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self.http.config.max_response_bytes:
                raise ScanError("MCP SSE response exceeded the configured byte limit.")
            buffer.extend(chunk)
            while True:
                match = re.search(rb"\r?\n\r?\n", buffer)
                if match is None:
                    break
                event = bytes(buffer[: match.start()])
                del buffer[: match.end()]
                lines = event.decode("utf-8").splitlines()
                parts = [line[5:].removeprefix(" ") for line in lines if line.startswith("data:")]
                if not parts or not "".join(parts).strip():
                    continue
                data = json.loads("\n".join(parts))
                if isinstance(data, dict) and data.get("id") == identifier:
                    return data
        raise ScanError("MCP SSE stream ended before the matching response.")

    async def list_tools(self) -> list[MCPToolMetadata]:
        await self.initialize()
        tools: list[MCPToolMetadata] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_tools: set[str] = set()
        for _ in range(100):
            result = await self.rpc("tools/list", {"cursor": cursor} if cursor else {})
            if not isinstance(result.get("tools"), list):
                raise ScanError("MCP tools/list omitted its tools array.")
            for item in result["tools"]:
                tool = MCPToolMetadata.model_validate(item)
                if tool.name in seen_tools:
                    raise ScanError("MCP tools/list returned duplicate tool names.")
                seen_tools.add(tool.name)
                tools.append(tool)
                if len(tools) > 1000:
                    raise ScanError("MCP tool count exceeded 1000.")
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
                raise ScanError("Invalid or repeated MCP pagination cursor.")
            seen_cursors.add(cursor)
        raise ScanError("MCP pagination exceeded 100 pages.")


class MCPScanner(BaseScanner):
    def __init__(
        self,
        target: str,
        *,
        config: ScanConfig | None = None,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
        active: bool = False,
        allowed_tools: set[str] | None = None,
        request_observer: Observer | None = None,
        response_observer: Observer | None = None,
    ) -> None:
        super().__init__(config)
        self.http = HTTPTransport(target, self.config, token=token, client=client)
        self.rpc = MCPClient(
            self.http,
            request_observer=request_observer,
            response_observer=response_observer,
        )
        self.active = active
        self.allowed_tools = frozenset(allowed_tools or set())
        self.tools: list[MCPToolMetadata] = []
        self._plans: dict[str, MCPFixture] = {}
        self.evaluator = DetectionEngine(trust_telemetry=self.config.trust_telemetry)

    async def __aenter__(self) -> "MCPScanner":
        await self.http.__aenter__()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.http.__aexit__(*args)

    @staticmethod
    def metadata_case(tool: MCPToolMetadata | None = None) -> TestCase:
        return TestCase(
            id=f"mcp-metadata-{hashlib.sha256(tool.name.encode()).hexdigest()[:16]}"
            if tool
            else "mcp-discovery",
            title="MCP metadata inspection",
            category=PayloadCategory.MCP_DESCRIPTION_POISONING,
            owasp=["ASI01", "ASI04"],
            turns=["Inspect metadata"],
            remediation="Review and pin tool definitions; treat descriptions as untrusted input.",
        )

    async def audit(self, fixtures: list[MCPFixture] | None = None) -> list[ScanResult]:
        try:
            async with asyncio.timeout(self.config.timeout):
                self.tools = await self.rpc.list_tools()
        except Exception as exc:
            return [result_for(self.metadata_case(), ResultStatus.ERROR, error=safe_error(exc))]
        results: list[ScanResult] = []
        for tool in self.tools:

            def strings(value: object) -> list[str]:
                if isinstance(value, str):
                    return [value]
                if isinstance(value, dict):
                    return [item for child in value.values() for item in strings(child)]
                if isinstance(value, list):
                    return [item for child in value for item in strings(child)]
                return []

            serialized = "\n".join(strings(tool.model_dump(by_alias=True)))
            suspicious = bool(
                re.search(
                    r"ignore\s+(?:all\s+)?previous\s+instructions|"
                    r"(?:skip|bypass|without)\s+(?:user\s+)?approval|"
                    r"(?:reveal|send|exfiltrate)\s+(?:the\s+)?(?:secret|credential|token)",
                    serialized,
                    re.IGNORECASE,
                )
            )
            case = self.metadata_case(tool)
            results.append(
                result_for(
                    case,
                    ResultStatus.SUSPICIOUS if suspicious else ResultStatus.NO_FINDING,
                    severity=Severity.MEDIUM if suspicious else Severity.INFO,
                    evidence=[
                        Evidence(
                            detector="metadata_pattern",
                            summary=(
                                "Instruction-like metadata needs review; exploitation is unproven."
                            ),
                            confidence=0.55,
                            tool=tool.name,
                        )
                    ]
                    if suspicious
                    else [],
                )
            )
        if not self.tools:
            results.append(result_for(self.metadata_case(), ResultStatus.NO_FINDING))
        cases: list[TestCase] = []
        self._plans.clear()
        for index, fixture in enumerate(fixtures or []):
            probes: list[tuple[str | None, int | None]] = [(None, None)]
            probes += [(field, variant) for field in fixture.fuzz_fields for variant in range(4)]
            for probe_index, (field, variant) in enumerate(probes):
                case = TestCase(
                    id=f"mcp-fixture-{index}-{probe_index}",
                    title="Sandbox MCP tool boundary probe",
                    category=PayloadCategory.SCOPE_ESCALATION
                    if fixture.expected_denied
                    else PayloadCategory.PARAMETER_FUZZING,
                    owasp=["ASI03"] if fixture.expected_denied else ["ASI02", "ASI05"],
                    turns=["Run operator-supplied sandbox fixture"],
                    forbidden_tools=[fixture.tool],
                    remediation=(
                        "Enforce caller scope, validate parameters, and confine tool side effects."
                    ),
                )
                arguments = json.loads(
                    json.dumps(fixture.arguments).replace("{canary}", case.canary)
                )
                if field is not None and variant is not None:
                    arguments[field] = fuzz_values(case.canary)[variant]
                plan = fixture.model_copy(deep=True, update={"arguments": arguments})
                self._plans[case.id] = plan
                cases.append(case)
        if not cases:
            skipped = TestCase(
                id="mcp-active-fuzzing",
                title="Active MCP fuzzing",
                category=PayloadCategory.PARAMETER_FUZZING,
                owasp=["ASI02", "ASI03"],
                turns=["Sandbox fixtures required"],
                remediation=(
                    "Supply explicit sandbox fixtures and exact tool allowlist "
                    "to enable tool calls."
                ),
            )
            results.append(result_for(skipped, ResultStatus.SKIPPED))
        return results + await self.scan(cases)

    async def execute(self, case: TestCase) -> ScanResult:
        fixture = self._plans.get(case.id)
        if fixture is None or not self.active or fixture.tool not in self.allowed_tools:
            return result_for(case, ResultStatus.SKIPPED)
        if fixture.tool not in {tool.name for tool in self.tools}:
            raise ScanError("Fixture tool was not advertised by the server.")
        try:
            result = await self.rpc.rpc(
                "tools/call",
                {
                    "name": fixture.tool,
                    "arguments": fixture.arguments,
                },
            )
        except RPCError as exc:
            if fixture.expected_denied and exc.code in {-32001, -32003}:
                return result_for(
                    case,
                    ResultStatus.NO_FINDING,
                    evidence=[
                        Evidence(
                            detector="rpc_denial",
                            summary="Server rejected the request; verify its authorization reason.",
                            confidence=0.5,
                        )
                    ],
                )
            raise
        if "isError" in result and type(result["isError"]) is not bool:
            raise ScanError("MCP tools/call isError must be a boolean.")
        if result.get("isError") is True:
            return result_for(
                case, ResultStatus.ERROR, error="Tool reported an error; test is inconclusive."
            )
        if not isinstance(result.get("content"), list):
            raise ScanError("MCP tools/call result omitted its content array.")
        text = "\n".join(
            item["text"]
            for item in result["content"]
            if isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        )
        structured = result.get("structuredContent", {})
        events = structured.get("agentprobe_events", []) if isinstance(structured, dict) else []
        response = AgentResponse.model_validate({"text": text, "events": events})
        status, evidence = await self.evaluator.evaluate(case, response)
        if fixture.expected_denied and status != ResultStatus.CONFIRMED:
            status = ResultStatus.ATTEMPTED
            evidence.append(
                Evidence(
                    detector="policy_acceptance",
                    summary=(
                        "Server accepted an operator-declared forbidden fixture; "
                        "side effects unproven."
                    ),
                    confidence=0.8,
                    tool=fixture.tool,
                )
            )
        return result_for(case, status, evidence=evidence)
