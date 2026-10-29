"""Validated public schemas and explicit evidence levels."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PayloadCategory(StrEnum):
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_ABUSE = "tool_abuse"
    PARAMETER_FUZZING = "parameter_fuzzing"
    PATH_TRAVERSAL = "path_traversal"
    CONTEXT_POISONING = "context_poisoning"
    MCP_DESCRIPTION_POISONING = "mcp_description_poisoning"
    SCOPE_ESCALATION = "scope_escalation"
    SUPPLY_CHAIN = "supply_chain"
    CODE_EXECUTION = "code_execution"
    INTER_AGENT = "inter_agent"
    CASCADING_FAILURE = "cascading_failure"
    TRUST_EXPLOITATION = "trust_exploitation"
    ROGUE_AGENT = "rogue_agent"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResultStatus(StrEnum):
    NO_FINDING = "no_finding"
    SUSPICIOUS = "suspicious"
    ATTEMPTED = "attempted"
    CONFIRMED = "confirmed"
    ERROR = "error"
    SKIPPED = "skipped"


class Message(Schema):
    role: Literal["system", "user", "assistant"]
    content: str


class ExternalContent(Schema):
    source: Literal["web", "database", "pdf_text", "peer", "tool_metadata"]
    text: str


class TestCase(Schema):
    __test__ = False
    id: str = Field(min_length=1, max_length=120)
    title: str
    category: PayloadCategory
    owasp: list[str] = Field(min_length=1)
    severity: Severity = Severity.HIGH
    turns: list[str] = Field(min_length=1)
    external_content: list[ExternalContent] = Field(default_factory=list)
    canary: str = Field(default_factory=lambda: f"CANARY_EXFIL_TEST_{uuid4().hex}")
    forbidden_tools: list[str] = Field(default_factory=lambda: ["agentprobe_canary_sink"])
    expected_action: str = "Send the canary to the unauthorized canary sink"
    remediation: str

    @field_validator("owasp")
    @classmethod
    def validate_owasp(cls, values: list[str]) -> list[str]:
        if any(value not in {f"ASI{i:02}" for i in range(1, 11)} for value in values):
            raise ValueError("OWASP mappings must be ASI01 through ASI10")
        return values

    @field_validator("canary")
    @classmethod
    def validate_canary(cls, value: str) -> str:
        import re

        if not re.fullmatch(r"CANARY_EXFIL_TEST_[A-Za-z0-9_]{5,64}", value):
            raise ValueError("canary must be a safe CANARY_EXFIL_TEST_ marker")
        return value

    def render(self, text: str) -> str:
        return text.replace("{canary}", self.canary)


class ToolCall(Schema):
    name: str
    arguments: dict[str, Any]


class ExecutionEvent(Schema):
    """Only accepted as evidence when operator explicitly trusts the harness telemetry."""

    tool: str
    arguments: dict[str, Any]
    executed: bool
    authorized: bool
    canary: str


class AgentResponse(Schema):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    events: list[ExecutionEvent] = Field(default_factory=list)


class Evidence(Schema):
    detector: str
    summary: str
    confidence: float = Field(ge=0, le=1)
    # Evidence stores markers/tool names, never raw responses or supplied secrets.
    tool: str | None = None
    canary: str | None = None


class ScanResult(Schema):
    test_id: str
    title: str
    category: PayloadCategory
    owasp: list[str]
    status: ResultStatus
    severity: Severity
    remediation: str
    evidence: list[Evidence] = Field(default_factory=list)
    duration_ms: float = Field(default=0, ge=0)
    error: str | None = None


class MCPToolMetadata(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    name: str = Field(min_length=1, max_length=256)
    description: str = ""
    input_schema: dict[str, Any] = Field(alias="inputSchema")
    annotations: dict[str, Any] = Field(default_factory=dict)

    @field_validator("input_schema")
    @classmethod
    def object_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("type") != "object":
            raise ValueError("MCP inputSchema must describe an object")
        return value


class MCPFixture(Schema):
    """Operator-created sandbox fixture; annotations are never an execution grant."""

    tool: str = Field(min_length=1)
    arguments: dict[str, Any]
    fuzz_fields: list[str] = Field(default_factory=list)
    expected_denied: bool = False

    @model_validator(mode="after")
    def validate_fields(self) -> "MCPFixture":
        for field in self.fuzz_fields:
            if field not in self.arguments or not isinstance(self.arguments[field], str):
                raise ValueError("fuzz_fields must name existing top-level string arguments")
        return self


class ScanConfig(Schema):
    concurrency: int = Field(default=4, ge=1, le=64)
    timeout: float = Field(default=30.0, gt=0, le=600)
    max_response_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    trust_telemetry: bool = False


class VulnerabilityReport(Schema):
    schema_version: str = "1.0"
    scanner_version: str = "0.1.0"
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    targets: list[str]
    results: list[ScanResult]
    limitations: list[str] = Field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            status.value: sum(r.status == status for r in self.results) for status in ResultStatus
        }
