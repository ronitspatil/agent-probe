"""Typer entry points. Authentication values never enter the report."""

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast

import httpx
import typer
from pydantic import TypeAdapter
from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentprobe.demo import demo_transport
from agentprobe.evaluators import DetectionEngine, SentenceTransformerProvider
from agentprobe.models import MCPFixture, PayloadCategory, ScanConfig, VulnerabilityReport
from agentprobe.payloads import build_registry
from agentprobe.reporting import exit_code, render_report, write_report
from agentprobe.scanners import AgentScanner, MCPScanner
from agentprobe.scanners.base import safe_error
from agentprobe.scanners.http import redact_url, validate_url

app = typer.Typer(
    no_args_is_help=True, help="Canary-based security tests for agent and MCP sandboxes."
)
console = Console()

LIMITATIONS = [
    "Canary probes are signals, not a comprehensive OWASP security assessment.",
    "Text echoes and semantic similarity do not prove execution; review evidence levels.",
    "Agent endpoints may execute configured tools. Use an isolated, authorized test harness.",
    "PDF vectors contain extracted text; no PDF parser or upload pipeline is exercised.",
]


def load_token(name: str) -> str | None:
    if not name:
        raise ValueError("Token environment variable name must not be empty.")
    return os.environ.get(name)


def load_fixtures(path: Path | None) -> list[MCPFixture]:
    if path is None:
        return []
    if path.stat().st_size > 1_048_576:
        raise ValueError("Fixture file exceeds 1 MiB.")
    fixtures = TypeAdapter(list[MCPFixture]).validate_json(path.read_text(encoding="utf-8"))
    if len(fixtures) > 100 or sum(len(f.fuzz_fields) for f in fixtures) > 100:
        raise ValueError("At most 100 fixtures and 100 total fuzz fields are supported.")
    return fixtures


async def run_scan(
    *,
    target: str | None,
    mcp_server: str | None,
    schema: Literal["generic", "openai"],
    model: str,
    config: ScanConfig,
    categories: list[PayloadCategory],
    token: str | None,
    mcp_token: str | None,
    active_mcp: bool,
    allowed_tools: set[str],
    fixtures: list[MCPFixture],
    semantic_model: str | None,
) -> VulnerabilityReport:
    started = datetime.now(UTC)
    results = []
    tools = []
    if mcp_server:
        async with MCPScanner(
            mcp_server,
            config=config,
            token=mcp_token,
            active=active_mcp,
            allowed_tools=allowed_tools,
        ) as scanner:
            results.extend(await scanner.audit(fixtures))
            tools = scanner.tools
    if target:
        evaluator = DetectionEngine(
            trust_telemetry=config.trust_telemetry,
            embeddings=SentenceTransformerProvider(semantic_model) if semantic_model else None,
        )
        async with AgentScanner(
            target,
            schema=schema,
            model=model,
            config=config,
            token=token,
            evaluator=evaluator,
            tools=tools or None,
        ) as agent:
            cases = [
                case for case in build_registry() if not categories or case.category in categories
            ]
            results.extend(await agent.scan(cases))
    limitations = list(LIMITATIONS)
    if mcp_server:
        limitations.append(
            "MCP supports HTTP revisions 2025-03-26, 2025-06-18 and 2025-11-25; "
            "Metadata inspection does not establish exploitation. "
            "Active calls require sandbox fixtures."
        )
    return VulnerabilityReport(
        started_at=started,
        finished_at=datetime.now(UTC),
        targets=[redact_url(url) for url in (target, mcp_server) if url],
        results=results,
        limitations=limitations,
    )


@app.command()
def scan(
    target: Annotated[str | None, typer.Option(help="Full agent endpoint URL.")] = None,
    mcp_server: Annotated[
        str | None, typer.Option(help="Full MCP Streamable HTTP endpoint URL.")
    ] = None,
    output: Annotated[Path, typer.Option(help="Atomic JSON report destination.")] = Path(
        "report.json"
    ),
    schema: Annotated[
        str, typer.Option(help="Agent request/response schema: generic or openai.")
    ] = "generic",
    model: Annotated[
        str, typer.Option(help="Model name for OpenAI-compatible endpoints.")
    ] = "agentprobe-target",
    category: Annotated[
        list[PayloadCategory] | None, typer.Option(help="Repeat to select agent categories.")
    ] = None,
    concurrency: Annotated[int, typer.Option(min=1, max=64)] = 4,
    timeout: Annotated[float, typer.Option(min=0.1, max=600)] = 30.0,
    max_response_bytes: Annotated[int, typer.Option(min=1024, max=16_777_216)] = 1_048_576,
    active_mcp: Annotated[
        bool, typer.Option(help="Allow sandbox tools/call with exact allowlist and fixtures.")
    ] = False,
    allow_tool: Annotated[
        list[str] | None, typer.Option(help="Exact allowed MCP tool name; repeatable.")
    ] = None,
    fixtures: Annotated[
        Path | None, typer.Option(help="JSON array of operator-supplied MCP fixtures.")
    ] = None,
    trust_telemetry: Annotated[
        bool, typer.Option(help="Trust out-of-band harness execution events.")
    ] = False,
    token_env: Annotated[
        str, typer.Option(help="Environment variable containing agent bearer token.")
    ] = "AGENTPROBE_TOKEN",
    mcp_token_env: Annotated[
        str, typer.Option(help="Environment variable containing MCP bearer token.")
    ] = "AGENTPROBE_MCP_TOKEN",
    semantic_model: Annotated[
        str | None, typer.Option(help="Optional sentence-transformers model (may download). ")
    ] = None,
) -> None:
    """Scan an authorized agent sandbox, MCP server, or both. MCP calls are opt-in."""
    if not target and not mcp_server:
        raise typer.BadParameter("Provide --target or --mcp-server.")
    if schema not in {"generic", "openai"}:
        raise typer.BadParameter("--schema must be generic or openai.")
    if active_mcp and (not mcp_server or not allow_tool or fixtures is None):
        raise typer.BadParameter("--active-mcp requires --mcp-server, --allow-tool and --fixtures.")
    if (allow_tool or fixtures) and not mcp_server:
        raise typer.BadParameter("MCP fixtures and allowlist require --mcp-server.")
    try:
        for url in (target, mcp_server):
            if url:
                validate_url(url)
        parsed_fixtures = load_fixtures(fixtures)
        config = ScanConfig(
            concurrency=concurrency,
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            trust_telemetry=trust_telemetry,
        )
        report = asyncio.run(
            run_scan(
                target=target,
                mcp_server=mcp_server,
                schema=cast(Literal["generic", "openai"], schema),
                model=model,
                config=config,
                categories=category or [],
                token=load_token(token_env),
                mcp_token=load_token(mcp_token_env),
                active_mcp=active_mcp,
                allowed_tools=set(allow_tool or []),
                fixtures=parsed_fixtures,
                semantic_model=semantic_model,
            )
        )
        write_report(report, output)
    except (OSError, ValueError) as exc:
        console.print(
            Text(
                f"Configuration or report error ({type(exc).__name__}); "
                "check options and file paths."
            )
        )
        raise typer.Exit(2) from exc
    except Exception as exc:
        console.print(Text(safe_error(exc)))
        raise typer.Exit(2) from exc
    render_report(report, console)
    console.print(Text(f"Report saved to {output}"))
    raise typer.Exit(exit_code(report))


@app.command()
def demo(
    output: Annotated[Path, typer.Option()] = Path("report-demo.json"),
    safe: Annotated[
        bool, typer.Option(help="Use the refusing fixture instead of the vulnerable fixture.")
    ] = False,
) -> None:
    """Run deterministic offline fixtures; no network or model credentials required."""

    async def run() -> VulnerabilityReport:
        started = datetime.now(UTC)
        async with httpx.AsyncClient(transport=demo_transport(safe=safe)) as client:
            async with AgentScanner("https://agentprobe.invalid/agent", client=client) as scanner:
                results = await scanner.scan(build_registry())
        return VulnerabilityReport(
            started_at=started,
            finished_at=datetime.now(UTC),
            targets=["offline-demo"],
            results=results,
            limitations=["Offline mock demonstration; no real endpoint was tested."],
        )

    try:
        report = asyncio.run(run())
        write_report(report, output)
    except Exception as exc:
        console.print(Text(safe_error(exc)))
        raise typer.Exit(2) from exc
    render_report(report, console)
    raise typer.Exit(exit_code(report))


@app.command()
def payloads() -> None:
    """List built-in test vectors and their OWASP mappings."""
    table = Table("ID", "Category", "OWASP", "Turns")
    for case in build_registry():
        table.add_row(case.id, case.category.value, ", ".join(case.owasp), str(len(case.turns)))
    console.print(table)
