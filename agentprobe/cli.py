"""Typer entry points. Authentication values never enter the report."""

import asyncio
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast

import httpx
import typer
from pydantic import TypeAdapter
from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentprobe.calibration import run_calibration
from agentprobe.demo import demo_transport
from agentprobe.evaluators import DetectionEngine, SentenceTransformerProvider
from agentprobe.model_eval import (
    ModelSettings,
    model_corpus,
    preview_request_budget,
    run_model_evaluation,
)
from agentprobe.models import MCPFixture, PayloadCategory, ScanConfig, VulnerabilityReport
from agentprobe.payloads import build_registry
from agentprobe.reporting import exit_code, render_report, write_report
from agentprobe.sandbox import Sandbox, SandboxMode
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


@app.command()
def sandbox(
    mode: Annotated[
        SandboxMode, typer.Option(help="Synthetic authorization enforcement mode.")
    ] = SandboxMode.PROTECTED,
    port: Annotated[
        int, typer.Option(min=0, max=65535, help="Loopback port; 0 selects a free port.")
    ] = 0,
) -> None:
    """Serve a deterministic synthetic agent and MCP fixture on loopback until interrupted."""
    try:
        with Sandbox(mode, port) as fixture:
            console.print(Text(f"Synthetic {mode.value} sandbox: {fixture.url}"))
            console.print(
                "Routes: /agent, /mcp, /audit. All effects stay in memory. Ctrl-C stops it."
            )
            threading.Event().wait()
    except KeyboardInterrupt:
        console.print("Sandbox stopped; disposable state released.")
    except OSError as exc:
        console.print(Text(f"Could not start loopback sandbox ({type(exc).__name__})."))
        raise typer.Exit(2) from exc


@app.command()
def calibrate(
    output: Annotated[Path, typer.Option(help="Synthetic calibration JSON destination.")] = Path(
        "calibration.json"
    ),
) -> None:
    """Measure synthetic boundary detection using real loopback HTTP and independent audit."""
    try:
        report = asyncio.run(run_calibration())
        write_report(report, output)
    except Exception as exc:
        console.print(Text(f"Calibration failed: {safe_error(exc)}"))
        raise typer.Exit(2) from exc
    table = Table(
        "Group", "Dimension", "TP", "FP", "TN", "FN", "Excluded", title="Synthetic calibration"
    )
    for group, metrics in report.metrics.items():
        for dimension, matrix in metrics.items():
            table.add_row(
                group,
                dimension,
                *(
                    str(value)
                    for value in (
                        matrix.tp,
                        matrix.fp,
                        matrix.tn,
                        matrix.fn,
                        matrix.excluded,
                    )
                ),
            )
    console.print(table)
    console.print(
        Text(
            f"{len(report.samples)} samples; {len(report.mismatches)} mismatches "
            f"({report.unexpected_mismatches} unexpected); "
            f"{len(report.incomplete_samples)} incomplete; "
            f"{len(report.integrity_errors)} fixture integrity errors."
        )
    )
    for issue in report.integrity_errors:
        console.print(Text(issue))
    for limitation in report.limitations:
        console.print(Text(limitation))
    console.print(Text(f"Report saved to {output}"))
    raise typer.Exit(report.exit_code)


@app.command("calibrate-model")
def calibrate_model(
    endpoint: Annotated[
        str, typer.Option(help="OpenAI-compatible /chat/completions endpoint URL.")
    ],
    model: Annotated[str, typer.Option(help="Provider model identifier.")],
    output: Annotated[Path, typer.Option(help="Owner-readable JSON report destination.")] = Path(
        "model-calibration.json"
    ),
    execute: Annotated[
        bool,
        typer.Option(help="Send provider requests; without this flag the command is preview-only."),
    ] = False,
    credential_env: Annotated[
        str, typer.Option(help="Environment variable containing provider API credential.")
    ] = "AGENTPROBE_API_KEY",
    temperature: Annotated[float, typer.Option(min=0.0, max=2.0)] = 0.0,
    top_p: Annotated[float, typer.Option(min=0.001, max=1.0)] = 1.0,
    max_tokens: Annotated[int, typer.Option(min=1, max=4096)] = 256,
    seed: Annotated[int | None, typer.Option(min=0, max=2**31 - 1)] = None,
    request_timeout: Annotated[float, typer.Option(min=0.1, max=120.0)] = 30.0,
    max_tool_rounds: Annotated[int, typer.Option(min=0, max=2)] = 1,
    repetitions: Annotated[int, typer.Option(min=1, max=10)] = 1,
    scenario: Annotated[
        list[str] | None, typer.Option(help="Scenario ID; repeat to select more than one.")
    ] = None,
    mode: Annotated[
        SandboxMode, typer.Option(help="Isolated sink enforcement mode: protected or vulnerable.")
    ] = SandboxMode.PROTECTED,
) -> None:
    """Repeat fixed model probes through a local in-memory synthetic sink."""
    selected = scenario or [name for name, _ in model_corpus()]
    available = {name for name, _ in model_corpus()}
    if set(selected) - available:
        raise typer.BadParameter(f"Scenario must be one of: {', '.join(sorted(available))}.")
    if len(selected) != len(set(selected)):
        raise typer.BadParameter("Do not select the same scenario more than once.")
    try:
        settings = ModelSettings(
            endpoint=endpoint,
            model=model,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            seed=seed,
            request_timeout=request_timeout,
            max_tool_rounds=max_tool_rounds,
        )
        max_turns = max(len(dict(model_corpus())[name].turns) for name in selected)
        budget = preview_request_budget(len(selected), repetitions, max_tool_rounds, max_turns)
    except (ValueError, KeyError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(
        Text(
            f"Model: {model}; mode: {mode.value}; samples: {len(selected) * repetitions}; "
            f"maximum provider requests: {budget}; max tokens/request: {max_tokens}; "
            f"maximum generated-token ceiling: {budget * max_tokens}; "
            f"provider timeout/request: {request_timeout:g}s."
        )
    )
    if not execute:
        console.print("Preview only. Add --execute to send requests; provider charges may apply.")
        return
    try:
        token = load_token(credential_env)
        if not token:
            raise ValueError(
                f"Credential environment variable {credential_env!r} is unset or empty."
            )
        report = asyncio.run(
            run_model_evaluation(
                settings,
                token=token,
                scenarios=selected,
                repetitions=repetitions,
                mode=mode,
            )
        )
        write_report(report, output)
    except Exception as exc:
        console.print(Text(f"Model evaluation failed: {safe_error(exc)}"))
        raise typer.Exit(2) from exc
    table = Table("Scenario", "Repeat", "Scanner", "Model Calls", "Dispatcher", "Unauthorized")
    for sample in report.samples:
        table.add_row(
            sample.scenario,
            str(sample.repetition),
            sample.observation.status.value,
            str(sum(len(trace.tool_names) for trace in sample.provider_traces)),
            str(len(sample.oracle_records)),
            str(sum(record.executed and not record.authorized for record in sample.oracle_records)),
        )
    console.print(table)
    console.print(Text(f"Report saved to {output}; metrics: {report.metrics}"))
    if report.metrics["incomplete"]:
        raise typer.Exit(2)
