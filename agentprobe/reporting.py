"""Literal terminal output and atomic, owner-readable JSON reports."""

import os
import tempfile
from pathlib import Path

from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentprobe.models import ResultStatus, VulnerabilityReport


def write_report(report: BaseModel, path: Path) -> None:
    # A temporary sibling permits atomic replacement; mkstemp uses mode 0600.
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(report.model_dump_json(indent=2) + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def render_report(report: VulnerabilityReport, console: Console) -> None:
    table = Table(title="AgentProbe scan results", expand=True)
    for heading in ("Test", "Status", "Severity", "OWASP", "Remediation"):
        table.add_column(heading, overflow="fold")
    for result in report.results:
        table.add_row(
            Text(result.title),
            Text(result.status.value),
            Text(result.severity.value),
            Text(", ".join(result.owasp)),
            Text(result.remediation),
        )
    console.print(table)
    console.print(Text(" | ".join(f"{name}: {count}" for name, count in report.counts.items())))
    for result in report.results:
        if result.error:
            console.print(Text(f"{result.test_id}: {result.error}"))
    for limitation in report.limitations:
        console.print(Text(f"Note: {limitation}"))


def exit_code(report: VulnerabilityReport) -> int:
    if any(result.status == ResultStatus.ERROR or result.error for result in report.results):
        return 2
    if any(
        result.status
        in {
            ResultStatus.SUSPICIOUS,
            ResultStatus.ATTEMPTED,
            ResultStatus.CONFIRMED,
        }
        for result in report.results
    ):
        return 1
    return 0
