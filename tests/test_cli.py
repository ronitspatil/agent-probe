import json
import stat

from typer.testing import CliRunner

from agentprobe.cli import app
from agentprobe.models import VulnerabilityReport

runner = CliRunner()


def test_demo_reports_attempt_without_network(tmp_path):
    output = tmp_path / "demo.json"
    result = runner.invoke(app, ["demo", "--output", str(output)])
    assert result.exit_code == 1, result.output
    report = VulnerabilityReport.model_validate_json(output.read_text())
    assert report.counts["attempted"] == 1
    assert report.counts["confirmed"] == 0
    assert report.counts["error"] == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_safe_demo_passes(tmp_path):
    output = tmp_path / "safe.json"
    result = runner.invoke(app, ["demo", "--safe", "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert all(r["status"] == "no_finding" for r in json.loads(output.read_text())["results"])


def test_cli_requires_endpoint():
    assert runner.invoke(app, ["scan"]).exit_code == 2


def test_cli_requires_active_fixture_and_allowlist():
    result = runner.invoke(
        app, ["scan", "--mcp-server", "https://test.invalid/mcp", "--active-mcp"]
    )
    assert result.exit_code == 2
    assert "requires" in result.output


def test_cli_rejects_url_secret_without_printing_it():
    result = runner.invoke(app, ["scan", "--target", "https://user:secret-value@example.test"])
    assert result.exit_code == 2
    assert "secret-value" not in result.output


def test_payload_listing():
    result = runner.invoke(app, ["payloads"])
    assert result.exit_code == 0
    assert "ASI10" in result.output


def test_report_write_failure_is_controlled(tmp_path):
    result = runner.invoke(app, ["demo", "--output", str(tmp_path / "missing" / "report.json")])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
