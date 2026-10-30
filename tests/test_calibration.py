import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agentprobe.calibration import (
    CalibrationReport,
    CalibrationSample,
    OracleFacts,
    Scenario,
    corpus,
    mismatches,
    run_calibration,
    score,
)
from agentprobe.cli import app
from agentprobe.models import ResultStatus
from agentprobe.sandbox import SINK, Dispatcher, SandboxMode
from agentprobe.scanners.base import result_for


def sample(
    identifier: str,
    status: ResultStatus,
    *,
    attempted: bool = False,
    executed: bool = False,
    scenario: Scenario = Scenario.DIRECT,
    error: str | None = None,
) -> CalibrationSample:
    case = dict(corpus())[scenario]
    dispatcher = Dispatcher(SandboxMode.VULNERABLE if executed else SandboxMode.PROTECTED)
    if attempted:
        dispatcher.call(case.id, SINK, case.canary)
    snapshot = dispatcher.snapshot()
    return CalibrationSample(
        id=identifier,
        scenario=scenario,
        mode=dispatcher.mode,
        trust_telemetry=True,
        canary=case.canary,
        observation=result_for(case, status, error=error),
        oracle=OracleFacts(records=snapshot.records, sink_markers=snapshot.sink),
    )


def report(
    samples: list[CalibrationSample], expected: list[str] | None = None
) -> CalibrationReport:
    now = datetime.now(UTC)
    return CalibrationReport(
        started_at=now,
        finished_at=now,
        samples=samples,
        expected_sample_ids=expected if expected is not None else [row.id for row in samples],
    )


def test_corpus_markers_and_ids_repeat_and_are_unique() -> None:
    first, second = corpus(), corpus()
    assert first == second
    assert len(first) == 9
    assert len({case.id for _, case in first}) == 9
    assert len({case.canary for _, case in first}) == 9
    assert len(dict(first)[Scenario.MULTITURN].turns) >= 6


def test_attempt_matrix_accounts_for_every_sample_and_excludes_errors() -> None:
    rows = [
        sample("tp", ResultStatus.ATTEMPTED, attempted=True),
        sample("fp", ResultStatus.CONFIRMED),
        sample("tn", ResultStatus.NO_FINDING),
        sample("fn", ResultStatus.SUSPICIOUS, attempted=True),
        sample("error", ResultStatus.ERROR),
        sample("skipped", ResultStatus.SKIPPED),
        sample(
            "partial", ResultStatus.CONFIRMED, attempted=True, executed=True, error="late error"
        ),
    ]
    matrix = score(rows, "attempt")
    assert (matrix.tp, matrix.fp, matrix.tn, matrix.fn, matrix.excluded) == (1, 1, 1, 1, 3)
    assert matrix.evaluated + matrix.excluded == len(rows)
    assert matrix.precision == matrix.recall == matrix.false_positive_rate == 0.5


def test_execution_labels_are_independent_of_returned_confirmation() -> None:
    rows = [
        sample("actual", ResultStatus.NO_FINDING, attempted=True, executed=True),
        sample("forged", ResultStatus.CONFIRMED, scenario=Scenario.FORGED),
        sample("blocked", ResultStatus.ATTEMPTED, attempted=True),
    ]
    matrix = score(rows, "execution")
    assert (matrix.tp, matrix.fp, matrix.tn, matrix.fn) == (0, 1, 1, 1)
    assert rows[0].oracle.unauthorized_execution
    assert not rows[1].oracle.unauthorized_execution


def test_zero_denominators_are_null_not_perfect_scores() -> None:
    empty = score([], "execution")
    assert empty.evaluated == 0
    assert empty.precision is None and empty.recall is None and empty.false_positive_rate is None
    negative = score([sample("negative", ResultStatus.NO_FINDING)], "execution")
    assert negative.precision is None and negative.recall is None
    assert negative.false_positive_rate == 0


def test_refusal_alert_burden_is_separate_from_execution() -> None:
    row = sample("refusal", ResultStatus.SUSPICIOUS, scenario=Scenario.REFUSAL)
    assert score([row], "triage").fp == 1
    assert score([row], "attempt").tn == 1
    assert score([row], "execution").tn == 1
    mismatch = mismatches([row])[0]
    assert mismatch.dimension == "triage" and mismatch.known_limitation


def test_oracle_requires_audit_and_actual_sink_to_agree() -> None:
    row = sample("executed", ResultStatus.CONFIRMED, attempted=True, executed=True)
    with pytest.raises(ValidationError, match="side effects"):
        OracleFacts(records=row.oracle.records, sink_markers=[])
    with pytest.raises(ValidationError, match="side effects"):
        OracleFacts(records=[], sink_markers=[row.canary])


@pytest.mark.parametrize("expected", [[], ["missing"], ["one", "two"], ["one", "one"]])
def test_manifest_detects_missing_or_duplicate_samples(expected: list[str]) -> None:
    with pytest.raises(ValidationError):
        report([sample("one", ResultStatus.NO_FINDING)], expected)


def test_duplicate_result_ids_rejected() -> None:
    with pytest.raises(ValidationError):
        report([sample("one", ResultStatus.NO_FINDING), sample("one", ResultStatus.NO_FINDING)])


def test_protected_execution_is_a_sandbox_failure() -> None:
    row = sample("bad", ResultStatus.CONFIRMED, attempted=True, executed=True)
    row.mode = SandboxMode.PROTECTED
    invalid = report([row])
    assert invalid.integrity_errors
    assert invalid.exit_code == 1


def test_expected_limitations_remain_in_metrics_and_unexpected_failures_fail_gate() -> None:
    known = sample(
        "hidden", ResultStatus.NO_FINDING, attempted=True, executed=True, scenario=Scenario.HIDDEN
    )
    known_report = report([known])
    assert known_report.metrics["all"]["execution"].fn == 1
    assert known_report.exit_code == 0
    assert len(known_report.mismatches) == 3
    unexpected = sample("unexpected", ResultStatus.CONFIRMED, scenario=Scenario.BENIGN)
    assert report([unexpected]).unexpected_mismatches == 3
    assert report([unexpected]).exit_code == 1
    assert report([sample("incomplete", ResultStatus.ERROR)]).exit_code == 2


async def test_real_http_calibration_exposes_known_false_positives_and_misses() -> None:
    result = await run_calibration()
    assert len(result.samples) == 36
    assert result.exit_code == 0
    assert not result.incomplete_samples
    groups = result.metrics
    assert groups["protected/trusted"]["execution"].fp == 1
    assert groups["vulnerable/trusted"]["execution"].tp == 3
    assert groups["vulnerable/trusted"]["execution"].fn == 1
    assert groups["vulnerable/untrusted"]["execution"].fn == 4
    for row in result.samples:
        if row.mode == SandboxMode.PROTECTED:
            assert not row.oracle.sink_markers
        if row.scenario == Scenario.FORGED:
            assert row.oracle.records == []
            expected = ResultStatus.CONFIRMED if row.trust_telemetry else ResultStatus.SUSPICIOUS
            assert row.observation.status == expected
        if row.scenario == Scenario.REFUSAL:
            assert not row.oracle.attempted
            assert row.observation.status == ResultStatus.SUSPICIOUS
    for metrics in groups.values():
        for matrix in metrics.values():
            assert matrix.evaluated > 0 and matrix.excluded == 0


async def test_metrics_and_markers_repeat_across_independent_servers() -> None:
    first = await run_calibration()
    second = await run_calibration()
    assert [row.id for row in first.samples] == [row.id for row in second.samples]
    assert [row.canary for row in first.samples] == [row.canary for row in second.samples]
    assert first.metrics == second.metrics
    assert first.mismatches == second.mismatches


def test_cli_calibration_writes_private_report_and_reports_limitations(tmp_path: Path) -> None:
    destination = tmp_path / "calibration.json"
    result = CliRunner().invoke(app, ["calibrate", "--output", str(destination)])
    assert result.exit_code == 0, result.output
    data = json.loads(destination.read_text())
    assert len(data["samples"]) == 36
    assert data["metrics"]["all"]["execution"]["fp"] > 0
    assert data["mismatches"]
    assert data["unexpected_mismatches"] == 0
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert "synthetic" in result.output.lower()
    assert "real LLM effectiveness" in " ".join(result.output.split())


def test_cli_bad_output_is_controlled(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["calibrate", "--output", str(tmp_path / "missing" / "x.json")]
    )
    assert result.exit_code == 2
    assert "Traceback" not in result.output


async def test_saved_report_roundtrips_and_derived_values_cannot_override_truth() -> None:
    original = await run_calibration()
    restored = CalibrationReport.model_validate_json(original.model_dump_json())
    assert restored.metrics == original.metrics
    assert restored.mismatches == original.mismatches
    data = json.loads(original.model_dump_json())
    data["metrics"] = {"all": {"execution": {"fp": 0}}}
    data["unexpected_mismatches"] = 0
    data["samples"][0]["oracle"]["attempted"] = False
    data["samples"][0]["oracle"]["unauthorized_execution"] = True
    checked = CalibrationReport.model_validate(data)
    assert checked.metrics == original.metrics
    assert checked.samples[0].oracle.attempted
    assert not checked.samples[0].oracle.unauthorized_execution


def test_missing_fixture_action_is_an_integrity_failure_not_a_good_true_negative() -> None:
    absent = report([sample("absent", ResultStatus.NO_FINDING, scenario=Scenario.DIRECT)])
    assert absent.metrics["all"]["attempt"].tn == 1
    assert absent.integrity_errors
    assert absent.exit_code == 1


async def test_suppressed_dispatches_fail_integrity_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentprobe.models import AgentResponse

    monkeypatch.setattr(
        "agentprobe.sandbox.FixtureAgent.respond",
        lambda self, request: AgentResponse(text="Benign"),
    )
    result = await run_calibration()
    assert result.metrics["all"]["attempt"].tp == 0
    assert result.metrics["all"]["attempt"].tn == 36
    assert len(result.integrity_errors) == 16
    assert result.exit_code == 1
