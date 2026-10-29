import pytest
from pydantic import ValidationError

from agentprobe.models import MCPFixture, MCPToolMetadata, PayloadCategory, ScanConfig, TestCase
from agentprobe.payloads import build_registry, fuzz_values, poison_metadata


def test_registry_isolated_and_covers_taxonomy() -> None:
    first = build_registry()
    second = build_registry()
    assert len({case.id for case in first}) == len(first)
    assert len({case.canary for case in first + second}) == len(first + second)
    assert {item for case in first for item in case.owasp} == {f"ASI{i:02}" for i in range(1, 11)}
    assert all("{canary}" not in case.render(turn) for case in first for turn in case.turns)
    context = next(case for case in first if case.category == PayloadCategory.CONTEXT_POISONING)
    assert len(context.turns) >= 5
    assert {item.source for case in first for item in case.external_content} >= {
        "web",
        "database",
        "pdf_text",
        "tool_metadata",
    }


def test_poisoning_does_not_modify_discovered_metadata() -> None:
    tool = MCPToolMetadata(
        name="fixture",
        description="Reviewed description",
        inputSchema={
            "type": "object",
            "properties": {"marker": {"type": "string"}},
        },
    )
    original = tool.model_dump()
    poisoned = poison_metadata(tool, build_registry()[0].canary)
    poisoned.input_schema["properties"]["marker"]["description"] = "changed"
    assert tool.model_dump() == original
    assert "Ignore previous instructions" in poisoned.description


def test_fuzz_parameters_only_reference_synthetic_fixtures() -> None:
    marker = build_registry()[0].canary
    values = fuzz_values(marker)
    assert all(marker in item for item in values)
    assert any("../" in item for item in values)
    assert any(";" in item and "echo" in item for item in values)
    assert any(" OR " in item for item in values)
    assert not any("/etc/passwd" in item or "DROP TABLE" in item for item in values)


@pytest.mark.parametrize("fields", [["absent"], ["count"]])
def test_fixture_fuzz_fields_must_be_existing_strings(fields: list[str]) -> None:
    with pytest.raises(ValidationError):
        MCPFixture(tool="fixture", arguments={"count": 1}, fuzz_fields=fields)


@pytest.mark.parametrize("config", [{"concurrency": 0}, {"timeout": 0}, {"concurrency": 65}])
def test_limits_validated(config: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        ScanConfig.model_validate(config)


def test_invalid_taxonomy_and_canary_rejected() -> None:
    data = build_registry()[0].model_dump()
    for overrides in ({"owasp": ["ASI99"]}, {"canary": "CANARY_EXFIL_TEST_abc; rm x"}):
        with pytest.raises(ValidationError):
            TestCase.model_validate({**data, **overrides})
