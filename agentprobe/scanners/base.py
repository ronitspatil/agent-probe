"""Common execution limits and sanitized failure handling."""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Sequence
from time import monotonic

import httpx
from pydantic import ValidationError

from agentprobe.models import ResultStatus, ScanConfig, ScanResult, Severity, TestCase


class ScanError(Exception):
    """Public messages must not contain response bodies, URLs, headers or credentials."""


def safe_error(exc: Exception) -> str:
    if isinstance(exc, ScanError):
        return str(exc)
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return "Request exceeded its configured timeout."
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP request failed with status {exc.response.status_code}."
    if isinstance(exc, httpx.HTTPError):
        return "HTTP transport failed; check endpoint connectivity and TLS."
    if isinstance(exc, ValidationError):
        return "Response or configuration does not match the declared schema."
    return f"Test failed ({type(exc).__name__}); response details withheld."


def result_for(case: TestCase, status: ResultStatus, **kwargs: object) -> ScanResult:
    return ScanResult.model_validate(
        {
            "test_id": case.id,
            "title": case.title,
            "category": case.category,
            "owasp": case.owasp,
            "status": status,
            "severity": case.severity
            if status in {ResultStatus.ATTEMPTED, ResultStatus.CONFIRMED}
            else Severity.INFO,
            "remediation": case.remediation,
            **kwargs,
        }
    )


class BaseScanner(ABC):
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    @abstractmethod
    async def execute(self, case: TestCase) -> ScanResult:
        raise NotImplementedError

    def failure_result(self, case: TestCase, exc: Exception) -> ScanResult:
        return result_for(case, ResultStatus.ERROR, error=safe_error(exc))

    async def scan(self, cases: Sequence[TestCase]) -> list[ScanResult]:
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run(case: TestCase) -> ScanResult:
            async with semaphore:
                start = monotonic()
                try:
                    async with asyncio.timeout(self.config.timeout):
                        result = await self.execute(case)
                except Exception as exc:
                    result = self.failure_result(case, exc)
                result.duration_ms = (monotonic() - start) * 1000
                return result

        return list(await asyncio.gather(*(run(case) for case in cases)))
