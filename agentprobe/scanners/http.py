"""Bounded HTTP reads shared by both scanners; no redirects or retries."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from agentprobe.models import ScanConfig
from agentprobe.scanners.base import ScanError


def validate_url(value: str) -> str:
    if any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("endpoint contains whitespace or control characters")
    parsed = urlsplit(value)
    _ = parsed.port
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("endpoint must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError(
            "endpoint credentials and fragments are forbidden; use token environment variables"
        )
    return value


def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class HTTPTransport:
    def __init__(
        self,
        url: str,
        config: ScanConfig,
        *,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = validate_url(url)
        self.config = config
        self._client = client
        self._owned = client is None
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    async def __aenter__(self) -> "HTTPTransport":
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_connections=self.config.concurrency),
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._owned and self._client is not None:
            await self._client.aclose()
            self._client = None

    @asynccontextmanager
    async def stream(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> AsyncIterator[httpx.Response]:
        if self._client is None:
            raise ScanError("Transport must be opened with async with before scanning.")
        async with self._client.stream(
            "POST",
            self.url,
            json=body,
            headers={**self.headers, **(headers or {})},
            timeout=self.config.timeout,
            follow_redirects=False,
        ) as response:
            response.raise_for_status()
            yield response

    async def read(self, response: httpx.Response) -> bytes:
        result = bytearray()
        async for chunk in response.aiter_bytes():
            result.extend(chunk)
            if len(result) > self.config.max_response_bytes:
                raise ScanError("Response exceeded the configured byte limit.")
        return bytes(result)

    async def post(self, body: dict[str, Any]) -> dict[str, Any]:
        async with self.stream(body) as response:
            data = json.loads(await self.read(response))
        if not isinstance(data, dict):
            raise ScanError("Expected a JSON object response.")
        return data
