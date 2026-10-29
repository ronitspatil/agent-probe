# Development

```sh
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
ruff format --check .
mypy agentprobe
python -m build
agentprobe --help
agentprobe demo --output report.json
```

The demo exits `1` intentionally. Tests use `httpx.MockTransport` to exercise requests,
response parsing, MCP sessions/SSE, and detector boundaries without live credentials.
They are not live endpoint validation. CI runs the checks on Python 3.11, 3.12, and 3.13.
Semantic model downloads and real provider endpoints are not required by CI.

The package separates validated schemas (`models.py`), fresh payload construction
(`payloads`), network execution (`scanners`), evaluation (`evaluators`), and CLI/report
presentation. `BaseScanner.scan` limits concurrency, applies total per-case timeouts,
and preserves ordering while isolating per-case exceptions.

To add a test vector, create a `TestCase` with a unique stable ID, safe canary template,
OWASP mapping, and concrete remediation. To add semantics, implement the async
`EmbeddingProvider.embed` protocol and pass it to `DetectionEngine`. Return one finite
vector per input; cosine similarity remains a heuristic signal.

Use a fresh scanner context for each scan. Caller-supplied `httpx.AsyncClient` objects
remain caller owned. Request/response hooks receive copies and cannot alter actions.
Keep integrations and reports free of secrets; do not commit tokens or real endpoint
responses. No release, package publishing, or deployment occurs automatically.
