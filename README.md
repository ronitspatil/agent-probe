# AgentProbe

AgentProbe tests LLM agents and MCP integrations with synthetic canaries.
It combines async HTTP scanning, a structured payload registry, evidence-aware
detection, and terminal/JSON reports. Python 3.11 or newer is required.

## Quick start

```sh
git clone https://github.com/ronitspatil/agent-probe.git
cd agent-probe
python -m venv .venv
source .venv/bin/activate
pip install -e .
agentprobe demo --output report.json
```

The offline demo intentionally returns exit code `1` because it detects findings.
To scan your sandbox agent and inspect MCP metadata:

```sh
agentprobe scan --target http://127.0.0.1:8000/agent \
  --mcp-server http://127.0.0.1:8001/mcp --output report.json
```

MCP tool calls are disabled by default. Agent endpoints can execute their own tools;
use an isolated harness. A clean report is not proof that an agent is secure.

Read the [CLI guide](docs/usage.md), [adapter contract](docs/integrations.md),
[coverage and evidence limits](docs/coverage.md), and [development guide](docs/development.md).

```sh
pip install -e '.[dev]'
pytest && ruff check . && ruff format --check . && mypy agentprobe
```

Licensed under the [MIT License](LICENSE).
