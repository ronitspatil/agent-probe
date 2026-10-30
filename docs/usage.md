# CLI guide

`agentprobe payloads` lists available cases. `agentprobe demo --output report.json`
runs a local deterministic HTTP mock; it needs no model credentials or listening server.
The demo exercises transport adapters and reporting, not a real model's safety behavior.

Use only endpoints and sandbox tools you are authorized to test. Synthetic payloads
avoid production file paths and destructive commands, but a remote agent or MCP tool
can still perform side effects. AgentProbe cannot sandbox a remote service.

```sh
agentprobe scan --target http://127.0.0.1:8000/agent --output report.json
agentprobe scan --mcp-server http://127.0.0.1:8001/mcp --output report.json
agentprobe scan --target https://agent.example.test/v1/chat/completions \
  --schema openai --model your-model --category indirect_injection --output report.json
```

The target URL is the complete endpoint path. OpenAI mode uses chat-completions
schemas; it does not implement the Responses API. The generic contract is documented
in [integrations.md](integrations.md). A category can be repeated to narrow agent tests.

Authentication is read from `AGENTPROBE_TOKEN` and `AGENTPROBE_MCP_TOKEN` by default;
`--token-env` and `--mcp-token-env` select different environment variable names.
Keep tokens out of URLs and fixture files. Redirects and HTTP retries are disabled;
TLS verification remains enabled. HTTP proxy environment variables are not used.

## Active MCP fixtures

Discovery sends `initialize`, `notifications/initialized`, and paginated `tools/list`.
It does not call advertised tools, even if their metadata says `readOnlyHint: true`.
Tool calls require all three: `--active-mcp`, an exact `--allow-tool` name, and a
fixture. Prepare a disposable server whose allowed tool only handles synthetic data.

Example `fixtures.json`:

```json
[
  {
    "tool": "fixture",
    "arguments": {"marker": "{canary}"},
    "fuzz_fields": ["marker"],
    "expected_denied": false
  }
]
```

```sh
agentprobe scan --mcp-server http://127.0.0.1:8001/mcp \
  --active-mcp --allow-tool fixture --fixtures fixtures.json --output report.json
```

Each fixture has a baseline call plus four syntax variants per selected top-level
string field: traversal, shell separators, pipeline syntax, and SQL quoting. All
other arguments remain operator supplied. A new canary is used for each call.
`expected_denied: true` records an independently established authorization expectation;
acceptance is a policy signal, not proof of execution or a substitute for a real
principal/scope comparison. Set it only when the authenticated caller should be denied.

## Reporting and exit codes

The JSON report contains schema/scanner versions, scan identity, timestamps, sanitized
targets, results, evidence, remediation, and limitations. The terminal table uses the
same results. Raw response bodies and credential headers are not saved.

| Exit | Meaning |
|---|---|
| `0` | Completed without findings; skipped cases may still be present |
| `1` | At least one suspicious, attempted, or confirmed result |
| `2` | Configuration, transport, protocol, or execution error; inspect partial results |

`--trust-telemetry` enables confirmation from execution events supplied by your
trusted harness. Never enable it for raw model-generated event claims.

Semantic detection is optional: install `pip install -e '.[semantic]'`, then use
`--semantic-model` with a reviewed local model path or model identifier. Loading a
remote model identifier may download weights. Cosine similarity is always reported
as heuristic evidence; it cannot confirm execution.


## Local calibration

`agentprobe calibrate --output calibration.json` starts disposable loopback fixtures,
measures scanner results against independent synthetic tool audit records, and stops
the servers. `agentprobe sandbox --mode protected --port 8765` serves a fixture until
interrupted. See [synthetic calibration](calibration.md) for modes, metrics, expected
false positives and false negatives, and the distinction from real-model testing.
