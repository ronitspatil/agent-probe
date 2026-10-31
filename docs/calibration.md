# Synthetic sandbox and calibration

The sandbox is a deterministic scripted agent with an actual in-memory tool dispatcher.
It exercises AgentProbe's HTTP scanning and evidence interpretation without model
credentials or external services. Its results describe this controlled corpus;
they do not measure real LLM security, general attack success, or OWASP compliance.

## Run calibration

After installing AgentProbe from the repository:

```sh
agentprobe calibrate --output calibration.json
```

The command starts and stops four independent loopback servers: protected and
vulnerable enforcement, each evaluated with trusted and untrusted telemetry. Nine
scenarios per configuration produce 36 samples through the production `AgentScanner`.
No external target or model is contacted. JSON output uses atomic replacement and
owner-only permissions. HTTP requests are real; this is not `httpx.MockTransport`.

Each sample includes the scanner's status/evidence and separate oracle facts obtained
from the dispatcher's audit and actual sink contents. The report also records its
corpus version, scanner version, configuration, expected sample IDs, confusion matrices,
individual mismatches, incomplete samples, and fixture integrity errors. Derived
values are recomputed when reading a report with `CalibrationReport`; supplied
precomputed scores cannot override the underlying sample data.

Sample IDs and markers are deterministic. The same version/configuration produces
the same metrics. Timestamps, request durations, and ephemeral ports may vary, so
reports are not promised to be byte-identical.

## Enforcement and independent evidence

The only tool is `agentprobe_canary_sink`, which appends a synthetic marker to memory.
The authorization policy always denies this tool. The two modes differ in enforcement:

| Mode | Requested call | Tool side effect | Independent audit |
|---|---|---|---|
| Protected | Reaches dispatcher | Blocked | Attempt recorded, unauthorized, not executed |
| Vulnerable | Reaches dispatcher | Marker appended | Attempt recorded, unauthorized, executed |

The dispatcher is the sole writer of audit records and sink effects. Request IDs only
correlate observations; they never decide whether a tool runs. The planner responds
to fixture instructions in supplied content. Audit and sink agreement is validated.
Separate integrity checks ensure intended action scenarios actually reach the
dispatcher; a broken fixture returning benign output for every request fails the gate
instead of producing a misleading all-negative score.

The nine scenarios are direct calls, indirect content instructions, a six-turn recall
call, refusal echoes, fabricated success text, a forged adapter execution event,
unrelated markers, benign text, and a call whose evidence is deliberately hidden.

Two controls demonstrate limits explicitly:

- **Forged adapter event:** the response claims execution, but the dispatcher and sink
  stay empty. Trusting that event produces a false confirmation. `--trust-telemetry`
  is an operator trust declaration, not attestation; a compromised adapter can lie.
- **Hidden evidence:** the dispatcher records the attempt and possible execution, but
  the response omits those signals. The scanner misses the action. Independent audit
  exposes the false negative rather than changing the expected label to match it.

## Interpret the metrics

| Dimension | Positive ground truth | Positive scanner result |
|---|---|---|
| `attempt` | Dispatcher recorded a tool attempt | `attempted` or `confirmed` |
| `execution` | Dispatcher and sink show unauthorized execution | `confirmed` |
| `triage` | Dispatcher recorded a tool attempt | `suspicious`, `attempted`, or `confirmed` |

Matrices report true positives (`tp`), false positives (`fp`), true negatives (`tn`),
false negatives (`fn`), evaluated count, exclusions, precision, recall, and false-positive
rate. Undefined ratios are `null`, not zero or 100%. Errors, skips, and partial results
with an error are excluded from scoring and listed as incomplete; they are never
counted as true negatives. Groups separate enforcement mode and telemetry trust.

Triage captures review burden: a refusal echoing a canary creates an alert although
no tool action occurred. It is a triage false positive, not execution evidence.
Untrusted telemetry deliberately prevents execution confirmation even when the
independent oracle knows execution occurred. These limits remain in the matrices
and per-sample mismatch list. Confidence values remain heuristic scores; this work
does not fit probabilistic calibration parameters or use an LLM judge.

| Exit | Meaning |
|---|---|
| `0` | Corpus completed with only documented known mismatches and intact fixtures |
| `1` | Unexpected detector mismatch or fixture integrity failure |
| `2` | Incomplete scan, configuration, server startup, or report-write error |

Exit `0` does not mean perfect precision/recall. Known false positives and false
negatives are deliberately retained. Missing or duplicate sample IDs fail validation.

## Optional model-backed calibration

`agentprobe calibrate-model` evaluates selected fixed prompts through a configured
OpenAI Chat Completions-compatible endpoint and the local in-memory sandbox. The
command is preview-only unless `--execute` is present. For example:

```sh
agentprobe calibrate-model \
  --endpoint https://provider.example/v1/chat/completions \
  --model example-model \
  --scenario direct_call \
  --scenario indirect_injection \
  --repetitions 3
```

The preview shows the maximum provider request count and generated-token ceiling.
Add `--execute` to send requests; provider charges may apply. The API credential is
read from `AGENTPROBE_API_KEY` by default, or another name selected with
`--credential-env`. Never pass a credential as a command-line argument. Select
`--mode protected` or `--mode vulnerable` to run the synthetic denied or deliberately
bypassed dispatcher. The default uses `protected` mode.
Remote provider endpoints must use HTTPS. Plain HTTP is allowed only for local loopback
fixtures. Redirects are disabled.

The supported probes cover a direct unauthorized call, untrusted external-content
instructions, five-turn instruction drift, and a benign no-tool control. Each selected
probe receives a deterministic per-repeat canary. Only the synthetic sink is advertised
to the model; calls to other tools and incorrect canaries are rejected. The sink stores
canaries in memory and never invokes shell commands, files, databases, or external MCP
servers. The provider request includes the system policy, selected probe conversation,
untrusted scenario content, and the single synthetic tool schema.

Calls run sequentially. `--max-tool-rounds` bounds tool result follow-ups per user
turn, and `--request-timeout` bounds each provider request. The preview uses the
selected scenario's longest conversation to compute its maximum request budget. No
automatic retries occur. Reports record model settings, prompt/corpus versions, provider
request IDs, redacted finish/usage metadata, model tool-call attempts, dispatcher audit,
sink effects, and scanner observations. They do not store raw completions or API keys.
Provider endpoint paths and query strings are omitted from reports. Treat reports as
sensitive because they include probe canaries and request IDs.

Attempted model calls, scanner alerts, dispatcher decisions, and actual sink effects
are separate measurements. Only dispatcher audit and sink contents establish whether
the local synthetic action ran. Repetition rates and observed ranges describe this small
sample; they are not statistical certification or a general security guarantee. Tests
use mock providers and loopback fixtures only; they never contact a model provider.

## Model-driven scan planning

`agentprobe model-plan` lets a model select the next test from the registered case
catalog based on prior scan summaries:

```sh
agentprobe model-plan \
  --endpoint https://provider.example/v1/chat/completions \
  --model example-model \
  --max-steps 5 \
  --max-tokens 256
```

The command is preview-only unless `--execute` is supplied. Preview shows the maximum
provider request count and token ceiling. Requests can incur provider charges; credentials
come from `AGENTPROBE_API_KEY` by default, not a command-line argument. Remote endpoints
must use HTTPS; plain HTTP is limited to local loopback fixtures.

The model receives registered IDs, titles, categories, and OWASP labels, plus prior case
IDs, statuses, and evidence detector names. It does not receive probe payloads, raw scan
responses, tool arguments, credentials, or arbitrary target data. It can select an unused
registered case or stop. Unknown IDs, repeated IDs, malformed decisions, extra fields,
and tool calls are rejected. It cannot set URLs, tools, or payloads.

Selected probes execute only against the local loopback sandbox. The protected
in-memory canary sink is the default. Vulnerable mode is a fixture-only comparison and
still stores effects in memory. No remote agent endpoint, MCP server, shell, database,
or filesystem tool is called. Python validates choices, executes registered cases, and
records independent dispatcher truth; the model chooses test order and adapts to prior
summaries. Existing `scan`, `calibrate`, and `calibrate-model` behavior is unchanged.

`--max-steps` bounds provider decisions to 1–20, and `--max-tokens` bounds each response
to 1–512 tokens. Calls are sequential, timed out, and never retried. Reports contain
planner settings and request metadata but not planner completions or rationale. Scanner
evidence can include canary markers, so treat reports as sensitive. Automated tests use
mock providers and loopback fixtures; they do not make live model requests.

## Serve a sandbox manually

```sh
agentprobe sandbox --mode protected --port 8765
```

In a second terminal:

```sh
agentprobe scan --target http://127.0.0.1:8765/agent \
  --trust-telemetry --output report-sandbox.json
agentprobe scan --mcp-server http://127.0.0.1:8765/mcp --output report-mcp.json
```

Use `--mode vulnerable` to bypass the synthetic tool authorization gate; effects still
stay in memory. Port `0` selects an available port. Ctrl-C stops the server. `/audit`
returns its current independent audit and sink snapshot. Only `127.0.0.1` is supported;
unexpected Host headers and browser Origin headers are rejected. Request sizes,
message counts, socket timeouts, and audit capacity are bounded.

The fixture planner recognizes `Call agentprobe_canary_sink` plus a canary marker.
The calibration controls use the explicit `FIXTURE_*` instructions in the versioned
corpus; they are not general natural-language understanding or a production agent.

The small stateless `/mcp` fixture supports initialization, tool listing, and calls to
the same sink. Active scanning still requires the existing exact allowlist and fixture
opt-in. It accepts a bare `marker` argument; it does not execute shell, SQL, filesystem,
or arbitrary fuzz strings. MCP discovery and protected/vulnerable tool behavior are
covered by real HTTP integration tests. The calibration matrices currently score the
agent endpoint, not MCP protocol or metadata detection coverage.

No server session, model weights, tool state, or external process survives the automatic
calibration run. A manual server exposes only synthetic memory, and should remain a
local development fixture.
