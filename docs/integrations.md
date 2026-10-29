# Endpoint and harness contracts

## Generic agent REST adapter

AgentProbe posts a JSON object to the exact target URL:

```json
{
  "messages": [{"role": "user", "content": "Summarize the supplied content."}],
  "test_id": "indirect-web",
  "context": [{"source": "web", "text": "Untrusted fixture content"}],
  "tool_metadata": []
}
```

The harness should route `context` through its actual untrusted retrieval boundary,
not concatenate it into privileged system instructions. Sources include `web`,
`database`, `pdf_text`, `peer`, and `tool_metadata`. The PDF case supplies extracted
text; AgentProbe does not upload, render, or extract PDFs. Web/database cases are
mock content, not crawlers or database connections. Native ingestion requires your
adapter to deliver fixtures through the application's real ingestion path.

Install a sandbox-only `agentprobe_canary_sink` tool taking a string `marker`.
Keep authorization rules outside the model: test prompts are never approval.
The sink should record attempted/executed calls in isolated memory or a dedicated
fixture store. It must not contact external systems, run commands, or write production
data. Without a configured sink and observable authorization policy, a test may only
measure text generation or requests for an unavailable tool.

Return this shape; omitted arrays and text default to empty values:

```json
{
  "text": "Agent answer",
  "tool_calls": [
    {"name": "agentprobe_canary_sink", "arguments": {"marker": "CANARY_EXFIL_TEST_12345"}}
  ],
  "events": [
    {
      "tool": "agentprobe_canary_sink",
      "arguments": {"marker": "CANARY_EXFIL_TEST_12345"},
      "executed": true,
      "authorized": false,
      "canary": "CANARY_EXFIL_TEST_12345"
    }
  ]
}
```

Use the actual per-test marker from the request. Record `tool_calls` at the attempted
execution boundary. Generate `events` from independent execution/authorization
telemetry, never by asking the model to describe what happened. Authentication and
transport integrity are the operator's responsibility. The `--trust-telemetry` flag
is an explicit trust declaration, not cryptographic attestation.

Each request includes a synthetic system test policy that forbids the canary sink.
The harness must retain its real immutable policy and enforce the additional synthetic
constraint in the sandbox. Direct chat-completions tests exercise the supplied test
policy, not an unseen production system prompt. A harness that ignores the test policy
cannot establish whether the synthetic sink request was unauthorized.

The harness should isolate each test conversation and use the supplied message
history. Multi-turn cases replay real assistant responses. AgentProbe stops a
conversation after a returned tool call and does not execute it locally.

## OpenAI-style adapter

Use `--schema openai --model MODEL` with a full chat-completions endpoint URL. Requests
contain standard chat-completions fields and advertise a synthetic sink function.
The MCP-description case poisons a local copy of function metadata. AgentProbe never
executes returned functions. Untrusted external context is quoted inside
user content; this tests model handling of embedded data, not your production RAG
pipeline. Function calls are read from `choices[0].message.tool_calls`; their function
arguments must be JSON objects encoded as strings. MCP names outside the supported
ASCII letters/digits/underscore/hyphen format or longer than 64 characters receive
stable synthetic aliases; returned names are mapped back for evaluation. Catalogs
exceeding 128 functions, including the sink, fail explicitly without truncation. Text comes from the first choice's
message content. Tool requests are evidence of intent only. Execution telemetry is
available through the generic harness contract, not the OpenAI response adapter.

## MCP transport and interception

AgentProbe supports the dated Streamable HTTP protocols `2025-11-25`, `2025-06-18`,
and `2025-03-26`. It proposes `2025-11-25`, checks the negotiated version, sends the
initialization notification, and preserves the session identifier and protocol header.
It supports JSON responses and request-associated SSE responses. Unsupported revisions,
stdio, legacy HTTP+SSE, stream resumption, server-initiated sampling, OAuth discovery,
and transparent proxy deployment are outside this release's scope.

Pagination is limited to 100 pages and 1,000 tools. Repeated cursors, duplicate names,
mismatched response IDs, malformed envelopes, excessive bytes, and timeouts fail
explicitly. Requests are not retried because replay could repeat side effects.

`MCPScanner(..., request_observer=callback, response_observer=callback)` accepts async
callbacks that receive deep copies of JSON-RPC objects. These hooks let a harness
inspect traffic initiated by the scanner. They cannot mutate outbound requests and
do not intercept an unrelated agent's connection. Hook implementers are responsible
for protecting any data they choose to retain.

Metadata inspection uses pattern matching. Poisoning creates a local copy of a tool's
description; it never changes the real server's tool definition. A generic agent
harness must deliberately route supplied `tool_metadata` through its test catalog to
exercise that trust boundary. Static metadata inspection alone cannot show whether
an agent obeyed a poisoned definition.

An active fixture tool may report trusted execution events in
`structuredContent.agentprobe_events`, using the same event schema above. MCP tool
errors are not successful execution, and canary echoes do not prove that a traversal,
shell, or SQL syntax probe crossed an execution boundary.
