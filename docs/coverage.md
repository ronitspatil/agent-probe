# Coverage and interpretation

AgentProbe provides reproducible canary probes and explicit evidence levels. It does
not certify OWASP compliance or comprehensively exploit every category. Synthetic
prompts mapped to a risk are narrower than an end-to-end test of that risk.

| OWASP category | Included probe | What it cannot establish alone |
|---|---|---|
| ASI01 Agent Goal Hijack | Indirect web/database/PDF-text injection; poisoned metadata | Native ingestion behavior or real exfiltration |
| ASI02 Tool Misuse & Exploitation | Approval bypass and tool-parameter syntax | Actual side effects without independent telemetry |
| ASI03 Identity & Privilege Abuse | Confused-deputy prompt; operator-declared denied MCP fixture | Credential inheritance or principal separation without a scoped harness |
| ASI04 Agentic Supply Chain Vulnerabilities | Untrusted plugin claim and metadata poisoning | Package compromise, signature validity, or dependency provenance |
| ASI05 Unexpected Code Execution | Synthetic execution prompt and syntax probes | Actual RCE, SQL injection, or filesystem traversal |
| ASI06 Memory & Context Poisoning | Six-turn instruction drift | Persistent memory poisoning across independent sessions |
| ASI07 Insecure Inter-Agent Communication | Spoofed peer-authority prompt | Network authentication or protocol-level peer compromise |
| ASI08 Cascading Failures | Fail-open recovery prompt | Fault propagation, availability, or real denial of service |
| ASI09 Human-Agent Trust Exploitation | Fabricated approval claim | A real human's response to a deceptive interface |
| ASI10 Rogue Agents | Unrequested, concealed extra-action prompt | Long-horizon autonomous behavior or all task-boundary failures |

Mappings follow the [official OWASP Agentic Top 10 publication](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).
Parameter fuzzing maps to ASI02/ASI05; ASI03 is Identity & Privilege Abuse.
MCP behavior targets the [dated Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Evidence levels

| Result | Meaning |
|---|---|
| `no_finding` | The observation did not satisfy a detector; not proof of safety |
| `suspicious` | Canary text, metadata pattern, untrusted event claim, or semantic heuristic |
| `attempted` | Structured forbidden canary call, or acceptance of an operator-declared forbidden fixture |
| `confirmed` | Explicitly trusted harness reports executed, unauthorized, matching canary action |
| `error` | Test could not be evaluated reliably |
| `skipped` | Required execution opt-in, allowlist, or fixture was absent |

A refusal quoting the canary can be suspicious because exact marker matching cannot
infer intent. It is never confirmed execution. Semantic similarity can match denials
and descriptions; use it to prioritize review. Confidence values express detector
strength, not calibrated probabilities. Severity concerns the observed finding, and
should be reviewed against the actual tool impact and deployment context.

All tests use synthetic markers and synthetic fixture paths. The scanner never
executes returned agent tool calls locally. Active MCP fuzzing invokes the allowed
remote tool, so a canary does not make arbitrary tool implementations safe. Use an
isolated, instrumented harness with bounded resources and no production privileges.

If a later turn, deadline, or optional semantic evaluator fails, earlier deterministic
evidence is retained with its original result status and an `error` message. Such a
scan is incomplete and exits with code `2`, even when it also contains findings.
