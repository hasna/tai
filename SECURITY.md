# Security Policy

Report vulnerabilities privately to the Hasna maintainers. Do not file public issues for exploitable command execution, credential exposure, prompt injection, provider routing, or MCP boundary problems.

Credential redaction of displayed, logged and MCP-returned text is documented in
[`docs/redaction.md`](docs/redaction.md), including the shapes that are **not**
covered. Read the residual list there before assuming a given shape is masked.

`tai` is designed to preview commands and classify risk before execution. Treat command classification as defense in depth, not as a sandbox. Users remain responsible for confirming commands before they run.
