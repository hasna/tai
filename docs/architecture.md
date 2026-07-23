# tai Architecture

`tai` should feel like the user's normal terminal. It should not become a decorative TUI, hide the shell, or replace prompt/output semantics.

## Terminal Boundary

The first scaffold includes a simple shell runner for safe command execution tests and CLI smoke use. The production terminal boundary should be PTY-backed:

- Start the user's configured shell inside a PTY.
- Preserve cwd, env, prompt rendering, colors, terminal modes, and command exit status.
- Forward stdin/stdout/stderr as terminal streams rather than rendering a separate UI frame.
- Forward signals including `SIGINT`, `SIGTERM`, `SIGHUP`, and resize events through `SIGWINCH`.
- Keep AI proposal text outside shell history unless the user explicitly accepts and runs a command.
- When a command is accepted, write only the accepted shell command to the PTY and stream output directly.
- Record the final exit status without fabricating success or swallowing shell errors.

## AI Boundary

Provider responses are never displayed as hidden reasoning. The SDK strips common thinking blocks, parses JSON command proposals, redacts secrets, and reclassifies command risk locally instead of trusting provider-supplied safety metadata.

## Agentic Planning

Agentic planning is built on AI SDK Core rather than a custom loop. Current docs checked on 2026-06-26 describe `generateText` plus `tool` plus `stopWhen: stepCountIs(n)` as the multi-step tool-calling mechanism, and describe `ToolLoopAgent` as the reusable agent abstraction. `tai` starts with `generateText` because terminal planning needs explicit control over final command data and safety gates.

The model receives a constrained tool set:

- inspect safe terminal context
- classify candidate commands with local policy
- run narrowly allowlisted read-only inspections with `execFile`, timeout, redaction, and a scrubbed environment
- submit a final multi-command plan

The model never receives a write-capable shell tool or arbitrary shell-string execution. Final steps are parsed as data and classified again locally before display or MCP return. Confirmation and override decisions remain outside the model loop.

## Provider Routing

Routing is local-first:

1. OpenAI-compatible local endpoint.
2. Groq fallback when configured.
3. Cerebras fallback when configured.

Model IDs are intentionally configuration-driven because availability is time-sensitive.

## Agent Visibility Facade

The `tai agents` surface is separate from model routing. It is a stateless, read-only facade over provider-owned structured APIs that are demonstrably side-effect free. It does not invoke installed Codewith, Claude, or Todos list commands because those routes can initialize state, change permissions, create databases, or mutate expired task locks.

Codewith and Claude remain explicit unavailable sources until they expose a safe structured read surface. Todos list is also unavailable: its task-list implementation performs expired-lock cleanup, and its agent-list API has no authoritative source-level limit. A configured Todos API may perform one exact task `GET`, with a one-MiB response cap and a five-second wall-clock bound. Exact show calls only its selected provider. Absence is reported only after a complete targeted 404; unavailable, truncated, or unproven results remain incomplete.

Normalization is omission-first. Only canonical UUIDs, narrow task short IDs, closed-set statuses, ISO timestamps within bounded clock skew, and `accountNNN` profile aliases may cross the output boundary. Provider-controlled titles, paths, branch names, tool text, goal text, raw diagnostics, URI credentials, query/fragment values, account identifiers, and nonprinting Unicode controls never do. Every null field has a stable named gap, and every source reports explicit complete/returned/dropped coverage.

Todos tasks require authoritative agent, session, runner, or live-lease provenance before projection. Assignment or task status does not establish an agent. Duplicate state is selected by newest valid observation first, then explicit status precedence and a canonical tie-breaker; unknown status and invalid or future timestamps fail closed.

The reusable process boundary used by provider integrations creates a process group and force-resolves on deadline or stdout/stderr byte overflow, including when descendants retain pipes. Current agent visibility uses no provider process because no installed command meets the side-effect-free contract.

TAI owns no database, daemon, cache, task assignment, authorization, WorkRun, or agent lifecycle state, and this surface contains no stop, retry, resume, profile-switch, notification, fleet, web, or TUI behavior.

## Safety Policy

Read-only commands may run without confirmation. Writes, network calls, package manager operations, process control, and mutable git operations require confirmation. Destructive operations, credential disclosure, privilege escalation, deploy/publish, and force-push operations are blocked unless the user uses an explicit override.
