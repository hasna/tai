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

The `tai agents` surface is separate from model routing. It is a stateless, read-only facade over the installed Codewith background-agent list, Claude agent list, and Todos active-task command surfaces. A request makes one bounded, non-shell provider call per source and projects the returned batch locally; it never performs a provider read for each result.

The normalized schema records only bounded status/context fields exposed by those list surfaces. Missing worktree, branch, tool, goal, task, profile, timestamp, or freshness data stays `null` and is named in `gaps`. Source failures are isolated and diagnosed with stable codes. TAI owns no database, daemon, cache, task assignment, authorization, or agent lifecycle state, and this surface contains no stop, retry, resume, profile-switch, notification, fleet, web, or TUI behavior.

## Safety Policy

Read-only commands may run without confirmation. Writes, network calls, package manager operations, process control, and mutable git operations require confirmation. Destructive operations, credential disclosure, privilege escalation, deploy/publish, and force-push operations are blocked unless the user uses an explicit override.
