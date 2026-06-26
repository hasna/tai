# tai

`tai` is Terminal AI for people who want their terminal to keep behaving like a terminal. It turns natural-language requests into concise shell command proposals, classifies risk, asks before sensitive actions, streams command output, and reports exit status.

It does not expose hidden reasoning or chain-of-thought. Provider outputs are parsed as command proposals, and any model-generated thinking blocks are stripped before user-facing display.

## Install

```bash
bun install
bun run build
```

The package installs the local data directory at `~/.hasna/tai/`.

## Surfaces

- npm package: `@hasna/tai`
- CLI binary: `tai`
- MCP binary: `tai-mcp`
- SDK export: `createTai`, `classifyCommand`, `redactSensitiveText`, `parseCommandProposal`, `planAgenticCommands`

## CLI

```bash
tai propose "show the largest files in this repo"
tai plan "inspect the repo status, run the relevant checks, and show me the safe next commands"
tai classify "rm -rf dist"
tai run "ls -la" --yes
```

`tai run` streams stdout/stderr directly and exits with the child command status. It preserves the current working directory and environment by default, and forwards common process signals to the child.

## Provider Routing

Defaults are local-first and configurable:

1. OpenAI-compatible local endpoint, default `http://localhost:11434/v1` with `TAI_LOCAL_MODEL`.
2. Groq fallback when `GROQ_API_KEY` and `TAI_GROQ_MODEL` are set.
3. Cerebras fallback when `CEREBRAS_API_KEY` and `TAI_CEREBRAS_MODEL` are set.

Model availability changes over time. Verified on 2026-06-26:

- Ollama documents OpenAI-compatible endpoints at `https://docs.ollama.com/api/openai-compatibility`.
- Groq publishes the current hosted model catalog at `https://console.groq.com/docs/models`.
- Cerebras publishes the current hosted model catalog at `https://inference-docs.cerebras.ai/models/overview`.
- Candidate local/open model examples worth evaluating, if available in your runtime, include OpenThinker/OpenThoughts agent models, North Mini Code GGUF, and Devstral Small. Do not assume these IDs are installed locally; set `TAI_LOCAL_MODEL`.

Example:

```bash
export TAI_LOCAL_BASE_URL=http://localhost:11434/v1
export TAI_LOCAL_MODEL=devstral
export TAI_GROQ_MODEL=openai/gpt-oss-120b
export TAI_CEREBRAS_MODEL=qwen-3-coder-480b
```

## Agentic Planning

`tai plan` uses AI SDK Core for native tool calling and multi-step loops. Verified against the current AI SDK docs on 2026-06-26:

- `generateText` supports tool calling for agentic automation.
- `tool` defines executable tools with typed input schemas.
- `stopWhen: stepCountIs(n)` lets the model call tools over multiple steps.
- `@ai-sdk/openai-compatible`, `@ai-sdk/groq`, and `@ai-sdk/cerebras` provide the local/open-provider routing surface.

The planner gives the model constrained tools to inspect safe terminal context, classify candidate commands, run strictly read-only inspection commands with timeout and redaction, and submit a final multi-command plan. The model never gets a write-capable shell tool. Every final command is reclassified locally before it is shown to the user or returned through MCP.

The read-only inspection tool does not invoke a shell. It uses a small `execFile` allowlist with a scrubbed environment, so shell substitution and interpreter side effects are refused before execution.

## Safety Policy

- Allow: clearly read-only commands such as `ls`, `cat`, `git status`, `pwd`, `find`, and simple inspections.
- Confirm: writes, network calls, long-running processes, package managers, process control, and system changes.
- Block unless explicitly overridden: destructive filesystem actions, credential exfiltration, privilege escalation, deploy/publish operations, and force pushes.

See `docs/architecture.md` for the PTY/shell boundary design.

## MCP

Run the stdio MCP server:

```bash
tai-mcp
```

Initial tools:

- `tai.propose_command`
- `tai.plan_commands`
- `tai.classify_command`
- `tai.redact`

## Development

```bash
bun install
bun run build
bun run typecheck
bun test
```

## GitHub Status

The intended remote is `https://github.com/hasna/tai.git`. As of 2026-06-26, private repo creation/view is blocked on this machine because `gh repo create hasna/tai --private` failed with `GraphQL: Resource not accessible by integration (createRepository)`, and `gh repo view hasna/tai` cannot resolve the repository. Do not publish this as a public repo before release approval.
