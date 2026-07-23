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
tai agents
tai agents --json
tai agents show todos:<task-uuid>
tai classify "rm -rf dist"
tai run "ls -la" --yes
```

`tai run` streams stdout/stderr directly and exits with the child command status. It preserves the current working directory and environment by default, and forwards common process signals to the child.

### Headless agent visibility

`tai agents [--limit <1-200>]` is a stateless, read-only projection of independently safe provider surfaces. The default output limit is 50. `tai agents show <provider>:<safe-run-id>` performs an exact lookup against only the selected provider. Add `--json` to either form for the versioned machine contract. `--limit` is rejected for exact lookup.

TAI does not invoke the installed `codewith agent list`, `claude agents`, or `todos active` routes: those routes can create configuration or database files, change permissions, or clean expired locks. It also does not call the authenticated Todos `/v1` GET surface because the provider initializes database schema before request dispatch. Codewith, Claude, and exact Todos therefore report `side-effect-free-surface-unavailable` until those providers expose a demonstrably side-effect-free structured read API. Todos list reports `side-effect-free-source-limit-unavailable`: its task-list implementation cleans expired locks, while its agent-list API has no authoritative source limit.

No current provider surface satisfies the full read-only proof, so `tai agents` returns a structured unavailable envelope and nonzero exit without consulting provider configuration, credentials, HTTP endpoints, or local state. Exact show still selects only the encoded provider, but an unsupported source returns `agent-lookup-incomplete` without performing an operation. Configuration such as `TODOS_URL`, including loopback URLs, does not enable Todos visibility.

Missing providers fail soft while any independently safe source responds. If every source is unavailable or errors, the command exits nonzero. Exact lookup may return `agent-not-found` only after a future safe provider surface proves structured, canonical absence; HTTP status, HTML, redirects, partial responses, malformed bodies, unavailable, truncated, or otherwise unproven evidence remains `agent-lookup-incomplete`. A future Todos projection must follow authoritative provider lease ownership and expiry semantics; assignment, task status, or a printable `agent_id` alone is insufficient.

JSON v1 has these stable fields:

- Envelope: `schema_version` (number, currently `1`), `generated_at` (ISO-8601 string), `partial` (boolean), `sources` (source diagnostics), and `agents` (normalized records). Command errors add a bounded `error` object.
- Source diagnostic: `provider` (`codewith|claude|todos`), `status` (`ok|partial|unavailable|error`), `freshness_at` (the bounded source-operation completion time or `null`), `coverage: {complete, provider_records, projected_records, dropped_records}`, and optional `error: {code, message}`.
- Agent identity/state: `id`, `provider`, `run_id`, `status`, `active`, `started_at`, `updated_at`, `freshness_at`.
- Agent context: `worktree`, `branch`, `last_tool_call: {name, at, summary}`, `goal: {id, title, status}`, `task: {id, short_id, title, status}`, and `profile: {alias}`.
- `gaps` is a sorted array of stable field names for every missing normalized value. Unavailable or withheld fields remain `null`; they are never inferred from prompts, transcripts, paths, matching text, or task assignment.

Output is allowlisted rather than denylist-redacted. Run and task IDs must be canonical lowercase UUIDs, task short IDs use a narrow `E-00104`-style form, statuses use an explicit own closed set, and profile aliases use the configured `accountNNN` form. Timestamps must be strict RFC3339 with an explicit timezone and are emitted as canonical UTC; ambiguous locale strings and missing, invalid, or future observations fail closed. Future live-agent sources must also reject stale liveness evidence. Provider-controlled titles, paths, branches, last-tool text, goal text, raw diagnostics, account IDs, credential labels or values, signed URI components, query or fragment values, and nonprinting Unicode controls are omitted. Human cells are truncated by grapheme cluster.

List coverage remains explicitly unknown until a provider exposes a side-effect-free source limit. Future safe sources may perform at most one bounded operation per selected source, must use the default output limit of 50 and hard maximum of 200, and must mark any source or result truncation `partial: true` with known or unknown dropped coverage. TAI never persists agent data, initializes a provider, mutates locks or tasks, inspects transcripts or prompts, calls a provider once per result, switches profiles, or owns agent lifecycle state.

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

Canonical public repository: https://github.com/hasna/tai. Publishing `@hasna/tai` or creating a GitHub release requires explicit maintainer approval.
