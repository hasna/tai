import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";
import { redactSensitiveText } from "./redaction";

export const AGENTS_SCHEMA_VERSION = 1 as const;
export const DEFAULT_AGENTS_LIMIT = 50;
export const MAX_AGENTS_LIMIT = 200;

const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const PROVIDER_TIMEOUT_MS = 15_000;

export type AgentProvider = "codewith" | "claude" | "todos";
export type AgentSourceStatus = "ok" | "partial" | "unavailable" | "error";

export interface AgentSourceError {
  code: string;
  message: string;
}

export interface AgentSource {
  provider: AgentProvider;
  status: AgentSourceStatus;
  freshness_at: string | null;
  error?: AgentSourceError;
}

export interface AgentRecord {
  id: string;
  provider: AgentProvider;
  run_id: string;
  status: string;
  active: boolean;
  started_at: string | null;
  updated_at: string | null;
  worktree: string | null;
  branch: string | null;
  last_tool_call: {
    name: string | null;
    at: string | null;
    summary: string | null;
  };
  goal: {
    id: string | null;
    title: string | null;
    status: string | null;
  };
  task: {
    id: string | null;
    short_id: string | null;
    title: string | null;
    status: string | null;
  };
  profile: {
    alias: string | null;
  };
  freshness_at: string | null;
  gaps: string[];
}

export interface AgentsEnvelope {
  schema_version: typeof AGENTS_SCHEMA_VERSION;
  generated_at: string;
  partial: boolean;
  sources: AgentSource[];
  agents: AgentRecord[];
  error?: AgentSourceError;
}

export interface ProviderCommand {
  provider: AgentProvider;
  command: string;
  args: string[];
}

export interface ProviderCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  failure?: "not-found" | "timeout" | "output-limit" | "spawn-error";
}

export type ProviderCommandRunner = (command: ProviderCommand) => Promise<ProviderCommandResult>;

export interface CollectAgentsOptions {
  runner?: ProviderCommandRunner;
  now?: () => Date;
}

export interface AgentsCliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

interface ProviderCollection {
  source: AgentSource;
  agents: AgentRecord[];
}

interface NormalizeResult {
  agents: AgentRecord[];
  skipped: number;
}

interface ParsedAgentsArguments {
  json: boolean;
  limit: number;
  mode: "list" | "show";
  id: string | null;
}

const PROVIDER_COMMANDS: ProviderCommand[] = [
  {
    provider: "codewith",
    command: "codewith",
    args: ["agent", "list", "--json", "--limit", String(MAX_AGENTS_LIMIT)]
  },
  {
    provider: "claude",
    command: "claude",
    args: ["agents", "--json"]
  },
  {
    provider: "todos",
    command: "todos",
    args: ["active", "--json"]
  }
];

export async function collectAgentVisibility(options: CollectAgentsOptions = {}): Promise<AgentsEnvelope> {
  const runner = options.runner ?? runProviderCommand;
  const generatedAt = (options.now ?? (() => new Date()))().toISOString();
  const collections = await Promise.all(
    PROVIDER_COMMANDS.map((command) => collectProvider(command, runner, generatedAt))
  );
  const sources = collections.map(({ source }) => source);
  const agents = sortAgents(dedupeAgents(collections.flatMap((collection) => collection.agents)));

  return {
    schema_version: AGENTS_SCHEMA_VERSION,
    generated_at: generatedAt,
    partial: sources.some(({ status }) => status !== "ok"),
    sources,
    agents
  };
}

export async function runAgentsCli(
  args: string[],
  options: CollectAgentsOptions = {}
): Promise<AgentsCliResult> {
  const generatedAt = (options.now ?? (() => new Date()))().toISOString();
  let parsed: ParsedAgentsArguments;

  try {
    parsed = parseAgentsArguments(args);
  } catch (error) {
    const diagnostic = makeDiagnostic("invalid-arguments", error);
    const json = args.includes("--json");
    return {
      exitCode: 2,
      stdout: json ? JSON.stringify(errorEnvelope(generatedAt, diagnostic), null, 2) : "",
      stderr: json ? "" : `error: ${diagnostic.message}`
    };
  }

  if (parsed.mode === "show" && !isValidAgentId(parsed.id)) {
    const diagnostic: AgentSourceError = {
      code: "invalid-agent-id",
      message: "Agent ID must use <codewith|claude|todos>:<run-id>."
    };
    return {
      exitCode: 2,
      stdout: parsed.json ? JSON.stringify(errorEnvelope(generatedAt, diagnostic), null, 2) : "",
      stderr: parsed.json ? "" : `error: ${diagnostic.message}`
    };
  }

  const envelope = await collectAgentVisibility(options);
  const availableSources = envelope.sources.filter(
    ({ status }) => status === "ok" || status === "partial"
  );

  if (availableSources.length === 0) {
    const diagnostic: AgentSourceError = {
      code: "all-sources-failed",
      message: "No authoritative agent source is currently available."
    };
    const failedEnvelope = { ...envelope, error: diagnostic };
    return {
      exitCode: 3,
      stdout: parsed.json ? JSON.stringify(failedEnvelope, null, 2) : "",
      stderr: parsed.json ? "" : `error: ${diagnostic.message}`
    };
  }

  if (parsed.mode === "show") {
    const agent = envelope.agents.find(({ id }) => id === parsed.id);
    if (!agent) {
      const diagnostic: AgentSourceError = {
        code: "agent-not-found",
        message: "No normalized agent record matched the requested ID."
      };
      const unknownEnvelope: AgentsEnvelope = { ...envelope, agents: [], error: diagnostic };
      return {
        exitCode: 4,
        stdout: parsed.json ? JSON.stringify(unknownEnvelope, null, 2) : "",
        stderr: parsed.json ? "" : `error: ${diagnostic.message}`
      };
    }

    const showEnvelope: AgentsEnvelope = { ...envelope, agents: [agent] };
    return {
      exitCode: 0,
      stdout: parsed.json ? JSON.stringify(showEnvelope, null, 2) : formatAgentDetails(agent, envelope.sources),
      stderr: ""
    };
  }

  const limitedEnvelope: AgentsEnvelope = {
    ...envelope,
    agents: envelope.agents.slice(0, parsed.limit)
  };
  return {
    exitCode: 0,
    stdout: parsed.json ? JSON.stringify(limitedEnvelope, null, 2) : formatAgentsTable(limitedEnvelope),
    stderr: ""
  };
}

export function formatAgentsTable(envelope: AgentsEnvelope): string {
  const rows = envelope.agents.map((agent) => [
    `${agent.active ? "active" : "inactive"}:${agent.status}`,
    agent.id,
    agent.worktree ?? "—",
    formatTaskGoal(agent),
    agent.last_tool_call.name ?? "—",
    agent.freshness_at ?? "—"
  ]);
  const widths = [24, 36, 36, 30, 22, 24];
  const headers = ["STATUS", "PROVIDER/RUN", "WORKTREE", "TASK/GOAL", "LAST TOOL", "FRESHNESS"];
  const lines = [
    headers.map((value, index) => padCell(value, widths[index] ?? value.length)).join("  "),
    rows
      .map((row) => row.map((value, index) => padCell(value, widths[index] ?? value.length)).join("  "))
      .join("\n")
  ].filter(Boolean);

  if (envelope.agents.length === 0) {
    lines.push("No agents found.");
  }

  const warnings = envelope.sources
    .filter(({ status }) => status !== "ok")
    .map((source) => `${source.provider}=${source.status}${source.error ? `:${source.error.code}` : ""}`);
  if (warnings.length > 0) {
    lines.push(`WARNING partial sources: ${warnings.join(", ")}`);
  }

  return lines.join("\n");
}

export function dedupeAgents(agents: AgentRecord[]): AgentRecord[] {
  const deduped = new Map<string, AgentRecord>();
  for (const agent of agents) {
    const current = deduped.get(agent.id);
    if (!current || compareFreshness(agent, current) < 0) {
      deduped.set(agent.id, agent);
    }
  }
  return [...deduped.values()];
}

export function sortAgents(agents: AgentRecord[]): AgentRecord[] {
  return [...agents].sort(compareFreshness);
}

function compareFreshness(left: AgentRecord, right: AgentRecord): number {
  if (left.active !== right.active) {
    return left.active ? -1 : 1;
  }
  const leftTime = Date.parse(left.updated_at ?? "");
  const rightTime = Date.parse(right.updated_at ?? "");
  const normalizedLeft = Number.isFinite(leftTime) ? leftTime : Number.NEGATIVE_INFINITY;
  const normalizedRight = Number.isFinite(rightTime) ? rightTime : Number.NEGATIVE_INFINITY;
  if (normalizedLeft !== normalizedRight) {
    return normalizedRight - normalizedLeft;
  }
  return left.id.localeCompare(right.id);
}

async function collectProvider(
  command: ProviderCommand,
  runner: ProviderCommandRunner,
  generatedAt: string
): Promise<ProviderCollection> {
  let result: ProviderCommandResult;
  try {
    result = await runner(command);
  } catch (error) {
    return failedCollection(command.provider, "provider-execution-error", error, "error");
  }

  if (result.failure) {
    const errorByFailure: Record<
      NonNullable<ProviderCommandResult["failure"]>,
      { code: string; message: string; status: AgentSourceStatus }
    > = {
      "not-found": {
        code: "provider-command-unavailable",
        message: `${command.provider} command is not installed or discoverable.`,
        status: "unavailable"
      },
      timeout: {
        code: "provider-timeout",
        message: `${command.provider} did not respond within the bounded timeout.`,
        status: "error"
      },
      "output-limit": {
        code: "provider-output-limit",
        message: `${command.provider} exceeded the bounded output limit.`,
        status: "error"
      },
      "spawn-error": {
        code: "provider-spawn-error",
        message: `Unable to execute the ${command.provider} read-only surface.`,
        status: "error"
      }
    };
    const failure = errorByFailure[result.failure];
    return failedCollection(command.provider, failure.code, failure.message, failure.status);
  }

  if (result.exitCode !== 0) {
    const message = sanitizeDiagnostic(result.stderr) || `${command.provider} returned a nonzero exit.`;
    return failedCollection(command.provider, "provider-nonzero-exit", message, "error");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(result.stdout) as unknown;
  } catch {
    return failedCollection(
      command.provider,
      "provider-invalid-json",
      `${command.provider} returned invalid JSON.`,
      "error"
    );
  }

  let normalized: NormalizeResult;
  try {
    normalized = normalizeProvider(command.provider, payload, generatedAt);
  } catch {
    return failedCollection(
      command.provider,
      "provider-invalid-payload",
      `${command.provider} returned an unsupported JSON shape.`,
      "error"
    );
  }

  if (normalized.skipped > 0) {
    return {
      source: {
        provider: command.provider,
        status: "partial",
        freshness_at: generatedAt,
        error: {
          code: "provider-records-skipped",
          message: `${normalized.skipped} malformed provider record(s) were skipped.`
        }
      },
      agents: normalized.agents
    };
  }

  return {
    source: {
      provider: command.provider,
      status: "ok",
      freshness_at: generatedAt
    },
    agents: normalized.agents
  };
}

function normalizeProvider(
  provider: AgentProvider,
  payload: unknown,
  sourceFreshness: string
): NormalizeResult {
  switch (provider) {
    case "codewith":
      return normalizeCodewith(payload, sourceFreshness);
    case "claude":
      return normalizeClaude(payload, sourceFreshness);
    case "todos":
      return normalizeTodos(payload, sourceFreshness);
  }
}

function normalizeCodewith(payload: unknown, sourceFreshness: string): NormalizeResult {
  if (!isRecord(payload) || !Array.isArray(payload.data)) {
    throw new Error("unsupported Codewith payload");
  }
  const agents: AgentRecord[] = [];
  let skipped = 0;

  for (const raw of payload.data.slice(0, MAX_AGENTS_LIMIT)) {
    if (!isRecord(raw)) {
      skipped += 1;
      continue;
    }
    const runId = safeOpaqueId(raw.agentId);
    if (!runId) {
      skipped += 1;
      continue;
    }
    const status = boundedText(raw.status, 64) ?? "unknown";
    const updatedAt = latestTimestamp(raw.updatedAt, raw.heartbeatAt);
    const profileAlias = safeProfileAlias(raw.authProfileRef);
    const gaps = [
      "worktree unavailable from Codewith list surface",
      "branch unavailable from Codewith list surface",
      "last_tool_call unavailable from Codewith list surface",
      "goal unavailable from Codewith list surface",
      "task unavailable from Codewith list surface"
    ];
    if (status === "unknown") {
      gaps.push("status unavailable from Codewith list surface");
    }
    if (!updatedAt) {
      gaps.push("updated_at unavailable from Codewith list surface");
    }
    if (!profileAlias) {
      gaps.push(
        raw.authProfileRef == null
          ? "profile unavailable from Codewith list surface"
          : "profile reference withheld because it is not a safe alias"
      );
    }

    agents.push({
      id: `codewith:${runId}`,
      provider: "codewith",
      run_id: runId,
      status,
      active: isActiveStatus(status),
      started_at: normalizeTimestamp(raw.startedAt ?? raw.createdAt),
      updated_at: updatedAt,
      worktree: null,
      branch: null,
      last_tool_call: emptyLastToolCall(),
      goal: emptyGoal(),
      task: emptyTask(),
      profile: { alias: profileAlias },
      freshness_at: updatedAt ?? sourceFreshness,
      gaps
    });
  }

  return { agents, skipped };
}

function normalizeClaude(payload: unknown, sourceFreshness: string): NormalizeResult {
  if (!Array.isArray(payload)) {
    throw new Error("unsupported Claude payload");
  }
  const agents: AgentRecord[] = [];
  let skipped = 0;

  for (const raw of payload.slice(0, MAX_AGENTS_LIMIT)) {
    if (!isRecord(raw)) {
      skipped += 1;
      continue;
    }
    const runId = safeOpaqueId(raw.sessionId ?? raw.id);
    if (!runId) {
      skipped += 1;
      continue;
    }
    const status = boundedText(raw.status ?? raw.state, 64) ?? "unknown";
    const worktree = safeAbsolutePath(raw.cwd);
    const gaps = [
      "updated_at unavailable from Claude agents surface",
      "branch unavailable from Claude agents surface",
      "last_tool_call unavailable from Claude agents surface",
      "goal unavailable from Claude agents surface",
      "task unavailable from Claude agents surface",
      "profile unavailable from Claude agents surface",
      "agent freshness unavailable; using source observation time"
    ];
    if (status === "unknown") {
      gaps.push("status unavailable from Claude agents surface");
    }
    if (!worktree) {
      gaps.push("worktree unavailable from Claude agents surface");
    }

    agents.push({
      id: `claude:${runId}`,
      provider: "claude",
      run_id: runId,
      status,
      active: !isTerminalStatus(status),
      started_at: normalizeTimestamp(raw.startedAt),
      updated_at: null,
      worktree,
      branch: null,
      last_tool_call: emptyLastToolCall(),
      goal: emptyGoal(),
      task: emptyTask(),
      profile: { alias: null },
      freshness_at: sourceFreshness,
      gaps
    });
  }

  return { agents, skipped };
}

function normalizeTodos(payload: unknown, sourceFreshness: string): NormalizeResult {
  if (!Array.isArray(payload)) {
    throw new Error("unsupported Todos payload");
  }
  const agents: AgentRecord[] = [];
  let skipped = 0;

  for (const raw of payload.slice(0, MAX_AGENTS_LIMIT)) {
    if (!isRecord(raw)) {
      skipped += 1;
      continue;
    }
    const runId = safeOpaqueId(raw.id);
    if (!runId) {
      skipped += 1;
      continue;
    }
    const status = boundedText(raw.status, 64) ?? "unknown";
    const metadata = isRecord(raw.metadata) ? raw.metadata : {};
    const worktree = safeAbsolutePath(raw.working_dir ?? metadata.worktree);
    const branch = safeBranch(metadata.branch);
    const updatedAt = normalizeTimestamp(raw.updated_at ?? raw.synced_at);
    const gaps = [
      "last_tool_call unavailable from Todos active surface",
      "goal unavailable from Todos active surface",
      "profile unavailable from Todos active surface"
    ];
    if (status === "unknown") {
      gaps.push("status unavailable from Todos active surface");
    }
    if (!worktree) {
      gaps.push("worktree unavailable from Todos active surface");
    }
    if (!branch) {
      gaps.push("branch unavailable from Todos active surface");
    }
    if (!updatedAt) {
      gaps.push("updated_at unavailable from Todos active surface");
    }

    agents.push({
      id: `todos:${runId}`,
      provider: "todos",
      run_id: runId,
      status,
      active: !isTerminalStatus(status),
      started_at: normalizeTimestamp(raw.started_at ?? raw.created_at),
      updated_at: updatedAt,
      worktree,
      branch,
      last_tool_call: emptyLastToolCall(),
      goal: emptyGoal(),
      task: {
        id: runId,
        short_id: boundedText(raw.short_id, 40),
        title: boundedText(raw.title, 120),
        status
      },
      profile: { alias: null },
      freshness_at: updatedAt ?? sourceFreshness,
      gaps
    });
  }

  return { agents, skipped };
}

function failedCollection(
  provider: AgentProvider,
  code: string,
  message: unknown,
  status: AgentSourceStatus
): ProviderCollection {
  return {
    source: {
      provider,
      status,
      freshness_at: null,
      error: makeDiagnostic(code, message)
    },
    agents: []
  };
}

function errorEnvelope(generatedAt: string, error: AgentSourceError): AgentsEnvelope {
  return {
    schema_version: AGENTS_SCHEMA_VERSION,
    generated_at: generatedAt,
    partial: true,
    sources: [],
    agents: [],
    error
  };
}

function makeDiagnostic(code: string, value: unknown): AgentSourceError {
  const raw = value instanceof Error ? value.message : String(value);
  return {
    code,
    message: sanitizeDiagnostic(raw) || "Provider visibility failed without a safe diagnostic."
  };
}

function sanitizeDiagnostic(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  return bound(
    redactVisibilitySecrets(value)
      .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
      .replace(/\/(?:home|Users)\/[^/\s]+/g, "~")
      .replace(/[\u0000-\u001f\u007f]+/g, " ")
      .replace(/\s+/g, " ")
      .trim(),
    200
  );
}

function boundedText(value: unknown, maximum: number): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const sanitized = redactVisibilitySecrets(value)
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return sanitized ? bound(sanitized, maximum) : null;
}

function safeOpaqueId(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return /^[A-Za-z0-9._-]{1,256}$/.test(trimmed) && redactVisibilitySecrets(trimmed) === trimmed
    ? trimmed
    : null;
}

function safeProfileAlias(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (
    !/^[A-Za-z][A-Za-z0-9._-]{0,31}$/.test(trimmed) ||
    /^(?:sk|gh[pousr]|token|secret|key|auth|cred)[._-]/i.test(trimmed) ||
    /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(trimmed) ||
    redactVisibilitySecrets(trimmed) !== trimmed
  ) {
    return null;
  }
  return trimmed;
}

function redactVisibilitySecrets(value: string): string {
  return redactSensitiveText(value)
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_ANTHROPIC_KEY]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[REDACTED_JWT]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]")
    .replace(/(https?:\/\/)[^/\s:@]+:[^@\s]+@/gi, "$1[REDACTED]@");
}

function safeAbsolutePath(value: unknown): string | null {
  if (typeof value !== "string" || !isAbsolute(value) || value.length > 512) {
    return null;
  }
  if (
    /(?:^|\/)\.(?:ssh|aws|config|codewith|claude)(?:\/|$)/i.test(value) ||
    /(?:^|\/)(?:secrets?|credentials?)(?:\/|$)/i.test(value) ||
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(value) ||
    redactVisibilitySecrets(value) !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return null;
  }
  return value;
}

function safeBranch(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return /^[A-Za-z0-9._/-]{1,200}$/.test(trimmed) && redactVisibilitySecrets(trimmed) === trimmed
    ? trimmed
    : null;
}

function normalizeTimestamp(value: unknown): string | null {
  let milliseconds: number;
  if (typeof value === "number" && Number.isFinite(value)) {
    milliseconds = value > 10_000_000_000 ? value : value * 1000;
  } else if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    milliseconds = Number.isFinite(numeric)
      ? numeric > 10_000_000_000
        ? numeric
        : numeric * 1000
      : Date.parse(value);
  } else {
    return null;
  }
  if (!Number.isFinite(milliseconds)) {
    return null;
  }
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function latestTimestamp(...values: unknown[]): string | null {
  const timestamps = values
    .map(normalizeTimestamp)
    .filter((value): value is string => value !== null)
    .sort((left, right) => Date.parse(right) - Date.parse(left));
  return timestamps[0] ?? null;
}

function isTerminalStatus(status: string): boolean {
  return /^(?:cancelled|completed|done|failed|stopped|terminated|archived|succeeded)$/i.test(status);
}

function isActiveStatus(status: string): boolean {
  return !isTerminalStatus(status);
}

function emptyLastToolCall(): AgentRecord["last_tool_call"] {
  return { name: null, at: null, summary: null };
}

function emptyGoal(): AgentRecord["goal"] {
  return { id: null, title: null, status: null };
}

function emptyTask(): AgentRecord["task"] {
  return { id: null, short_id: null, title: null, status: null };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bound(value: string, maximum: number): string {
  if (value.length <= maximum) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maximum - 1))}…`;
}

function parseAgentsArguments(args: string[]): ParsedAgentsArguments {
  let json = false;
  let limit = DEFAULT_AGENTS_LIMIT;
  const positionals: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] ?? "";
    if (argument === "--json") {
      json = true;
      continue;
    }
    if (argument === "--limit") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("--limit requires an integer.");
      }
      limit = parseLimit(value);
      index += 1;
      continue;
    }
    if (argument.startsWith("--limit=")) {
      limit = parseLimit(argument.slice("--limit=".length));
      continue;
    }
    if (argument.startsWith("-")) {
      throw new Error(`Unknown option: ${argument}`);
    }
    positionals.push(argument);
  }

  if (positionals.length === 0 || (positionals.length === 1 && positionals[0] === "list")) {
    return { json, limit, mode: "list", id: null };
  }
  if (positionals[0] === "show" && positionals.length === 2) {
    return { json, limit, mode: "show", id: positionals[1] ?? null };
  }
  throw new Error("Usage: tai agents [--json] [--limit <1-200>] | tai agents show <provider>:<run-id> [--json]");
}

function parseLimit(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error("--limit must be an integer between 1 and 200.");
  }
  const parsed = Number(value);
  if (parsed < 1 || parsed > MAX_AGENTS_LIMIT) {
    throw new Error("--limit must be between 1 and 200.");
  }
  return parsed;
}

function isValidAgentId(value: string | null): value is string {
  if (!value) {
    return false;
  }
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) {
    return false;
  }
  const provider = value.slice(0, separator);
  const runId = value.slice(separator + 1);
  return (
    (provider === "codewith" || provider === "claude" || provider === "todos") &&
    safeOpaqueId(runId) === runId
  );
}

function formatTaskGoal(agent: AgentRecord): string {
  if (agent.task.id) {
    return bound(`${agent.task.short_id ?? agent.task.id} ${agent.task.title ?? ""}`.trim(), 30);
  }
  if (agent.goal.id) {
    return bound(`${agent.goal.id} ${agent.goal.title ?? ""}`.trim(), 30);
  }
  return "—";
}

function formatAgentDetails(agent: AgentRecord, sources: AgentSource[]): string {
  const sourceLines = sources.map(
    (source) =>
      `  ${source.provider}: ${source.status}${source.error ? ` (${source.error.code})` : ""}`
  );
  return [
    `Agent: ${agent.id}`,
    `Status: ${agent.status} (${agent.active ? "active" : "inactive"})`,
    `Started: ${agent.started_at ?? "—"}`,
    `Updated: ${agent.updated_at ?? "—"}`,
    `Worktree: ${agent.worktree ?? "—"}`,
    `Branch: ${agent.branch ?? "—"}`,
    `Task: ${agent.task.id ? `${agent.task.short_id ?? agent.task.id} ${agent.task.title ?? ""}`.trim() : "—"}`,
    `Goal: ${agent.goal.id ? `${agent.goal.id} ${agent.goal.title ?? ""}`.trim() : "—"}`,
    `Last tool: ${agent.last_tool_call.name ?? "—"}`,
    `Profile: ${agent.profile.alias ?? "—"}`,
    `Freshness: ${agent.freshness_at ?? "—"}`,
    `Gaps: ${agent.gaps.length > 0 ? agent.gaps.join("; ") : "none"}`,
    "Sources:",
    ...sourceLines
  ].join("\n");
}

function padCell(value: string, width: number): string {
  return bound(value, width).padEnd(width, " ");
}

async function runProviderCommand(command: ProviderCommand): Promise<ProviderCommandResult> {
  return await new Promise((resolve) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let failure: ProviderCommandResult["failure"];
    let resolved = false;
    const child = spawn(command.command, command.args, {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });

    const finish = (exitCode: number | null): void => {
      if (resolved) {
        return;
      }
      resolved = true;
      clearTimeout(timer);
      resolve({
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        exitCode,
        ...(failure ? { failure } : {})
      });
    };

    const timer = setTimeout(() => {
      failure = "timeout";
      child.kill("SIGKILL");
    }, PROVIDER_TIMEOUT_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdout.length + chunk.length > MAX_STDOUT_BYTES) {
        failure = "output-limit";
        child.kill("SIGKILL");
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = MAX_STDERR_BYTES - stderr.length;
      if (remaining > 0) {
        stderr = Buffer.concat([stderr, chunk.subarray(0, remaining)]);
      }
    });

    child.on("error", (error: NodeJS.ErrnoException) => {
      failure = error.code === "ENOENT" ? "not-found" : "spawn-error";
      finish(null);
    });
    child.on("close", (exitCode) => finish(exitCode));
  });
}
