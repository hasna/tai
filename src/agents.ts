import { spawn } from "node:child_process";

export const AGENTS_SCHEMA_VERSION = 1 as const;
export const DEFAULT_AGENTS_LIMIT = 50;
export const MAX_AGENTS_LIMIT = 200;

const DEFAULT_HTTP_TIMEOUT_MS = 5_000;
const DEFAULT_HTTP_BYTES = 1024 * 1024;
const DEFAULT_PROCESS_TIMEOUT_MS = 15_000;
const DEFAULT_PROCESS_STDOUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_PROCESS_STDERR_BYTES = 16 * 1024;
const EARLIEST_VALID_TIME_MS = Date.parse("2000-01-01T00:00:00.000Z");

const PROVIDERS = ["codewith", "claude", "todos"] as const;
const ACTIVE_STATUSES = new Set(["idle", "in_progress", "running"]);
const STATUS_PRECEDENCE: Readonly<Record<string, number>> = {
  running: 80,
  in_progress: 70,
  idle: 60,
  blocked: 50,
  pending: 40,
  succeeded: 30,
  completed: 30,
  failed: 20,
  stopped: 10,
  cancelled: 10,
  unknown: 0
};

export type AgentProvider = (typeof PROVIDERS)[number];
export type AgentSourceStatus = "ok" | "partial" | "unavailable" | "error";

export interface AgentSourceError {
  code: string;
  message: string;
}

export interface AgentSourceCoverage {
  complete: boolean;
  provider_records: number | null;
  projected_records: number;
  dropped_records: number | null;
}

export interface AgentSource {
  provider: AgentProvider;
  status: AgentSourceStatus;
  freshness_at: string | null;
  coverage: AgentSourceCoverage;
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

export interface ProviderHttpRequest {
  provider: AgentProvider;
  method: "GET";
  url: string;
  headers: Readonly<Record<string, string>>;
  timeoutMs: number;
  maxBytes: number;
}

export interface ProviderHttpResult {
  status: number | null;
  body: string;
  failure?: "network-error" | "output-limit" | "timeout";
}

export type ProviderHttpRunner = (request: ProviderHttpRequest) => Promise<ProviderHttpResult>;

export interface ProviderProcessRequest {
  command: string;
  args: string[];
  timeoutMs?: number;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ProviderProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  failure?: "not-found" | "output-limit" | "spawn-error" | "timeout";
}

export interface CollectAgentsOptions {
  env?: Readonly<Record<string, string | undefined>>;
  httpRunner?: ProviderHttpRunner;
  limit?: number;
  now?: () => Date;
}

export interface AgentsCliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

interface ParsedAgentsArguments {
  json: boolean;
  limit: number;
  limitSpecified: boolean;
  mode: "list" | "show";
  id: string | null;
}

interface ProviderCollection {
  source: AgentSource;
  agents: AgentRecord[];
}

interface TodosConfig {
  baseUrl: URL;
  apiKey: string | null;
}

interface NormalizedStatus {
  value: string;
  active: boolean;
  complete: boolean;
}

export async function collectAgentVisibility(
  options: CollectAgentsOptions = {}
): Promise<AgentsEnvelope> {
  const now = options.now ?? (() => new Date());
  const generatedAt = safeNow(now);
  const limit = validateLimit(options.limit ?? DEFAULT_AGENTS_LIMIT);
  const collections = await Promise.all(
    PROVIDERS.map((provider) => collectProvider(provider, null, options, now))
  );
  const sources = collections.map(({ source }) => source);
  const allAgents = sortAgents(dedupeAgents(collections.flatMap(({ agents }) => agents)));
  const visibleAgents = allAgents.slice(0, limit);
  applyResultLimitCoverage(sources, allAgents, visibleAgents);

  return {
    schema_version: AGENTS_SCHEMA_VERSION,
    generated_at: generatedAt,
    partial: sources.some(({ status, coverage }) => status !== "ok" || !coverage.complete),
    sources,
    agents: visibleAgents
  };
}

export async function runAgentsCli(
  args: string[],
  options: CollectAgentsOptions = {}
): Promise<AgentsCliResult> {
  const now = options.now ?? (() => new Date());
  const generatedAt = safeNow(now);
  let parsed: ParsedAgentsArguments;

  try {
    parsed = parseAgentsArguments(args);
  } catch {
    return cliError(
      2,
      args.includes("--json"),
      errorEnvelope(generatedAt, {
        code: "invalid-arguments",
        message:
          "Usage: tai agents [--json] [--limit <1-200>] | tai agents show <provider>:<run-id> [--json]."
      })
    );
  }

  const parsedId = parsed.mode === "show" ? parseAgentId(parsed.id) : null;
  if (parsed.mode === "show" && !parsedId) {
    return cliError(
      2,
      parsed.json,
      errorEnvelope(generatedAt, {
        code: "invalid-agent-id",
        message: "Agent ID must use <codewith|claude|todos>:<safe-run-id>."
      })
    );
  }

  if (parsed.mode === "show" && parsed.limitSpecified) {
    return cliError(
      2,
      parsed.json,
      errorEnvelope(generatedAt, {
        code: "invalid-arguments",
        message: "--limit is not valid for an exact agent lookup."
      })
    );
  }

  if (parsed.mode === "show" && parsedId) {
    const collection = await collectProvider(parsedId.provider, parsedId.runId, options, now);
    const envelope: AgentsEnvelope = {
      schema_version: AGENTS_SCHEMA_VERSION,
      generated_at: generatedAt,
      partial:
        collection.source.status !== "ok" || !collection.source.coverage.complete,
      sources: [collection.source],
      agents: sortAgents(dedupeAgents(collection.agents))
    };
    const agent = envelope.agents.find(({ id }) => id === parsed.id);

    if (agent) {
      envelope.agents = [agent];
      return {
        exitCode: 0,
        stdout: parsed.json
          ? JSON.stringify(envelope, null, 2)
          : formatAgentDetails(agent, envelope.sources),
        stderr: ""
      };
    }

    if (
      collection.source.status === "ok" &&
      collection.source.coverage.complete &&
      collection.source.coverage.dropped_records === 0
    ) {
      envelope.error = {
        code: "agent-not-found",
        message: "The selected provider proved that no exact agent record exists."
      };
      return cliError(4, parsed.json, envelope);
    }

    envelope.error = {
      code: "agent-lookup-incomplete",
      message: "The selected provider could not prove an exact lookup result."
    };
    return cliError(5, parsed.json, envelope);
  }

  const envelope = await collectAgentVisibility({ ...options, limit: parsed.limit, now });
  if (!envelope.sources.some(({ status }) => status === "ok" || status === "partial")) {
    envelope.error = {
      code: "all-sources-unavailable",
      message: "No side-effect-free authoritative agent source is configured."
    };
    return parsed.json
      ? cliError(3, true, envelope)
      : {
          exitCode: 3,
          stdout: formatAgentsTable(envelope),
          stderr: `error: ${envelope.error.message}`
        };
  }

  return {
    exitCode: 0,
    stdout: parsed.json ? JSON.stringify(envelope, null, 2) : formatAgentsTable(envelope),
    stderr: ""
  };
}

export function formatAgentsTable(envelope: AgentsEnvelope): string {
  const widths = [23, 46, 12, 28, 20, 24];
  const headers = [
    "STATUS",
    "PROVIDER/RUN",
    "WORKTREE",
    "TASK/GOAL",
    "LAST TOOL",
    "FRESHNESS"
  ];
  const rows = envelope.agents.map((agent) => {
    const status = safeOutputStatus(agent.status);
    const active = agent.active && ACTIVE_STATUSES.has(status);
    return [
      `${active ? "active" : "inactive"}:${status}`,
      safeOutputAgentId(agent.id),
      "—",
      formatTaskGoal(agent),
      "—",
      safeOutputTimestamp(agent.freshness_at)
    ];
  });
  const lines = [
    headers.map((value, index) => fitCell(value, widths[index] ?? 20)).join("  "),
    ...rows.map((row) =>
      row.map((value, index) => fitCell(value, widths[index] ?? 20)).join("  ")
    )
  ];

  if (envelope.agents.length === 0) {
    lines.push("No safely projectable agents found.");
  }

  const warnings = envelope.sources.flatMap((source) => {
    if (
      !PROVIDERS.includes(source.provider) ||
      (source.status === "ok" && source.coverage.complete)
    ) {
      return [];
    }
    return [
      `${source.provider}=${safeSourceStatus(source.status)}${
        source.error ? `:${safeDiagnosticCode(source.error.code)}` : ""
      }`
    ];
  });
  if (warnings.length > 0) {
    lines.push(`WARNING incomplete sources: ${warnings.join(", ")}`);
  }

  return lines.join("\n");
}

export function dedupeAgents(agents: AgentRecord[]): AgentRecord[] {
  const deduped = new Map<string, AgentRecord>();
  for (const candidate of agents) {
    const current = deduped.get(candidate.id);
    if (!current || compareObservations(candidate, current) < 0) {
      deduped.set(candidate.id, candidate);
    }
  }
  return [...deduped.values()];
}

export function sortAgents(agents: AgentRecord[]): AgentRecord[] {
  return [...agents].sort((left, right) => {
    if (left.active !== right.active) {
      return left.active ? -1 : 1;
    }
    const observationOrder = compareObservationTime(left, right);
    if (observationOrder !== 0) {
      return observationOrder;
    }
    return left.id.localeCompare(right.id);
  });
}

export async function runBoundedProviderProcess(
  request: ProviderProcessRequest
): Promise<ProviderProcessResult> {
  const timeoutMs = positiveBound(request.timeoutMs, DEFAULT_PROCESS_TIMEOUT_MS);
  const maxStdoutBytes = positiveBound(
    request.maxStdoutBytes,
    DEFAULT_PROCESS_STDOUT_BYTES
  );
  const maxStderrBytes = positiveBound(
    request.maxStderrBytes,
    DEFAULT_PROCESS_STDERR_BYTES
  );

  return await new Promise((resolve) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    const child = spawn(request.command, request.args, {
      cwd: request.cwd,
      detached: process.platform !== "win32",
      env: request.env ?? process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });

    const finish = (
      exitCode: number | null,
      failure?: ProviderProcessResult["failure"]
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        exitCode,
        ...(failure ? { failure } : {})
      });
    };

    const terminateGroup = (failure: "output-limit" | "timeout"): void => {
      if (settled) {
        return;
      }
      if (child.pid && process.platform !== "win32") {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // The process group may already be gone.
        }
      }
      try {
        child.kill("SIGKILL");
      } catch {
        // The direct child may already be gone.
      }
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
      finish(null, failure);
    };

    const timer = setTimeout(() => terminateGroup("timeout"), timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdout.length + chunk.length > maxStdoutBytes) {
        terminateGroup("output-limit");
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length + chunk.length > maxStderrBytes) {
        terminateGroup("output-limit");
        return;
      }
      stderr = Buffer.concat([stderr, chunk]);
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      finish(null, error.code === "ENOENT" ? "not-found" : "spawn-error");
    });
    child.on("close", (exitCode) => finish(exitCode));
  });
}

async function collectProvider(
  provider: AgentProvider,
  exactRunId: string | null,
  options: CollectAgentsOptions,
  now: () => Date
): Promise<ProviderCollection> {
  if (provider === "codewith" || provider === "claude") {
    return unsupportedCollection(
      provider,
      "side-effect-free-surface-unavailable",
      `No side-effect-free structured ${provider} agent read surface is configured.`
    );
  }
  return await collectTodos(exactRunId, options, now);
}

async function collectTodos(
  exactRunId: string | null,
  options: CollectAgentsOptions,
  now: () => Date
): Promise<ProviderCollection> {
  if (!exactRunId) {
    return unsupportedCollection(
      "todos",
      "side-effect-free-source-limit-unavailable",
      "Todos has no side-effect-free source-level bounded list surface."
    );
  }
  const env = options.env ?? process.env;
  const config = resolveTodosConfig(env);
  if (!config) {
    return unsupportedCollection(
      "todos",
      "side-effect-free-surface-unavailable",
      "No side-effect-free Todos API is configured."
    );
  }

  const url = buildTodosUrl(config.baseUrl, exactRunId);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (config.apiKey) {
    headers["x-api-key"] = config.apiKey;
  }
  const result = await (options.httpRunner ?? runBoundedHttpRequest)({
    provider: "todos",
    method: "GET",
    url,
    headers,
    timeoutMs: DEFAULT_HTTP_TIMEOUT_MS,
    maxBytes: DEFAULT_HTTP_BYTES
  });
  const observedAt = safeNow(now);

  if (result.failure) {
    const failureMessages: Record<
      NonNullable<ProviderHttpResult["failure"]>,
      AgentSourceError
    > = {
      "network-error": {
        code: "provider-network-error",
        message: "The side-effect-free Todos API request failed."
      },
      "output-limit": {
        code: "provider-output-limit",
        message: "The side-effect-free Todos API exceeded the response byte limit."
      },
      timeout: {
        code: "provider-timeout",
        message: "The side-effect-free Todos API exceeded the wall-clock limit."
      }
    };
    return failedCollection("todos", observedAt, failureMessages[result.failure]);
  }

  if (exactRunId && result.status === 404) {
    return {
      source: {
        provider: "todos",
        status: "ok",
        freshness_at: observedAt,
        coverage: {
          complete: true,
          provider_records: 0,
          projected_records: 0,
          dropped_records: 0
        }
      },
      agents: []
    };
  }

  if (result.status === null || result.status < 200 || result.status >= 300) {
    return failedCollection("todos", observedAt, {
      code: "provider-http-error",
      message: "The side-effect-free Todos API returned a non-success status."
    });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(result.body) as unknown;
  } catch {
    return failedCollection("todos", observedAt, {
      code: "provider-invalid-json",
      message: "The side-effect-free Todos API returned invalid JSON."
    });
  }

  return normalizeTodosExact(payload, exactRunId, observedAt);
}

function normalizeTodosExact(
  payload: unknown,
  exactRunId: string,
  observedAt: string
): ProviderCollection {
  if (!isRecord(payload) || !isRecord(payload.task)) {
    return failedCollection("todos", observedAt, {
      code: "provider-invalid-payload",
      message: "The side-effect-free Todos API returned an unsupported exact record."
    });
  }
  const raw = payload.task;
  if (safeUuid(raw.id) !== exactRunId) {
    return failedCollection("todos", observedAt, {
      code: "provider-identity-mismatch",
      message: "The side-effect-free Todos API returned a different exact record."
    });
  }
  if (!hasTodosAgentProvenance(raw, observedAt)) {
    return {
      source: {
        provider: "todos",
        status: "partial",
        freshness_at: observedAt,
        coverage: {
          complete: true,
          provider_records: 1,
          projected_records: 0,
          dropped_records: 1
        },
        error: {
          code: "agent-provenance-missing",
          message: "The exact Todos task has no authoritative agent, session, or live lease provenance."
        }
      },
      agents: []
    };
  }
  const record = normalizeTodosTask(raw, observedAt);
  if (!record) {
    return {
      source: {
        provider: "todos",
        status: "partial",
        freshness_at: observedAt,
        coverage: {
          complete: false,
          provider_records: 1,
          projected_records: 0,
          dropped_records: 1
        },
        error: {
          code: "record-withheld",
          message: "The exact Todos record did not satisfy the safe-output contract."
        }
      },
      agents: []
    };
  }
  const incomplete = record.gaps.length > 0;
  return {
    source: {
      provider: "todos",
      status: incomplete ? "partial" : "ok",
      freshness_at: observedAt,
      coverage: {
        complete: true,
        provider_records: 1,
        projected_records: 1,
        dropped_records: 0
      },
      ...(incomplete
        ? {
            error: {
              code: "normalized-fields-unavailable",
              message: "The exact Todos record has explicit unavailable normalized fields."
            }
          }
        : {})
    },
    agents: [record]
  };
}

function normalizeTodosTask(
  raw: Record<string, unknown>,
  observedAt: string
): AgentRecord | null {
  const runId = safeUuid(raw.id);
  if (!runId) {
    return null;
  }
  const observedAtMs = Date.parse(observedAt);
  const status = normalizeStatus(raw.status);
  let startedAt = normalizeTimestamp(raw.started_at ?? raw.created_at, observedAtMs);
  const updatedAt = normalizeTimestamp(raw.updated_at ?? raw.synced_at, observedAtMs);
  if (startedAt && updatedAt && Date.parse(startedAt) > Date.parse(updatedAt)) {
    startedAt = null;
  }
  const metadata = isRecord(raw.metadata) ? raw.metadata : {};
  const shortId = safeShortId(raw.short_id);
  const profileAlias = safeProfileAlias(raw.profile_alias ?? metadata.profile_alias);
  const gaps: string[] = [];

  if (!status.complete) gaps.push("status");
  if (!startedAt) gaps.push("started_at");
  if (!updatedAt) gaps.push("updated_at");
  gaps.push(
    "worktree",
    "branch",
    "last_tool_call.name",
    "last_tool_call.at",
    "last_tool_call.summary",
    "goal.id",
    "goal.title",
    "goal.status"
  );
  if (!shortId) gaps.push("task.short_id");
  gaps.push("task.title");
  if (!status.complete) gaps.push("task.status");
  if (!profileAlias) gaps.push("profile.alias");
  if (!updatedAt) gaps.push("freshness_at");

  return {
    id: `todos:${runId}`,
    provider: "todos",
    run_id: runId,
    status: status.value,
    active: status.active,
    started_at: startedAt,
    updated_at: updatedAt,
    worktree: null,
    branch: null,
    last_tool_call: { name: null, at: null, summary: null },
    goal: { id: null, title: null, status: null },
    task: {
      id: runId,
      short_id: shortId,
      title: null,
      status: status.complete ? status.value : null
    },
    profile: { alias: profileAlias },
    freshness_at: updatedAt,
    gaps: [...new Set(gaps)].sort()
  };
}

function hasTodosAgentProvenance(
  raw: Record<string, unknown>,
  observedAt: string
): boolean {
  const metadata = isRecord(raw.metadata) ? raw.metadata : {};
  const directValues = [
    raw.agent_id,
    raw.session_id,
    raw.runner_id,
    metadata.agent_id,
    metadata.session_id,
    metadata.run_id
  ];
  if (directValues.some(hasOpaqueProvenanceValue)) {
    return true;
  }

  const leaseOwner = raw.locked_by ?? metadata.locked_by;
  const leaseExpiry = raw.lock_expires_at ?? metadata.lock_expires_at;
  if (!hasOpaqueProvenanceValue(leaseOwner)) {
    return false;
  }
  const expiryMs = parseTimestampMs(leaseExpiry);
  const observedMs = Date.parse(observedAt);
  return (
    expiryMs !== null &&
    expiryMs >= observedMs &&
    expiryMs <= observedMs + 24 * 60 * 60 * 1000
  );
}

function hasOpaqueProvenanceValue(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    value.trim() === value &&
    !NONPRINTING_PATTERN.test(value)
  );
}

function normalizeStatus(value: unknown): NormalizedStatus {
  if (typeof value !== "string") {
    return { value: "unknown", active: false, complete: false };
  }
  const candidate = value.trim().toLowerCase();
  if (candidate === "unknown" || !(candidate in STATUS_PRECEDENCE)) {
    return { value: "unknown", active: false, complete: false };
  }
  return {
    value: candidate,
    active: ACTIVE_STATUSES.has(candidate),
    complete: true
  };
}

function normalizeTimestamp(value: unknown, observedAtMs: number): string | null {
  const milliseconds = parseTimestampMs(value);
  if (
    milliseconds === null ||
    milliseconds < EARLIEST_VALID_TIME_MS ||
    milliseconds > observedAtMs
  ) {
    return null;
  }
  return new Date(milliseconds).toISOString();
}

function parseTimestampMs(value: unknown): number | null {
  let milliseconds: number;
  if (typeof value === "number" && Number.isFinite(value)) {
    milliseconds = value > 10_000_000_000 ? value : value * 1000;
  } else if (typeof value === "string" && value.trim() !== "") {
    const numeric = Number(value);
    milliseconds = Number.isFinite(numeric)
      ? numeric > 10_000_000_000
        ? numeric
        : numeric * 1000
      : Date.parse(value);
  } else {
    return null;
  }
  return Number.isFinite(milliseconds) ? milliseconds : null;
}

function safeUuid(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const candidate = value.toLowerCase();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    candidate
  )
    ? candidate
    : null;
}

function safeShortId(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  return /^[A-Z][A-Z0-9]{0,7}-[0-9]{1,8}$/.test(value) ? value : null;
}

function safeProfileAlias(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  return /^account[0-9]{3}$/.test(value) ? value : null;
}

function resolveTodosConfig(
  env: Readonly<Record<string, string | undefined>>
): TodosConfig | null {
  const rawBaseUrl = env.TODOS_URL ?? env.TODOS_API_URL;
  if (!rawBaseUrl) {
    return null;
  }
  let baseUrl: URL;
  try {
    baseUrl = new URL(rawBaseUrl);
  } catch {
    return null;
  }
  if (
    (baseUrl.protocol !== "https:" &&
      !(baseUrl.protocol === "http:" && isLoopbackHostname(baseUrl.hostname))) ||
    baseUrl.username !== "" ||
    baseUrl.password !== "" ||
    baseUrl.search !== "" ||
    baseUrl.hash !== ""
  ) {
    return null;
  }
  return {
    baseUrl,
    apiKey: env.TODOS_API_KEY || null
  };
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function buildTodosUrl(baseUrl: URL, exactRunId: string): string {
  const url = new URL(baseUrl.toString());
  const prefix = url.pathname.replace(/\/+$/, "");
  url.pathname = `${prefix}/v1/tasks/${encodeURIComponent(exactRunId)}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

export async function runBoundedHttpRequest(
  request: ProviderHttpRequest
): Promise<ProviderHttpResult> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, request.timeoutMs);

  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      signal: controller.signal,
      redirect: "error"
    });
    if (!response.body) {
      return { status: response.status, body: "" };
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) {
        break;
      }
      bytes += item.value.byteLength;
      if (bytes > request.maxBytes) {
        controller.abort();
        await reader.cancel().catch(() => undefined);
        return { status: response.status, body: "", failure: "output-limit" };
      }
      chunks.push(item.value);
    }
    return {
      status: response.status,
      body: Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8")
    };
  } catch {
    return {
      status: null,
      body: "",
      failure: timedOut ? "timeout" : "network-error"
    };
  } finally {
    clearTimeout(timer);
  }
}

function unsupportedCollection(
  provider: AgentProvider,
  code: string,
  message: string
): ProviderCollection {
  return {
    source: {
      provider,
      status: "unavailable",
      freshness_at: null,
      coverage: {
        complete: false,
        provider_records: null,
        projected_records: 0,
        dropped_records: null
      },
      error: { code, message }
    },
    agents: []
  };
}

function failedCollection(
  provider: AgentProvider,
  observedAt: string,
  error: AgentSourceError
): ProviderCollection {
  return {
    source: {
      provider,
      status: "error",
      freshness_at: observedAt,
      coverage: {
        complete: false,
        provider_records: null,
        projected_records: 0,
        dropped_records: null
      },
      error
    },
    agents: []
  };
}

function applyResultLimitCoverage(
  sources: AgentSource[],
  allAgents: AgentRecord[],
  visibleAgents: AgentRecord[]
): void {
  if (visibleAgents.length === allAgents.length) {
    return;
  }
  const visibleIds = new Set(visibleAgents.map(({ id }) => id));
  for (const source of sources) {
    const sourceAgents = allAgents.filter(({ provider }) => provider === source.provider);
    const visibleSourceAgents = sourceAgents.filter(({ id }) => visibleIds.has(id));
    const omitted = sourceAgents.length - visibleSourceAgents.length;
    if (omitted <= 0) {
      continue;
    }
    source.status = "partial";
    source.coverage = {
      ...source.coverage,
      complete: false,
      projected_records: visibleSourceAgents.length,
      dropped_records:
        source.coverage.dropped_records === null
          ? null
          : source.coverage.dropped_records + omitted
    };
    source.error ??= {
      code: "result-limit-applied",
      message: "The requested result limit omitted safely projectable records."
    };
  }
}

function compareObservations(left: AgentRecord, right: AgentRecord): number {
  const timeOrder = compareObservationTime(left, right);
  if (timeOrder !== 0) {
    return timeOrder;
  }
  const statusOrder =
    (STATUS_PRECEDENCE[right.status] ?? 0) - (STATUS_PRECEDENCE[left.status] ?? 0);
  if (statusOrder !== 0) {
    return statusOrder;
  }
  return canonicalRecord(left).localeCompare(canonicalRecord(right));
}

function compareObservationTime(left: AgentRecord, right: AgentRecord): number {
  return observationTime(right) - observationTime(left);
}

function observationTime(agent: AgentRecord): number {
  for (const value of [agent.updated_at, agent.freshness_at, agent.started_at]) {
    const parsed = value ? Date.parse(value) : Number.NaN;
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return Number.NEGATIVE_INFINITY;
}

function canonicalRecord(agent: AgentRecord): string {
  return JSON.stringify(agent);
}

function parseAgentsArguments(args: string[]): ParsedAgentsArguments {
  let json = false;
  let limit = DEFAULT_AGENTS_LIMIT;
  let limitSpecified = false;
  const positionals: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] ?? "";
    if (argument === "--json") {
      json = true;
      continue;
    }
    if (argument === "--limit") {
      const value = args[index + 1];
      if (!value) throw new Error("invalid limit");
      limit = validateLimit(Number(value));
      limitSpecified = true;
      index += 1;
      continue;
    }
    if (argument.startsWith("--limit=")) {
      limit = validateLimit(Number(argument.slice("--limit=".length)));
      limitSpecified = true;
      continue;
    }
    if (argument.startsWith("-")) {
      throw new Error("unknown option");
    }
    positionals.push(argument);
  }

  if (positionals.length === 0 || (positionals.length === 1 && positionals[0] === "list")) {
    return { json, limit, limitSpecified, mode: "list", id: null };
  }
  if (positionals.length === 2 && positionals[0] === "show") {
    return {
      json,
      limit,
      limitSpecified,
      mode: "show",
      id: positionals[1] ?? null
    };
  }
  throw new Error("invalid arguments");
}

function validateLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_AGENTS_LIMIT) {
    throw new Error("invalid limit");
  }
  return value;
}

function parseAgentId(
  value: string | null
): { provider: AgentProvider; runId: string } | null {
  if (!value) {
    return null;
  }
  const separator = value.indexOf(":");
  if (separator <= 0 || separator !== value.lastIndexOf(":")) {
    return null;
  }
  const provider = value.slice(0, separator);
  const runId = safeUuid(value.slice(separator + 1));
  return PROVIDERS.includes(provider as AgentProvider) && runId
    ? { provider: provider as AgentProvider, runId }
    : null;
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

function cliError(
  exitCode: number,
  json: boolean,
  envelope: AgentsEnvelope
): AgentsCliResult {
  return {
    exitCode,
    stdout: json ? JSON.stringify(envelope, null, 2) : "",
    stderr: json ? "" : `error: ${envelope.error?.message ?? "Agent visibility failed."}`
  };
}

function formatTaskGoal(agent: AgentRecord): string {
  const shortId = safeShortId(agent.task.short_id);
  if (shortId) {
    return shortId;
  }
  const taskId = safeUuid(agent.task.id);
  if (taskId) {
    return taskId;
  }
  const goalId = safeUuid(agent.goal.id);
  if (goalId) {
    return goalId;
  }
  return "—";
}

function formatAgentDetails(agent: AgentRecord, sources: AgentSource[]): string {
  const safeStatus = safeOutputStatus(agent.status);
  const safeGaps = agent.gaps.filter((gap) => SAFE_GAP_NAMES.has(gap)).sort();
  return [
    `Agent: ${safeOutputAgentId(agent.id)}`,
    `Status: ${safeStatus} (${agent.active && ACTIVE_STATUSES.has(safeStatus) ? "active" : "inactive"})`,
    `Started: ${safeOutputTimestamp(agent.started_at)}`,
    `Updated: ${safeOutputTimestamp(agent.updated_at)}`,
    "Worktree: —",
    "Branch: —",
    `Task: ${formatTaskGoal(agent)}`,
    `Goal: ${safeUuid(agent.goal.id) ?? "—"}`,
    "Last tool: —",
    `Profile: ${safeProfileAlias(agent.profile.alias) ?? "—"}`,
    `Freshness: ${safeOutputTimestamp(agent.freshness_at)}`,
    `Gaps: ${safeGaps.length > 0 ? safeGaps.join(", ") : "none"}`,
    "Sources:",
    ...sources.flatMap((source) =>
      PROVIDERS.includes(source.provider)
        ? [
            `  ${source.provider}: ${safeSourceStatus(source.status)}${
              source.error ? ` (${safeDiagnosticCode(source.error.code)})` : ""
            }`
          ]
        : []
    )
  ].join("\n");
}

function safeOutputAgentId(value: unknown): string {
  if (typeof value !== "string") {
    return "—";
  }
  const parsed = parseAgentId(value);
  return parsed && `${parsed.provider}:${parsed.runId}` === value ? value : "—";
}

function safeOutputStatus(value: unknown): string {
  return normalizeStatus(value).value;
}

function safeOutputTimestamp(value: unknown): string {
  if (typeof value !== "string") {
    return "—";
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) &&
    parsed >= EARLIEST_VALID_TIME_MS &&
    parsed <= Date.now() &&
    new Date(parsed).toISOString() === value
    ? value
    : "—";
}

function safeSourceStatus(value: unknown): AgentSourceStatus {
  return value === "ok" ||
    value === "partial" ||
    value === "unavailable" ||
    value === "error"
    ? value
    : "error";
}

function safeDiagnosticCode(value: unknown): string {
  return typeof value === "string" && SAFE_DIAGNOSTIC_CODES.has(value)
    ? value
    : "diagnostic-withheld";
}

function fitCell(value: string, width: number): string {
  const graphemes = [...new Intl.Segmenter("en", { granularity: "grapheme" }).segment(value)].map(
    ({ segment }) => segment
  );
  const fitted =
    graphemes.length <= width
      ? value
      : `${graphemes.slice(0, Math.max(0, width - 1)).join("")}…`;
  const fittedLength = [
    ...new Intl.Segmenter("en", { granularity: "grapheme" }).segment(fitted)
  ].length;
  return fitted.padEnd(fitted.length + Math.max(0, width - fittedLength), " ");
}

function safeNow(now: () => Date): string {
  const value = now();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return new Date(0).toISOString();
  }
  return value.toISOString();
}

function positiveBound(value: number | undefined, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const NONPRINTING_PATTERN =
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u0080-\u009f\u200b\u202a-\u202e\u2066-\u2069]/u;

const SAFE_GAP_NAMES = new Set([
  "branch",
  "freshness_at",
  "goal.id",
  "goal.status",
  "goal.title",
  "last_tool_call.at",
  "last_tool_call.name",
  "last_tool_call.summary",
  "profile.alias",
  "started_at",
  "status",
  "task.short_id",
  "task.status",
  "task.title",
  "updated_at",
  "worktree"
]);

const SAFE_DIAGNOSTIC_CODES = new Set([
  "agent-provenance-missing",
  "diagnostic-withheld",
  "normalized-fields-unavailable",
  "provider-http-error",
  "provider-identity-mismatch",
  "provider-invalid-json",
  "provider-invalid-payload",
  "provider-network-error",
  "provider-output-limit",
  "provider-timeout",
  "record-withheld",
  "result-limit-applied",
  "side-effect-free-source-limit-unavailable",
  "side-effect-free-surface-unavailable"
]);
