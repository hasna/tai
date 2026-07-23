import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";

export const AGENTS_SCHEMA_VERSION = 1 as const;
export const DEFAULT_AGENTS_LIMIT = 50;
export const MAX_AGENTS_LIMIT = 200;

const DEFAULT_PROCESS_TIMEOUT_MS = 15_000;
const DEFAULT_PROCESS_STDOUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_PROCESS_STDERR_BYTES = 16 * 1024;
const PROCESS_TERMINATION_RESERVE_MS = 250;
const EARLIEST_VALID_TIME_MS = Date.parse("2000-01-01T00:00:00.000Z");
const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

const PROVIDERS = ["codewith", "claude", "todos"] as const;
const ACTIVE_STATUSES = new Set(["idle", "in_progress", "running"]);
const STATUS_PRECEDENCE = new Map<string, number>([
  ["running", 80],
  ["in_progress", 70],
  ["idle", 60],
  ["blocked", 50],
  ["pending", 40],
  ["succeeded", 30],
  ["completed", 30],
  ["failed", 20],
  ["stopped", 10],
  ["cancelled", 10]
]);

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
    PROVIDERS.map((provider) => collectProvider(provider, null))
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
    const collection = await collectProvider(parsedId.provider, parsedId.runId);
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
    const active = isSafelyActive(agent);
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
    const leftActive = isSafelyActive(left);
    const rightActive = isSafelyActive(right);
    if (leftActive !== rightActive) {
      return leftActive ? -1 : 1;
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
    let terminating = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | null = null;
    let cleanupTimer: ReturnType<typeof setTimeout> | null = null;
    let descendantTimer: ReturnType<typeof setInterval> | null = null;
    const trackedDescendants = new Map<number, string>();
    const scopeId = randomUUID();
    const cleanupGraceMs = Math.min(50, Math.max(1, Math.floor(timeoutMs / 4)));
    const terminationReserveMs =
      timeoutMs >= 1_000
        ? Math.min(PROCESS_TERMINATION_RESERVE_MS, Math.max(1, timeoutMs - 1))
        : cleanupGraceMs;
    const child = spawn(request.command, request.args, {
      cwd: request.cwd,
      detached: process.platform !== "win32",
      env: {
        ...(request.env ?? process.env),
        TAI_PROVIDER_PROCESS_SCOPE: scopeId
      },
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
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
      }
      if (cleanupTimer) {
        clearTimeout(cleanupTimer);
      }
      if (descendantTimer) {
        clearInterval(descendantTimer);
      }
      resolve({
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        exitCode,
        ...(failure ? { failure } : {})
      });
    };

    const finishTermination = (
      failure: "output-limit" | "timeout",
      knownDescendants: number[]
    ): void => {
      if (settled || !terminating) {
        return;
      }
      const descendants = child.pid
        ? [
            ...new Set([
              ...knownDescendants,
              ...collectDescendantPids(child.pid)
            ])
          ]
        : knownDescendants;
      killPids(descendants);
      killTrackedPids(trackedDescendants);
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

    const beginTermination = (failure: "output-limit" | "timeout"): void => {
      if (settled || terminating) {
        return;
      }
      terminating = true;
      if (child.pid && process.platform !== "win32") {
        try {
          process.kill(-child.pid, "SIGSTOP");
        } catch {
          // The process group may already be gone.
        }
      }
      if (timeoutMs >= 1_000) {
        mergeTrackedPids(trackedDescendants, collectScopedProcesses(scopeId));
      }
      const descendants = child.pid
        ? collectDescendantPids(child.pid)
        : [];
      killPids(descendants);
      killTrackedPids(trackedDescendants);
      cleanupTimer = setTimeout(
        () => finishTermination(failure, descendants),
        cleanupGraceMs
      );
    };

    deadlineTimer = setTimeout(
      () => beginTermination("timeout"),
      Math.max(1, timeoutMs - terminationReserveMs)
    );
    const trackDescendants = (): void => {
      if (!child.pid || terminating) {
        return;
      }
      for (const pid of collectDescendantPids(child.pid)) {
        const startTime = readProcessStartTime(pid);
        if (startTime) {
          trackedDescendants.set(pid, startTime);
        }
      }
    };
    trackDescendants();
    descendantTimer = setInterval(trackDescendants, 2);
    descendantTimer.unref();

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdout.length + chunk.length > maxStdoutBytes) {
        beginTermination("output-limit");
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length + chunk.length > maxStderrBytes) {
        beginTermination("output-limit");
        return;
      }
      stderr = Buffer.concat([stderr, chunk]);
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      finish(null, error.code === "ENOENT" ? "not-found" : "spawn-error");
    });
    child.on("close", (exitCode) => {
      if (!terminating) {
        terminating = true;
        mergeTrackedPids(trackedDescendants, collectScopedProcesses(scopeId));
        killTrackedPids(trackedDescendants);
        cleanupTimer = setTimeout(() => {
          finish(exitCode);
        }, cleanupGraceMs);
      }
    });
  });
}

function collectDescendantPids(rootPid: number): number[] {
  if (process.platform !== "linux") {
    return [];
  }
  const pending = [rootPid];
  const seen = new Set<number>([rootPid]);
  const descendants: number[] = [];
  while (pending.length > 0) {
    const parentPid = pending.shift();
    if (!parentPid) {
      continue;
    }
    let children = "";
    try {
      children = readFileSync(
        `/proc/${parentPid}/task/${parentPid}/children`,
        "utf8"
      );
    } catch {
      continue;
    }
    for (const token of children.trim().split(/\s+/)) {
      const childPid = Number(token);
      if (
        !Number.isSafeInteger(childPid) ||
        childPid <= 1 ||
        childPid === process.pid ||
        seen.has(childPid)
      ) {
        continue;
      }
      seen.add(childPid);
      descendants.push(childPid);
      pending.push(childPid);
    }
  }
  return descendants.reverse();
}

function readProcessStartTime(pid: number): string | null {
  if (process.platform !== "linux") {
    return null;
  }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
    return fields[19] ?? null;
  } catch {
    return null;
  }
}

function collectScopedProcesses(scopeId: string): Map<number, string> {
  const matches = new Map<number, string>();
  if (process.platform !== "linux") {
    return matches;
  }
  const marker = Buffer.from(`TAI_PROVIDER_PROCESS_SCOPE=${scopeId}\0`);
  let entries: string[];
  try {
    entries = readdirSync("/proc");
  } catch {
    return matches;
  }
  for (const entry of entries) {
    if (!/^[0-9]+$/.test(entry)) {
      continue;
    }
    const pid = Number(entry);
    if (!Number.isSafeInteger(pid) || pid <= 1 || pid === process.pid) {
      continue;
    }
    let environment: Buffer | null = null;
    try {
      environment = readFileSync(`/proc/${pid}/environ`);
      if (!environment.includes(marker)) {
        continue;
      }
      const startTime = readProcessStartTime(pid);
      if (startTime) {
        matches.set(pid, startTime);
      }
    } catch {
      // The process may have exited or may not expose its environment.
    } finally {
      environment?.fill(0);
    }
  }
  return matches;
}

function mergeTrackedPids(
  target: Map<number, string>,
  source: ReadonlyMap<number, string>
): void {
  for (const [pid, startTime] of source) {
    target.set(pid, startTime);
  }
}

function killTrackedPids(tracked: ReadonlyMap<number, string>): void {
  for (const [pid, expectedStartTime] of tracked) {
    if (readProcessStartTime(pid) !== expectedStartTime) {
      continue;
    }
    killPids([pid]);
  }
}

function killPids(pids: number[]): void {
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // A descendant may have exited between the process-tree snapshot and kill.
    }
  }
}

async function collectProvider(
  provider: AgentProvider,
  exactRunId: string | null
): Promise<ProviderCollection> {
  if (provider === "codewith" || provider === "claude") {
    return unsupportedCollection(
      provider,
      "side-effect-free-surface-unavailable",
      `No side-effect-free structured ${provider} agent read surface is configured.`
    );
  }
  return collectTodos(exactRunId);
}

function collectTodos(exactRunId: string | null): ProviderCollection {
  if (!exactRunId) {
    return unsupportedCollection(
      "todos",
      "side-effect-free-source-limit-unavailable",
      "Todos has no side-effect-free source-level bounded list surface."
    );
  }
  return unsupportedCollection(
    "todos",
    "side-effect-free-surface-unavailable",
    "Todos has no demonstrably side-effect-free structured exact-read surface."
  );
}

function normalizeStatus(value: unknown): NormalizedStatus {
  if (typeof value !== "string") {
    return { value: "unknown", active: false, complete: false };
  }
  const candidate = value.trim().toLowerCase();
  if (candidate === "unknown" || !STATUS_PRECEDENCE.has(candidate)) {
    return { value: "unknown", active: false, complete: false };
  }
  return {
    value: candidate,
    active: ACTIVE_STATUSES.has(candidate),
    complete: true
  };
}

function parseTimestampMs(value: unknown): number | null {
  if (typeof value !== "string") {
    return null;
  }
  const match = RFC3339_PATTERN.exec(value);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[8] ?? "";
  if (
    year < 2000 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > new Date(Date.UTC(year, month, 0)).getUTCDate() ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  if (zone !== "Z") {
    const zoneHour = Number(zone.slice(1, 3));
    const zoneMinute = Number(zone.slice(4, 6));
    if (zoneHour > 23 || zoneMinute > 59) {
      return null;
    }
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? milliseconds : null;
}

function safeUuid(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    value
  )
    ? value
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
    (STATUS_PRECEDENCE.get(right.status) ?? 0) -
    (STATUS_PRECEDENCE.get(left.status) ?? 0);
  if (statusOrder !== 0) {
    return statusOrder;
  }
  return canonicalRecord(left).localeCompare(canonicalRecord(right));
}

function compareObservationTime(left: AgentRecord, right: AgentRecord): number {
  const leftTime = observationTime(left);
  const rightTime = observationTime(right);
  if (leftTime === rightTime) {
    return 0;
  }
  return leftTime > rightTime ? -1 : 1;
}

function observationTime(agent: AgentRecord): number {
  for (const value of [agent.updated_at, agent.freshness_at, agent.started_at]) {
    const parsed = parseTimestampMs(value);
    if (parsed !== null && parsed <= Date.now()) {
      return parsed;
    }
  }
  return Number.NEGATIVE_INFINITY;
}

function isSafelyActive(agent: AgentRecord): boolean {
  const status = normalizeStatus(agent.status);
  return (
    agent.active &&
    status.complete &&
    status.active &&
    observationTime(agent) !== Number.NEGATIVE_INFINITY
  );
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
  const active = isSafelyActive(agent);
  return [
    `Agent: ${safeOutputAgentId(agent.id)}`,
    `Status: ${safeStatus} (${active ? "active" : "inactive"})`,
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
  const parsed = parseTimestampMs(value);
  return parsed !== null &&
    parsed >= EARLIEST_VALID_TIME_MS &&
    parsed <= Date.now()
    ? new Date(parsed).toISOString()
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
