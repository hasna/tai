import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AGENTS_SCHEMA_VERSION,
  collectAgentVisibility,
  dedupeAgents,
  formatAgentsTable,
  runAgentsCli,
  runBoundedHttpRequest,
  runBoundedProviderProcess,
  type AgentRecord,
  type ProviderHttpRequest,
  type ProviderHttpResult,
  type ProviderHttpRunner
} from "../src/agents";

const REQUEST_AT = new Date("2026-07-23T12:00:00.000Z");
const OBSERVED_AT = new Date("2026-07-23T12:00:05.000Z");
const TODOS_ENV = {
  TODOS_URL: "https://todos.example.test",
  TODOS_API_KEY: "test-only-key"
};

function uuid(index: number): string {
  return `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

function task(
  index: number,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    id: uuid(index),
    short_id: `E-${String(index).padStart(5, "0")}`,
    title: `Task ${index}`,
    status: "in_progress",
    started_at: "2026-07-23T10:00:00.000Z",
    updated_at: "2026-07-23T11:00:00.000Z",
    agent_id: uuid(index + 10_000),
    ...overrides
  };
}

function listResult(
  tasks: unknown[],
  total = tasks.length,
  status = 200
): ProviderHttpResult {
  return {
    status,
    body: JSON.stringify({ tasks, count: tasks.length, total })
  };
}

function exactResult(value: unknown, status = 200): ProviderHttpResult {
  return {
    status,
    body: JSON.stringify({ task: value })
  };
}

function fakeHttp(
  resultOrHandler:
    | ProviderHttpResult
    | ((request: ProviderHttpRequest) => ProviderHttpResult | Promise<ProviderHttpResult>)
): { runner: ProviderHttpRunner; calls: ProviderHttpRequest[] } {
  const calls: ProviderHttpRequest[] = [];
  return {
    calls,
    runner: async (request) => {
      calls.push(request);
      return typeof resultOrHandler === "function"
        ? await resultOrHandler(request)
        : resultOrHandler;
    }
  };
}

function fixedNow(): Date {
  return REQUEST_AT;
}

function sequenceNow(...values: Date[]): () => Date {
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)] ?? REQUEST_AT;
}

function normalizedAgent(overrides: Partial<AgentRecord> = {}): AgentRecord {
  const id = overrides.run_id ?? uuid(1);
  return {
    id: `todos:${id}`,
    provider: "todos",
    run_id: id,
    status: "running",
    active: true,
    started_at: "2026-07-23T10:00:00.000Z",
    updated_at: "2026-07-23T11:00:00.000Z",
    worktree: null,
    branch: null,
    last_tool_call: { name: null, at: null, summary: null },
    goal: { id: null, title: null, status: null },
    task: { id, short_id: "E-00104", title: null, status: "running" },
    profile: { alias: null },
    freshness_at: "2026-07-23T11:00:00.000Z",
    gaps: [],
    ...overrides
  };
}

describe("side-effect-free provider selection", () => {
  test("does not invoke mutating installed CLIs when no safe source is configured", async () => {
    const http = fakeHttp(listResult([]));
    const envelope = await collectAgentVisibility({
      env: {},
      httpRunner: http.runner,
      now: fixedNow
    });

    expect(http.calls).toHaveLength(0);
    expect(envelope.partial).toBe(true);
    expect(envelope.agents).toEqual([]);
    expect(envelope.sources.map(({ provider, status }) => [provider, status])).toEqual([
      ["codewith", "unavailable"],
      ["claude", "unavailable"],
      ["todos", "unavailable"]
    ]);
    expect(envelope.sources.every(({ coverage }) => coverage.complete === false)).toBe(true);
  });

  test("keeps Todos list unavailable because no side-effect-free source limit exists", async () => {
    const http = fakeHttp(listResult([task(1)]));
    const envelope = await collectAgentVisibility({
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: sequenceNow(REQUEST_AT, OBSERVED_AT)
    });

    expect(http.calls).toHaveLength(0);
    const source = envelope.sources.find(({ provider }) => provider === "todos");
    expect(source?.status).toBe("unavailable");
    expect(source?.error?.code).toBe("side-effect-free-source-limit-unavailable");
    expect(source?.coverage).toEqual({
      complete: false,
      provider_records: null,
      projected_records: 0,
      dropped_records: null
    });
  });

  test("rejects credential-bearing or signed API base URLs without executing a request", async () => {
    for (const baseUrl of [
      "https://user:pass@todos.example.test",
      "https://todos.example.test?signature=value",
      "https://todos.example.test#credential",
      "http://todos.example.test"
    ]) {
      const http = fakeHttp(listResult([]));
      const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
        env: { TODOS_URL: baseUrl },
        httpRunner: http.runner,
        now: fixedNow
      });
      expect(http.calls).toHaveLength(0);
      expect(response.exitCode).toBe(5);
      expect(response.stdout).not.toContain("signature");
      expect(response.stdout).not.toContain("credential");
      expect(response.stdout).not.toContain("user");
    }
  });

  test("black-box CLI leaves provider homes untouched when safe APIs are absent", () => {
    const root = mkdtempSync(join(tmpdir(), "tai-agents-side-effects-"));
    const environment = { ...process.env };
    delete environment.TODOS_URL;
    delete environment.TODOS_API_URL;
    delete environment.TODOS_API_KEY;
    environment.HOME = root;
    environment.XDG_CONFIG_HOME = join(root, "xdg-config");
    environment.XDG_DATA_HOME = join(root, "xdg-data");
    environment.XDG_CACHE_HOME = join(root, "xdg-cache");

    try {
      const child = spawnSync(
        process.execPath,
        ["run", "src/cli/index.ts", "agents", "--json"],
        {
          cwd: process.cwd(),
          env: environment,
          encoding: "utf8",
          timeout: 5_000
        }
      );
      expect(child.status).toBe(3);
      expect(JSON.parse(child.stdout).error.code).toBe("all-sources-unavailable");
      expect(existsSync(join(root, ".codewith"))).toBe(false);
      expect(existsSync(join(root, ".claude"))).toBe(false);
      expect(existsSync(join(root, ".hasna", "todos"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("strict safe-output normalization", () => {
  test("omits all uncontrolled text, paths, credential metadata, and unsafe aliases", async () => {
    const hostile = [
      "X-API-Key secret-value",
      "Authorization Bearer secret-value",
      "--token secret-value",
      "AWS_SECRET_ACCESS_KEY secret-value",
      "https://user:pass@example.test/path?signature=secret#fragment",
      "/home/private-user/.env",
      "\u009b\u202e\u2066\u200b\u2028\u2029"
    ].join(" ");
    const hostileTask = task(1, {
      title: hostile,
      working_dir: hostile,
      branch: hostile,
      account_id: uuid(99),
      profile_alias: "prod-secret",
      metadata: {
        profile_alias: "prod-secret",
        last_tool: hostile,
        goal_title: hostile
      }
    });
    const http = fakeHttp(exactResult(hostileTask));
    const json = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const human = await runAgentsCli(["show", `todos:${uuid(1)}`], {
      env: TODOS_ENV,
      httpRunner: fakeHttp(exactResult(hostileTask)).runner,
      now: fixedNow
    });

    for (const output of [json.stdout, human.stdout]) {
      expect(output).not.toContain("secret-value");
      expect(output).not.toContain("private-user");
      expect(output).not.toContain("signature");
      expect(output).not.toContain("fragment");
      expect(output).not.toContain("prod-secret");
      expect(output).not.toContain(uuid(99));
      expect(output).not.toMatch(/[\u0080-\u009f\u200b\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);
    }

    const envelope = JSON.parse(json.stdout);
    const agent = envelope.agents[0];
    expect(agent.task.title).toBeNull();
    expect(agent.worktree).toBeNull();
    expect(agent.branch).toBeNull();
    expect(agent.profile.alias).toBeNull();
    expect(agent.gaps).toEqual(
      expect.arrayContaining(["task.title", "worktree", "branch", "profile.alias"])
    );
  });

  test("allows only an explicit safe configured profile alias form", async () => {
    const safe = fakeHttp(exactResult(task(1, { profile_alias: "account001" })));
    const unsafe = fakeHttp(exactResult(task(1, { profile_alias: "account-id-123" })));

    const safeResponse = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: safe.runner,
      now: fixedNow
    });
    const unsafeResponse = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: unsafe.runner,
      now: fixedNow
    });
    const safeEnvelope = JSON.parse(safeResponse.stdout);
    const unsafeEnvelope = JSON.parse(unsafeResponse.stdout);

    expect(safeEnvelope.agents[0]?.profile.alias).toBe("account001");
    expect(unsafeEnvelope.agents[0]?.profile.alias).toBeNull();
    expect(JSON.stringify(unsafeEnvelope)).not.toContain("account-id-123");
  });

  test("withholds secret-like opaque IDs instead of projecting them", async () => {
    const secretLikeId = ["glpat", "abcdefghijklmnopqrst"].join("-");
    const http = fakeHttp(
      exactResult({
        ...task(1),
        id: secretLikeId
      })
    );
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(5);
    expect(envelope.agents).toHaveLength(0);
    expect(JSON.stringify(envelope)).not.toContain(secretLikeId);
    expect(envelope.sources[0].error.code).toBe("provider-identity-mismatch");
  });

  test("never projects raw HTTP failure bodies as diagnostics", async () => {
    const raw = JSON.stringify({
      error: "Authorization Bearer secret-value",
      password: "secret-value",
      account_id: uuid(99)
    });
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: fakeHttp({ status: 500, body: raw }).runner,
      now: fixedNow
    });

    expect(response.exitCode).toBe(5);
    expect(response.stdout).not.toContain("secret-value");
    expect(response.stdout).not.toContain(uuid(99));
    expect(JSON.parse(response.stdout).sources[0].error.code).toBe("provider-http-error");
  });

  test("human formatting revalidates normalized fields instead of trusting callers", () => {
    const hostile = "secret-value\u202e";
    const malicious = normalizedAgent({
      id: hostile,
      run_id: hostile,
      status: hostile,
      active: true,
      updated_at: "9999-12-31T23:59:59.000Z",
      freshness_at: "9999-12-31T23:59:59.000Z",
      task: { id: hostile, short_id: hostile, title: hostile, status: hostile },
      profile: { alias: hostile },
      gaps: [hostile]
    });
    const output = formatAgentsTable({
      schema_version: 1,
      generated_at: REQUEST_AT.toISOString(),
      partial: true,
      agents: [malicious],
      sources: [
        {
          provider: "todos",
          status: "partial",
          freshness_at: REQUEST_AT.toISOString(),
          coverage: {
            complete: false,
            provider_records: 1,
            projected_records: 1,
            dropped_records: 0
          },
          error: { code: hostile, message: hostile }
        }
      ]
    });

    expect(output).not.toContain("secret-value");
    expect(output).not.toContain("9999");
    expect(output).not.toContain("\u202e");
    expect(output).toContain("inactive:unknown");
    expect(output).toContain("diagnostic-withheld");
  });
});

describe("truthful state and completeness", () => {
  test("missing or unsupported status and invalid future timestamps fail closed", async () => {
    for (const hostileTask of [
      task(1, {
        status: undefined,
        started_at: "9999-12-31T23:59:59.000Z",
        updated_at: "9999-12-31T23:59:59.000Z"
      }),
      task(2, {
        status: "mystery\u202e",
        started_at: "not-a-date",
        updated_at: "not-a-date"
      }),
      task(3, {
        status: "unknown",
        started_at: "2026-07-23T12:00:01.000Z",
        updated_at: "2026-07-23T12:00:01.000Z"
      })
    ]) {
      const response = await runAgentsCli(
        ["show", `todos:${String(hostileTask.id)}`, "--json"],
        {
          env: TODOS_ENV,
          httpRunner: fakeHttp(exactResult(hostileTask)).runner,
          now: fixedNow
        }
      );
      const envelope = JSON.parse(response.stdout);
      const agent = envelope.agents[0];
      expect(agent.status).toBe("unknown");
      expect(agent.active).toBe(false);
      expect(agent.started_at).toBeNull();
      expect(agent.updated_at).toBeNull();
      expect(agent.freshness_at).toBeNull();
      expect(agent.gaps).toEqual(
        expect.arrayContaining(["status", "started_at", "updated_at", "freshness_at"])
      );
      expect(response.stdout).not.toContain("mystery");
      expect(response.stdout).not.toContain("9999");
    }
  });

  test("every unavailable normalized field has one stable named gap", async () => {
    const http = fakeHttp(
      exactResult(
        task(1, {
          short_id: "unsafe short id",
          started_at: null,
          updated_at: null,
          profile_alias: null
        })
      )
    );
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);
    const agent = envelope.agents[0];

    expect(agent?.gaps).toEqual([
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
      "task.short_id",
      "task.title",
      "updated_at",
      "worktree"
    ]);
  });

  test("does not project unassigned or merely assigned Todos tasks as agents", async () => {
    const cases = [
      { value: task(1, { agent_id: undefined }), exitCode: 5 },
      {
        value: task(2, { agent_id: undefined, assigned_to: "account001" }),
        exitCode: 5
      },
      {
        value: task(3, { session_id: uuid(103), agent_id: undefined }),
        exitCode: 0
      },
      {
        value: task(4, {
          agent_id: undefined,
          locked_by: "lease-owner",
          lock_expires_at: "2026-07-23T12:10:00.000Z"
        }),
        exitCode: 0
      },
      {
        value: task(5, {
          agent_id: undefined,
          locked_by: "expired-owner",
          lock_expires_at: "2026-07-23T11:59:00.000Z"
        }),
        exitCode: 5
      }
    ];
    for (const item of cases) {
      const response = await runAgentsCli(
        ["show", `todos:${String(item.value.id)}`, "--json"],
        {
          env: TODOS_ENV,
          httpRunner: fakeHttp(exactResult(item.value)).runner,
          now: fixedNow
        }
      );
      expect(response.exitCode).toBe(item.exitCode);
    }
  });

  test("dedupe selects newest valid observation before status and ties canonically", () => {
    const olderActive = normalizedAgent({
      run_id: uuid(1),
      id: `todos:${uuid(1)}`,
      status: "running",
      active: true,
      updated_at: "2026-07-23T10:00:00.000Z",
      freshness_at: "2026-07-23T10:00:00.000Z",
      profile: { alias: "account001" }
    });
    const newerTerminal = normalizedAgent({
      run_id: uuid(1),
      id: `todos:${uuid(1)}`,
      status: "completed",
      active: false,
      updated_at: "2026-07-23T11:00:00.000Z",
      freshness_at: "2026-07-23T11:00:00.000Z",
      profile: { alias: "account002" }
    });
    const tieA = normalizedAgent({
      run_id: uuid(2),
      id: `todos:${uuid(2)}`,
      profile: { alias: "account001" }
    });
    const tieB = normalizedAgent({
      run_id: uuid(2),
      id: `todos:${uuid(2)}`,
      profile: { alias: "account002" }
    });

    expect(dedupeAgents([olderActive, newerTerminal])).toEqual([newerTerminal]);
    expect(dedupeAgents([newerTerminal, olderActive])).toEqual([newerTerminal]);
    expect(dedupeAgents([tieA, tieB])).toEqual(dedupeAgents([tieB, tieA]));
  });

  test("unsupported Todos list reports unknown coverage instead of capturing a stream", async () => {
    const http = fakeHttp(listResult(Array.from({ length: 201 }, (_, index) => task(index + 1)), 250));
    const envelope = await collectAgentVisibility({
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const source = envelope.sources.find(({ provider }) => provider === "todos");

    expect(http.calls).toHaveLength(0);
    expect(envelope.agents).toHaveLength(0);
    expect(envelope.partial).toBe(true);
    expect(source?.status).toBe("unavailable");
    expect(source?.error?.code).toBe("side-effect-free-source-limit-unavailable");
    expect(source?.coverage).toEqual({
      complete: false,
      provider_records: null,
      projected_records: 0,
      dropped_records: null
    });
  });

  test("list hard maximum is rejected before any source operation", async () => {
    const http = fakeHttp(listResult([]));
    const response = await runAgentsCli(["--limit", "201", "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });

    expect(response.exitCode).toBe(2);
    expect(JSON.parse(response.stdout).error.code).toBe("invalid-arguments");
    expect(http.calls).toHaveLength(0);
  });

  test("source freshness is the actual completion observation, not request start", async () => {
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: fakeHttp(exactResult(task(1))).runner,
      now: sequenceNow(REQUEST_AT, OBSERVED_AT)
    });
    const envelope = JSON.parse(response.stdout);
    const source = envelope.sources[0];

    expect(envelope.generated_at).toBe(REQUEST_AT.toISOString());
    expect(source?.freshness_at).toBe(OBSERVED_AT.toISOString());
  });
});

describe("exact lookup and CLI semantics", () => {
  test("exact show queries only the selected provider with one targeted GET", async () => {
    const target = task(201);
    const http = fakeHttp((request) => {
      expect(new URL(request.url).pathname).toBe(`/v1/tasks/${uuid(201)}`);
      expect(new URL(request.url).search).toBe("");
      return exactResult(target);
    });
    const response = await runAgentsCli(["show", `todos:${uuid(201)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(0);
    expect(http.calls).toHaveLength(1);
    expect(envelope.sources).toHaveLength(1);
    expect(envelope.sources[0].provider).toBe("todos");
    expect(envelope.agents[0].id).toBe(`todos:${uuid(201)}`);
  });

  test("selected-source unavailability is incomplete, never false not-found", async () => {
    const http = fakeHttp(listResult([task(1)]));
    const response = await runAgentsCli(["show", `claude:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: http.runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(5);
    expect(envelope.error.code).toBe("agent-lookup-incomplete");
    expect(envelope.sources).toHaveLength(1);
    expect(envelope.sources[0].provider).toBe("claude");
    expect(http.calls).toHaveLength(0);
  });

  test("only an exact complete 404 becomes agent-not-found", async () => {
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: fakeHttp({ status: 404, body: '{"error":"not found"}' }).runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(4);
    expect(envelope.error.code).toBe("agent-not-found");
    expect(envelope.sources[0].coverage.complete).toBe(true);
  });

  test("an exact task without agent provenance is incomplete, not absent", async () => {
    const unassigned = task(1, { agent_id: undefined, assigned_to: "account001" });
    const response = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: fakeHttp(exactResult(unassigned)).runner,
      now: fixedNow
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(5);
    expect(envelope.error.code).toBe("agent-lookup-incomplete");
    expect(envelope.sources[0].error.code).toBe("agent-provenance-missing");
  });

  test("show rejects --limit and malformed or secret-like IDs before provider execution", async () => {
    for (const args of [
      ["show", `todos:${uuid(1)}`, "--limit", "1", "--json"],
      ["show", "todos:not-a-safe-id", "--json"],
      ["show", ["todos:glpat", "abcdefghijklmnopqrst"].join("-"), "--json"]
    ]) {
      const http = fakeHttp(exactResult(task(1)));
      const response = await runAgentsCli(args, {
        env: TODOS_ENV,
        httpRunner: http.runner,
        now: fixedNow
      });
      expect(response.exitCode).toBe(2);
      expect(http.calls).toHaveLength(0);
    }
  });

  test("JSON v1 and human output expose stable shape and explicit warnings", async () => {
    const json = await runAgentsCli(["show", `todos:${uuid(1)}`, "--json"], {
      env: TODOS_ENV,
      httpRunner: fakeHttp(exactResult(task(1))).runner,
      now: fixedNow
    });
    const envelope = JSON.parse(json.stdout);

    expect(json.exitCode).toBe(0);
    expect(envelope.schema_version).toBe(AGENTS_SCHEMA_VERSION);
    expect(Object.keys(envelope.sources[0]).sort()).toEqual([
      "coverage",
      "error",
      "freshness_at",
      "provider",
      "status"
    ]);
    expect(Object.keys(envelope.sources[0].coverage).sort()).toEqual([
      "complete",
      "dropped_records",
      "projected_records",
      "provider_records"
    ]);
    expect(Object.keys(envelope.agents[0]).sort()).toEqual([
      "active",
      "branch",
      "freshness_at",
      "gaps",
      "goal",
      "id",
      "last_tool_call",
      "profile",
      "provider",
      "run_id",
      "started_at",
      "status",
      "task",
      "updated_at",
      "worktree"
    ]);
    expect(formatAgentsTable(envelope)).toContain("WARNING incomplete sources:");
  });

  test("all unavailable sources return a stable nonzero JSON error", async () => {
    const response = await runAgentsCli(["--json"], { env: {}, now: fixedNow });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(3);
    expect(envelope.error.code).toBe("all-sources-unavailable");
    expect(envelope.partial).toBe(true);
  });

  test("all unavailable sources still render the compact human table and warnings", async () => {
    const response = await runAgentsCli([], { env: {}, now: fixedNow });

    expect(response.exitCode).toBe(3);
    expect(response.stdout).toContain("STATUS");
    expect(response.stdout).toContain("WORKTREE");
    expect(response.stdout).toContain("No safely projectable agents found.");
    expect(response.stdout).toContain("WARNING incomplete sources:");
    expect(response.stderr).toBe(
      "error: No side-effect-free authoritative agent source is configured."
    );
  });
});

describe("real process wall-clock and byte bounds", () => {
  test("forces resolution for a direct hang", async () => {
    const started = performance.now();
    const result = await runBoundedProviderProcess({
      command: process.execPath,
      args: ["-e", "setInterval(() => {}, 1000)"],
      timeoutMs: 100
    });

    expect(result.failure).toBe("timeout");
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("terminates the process group when a descendant retains stdio", async () => {
    const script = [
      'const { spawn } = require("node:child_process");',
      'spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "inherit" });',
      "setInterval(() => {}, 1000);"
    ].join("");
    const started = performance.now();
    const result = await runBoundedProviderProcess({
      command: process.execPath,
      args: ["-e", script],
      timeoutMs: 150
    });

    expect(result.failure).toBe("timeout");
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("preserves a bounded nonzero result without projecting stderr", async () => {
    const result = await runBoundedProviderProcess({
      command: process.execPath,
      args: ["-e", 'process.stderr.write("sensitive stderr"); process.exit(7)'],
      timeoutMs: 1_000,
      maxStderrBytes: 32
    });

    expect(result.exitCode).toBe(7);
    expect(result.failure).toBeUndefined();
    expect(result.stderr.length).toBeLessThanOrEqual(32);
  });

  test("terminates the process group on stdout byte overflow", async () => {
    const started = performance.now();
    const result = await runBoundedProviderProcess({
      command: process.execPath,
      args: ["-e", 'process.stdout.write("x".repeat(4096)); setInterval(() => {}, 1000)'],
      timeoutMs: 2_000,
      maxStdoutBytes: 128
    });

    expect(result.failure).toBe("output-limit");
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("terminates the process group on stderr byte overflow", async () => {
    const started = performance.now();
    const result = await runBoundedProviderProcess({
      command: process.execPath,
      args: ["-e", 'process.stderr.write("x".repeat(4096)); setInterval(() => {}, 1000)'],
      timeoutMs: 2_000,
      maxStderrBytes: 128
    });

    expect(result.failure).toBe("output-limit");
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe("real HTTP wall-clock and byte bounds", () => {
  test("aborts and resolves a direct HTTP hang at the wall-clock deadline", async () => {
    const server = Bun.serve({
      port: 0,
      fetch: async () => await new Promise<Response>(() => undefined)
    });
    const started = performance.now();
    try {
      const result = await runBoundedHttpRequest({
        provider: "todos",
        method: "GET",
        url: `http://127.0.0.1:${server.port}/v1/tasks/${uuid(1)}`,
        headers: { Accept: "application/json" },
        timeoutMs: 100,
        maxBytes: 1024
      });
      expect(result.failure).toBe("timeout");
      expect(performance.now() - started).toBeLessThan(1_000);
    } finally {
      server.stop(true);
    }
  });

  test("aborts an HTTP response at the byte cap", async () => {
    const server = Bun.serve({
      port: 0,
      fetch: () => new Response("x".repeat(4096))
    });
    try {
      const result = await runBoundedHttpRequest({
        provider: "todos",
        method: "GET",
        url: `http://127.0.0.1:${server.port}/v1/tasks/${uuid(1)}`,
        headers: { Accept: "application/json" },
        timeoutMs: 1_000,
        maxBytes: 128
      });
      expect(result.failure).toBe("output-limit");
      expect(result.body).toBe("");
    } finally {
      server.stop(true);
    }
  });
});
