import { describe, expect, test } from "bun:test";
import {
  AGENTS_SCHEMA_VERSION,
  collectAgentVisibility,
  formatAgentsTable,
  runAgentsCli,
  type ProviderCommand,
  type ProviderCommandResult,
  type ProviderCommandRunner
} from "../src/agents";

const NOW = new Date("2026-07-23T12:00:00.000Z");
const SECRET_LIKE_GITHUB_TOKEN = ["ghp", "1234567890abcdefghijklmnopqrst"].join("_");

function result(payload: unknown): ProviderCommandResult {
  return {
    stdout: JSON.stringify(payload),
    stderr: "",
    exitCode: 0
  };
}

function fixtures(): Record<ProviderCommand["provider"], ProviderCommandResult> {
  return {
    codewith: result({
      data: [
        {
          agentId: "cw-old",
          status: "running",
          startedAt: 1_753_200_000,
          updatedAt: 1_753_200_100,
          authProfileRef: "account001",
          statusReason: "raw transcript and sk-1234567890abcdef"
        },
        {
          agentId: "cw-old",
          status: "running",
          startedAt: 1_753_200_000,
          updatedAt: 1_753_200_200,
          authProfileRef: "sk-secret-profile-reference"
        },
        {
          agentId: "cw-complete",
          status: "completed",
          startedAt: 1_753_100_000,
          updatedAt: 1_753_100_100
        }
      ]
    }),
    claude: result([
      {
        sessionId: "claude-new",
        status: "busy",
        startedAt: 1_753_300_000_000,
        cwd: "/workspace/repo"
      }
    ]),
    todos: result([
      {
        id: "task-newest",
        short_id: "E-00104",
        title: `Visible task ${SECRET_LIKE_GITHUB_TOKEN} ${"x".repeat(180)}`,
        status: "in_progress",
        started_at: "2026-07-23T10:00:00.000Z",
        updated_at: "2026-07-23T11:59:00.000Z",
        working_dir: "/workspace/tai",
        metadata: { branch: "feat/agents" },
        description: "full prompt must never be projected"
      }
    ])
  };
}

function fakeRunner(
  overrides: Partial<Record<ProviderCommand["provider"], ProviderCommandResult>> = {}
): { runner: ProviderCommandRunner; calls: ProviderCommand[] } {
  const calls: ProviderCommand[] = [];
  const responses = { ...fixtures(), ...overrides };
  return {
    calls,
    runner: async (command) => {
      calls.push(command);
      return responses[command.provider];
    }
  };
}

describe("agent visibility normalization", () => {
  test("normalizes, redacts, bounds, deduplicates, and sorts provider records", async () => {
    const { runner } = fakeRunner();
    const envelope = await collectAgentVisibility({ runner, now: () => NOW });

    expect(envelope.schema_version).toBe(AGENTS_SCHEMA_VERSION);
    expect(envelope.generated_at).toBe(NOW.toISOString());
    expect(envelope.partial).toBe(false);
    expect(envelope.sources.map(({ status }) => status)).toEqual(["ok", "ok", "ok"]);
    expect(envelope.agents).toHaveLength(4);
    expect(envelope.agents[0]?.id).toBe("todos:task-newest");
    expect(envelope.agents.at(-1)?.id).toBe("codewith:cw-complete");
    expect(envelope.agents.filter(({ id }) => id === "codewith:cw-old")).toHaveLength(1);

    const codewith = envelope.agents.find(({ id }) => id === "codewith:cw-old");
    expect(codewith?.updated_at).toBe("2025-07-22T16:03:20.000Z");
    expect(codewith?.profile.alias).toBeNull();
    expect(codewith?.last_tool_call).toEqual({ name: null, at: null, summary: null });
    expect(codewith?.gaps).toContain("last_tool_call unavailable from Codewith list surface");
    expect(codewith?.gaps).toContain("profile reference withheld because it is not a safe alias");

    const todos = envelope.agents.find(({ provider }) => provider === "todos");
    expect(todos?.task.title).toContain("[REDACTED_");
    expect(todos?.task.title).not.toContain(SECRET_LIKE_GITHUB_TOKEN);
    expect(todos?.task.title?.length).toBeLessThanOrEqual(120);
    expect(JSON.stringify(envelope)).not.toContain("full prompt");
    expect(JSON.stringify(envelope)).not.toContain("raw transcript");
    expect(JSON.stringify(envelope)).not.toContain("sk-secret-profile-reference");
  });

  test("marks one failed source partial and retains available records", async () => {
    const { runner } = fakeRunner({
      claude: {
        stdout: "",
        stderr: "",
        exitCode: null,
        failure: "not-found"
      }
    });
    const envelope = await collectAgentVisibility({ runner, now: () => NOW });

    expect(envelope.partial).toBe(true);
    expect(envelope.sources.find(({ provider }) => provider === "claude")).toEqual({
      provider: "claude",
      status: "unavailable",
      freshness_at: null,
      error: {
        code: "provider-command-unavailable",
        message: "claude command is not installed or discoverable."
      }
    });
    expect(envelope.agents.some(({ provider }) => provider === "codewith")).toBe(true);
    expect(envelope.agents.some(({ provider }) => provider === "todos")).toBe(true);
  });

  test("withholds secret-like identifiers and sensitive configuration paths", async () => {
    const secretId = SECRET_LIKE_GITHUB_TOKEN;
    const { runner } = fakeRunner({
      codewith: result({
        data: [
          { agentId: secretId, status: "running" },
          { agentId: "safe-run", status: "running" }
        ]
      }),
      claude: result([
        {
          sessionId: "claude-safe",
          status: "idle",
          cwd: "/home/operator/.codewith/auth"
        }
      ]),
      todos: result([])
    });
    const envelope = await collectAgentVisibility({ runner, now: () => NOW });

    expect(envelope.sources.find(({ provider }) => provider === "codewith")?.status).toBe("partial");
    expect(envelope.agents.some(({ run_id }) => run_id === secretId)).toBe(false);
    const claude = envelope.agents.find(({ id }) => id === "claude:claude-safe");
    expect(claude?.worktree).toBeNull();
    expect(claude?.gaps).toContain("worktree unavailable from Claude agents surface");
    expect(JSON.stringify(envelope)).not.toContain(".codewith/auth");
    expect(JSON.stringify(envelope)).not.toContain(secretId);
  });

  test("reports bounded-output failures without exposing captured provider text", async () => {
    const { runner } = fakeRunner({
      todos: {
        stdout: "raw transcript should be discarded",
        stderr: "Authorization: Bearer should-not-leak",
        exitCode: null,
        failure: "output-limit"
      }
    });
    const envelope = await collectAgentVisibility({ runner, now: () => NOW });
    const source = envelope.sources.find(({ provider }) => provider === "todos");

    expect(source?.status).toBe("error");
    expect(source?.error?.code).toBe("provider-output-limit");
    expect(JSON.stringify(envelope)).not.toContain("raw transcript");
    expect(JSON.stringify(envelope)).not.toContain("should-not-leak");
  });

  test("uses exactly one bounded command per provider and never does per-record calls", async () => {
    const { runner, calls } = fakeRunner();
    await collectAgentVisibility({ runner, now: () => NOW });

    expect(calls).toHaveLength(3);
    expect(calls.map(({ provider }) => provider)).toEqual(["codewith", "claude", "todos"]);
    expect(calls.find(({ provider }) => provider === "codewith")?.args).toEqual([
      "agent",
      "list",
      "--json",
      "--limit",
      "200"
    ]);
    expect(calls.find(({ provider }) => provider === "claude")?.args).toEqual(["agents", "--json"]);
    expect(calls.find(({ provider }) => provider === "todos")?.args).toEqual(["active", "--json"]);
  });
});

describe("agent visibility CLI", () => {
  test("emits the stable JSON schema shape", async () => {
    const { runner } = fakeRunner();
    const response = await runAgentsCli(["--json", "--limit", "2"], { runner, now: () => NOW });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(0);
    expect(Object.keys(envelope).sort()).toEqual([
      "agents",
      "generated_at",
      "partial",
      "schema_version",
      "sources"
    ]);
    expect(envelope.agents).toHaveLength(2);
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
    expect(Object.keys(envelope.sources[0]).sort()).toEqual([
      "freshness_at",
      "provider",
      "status"
    ]);
  });

  test("renders a compact human table and explicit partial warning", async () => {
    const { runner } = fakeRunner({
      claude: {
        stdout: "",
        stderr: "Authorization: Bearer should-not-leak",
        exitCode: 1
      }
    });
    const response = await runAgentsCli([], { runner, now: () => NOW });

    expect(response.exitCode).toBe(0);
    expect(response.stdout).toContain("STATUS");
    expect(response.stdout).toContain("PROVIDER/RUN");
    expect(response.stdout).toContain("TASK/GOAL");
    expect(response.stdout).toContain("WARNING partial sources: claude=error:provider-nonzero-exit");
    expect(response.stdout).not.toContain("should-not-leak");
    expect(formatAgentsTable(JSON.parse((await runAgentsCli(["--json"], { runner, now: () => NOW })).stdout))).toContain(
      "WARNING partial sources"
    );
  });

  test("returns a machine-readable malformed ID error without provider execution", async () => {
    const { runner, calls } = fakeRunner();
    const response = await runAgentsCli(["show", "bad", "--json"], { runner, now: () => NOW });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(2);
    expect(envelope.error.code).toBe("invalid-agent-id");
    expect(envelope.agents).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  test("returns a stable unknown ID error after one call to each source", async () => {
    const { runner, calls } = fakeRunner();
    const response = await runAgentsCli(["show", "codewith:missing", "--json"], {
      runner,
      now: () => NOW
    });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(4);
    expect(envelope.error.code).toBe("agent-not-found");
    expect(calls).toHaveLength(3);
    expect(calls.flatMap(({ args }) => args)).not.toContain("missing");
  });

  test("returns nonzero when every provider fails", async () => {
    const failure: ProviderCommandResult = {
      stdout: "",
      stderr: "provider unavailable",
      exitCode: 1
    };
    const { runner } = fakeRunner({
      codewith: failure,
      claude: failure,
      todos: failure
    });
    const response = await runAgentsCli(["--json"], { runner, now: () => NOW });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(3);
    expect(envelope.error.code).toBe("all-sources-failed");
    expect(envelope.partial).toBe(true);
    expect(envelope.sources.every(({ status }: { status: string }) => status === "error")).toBe(true);
  });

  test("rejects limits above the hard maximum", async () => {
    const { runner, calls } = fakeRunner();
    const response = await runAgentsCli(["--limit", "201", "--json"], { runner, now: () => NOW });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(2);
    expect(envelope.error.code).toBe("invalid-arguments");
    expect(calls).toHaveLength(0);
  });

  test("applies the default result limit of 50", async () => {
    const manyTasks = Array.from({ length: 60 }, (_, index) => ({
      id: `task-${String(index).padStart(3, "0")}`,
      title: `Task ${index}`,
      status: "in_progress",
      updated_at: new Date(NOW.getTime() - index * 1000).toISOString()
    }));
    const { runner } = fakeRunner({
      codewith: result({ data: [] }),
      claude: result([]),
      todos: result(manyTasks)
    });
    const response = await runAgentsCli(["--json"], { runner, now: () => NOW });
    const envelope = JSON.parse(response.stdout);

    expect(response.exitCode).toBe(0);
    expect(envelope.agents).toHaveLength(50);
  });
});
