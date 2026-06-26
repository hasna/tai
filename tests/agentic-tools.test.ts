import { expect, test } from "bun:test";
import { createTerminalPlanningTools } from "../src/agentic";
import type { CommandClassification } from "../src/types";

interface ReadOnlyShellResult {
  ok: boolean;
  classification: CommandClassification;
  stdout: string;
  stderr: string;
}

test("readOnlyShell refuses non-read-only commands", async () => {
  const tools = createTerminalPlanningTools({ cwd: process.cwd(), env: process.env });
  const result = await tools.readOnlyShell.execute?.({ command: "mkdir tmp-agentic-test" }, { toolCallId: "test", messages: [] }) as ReadOnlyShellResult | undefined;
  expect(result?.ok).toBe(false);
  expect(result?.classification.risk).toBe("confirm");
});

test("readOnlyShell refuses shell substitution and command-capable readers", async () => {
  const tools = createTerminalPlanningTools({ cwd: process.cwd(), env: process.env });
  const cases = [
    "ls $(touch /tmp/tai-pwn)",
    "cat `touch /tmp/tai-pwn`",
    "awk 'BEGIN { system(\"touch /tmp/tai-pwn\") }'",
    "find . -exec touch x {} +"
  ];

  for (const command of cases) {
    const result = await tools.readOnlyShell.execute?.({ command }, { toolCallId: "test", messages: [] }) as ReadOnlyShellResult | undefined;
    expect(result?.ok).toBe(false);
  }
});

test("classifyCommand tool uses local safety policy", async () => {
  const tools = createTerminalPlanningTools({ cwd: process.cwd(), env: process.env });
  const result = await tools.classifyCommand.execute?.({ command: "git push --force origin main" }, { toolCallId: "test", messages: [] }) as CommandClassification | undefined;
  expect(result?.risk).toBe("block");
});
