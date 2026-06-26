import { expect, test } from "bun:test";
import { spawn } from "node:child_process";

test("MCP notifications do not receive JSON-RPC responses", async () => {
  const child = spawn(process.execPath, ["src/mcp/index.ts"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stdout = "";
  child.stdout.on("data", (chunk) => {
    stdout += String(chunk);
  });

  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  await new Promise((resolve) => setTimeout(resolve, 100));
  child.kill();

  expect(stdout).toBe("");
});
