#!/usr/bin/env node
import { createInterface } from "node:readline";
import { createTai } from "../sdk";
import { classifyCommand } from "../safety";
import { redactSensitiveText } from "../redaction";

type JsonRpcRequest = {
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
};

const tai = createTai();

const tools = [
  {
    name: "tai.propose_command",
    description: "Turn a natural-language terminal request into a concise shell command proposal.",
    inputSchema: {
      type: "object",
      properties: { request: { type: "string" } },
      required: ["request"]
    }
  },
  {
    name: "tai.plan_commands",
    description: "Use tai's agentic AI SDK planner to create a multi-step terminal command plan.",
    inputSchema: {
      type: "object",
      properties: { request: { type: "string" } },
      required: ["request"]
    }
  },
  {
    name: "tai.classify_command",
    description: "Classify shell command risk.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"]
    }
  },
  {
    name: "tai.redact",
    description: "Redact common secrets from text.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"]
    }
  }
];

const rl = createInterface({ input: process.stdin });

rl.on("line", async (line) => {
  if (!line.trim()) {
    return;
  }

  const request = JSON.parse(line) as JsonRpcRequest;
  try {
    const result = await handle(request);
    if (request.id === undefined) {
      return;
    }
    respond(request.id, result);
  } catch (error) {
    if (request.id === undefined) {
      return;
    }
    respond(request.id, undefined, error instanceof Error ? error.message : String(error));
  }
});

async function handle(request: JsonRpcRequest): Promise<unknown> {
  if (request.method === "initialize") {
    return {
      protocolVersion: "2024-11-05",
      serverInfo: { name: "tai-mcp", version: "0.1.0" },
      capabilities: { tools: {} }
    };
  }

  if (request.method === "tools/list") {
    return { tools };
  }

  if (request.method?.startsWith("notifications/")) {
    return {};
  }

  if (request.method === "tools/call") {
    const name = String(request.params?.name ?? "");
    const args = request.params?.arguments as Record<string, unknown> | undefined;
    if (name === "tai.propose_command") {
      return { content: [{ type: "text", text: JSON.stringify(await tai.propose(String(args?.request ?? ""))) }] };
    }
    if (name === "tai.plan_commands") {
      return { content: [{ type: "text", text: JSON.stringify(await tai.plan(String(args?.request ?? ""))) }] };
    }
    if (name === "tai.classify_command") {
      return { content: [{ type: "text", text: JSON.stringify(classifyCommand(String(args?.command ?? ""))) }] };
    }
    if (name === "tai.redact") {
      return { content: [{ type: "text", text: redactSensitiveText(String(args?.text ?? "")) }] };
    }
  }

  throw new Error(`Unsupported MCP method: ${ request.method ?? "missing" }`);
}

function respond(id: JsonRpcRequest["id"], result?: unknown, error?: string): void {
  const payload = error
    ? { jsonrpc: "2.0", id, error: { code: -32000, message: error } }
    : { jsonrpc: "2.0", id, result };
  process.stdout.write(`${ JSON.stringify(payload) }\n`);
}
