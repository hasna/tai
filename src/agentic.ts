import { generateText, stepCountIs, tool, type LanguageModel } from "ai";
import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parseAgenticCommandPlan } from "./agentic-plan";
import { classifyCommand } from "./safety";
import { redactSensitiveText, stripHiddenReasoning } from "./redaction";
import type { AgenticCommandPlan } from "./types";

const execFileAsync = promisify(execFile);
const SAFE_EXECUTABLES = new Set(["pwd", "ls", "git", "rg", "grep", "cat", "head", "tail", "wc", "du", "df", "stat"]);

const AGENTIC_SYSTEM_PROMPT = [
  "You are tai, a terminal AI planner.",
  "Plan safe shell actions for the user's existing terminal.",
  "Use tools to inspect context, classify commands, and test read-only inspection commands when needed.",
  "Never run writes, network operations, package managers, deploys, force pushes, or credential-reading commands.",
  "Do not reveal hidden reasoning or chain-of-thought.",
  "Return only JSON: {\"objective\":string,\"summary\":string,\"steps\":[{\"command\":string,\"summary\":string}],\"notes\":string[]}."
].join(" ");

export interface AgenticPlanOptions {
  model: LanguageModel;
  request: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  maxSteps?: number;
  signal?: AbortSignal;
}

export async function planAgenticCommands(options: AgenticPlanOptions): Promise<AgenticCommandPlan> {
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const result = await generateText({
    model: options.model,
    system: AGENTIC_SYSTEM_PROMPT,
    prompt: [
      `cwd: ${ cwd }`,
      `shell: ${ env.SHELL ?? "unknown" }`,
      `request: ${ options.request }`
    ].join("\n"),
    tools: createTerminalPlanningTools({ cwd, env }),
    stopWhen: stepCountIs(options.maxSteps ?? 8),
    abortSignal: options.signal,
    temperature: 0,
    maxRetries: 1
  });

  return parseAgenticCommandPlan(stripHiddenReasoning(result.text), options.request);
}

export function createTerminalPlanningTools(options: { cwd: string; env: NodeJS.ProcessEnv }) {
  return {
    inspectContext: tool({
      description: "Inspect safe terminal context such as cwd, shell, platform, and environment key names.",
      inputSchema: z.object({}),
      execute: async () => ({
        cwd: options.cwd,
        shell: options.env.SHELL ?? null,
        platform: process.platform,
        envKeys: Object.keys(options.env).filter((key) => !/(TOKEN|SECRET|KEY|PASSWORD|PASSWD|PWD|AUTH|CREDENTIAL)/i.test(key)).sort()
      })
    }),
    classifyCommand: tool({
      description: "Classify a shell command with tai's local safety policy.",
      inputSchema: z.object({
        command: z.string().describe("The shell command to classify")
      }),
      execute: async ({ command }) => classifyCommand(command)
    }),
    readOnlyShell: tool({
      description: "Run a narrowly allowlisted read-only inspection command without invoking a shell.",
      inputSchema: z.object({
        command: z.string().describe("A read-only shell command to inspect local state")
      }),
      execute: async ({ command }) => {
        const classification = classifyCommand(command);
        if (classification.risk !== "allow") {
          return { ok: false, classification, stdout: "", stderr: "Command is not read-only; execution refused." };
        }

        const parsed = parseSafeReadOnlyCommand(command);
        if (!parsed.ok) {
          return { ok: false, classification, stdout: "", stderr: parsed.error };
        }

        try {
          const { stdout, stderr } = await execFileAsync(parsed.file, parsed.args, {
            cwd: options.cwd,
            env: scrubEnv(options.env),
            timeout: 5000,
            maxBuffer: 128 * 1024
          });
          return {
            ok: true,
            classification,
            stdout: redactSensitiveText(stdout).slice(0, 12000),
            stderr: redactSensitiveText(stderr).slice(0, 4000)
          };
        } catch (error) {
          const failure = error as { stdout?: string; stderr?: string; message?: string };
          return {
            ok: false,
            classification,
            stdout: redactSensitiveText(String(failure.stdout ?? "")).slice(0, 12000),
            stderr: redactSensitiveText(String(failure.stderr ?? failure.message ?? "")).slice(0, 4000)
          };
        }
      }
    })
  };
}

function parseSafeReadOnlyCommand(command: string): { ok: true; file: string; args: string[] } | { ok: false; error: string } {
  if (/[;&|<>$`\\\n\r]/.test(command)) {
    return { ok: false, error: "Shell metacharacters are not allowed in read-only tool execution." };
  }

  const parts = command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((part) => part.replace(/^(['"])(.*)\1$/, "$2")) ?? [];
  const [file, ...args] = parts;
  if (!file || !SAFE_EXECUTABLES.has(file)) {
    return { ok: false, error: "Command is not in the read-only execution allowlist." };
  }

  if (file === "git" && !isSafeGitArgs(args)) {
    return { ok: false, error: "Git arguments are not in the read-only execution allowlist." };
  }

  return { ok: true, file, args };
}

function isSafeGitArgs(args: string[]): boolean {
  const subcommand = args[0];
  if (!subcommand || !["status", "log", "show", "diff", "ls-files", "rev-parse", "branch"].includes(subcommand)) {
    return false;
  }
  return !args.some((arg) => /(?:\.env|id_rsa|id_ed25519|credentials|secrets?|token|keychain)/i.test(arg));
}

function scrubEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(env).filter(([key]) => !/(TOKEN|SECRET|KEY|PASSWORD|PASSWD|AUTH|CREDENTIAL)/i.test(key))
  );
}
