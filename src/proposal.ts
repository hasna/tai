import { redactSensitiveText, stripHiddenReasoning } from "./redaction";
import { classifyCommand } from "./safety";
import type { CommandProposal } from "./types";

export function parseCommandProposal(raw: string): CommandProposal {
  const cleaned = stripHiddenReasoning(raw);
  const jsonText = extractJson(cleaned);
  const parsed = JSON.parse(jsonText) as Partial<CommandProposal>;

  if (!parsed.command || typeof parsed.command !== "string") {
    throw new Error("Provider response did not include a command string.");
  }

  const command = redactSensitiveText(parsed.command.trim());
  const summary = typeof parsed.summary === "string" && parsed.summary.trim().length > 0
    ? redactSensitiveText(parsed.summary.trim())
    : "Proposed shell command";

  return {
    command,
    summary,
    cwd: parsed.cwd,
    env: redactEnv(parsed.env),
    classification: classifyCommand(command)
  };
}

export function formatCommandPreview(proposal: CommandProposal): string {
  const reasons = proposal.classification.reasons.join("; ");
  return [
    proposal.summary,
    `$ ${ proposal.command }`,
    `risk: ${ proposal.classification.risk }${ reasons ? ` (${ reasons })` : "" }`
  ].join("\n");
}

function extractJson(value: string): string {
  const fenced = value.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced?.[1]) {
    return fenced[1].trim();
  }

  const start = value.indexOf("{");
  const end = value.lastIndexOf("}");
  if (start >= 0 && end > start) {
    return value.slice(start, end + 1);
  }

  throw new Error("Provider response did not contain a JSON object.");
}

function redactEnv(env: unknown): Record<string, string> | undefined {
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    return undefined;
  }

  const entries = Object.entries(env as Record<string, unknown>)
    .filter(([key, value]) => /^[A-Z_][A-Z0-9_]*$/i.test(key) && typeof value === "string")
    .map(([key, value]) => [key, redactSensitiveText(value as string)] as const);

  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}
