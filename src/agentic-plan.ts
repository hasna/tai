import { classifyCommand } from "./safety";
import { redactSensitiveText, stripHiddenReasoning } from "./redaction";
import type { AgenticCommandPlan, AgenticCommandStep } from "./types";

export function parseAgenticCommandPlan(raw: string, fallbackObjective = "Terminal request"): AgenticCommandPlan {
  const parsed = JSON.parse(extractJson(stripHiddenReasoning(raw))) as {
    objective?: unknown;
    summary?: unknown;
    steps?: unknown;
    notes?: unknown;
  };

  const steps = Array.isArray(parsed.steps)
    ? parsed.steps.map(parseStep).filter((step): step is AgenticCommandStep => step !== undefined)
    : [];

  if (steps.length === 0) {
    throw new Error("Agentic plan did not include any command steps.");
  }

  const notes = Array.isArray(parsed.notes)
    ? parsed.notes.filter((note): note is string => typeof note === "string").map(redactSensitiveText)
    : [];

  return {
    objective: typeof parsed.objective === "string" ? redactSensitiveText(parsed.objective) : fallbackObjective,
    summary: typeof parsed.summary === "string" ? redactSensitiveText(parsed.summary) : "Proposed multi-step terminal plan",
    steps,
    requiresConfirmation: steps.some((step) => step.classification.risk === "confirm"),
    blocked: steps.some((step) => step.classification.risk === "block"),
    notes
  };
}

export function formatAgenticPlan(plan: AgenticCommandPlan): string {
  const lines = [
    plan.summary,
    `risk: ${ plan.blocked ? "block" : plan.requiresConfirmation ? "confirm" : "allow" }`
  ];

  for (const [index, step] of plan.steps.entries()) {
    const reasons = step.classification.reasons.join("; ");
    lines.push(`${ index + 1 }. ${ step.summary }`);
    lines.push(`   $ ${ step.command }`);
    lines.push(`   risk: ${ step.classification.risk }${ reasons ? ` (${ reasons })` : "" }`);
  }

  for (const note of plan.notes) {
    lines.push(`note: ${ note }`);
  }

  return lines.join("\n");
}

function parseStep(value: unknown): AgenticCommandStep | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const candidate = value as { command?: unknown; summary?: unknown };
  if (typeof candidate.command !== "string" || candidate.command.trim().length === 0) {
    return undefined;
  }

  const command = redactSensitiveText(candidate.command.trim());
  return {
    command,
    summary: typeof candidate.summary === "string" ? redactSensitiveText(candidate.summary.trim()) : "Run command",
    classification: classifyCommand(command)
  };
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

  throw new Error("Agentic plan did not contain a JSON object.");
}
