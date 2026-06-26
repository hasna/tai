import { expect, test } from "bun:test";
import { parseAgenticCommandPlan } from "../src/agentic-plan";

test("parses multi-step plans and classifies each command", () => {
  const plan = parseAgenticCommandPlan(JSON.stringify({
    objective: "Inspect repo",
    summary: "Inspect then test",
    steps: [
      { command: "git status --short", summary: "Check git state" },
      { command: "bun test", summary: "Run tests" }
    ],
    notes: ["No writes until confirmation"]
  }));

  expect(plan.steps).toHaveLength(2);
  expect(plan.steps[0]?.classification.risk).toBe("allow");
  expect(plan.steps[1]?.classification.risk).toBe("confirm");
  expect(plan.requiresConfirmation).toBe(true);
  expect(plan.blocked).toBe(false);
});

test("blocks destructive steps even if the plan looks benign", () => {
  const plan = parseAgenticCommandPlan(JSON.stringify({
    summary: "Clean up",
    steps: [{ command: "rm -rf .", summary: "Clean" }]
  }));

  expect(plan.blocked).toBe(true);
  expect(plan.steps[0]?.classification.requiresOverride).toBe(true);
});
