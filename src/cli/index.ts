#!/usr/bin/env node
import { createTai } from "../sdk";
import { formatAgenticPlan } from "../agentic-plan";
import { runAgentsCli } from "../agents";
import { formatCommandPreview } from "../proposal";
import { classifyCommand } from "../safety";
import { runShellCommand } from "../shell";

const [, , command, ...args] = process.argv;

async function main(): Promise<number> {
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return 0;
  }

  if (command === "classify") {
    const shellCommand = args.join(" ");
    console.log(JSON.stringify(classifyCommand(shellCommand), null, 2));
    return 0;
  }

  if (command === "propose") {
    const request = args.join(" ");
    const proposal = await createTai().propose(request);
    console.log(formatCommandPreview(proposal));
    return 0;
  }

  if (command === "plan") {
    const request = args.join(" ");
    const plan = await createTai().plan(request);
    console.log(formatAgenticPlan(plan));
    return plan.blocked ? 2 : 0;
  }

  if (command === "agents") {
    const result = await runAgentsCli(args);
    if (result.stdout) {
      console.log(result.stdout);
    }
    if (result.stderr) {
      console.error(result.stderr);
    }
    return result.exitCode;
  }

  if (command === "run") {
    const yesIndex = args.indexOf("--yes");
    const overrideIndex = args.indexOf("--override");
    const yes = yesIndex >= 0;
    const override = overrideIndex >= 0;
    const shellCommand = args.filter((_, index) => index !== yesIndex && index !== overrideIndex).join(" ");
    const classification = classifyCommand(shellCommand);
    console.error(`risk: ${ classification.risk }${ classification.reasons.length ? ` (${ classification.reasons.join("; ") })` : "" }`);

    if (classification.risk === "block" && !override) {
      console.error("blocked: rerun with --override only after reviewing the command manually.");
      return 2;
    }
    if (classification.risk === "confirm" && !yes) {
      console.error("confirmation required: rerun with --yes after reviewing the command.");
      return 2;
    }

    return await runShellCommand(shellCommand);
  }

  console.error(`Unknown command: ${ command }`);
  printHelp();
  return 2;
}

function printHelp(): void {
  console.log(`tai

Usage:
  tai propose <request>
  tai plan <request>
  tai agents [--json] [--limit <1-200>]
  tai agents show <provider>:<run-id> [--json]
  tai classify <command>
  tai run <command> [--yes] [--override]
`);
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
