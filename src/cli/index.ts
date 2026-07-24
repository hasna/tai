#!/usr/bin/env node
import { createRequire } from "node:module";
import { createTai } from "../sdk";
import { formatAgenticPlan } from "../agentic-plan";
import { formatCommandPreview } from "../proposal";
import { classifyCommand } from "../safety";
import { runShellCommand } from "../shell";

const [, , command, ...args] = process.argv;

async function main(): Promise<number> {
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return 0;
  }

  if (command === "--version" || command === "-v" || command === "version") {
    console.log(readPackageVersion());
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

function readPackageVersion(): string {
  // Resolved from the shipped package.json so the version is never duplicated in source.
  // Works both from src/cli/index.ts and from the bundled dist/cli/index.js.
  try {
    const require = createRequire(import.meta.url);
    const manifest = require("../../package.json") as { version?: string };
    return manifest.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function printHelp(): void {
  console.log(`tai ${ readPackageVersion() }

Usage:
  tai propose <request>
  tai plan <request>
  tai classify <command>
  tai run <command> [--yes] [--override]
  tai --version
`);
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
