import { spawn } from "node:child_process";

export interface RunCommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  shell?: string;
  stdin?: NodeJS.ReadStream;
  stdout?: NodeJS.WriteStream;
  stderr?: NodeJS.WriteStream;
}

export async function runShellCommand(command: string, options: RunCommandOptions = {}): Promise<number> {
  const child = spawn(command, {
    cwd: options.cwd ?? process.cwd(),
    env: options.env ?? process.env,
    shell: options.shell ?? process.env.SHELL ?? "/bin/sh",
    stdio: [
      options.stdin ? "pipe" : "inherit",
      options.stdout ? "pipe" : "inherit",
      options.stderr ? "pipe" : "inherit"
    ]
  });

  if (options.stdin && child.stdin) {
    options.stdin.pipe(child.stdin);
  }
  child.stdout?.pipe(options.stdout ?? process.stdout);
  child.stderr?.pipe(options.stderr ?? process.stderr);

  const forward = (signal: NodeJS.Signals) => child.kill(signal);
  process.once("SIGINT", forward);
  process.once("SIGTERM", forward);
  process.once("SIGHUP", forward);

  return await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      process.off("SIGINT", forward);
      process.off("SIGTERM", forward);
      process.off("SIGHUP", forward);
      if (signal) {
        resolve(128);
        return;
      }
      resolve(code ?? 0);
    });
  });
}
