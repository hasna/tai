import { expect, test } from "bun:test";
import { classifyCommand } from "../src/safety";

test("allows clear read-only commands", () => {
  expect(classifyCommand("ls -la").risk).toBe("allow");
  expect(classifyCommand("git status --short").risk).toBe("allow");
  expect(classifyCommand("git log --oneline -5").risk).toBe("allow");
});

test("requires confirmation for writes and network operations", () => {
  expect(classifyCommand("mkdir tmp").risk).toBe("confirm");
  expect(classifyCommand("curl https://example.com").risk).toBe("confirm");
  expect(classifyCommand("git commit -am test").risk).toBe("confirm");
  expect(classifyCommand("git push origin main").risk).toBe("confirm");
});

test("blocks destructive and credential-sensitive operations", () => {
  expect(classifyCommand("rm -rf /tmp/example").risk).toBe("block");
  expect(classifyCommand("git push --force origin main").risk).toBe("block");
  expect(classifyCommand("git reset --hard HEAD~1").risk).toBe("block");
  expect(classifyCommand("cat .env").risk).toBe("block");
  expect(classifyCommand("git show HEAD:.env").risk).toBe("block");
  expect(classifyCommand("git diff --no-index .env /dev/null").risk).toBe("block");
  expect(classifyCommand("ls $(touch /tmp/tai-pwn)").risk).toBe("block");
  expect(classifyCommand("cat `touch /tmp/tai-pwn`").risk).toBe("block");
  expect(classifyCommand("awk 'BEGIN { system(\"touch /tmp/tai-pwn\") }'").risk).toBe("block");
  expect(classifyCommand("find . -delete").risk).toBe("block");
  expect(classifyCommand("find . -exec touch x {} +").risk).toBe("block");
});
