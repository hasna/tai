import { expect, test } from "bun:test";
import { redactSensitiveText, stripHiddenReasoning } from "../src/redaction";

test("redacts common provider keys and bearer tokens", () => {
  const input = "Authorization: Bearer secret-token sk-1234567890abcdef gsk_1234567890abcdef GITHUB_TOKEN=ghp_secret PASSWORD=hunter2";
  expect(redactSensitiveText(input)).not.toContain("secret-token");
  expect(redactSensitiveText(input)).not.toContain("sk-1234567890abcdef");
  expect(redactSensitiveText(input)).not.toContain("gsk_1234567890abcdef");
  expect(redactSensitiveText(input)).not.toContain("ghp_secret");
  expect(redactSensitiveText(input)).not.toContain("hunter2");
});

test("redacts named credential values in assignments and mappings", () => {
  const cases = [
    ['export DB_PASSWORD="hunter2-correct-horse"', "hunter2-correct-horse"],
    ["AUTH_TOKEN='abcdef123456'", "abcdef123456"],
    ["DB_PASSWORD=hunter2", "hunter2"],
    ['{"API_TOKEN": "json-secret-123"}', "json-secret-123"],
    ['{"auth_token": "lowercase-json-token-789"}', "lowercase-json-token-789"],
    ['{"api_key": "lowercase-secret-456"}', "lowercase-secret-456"]
  ] as const;

  for (const [input, secret] of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(secret);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }

  const safeText = 'export APP_MODE="development"';
  expect(redactSensitiveText(safeText)).toBe(safeText);
});

test("strips hidden reasoning blocks", () => {
  expect(stripHiddenReasoning("<think>private</think>{\"command\":\"ls\",\"summary\":\"list\"}")).toBe("{\"command\":\"ls\",\"summary\":\"list\"}");
});
