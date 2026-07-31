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

// Synthetic, never-issued values. BASIC_CREDENTIALS is base64 of the literal
// string "synthetic-user:synthetic-not-a-real-password" — for Basic auth this
// segment IS the credential, so it must never survive redaction.
const BASIC_CREDENTIALS = "c3ludGhldGljLXVzZXI6c3ludGhldGljLW5vdC1hLXJlYWwtcGFzc3dvcmQ=";
const BEARER_CREDENTIALS = "synthetic-bearer-token-000000";

test("removes the credentials segment of an Authorization header", () => {
  const cases = [
    `Authorization: Basic ${BASIC_CREDENTIALS}`,
    `Authorization: Bearer ${BEARER_CREDENTIALS}`,
    // Header keys are case-insensitive on the wire, and a regex without the `i`
    // flag has already let one shape through this file before.
    `authorization: basic ${BASIC_CREDENTIALS}`,
    `AUTHORIZATION: BASIC ${BASIC_CREDENTIALS}`,
    // Both the header-line and the object-literal spellings reach logs.
    `{"Authorization": "Basic ${BASIC_CREDENTIALS}"}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    // Assert the SECRET IS GONE. Asserting that a "[REDACTED]" marker is
    // present would pass against the pre-fix behaviour, which emitted
    // `Authorization: [REDACTED] <base64>` — marker shown, credential intact.
    expect(redacted).not.toContain(BASIC_CREDENTIALS);
    expect(redacted).not.toContain(BEARER_CREDENTIALS);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("positive control: the absence assertion can fail", () => {
  // If `not.toContain(BASIC_CREDENTIALS)` passed no matter what was fed in, the
  // test above would prove nothing. This anchors it: the identical literal, in
  // free prose that carries no credential context, is left alone and IS found.
  const prose = `The build log mentioned ${BASIC_CREDENTIALS} in passing.`;
  expect(redactSensitiveText(prose)).toContain(BASIC_CREDENTIALS);
});

test("does not over-redact text that carries no credential", () => {
  const safe = [
    "Authorization is handled by the gateway.",
    "GET /v1/models 200 in 42ms",
    'export APP_MODE="development"'
  ] as const;

  for (const input of safe) {
    expect(redactSensitiveText(input)).toBe(input);
  }
});

test("strips hidden reasoning blocks", () => {
  expect(stripHiddenReasoning("<think>private</think>{\"command\":\"ls\",\"summary\":\"list\"}")).toBe("{\"command\":\"ls\",\"summary\":\"list\"}");
});
