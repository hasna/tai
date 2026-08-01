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
    `{"Authorization": "Basic ${BASIC_CREDENTIALS}"}`,
    // `=` rather than `:` — an env dump or a query string, not a header line.
    // Every one of these produced `[REDACTED] <credential>` until the separator
    // class was widened: marker shown, credential intact.
    `authorization=Basic ${BASIC_CREDENTIALS}`,
    `AUTHORIZATION=Basic ${BASIC_CREDENTIALS}`,
    `authorization = Basic ${BASIC_CREDENTIALS}`,
    `authorization=Digest ${BEARER_CREDENTIALS}`,
    `Authorization=Bearer ${BEARER_CREDENTIALS}`,
    // `_` is a word character, so the `\b` this rule used to carry could never
    // match inside any of these. That one fact accounts for the whole family.
    `HTTP_AUTHORIZATION=Basic ${BASIC_CREDENTIALS}`,
    `AUTHORIZATION_HEADER=Basic ${BASIC_CREDENTIALS}`,
    `authorization_header: Basic ${BASIC_CREDENTIALS}`,
    `proxy_authorization=Basic ${BASIC_CREDENTIALS}`,
    // The hyphen and underscore spellings are NOT the same case: `\b` does match
    // after a hyphen, so `Proxy-Authorization:` was already clean while
    // `proxy-authorization=` was not. Both are pinned so neither regresses alone.
    `proxy-authorization=Basic ${BASIC_CREDENTIALS}`,
    `Proxy-Authorization: Basic ${BASIC_CREDENTIALS}`,
    // Not at the start of the line — a log line wraps the header in context.
    `req headers AUTHORIZATION=Basic ${BASIC_CREDENTIALS} done`,
    // Serialized JSON reaches logs whenever a request is logged as a string
    // rather than as an object.
    `{"headers":{"authorization":"Basic ${BASIC_CREDENTIALS}"}}`,
    `{"headers":{"HTTP_AUTHORIZATION":"Basic ${BASIC_CREDENTIALS}"}}`
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

// AWS SigV4 carries the signature in a trailing `Signature=` segment. The
// Authorization rule eats the scheme and the first comma-delimited part, so
// before this was covered the header printed a marker at the front of a line
// whose end was still a live signature.
const SIGV4_SIGNATURE = "0000deadbeefsyntheticsignature1111notreal2222abcdef3333abcdef4444";
const DIGEST_RESPONSE = "syntheticdigestresponse000000000000000000";
const PARAMETERIZED_AUTH_CREDENTIAL = "syntheticparameterizedauthproof000000";

test("removes a Digest Authorization response value", () => {
  const cases = [
    `Authorization: Digest username="synthetic-user", realm="synthetic", nonce="abc", response="${DIGEST_RESPONSE}"`,
    `authorization=Digest username="synthetic-user", realm="synthetic", nonce="abc", response=${DIGEST_RESPONSE}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(DIGEST_RESPONSE);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("removes a Digest response that sits far into a long header", () => {
  // A real Digest header reaches this length honestly: `nonce`, `opaque`,
  // `cnonce` and a long `uri` all precede `response=`, and none is bounded by
  // the RFC. Pinned because the ReDoS fix above had to keep working at this
  // length rather than buying speed with a length ceiling.
  //
  // WHAT THIS TEST DOES NOT PROVE, stated because it was written believing the
  // opposite: it does NOT discriminate against a bounded-scan fix. Measured —
  // a `[^\r\n]{0,256}?` variant passes this too, because the broader
  // Authorization rule masks the whole header downstream. So this pins an
  // end-to-end property ("the response value never survives a long header")
  // and is NOT a guard on the Digest rule in isolation. The evidence that the
  // restructure changed no behaviour is the A/B corpus run in the PR body
  // (22 shapes, zero output drift), not this assertion.
  const longNonce = "n".repeat(2048);
  const input = `Authorization: Digest username="synthetic-user", uri="/${ "segment/".repeat(128) }", nonce="${ longNonce }", response="${ DIGEST_RESPONSE }"`;

  const redacted = redactSensitiveText(input);
  expect(redacted).not.toContain(DIGEST_RESPONSE);
  expect(redactSensitiveText(redacted)).toBe(redacted);
});

// The Digest rule shipped a ReDoS in 0.1.3: a lazy `[^\r\n]*?` between
// `Digest\s+` and `response=` rescanned to end-of-line from every position where
// `authorization...Digest` matched, which is O(n^2) on a single long line.
//
// These assert a GROWTH RATIO rather than a millisecond figure. An absolute
// threshold turns machine load into a test result — this suite runs on
// contended boxes — while the exponent does not move with load: linear stays
// ~2x per doubling and quadratic stays ~4x whether the box is idle or busy.
const GROWTH_SIZES_KIB = [16, 32, 64] as const;

function medianMillis(input: string, runs = 5): number {
  const samples = Array.from({ length: runs }, () => {
    const started = process.hrtime.bigint();
    redactSensitiveText(input);
    return Number(process.hrtime.bigint() - started) / 1e6;
  }).sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

function growthPerDoubling(unit: string, separator: string): number {
  const times = GROWTH_SIZES_KIB.map((kib) =>
    medianMillis(Array.from({ length: Math.floor((kib * 1024) / unit.length) }, () => unit).join(separator))
  );
  const ratios = times.slice(1).map((time, index) => time / times[index]);
  return ratios.reduce((total, ratio) => total + ratio, 0) / ratios.length;
}

test("the Digest rule stays linear on a single long line", () => {
  // Repeated `Authorization: Digest ` with no `response=` anywhere: every match
  // starts a scan that runs to end-of-line and fails. This is the adversarial
  // input, and it is what a caller controls at src/mcp/index.ts (no bound) and
  // src/agentic.ts (bounded only by maxBuffer, 128 KiB — the `.slice(0, 12000)`
  // there runs AFTER redaction and so bounds nothing).
  const growth = growthPerDoubling("Authorization: Digest ", "");

  // Measured pre-fix on station02 at loadavg 1.23: 3.94x / 3.97x / 3.99x per
  // doubling (10.2 -> 40.1 -> 159.4 -> 635.9 ms across 16/32/64/128 KiB).
  // Post-fix on the same box: see the paired control below. 2.8x sits clear of
  // both a linear ~2.0x and a quadratic ~4.0x, so this fails loudly on the
  // shipped behaviour without flaking on a loaded machine.
  expect(growth).toBeLessThan(2.8);
});

test("newline-separated control: identical bytes, bounded rescans", () => {
  // The PAIR is the point, not either number alone. This shape carries the same
  // bytes as the test above with newlines between them, so each rescan is
  // bounded by its own line and it was linear even before the fix. If a future
  // change reintroduces end-of-line rescanning, the two diverge — the test
  // above goes quadratic while this one stays flat — and that divergence is the
  // signal. A single timing cannot distinguish "the regex got slow" from "the
  // box got busy"; two shapes measured together can.
  const growth = growthPerDoubling("Authorization: Digest ", "\n");

  expect(growth).toBeLessThan(2.8);
});

test("removes key-value credential parameters from Authorization schemes", () => {
  const cases = [
    `Authorization: Scheme sig=${PARAMETERIZED_AUTH_CREDENTIAL}`,
    `Authorization: MAC mac=${PARAMETERIZED_AUTH_CREDENTIAL}`,
    `Authorization: Scheme nonce=${PARAMETERIZED_AUTH_CREDENTIAL}`,
    `Authorization: HMAC hash=${PARAMETERIZED_AUTH_CREDENTIAL}`,
    `authorization=Basic abc=${PARAMETERIZED_AUTH_CREDENTIAL}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(PARAMETERIZED_AUTH_CREDENTIAL);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("removes an AWS SigV4 signature wherever it appears", () => {
  const cases = [
    `Signature=${SIGV4_SIGNATURE}`,
    // The credential-id segment is deliberately NOT written in AWS's `AKIA…`
    // shape: the staged-secrets gate matches that prefix on sight, and a fixture
    // that trips the gate teaches people to wave the gate through. The assertion
    // here is about the TRAILING `Signature=` segment, which needs no key id.
    `Authorization: AWS4-HMAC-SHA256 Credential=SYNTHETIC-KEY-ID/20260731/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=${SIGV4_SIGNATURE}`,
    `https://example.com/object?X-Amz-Signature=${SIGV4_SIGNATURE}&x=1`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(SIGV4_SIGNATURE);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }

  // Redacting a signature inside a query string must not swallow the unrelated
  // parameters that follow it — over-consuming would be its own defect.
  expect(redactSensitiveText(`https://example.com/object?X-Amz-Signature=${SIGV4_SIGNATURE}&x=1`)).toContain("&x=1");
});

test("removes a credential from a log line truncated mid-value", () => {
  // syslog caps a line at 1024 bytes; journald and CloudWatch truncate too. A
  // long structured line therefore arrives with its closing quote missing, which
  // is the NORMAL state of a big log line rather than an edge case. While the
  // quoted alternative required its closing backreference the rule declined and
  // a weaker rule took over, printing the marker and then the credential.
  const cases = [
    `{"lvl":"info","headers":{"authorization":"Basic ${BASIC_CREDENTIALS}`,
    `{"lvl":"info","headers":{"HTTP_AUTHORIZATION":"Basic ${BASIC_CREDENTIALS}`,
    `authorization="Basic ${BASIC_CREDENTIALS}`,
    `authorization='Basic ${BASIC_CREDENTIALS}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(BASIC_CREDENTIALS);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("masks the authorization value without deleting the fields beside it", () => {
  // Over-redaction that DESTROYS an adjacent field is worse than over-masking:
  // the value is gone from the log entirely. The scheme-consuming branch used to
  // swallow `user=bob` here, because `denied` looks like a scheme and `user=bob`
  // looks like the credential after it.
  const cases = [
    ["authorization=denied user=bob reason=scope", ["user=bob", "reason=scope"]],
    ["authorization: denied user=bob reason=scope", ["user=bob", "reason=scope"]],
    ["proxy_authorization=none user=alice path=/v1", ["user=alice", "path=/v1"]]
  ] as const;

  for (const [input, survivors] of cases) {
    const redacted = redactSensitiveText(input);
    for (const survivor of survivors) {
      expect(redacted).toContain(survivor);
    }
  }

  // …and the scheme-consuming branch must still work where it is genuinely a
  // scheme, or the guard above would have been bought by reintroducing the leak.
  expect(redactSensitiveText(`authorization=Basic ${BASIC_CREDENTIALS}`)).not.toContain(BASIC_CREDENTIALS);
});

test("positive control: the absence assertion can fail", () => {
  // If `not.toContain(BASIC_CREDENTIALS)` passed no matter what was fed in, the
  // test above would prove nothing. This anchors it: the identical literal, in
  // free prose that carries no credential context, is left alone and IS found.
  const prose = `The build log mentioned ${BASIC_CREDENTIALS} in passing.`;
  expect(redactSensitiveText(prose)).toContain(BASIC_CREDENTIALS);
  // Same anchor for the SigV4 literal, so that test cannot pass vacuously either.
  const sigProse = `The build log mentioned ${SIGV4_SIGNATURE} in passing.`;
  expect(redactSensitiveText(sigProse)).toContain(SIGV4_SIGNATURE);
  const digestProse = `The build log mentioned ${DIGEST_RESPONSE} in passing.`;
  expect(redactSensitiveText(digestProse)).toContain(DIGEST_RESPONSE);
  const parameterizedProse = `The build log mentioned ${PARAMETERIZED_AUTH_CREDENTIAL} in passing.`;
  expect(redactSensitiveText(parameterizedProse)).toContain(PARAMETERIZED_AUTH_CREDENTIAL);
});

test("does not over-redact text that carries no credential", () => {
  const safe = [
    "Authorization is handled by the gateway.",
    "GET /v1/models 200 in 42ms",
    'export APP_MODE="development"',
    // Widening the separator to `[:=]` must not let the rule reach across an
    // unrelated assignment. Without these the over-redaction test only feeds in
    // strings nothing would ever have matched, and so guards nothing.
    "mode=production",
    "retries=3 timeout=30",
    "status=ok count=42 duration=1.5s",
    // Dropping the `\b` widened what counts as a key; prose that merely contains
    // the words must still come back byte-identical.
    "signature verified for block 1234",
    // NOTE: `SignedHeaders` contains no `signature` substring, so it cannot
    // detect the class it looks like it is guarding. It is kept because it is a
    // real SigV4 token, but the actual guard for `signature`-keyed masking is
    // the assertion below, and in this repo that masking is INTENTIONAL — see
    // docs/redaction.md. A benign case that cannot fail is not a guard.
    "SignedHeaders=host;x-amz-date"
  ] as const;

  for (const input of safe) {
    expect(redactSensitiveText(input)).toBe(input);
  }

  // The `signature`-keyed rule masks ANY key containing `signature`, including
  // `SignatureVersion=4`, which is not a secret. That is a deliberate trade —
  // over-masking a non-secret is cheap, a leaked signature is not — and it is
  // pinned here so the behaviour is a decision on record rather than a surprise.
  // This repo and hasnaxyz/iapp-sms differ here; see docs/redaction.md.
  expect(redactSensitiveText("SignatureVersion=4")).toBe("SignatureVersion=[REDACTED]");
});

test("strips hidden reasoning blocks", () => {
  expect(stripHiddenReasoning("<think>private</think>{\"command\":\"ls\",\"summary\":\"list\"}")).toBe("{\"command\":\"ls\",\"summary\":\"list\"}");
});
