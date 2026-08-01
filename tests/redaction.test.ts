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

// Shared calibration bounds for both growth helpers.
const RUN_GROWTH_FLOOR_MS = 1.5;
const RUN_GROWTH_MIN_KIB = 8;
const RUN_GROWTH_MAX_BASE_KIB = 128;

// TAKE THE FASTEST SAMPLE, NOT THE MEDIAN, and warm up before sampling. This
// suite runs on contended boxes, and CPU contention is strictly ADDITIVE noise:
// a sample can be slowed by another process but never sped up, so the minimum is
// the sample closest to uncontended execution while the median drags with load.
// A median-based estimator failed the newline control at ratio 6.40 on a box at
// loadavg 25, and an adversarial reviewer measured it failing 2 runs in 10.
//
// This does NOT weaken the guard, which is the thing to check before changing an
// estimator: a genuinely quadratic implementation has a quadratic minimum too,
// so the naive mutant still returns ~4.0 here. Verified against the mutant after
// the change, not assumed.
function fastestMillis(input: string, runs = 9): number {
  redactSensitiveText(input);
  let fastest = Infinity;
  for (let run = 0; run < runs; run += 1) {
    const started = process.hrtime.bigint();
    redactSensitiveText(input);
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    if (elapsed < fastest) {
      fastest = elapsed;
    }
  }
  return fastest;
}

function repeatedInput(unit: string, separator: string, kib: number): string {
  return Array.from({ length: Math.floor((kib * 1024) / unit.length) }, () => unit).join(separator);
}

// Calibrated to the machine for the same reason as the run-length helper below:
// at a fixed small size a fast, quiet runner finishes in a fraction of a
// millisecond, timer resolution dominates the ratio, and the assertion fails
// while the implementation is perfectly linear. This family has been the source
// of every flake in this suite — the Digest control failed 1 run in 8 here at
// loadavg 25, and was measured at 2 in 10 before the estimator was changed.
// Growing until the measurement is solid removes the noise without touching the
// threshold, which is the part that must not move.
function growthPerDoubling(unit: string, separator: string): number {
  let baseKib = GROWTH_SIZES_KIB[0];
  while (
    baseKib < RUN_GROWTH_MAX_BASE_KIB
    && fastestMillis(repeatedInput(unit, separator, baseKib), 3) < RUN_GROWTH_FLOOR_MS
  ) {
    baseKib *= 2;
  }

  const times = [baseKib, baseKib * 2, baseKib * 4].map((kib) =>
    fastestMillis(repeatedInput(unit, separator, kib))
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

// ---------------------------------------------------------------------------
// Cookie headers. A `Cookie:` / `Set-Cookie:` value is a THIRD delimiter role:
// the header value is itself a `;`-delimited list of `name=value` pairs, and the
// credential is one pair among several. Nothing in this file keyed on that
// shape, so every cookie below survived verbatim on a PUBLIC repository whose
// SECURITY.md points readers at docs/redaction.md.
//
// Synthetic, never-issued. Deliberately carries no substring any other rule in
// this file keys on — no `token`, `secret`, `auth`, `key`, `sk-`, `gsk_`. A
// fixture that another rule happens to catch cannot detect a cookie rule at all,
// and that is not hypothetical: `__Secure-next-auth.session-token=<value>` was
// ALREADY redacted before this change, purely because the generic `*TOKEN*` key
// rule matched the substring `token` in the cookie NAME. One spelling covered by
// an unrelated rule is exactly what makes a family read as handled.
const COOKIE_CREDENTIAL = "syntheticcookievalue0000notreal1111";

test("removes cookie values from Cookie and Set-Cookie headers", () => {
  const cases = [
    // AXIS: cookie name. Names are chosen by the application, so any list of
    // "session-ish" names fails open on the next framework. None of these
    // contains a substring another rule in this file keys on.
    `Cookie: session=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=${COOKIE_CREDENTIAL}`,
    `Cookie: PHPSESSID=${COOKIE_CREDENTIAL}`,
    `Cookie: JSESSIONID=${COOKIE_CREDENTIAL}`,
    `Cookie: connect.sid=${COOKIE_CREDENTIAL}`,
    `Cookie: laravel_session=${COOKIE_CREDENTIAL}`,
    `Cookie: _csrf=${COOKIE_CREDENTIAL}`,
    `Cookie: __Host-sid=${COOKIE_CREDENTIAL}`,
    `Cookie: __Secure-sid=${COOKIE_CREDENTIAL}`,
    // AXIS: header spelling and case. `Set-Cookie` is the response direction and
    // leaks the same value; `\b` would never have matched inside `HTTP_COOKIE`.
    `Set-Cookie: sid=${COOKIE_CREDENTIAL}`,
    `set-cookie: sid=${COOKIE_CREDENTIAL}`,
    `SET-COOKIE: SID=${COOKIE_CREDENTIAL}`,
    `HTTP_COOKIE=session=${COOKIE_CREDENTIAL}`,
    `cookie_header: sid=${COOKIE_CREDENTIAL}`,
    // AXIS: separator, and whitespace around it.
    `cookie=sid=${COOKIE_CREDENTIAL}`,
    `cookie = sid=${COOKIE_CREDENTIAL}`,
    `Cookie:sid=${COOKIE_CREDENTIAL}`,
    // AXIS: position of the credential-bearing pair among several. A rule that
    // only reaches the first pair passes the single-pair cases above.
    `Cookie: theme=dark; sid=${COOKIE_CREDENTIAL}; lang=en`,
    `Cookie: a=1; b=2; c=3; sid=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=${COOKIE_CREDENTIAL}; theme=dark`,
    // AXIS: quoting, including the truncated line that syslog/journald/CloudWatch
    // produce — the closing quote is simply absent.
    `{"headers":{"cookie":"session=${COOKIE_CREDENTIAL}"}}`,
    `{"Set-Cookie": "sid=${COOKIE_CREDENTIAL}; Path=/"}`,
    `cookie='sid=${COOKIE_CREDENTIAL}'`,
    `{"lvl":"info","headers":{"cookie":"sid=${COOKIE_CREDENTIAL}`,
    // AXIS: Set-Cookie attributes trailing the pair.
    `Set-Cookie: sid=${COOKIE_CREDENTIAL}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    `Set-Cookie: sid=${COOKIE_CREDENTIAL}; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Max-Age=3600`,
    // AXIS: an attribute NAME reused as a cookie name. The exemption that keeps
    // `Path=/` readable must not become a way to smuggle a credential past it.
    `Set-Cookie: sid=1; path=${COOKIE_CREDENTIAL}`,
    `Cookie: domain=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; path=/${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; domain=${COOKIE_CREDENTIAL}.example`,
    // AXIS: not at the start of the line, and more than one header per input.
    `req GET /v1 cookie: sid=${COOKIE_CREDENTIAL} done`,
    `Cookie: sid=${COOKIE_CREDENTIAL}\nAuthorization: Bearer ${BEARER_CREDENTIALS}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    // Assert the CREDENTIAL IS GONE. A `[REDACTED]`-present assertion would pass
    // against `Cookie: session=<live value>` unchanged, because other rules on
    // the same line can print a marker.
    expect(redacted).not.toContain(COOKIE_CREDENTIAL);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("positive control: the cookie absence assertion can fail", () => {
  // Without this, `not.toContain(COOKIE_CREDENTIAL)` could be passing because the
  // literal never survives anything, rather than because a cookie rule masked it.
  const prose = `The build log mentioned ${COOKIE_CREDENTIAL} in passing.`;
  expect(redactSensitiveText(prose)).toContain(COOKIE_CREDENTIAL);

  // …and the paired must-redact control, so the two point in opposite directions:
  // the same literal under a shape this file already covers IS removed.
  expect(redactSensitiveText(`Authorization: Bearer ${COOKIE_CREDENTIAL}`)).not.toContain(COOKIE_CREDENTIAL);
});

test("keeps Set-Cookie attributes and neighbouring log fields readable", () => {
  // Over-redaction that DESTROYS context is its own defect — a masked cookie
  // whose Path/Domain/Expires went with it loses the forensic value of the log
  // line. RFC 6265's attribute vocabulary is CLOSED, which is what makes an
  // attribute exemption safe where a cookie-name allowlist would not be: an
  // unrecognised name is treated as a cookie and masked.
  const attributed = `Set-Cookie: sid=${COOKIE_CREDENTIAL}; Path=/admin; Domain=example.test; Max-Age=3600; SameSite=Lax; Expires=Wed, 09 Jun 2027 10:18:14 GMT; HttpOnly; Secure`;
  const redacted = redactSensitiveText(attributed);
  expect(redacted).not.toContain(COOKIE_CREDENTIAL);
  for (const survivor of ["Path=/admin", "Domain=example.test", "Max-Age=3600", "SameSite=Lax", "Expires=Wed, 09 Jun 2027 10:18:14 GMT", "HttpOnly", "Secure"]) {
    expect(redacted).toContain(survivor);
  }

  // A cookie header sitting mid-line must not turn the rest of the line into
  // markers. RFC 6265 delimits cookie pairs with `;` — whitespace-separated
  // `key=value` text after the header is ordinary log context, not a cookie.
  const inline = `cookie: sid=${COOKIE_CREDENTIAL} status=200 user=bob duration=1.5s`;
  const inlineRedacted = redactSensitiveText(inline);
  expect(inlineRedacted).not.toContain(COOKIE_CREDENTIAL);
  for (const survivor of ["status=200", "user=bob", "duration=1.5s"]) {
    expect(inlineRedacted).toContain(survivor);
  }

  // Prose that merely contains the word must come back byte-identical.
  for (const safe of [
    "Cookie consent is handled by the gateway.",
    "The cookie policy changed in June.",
    "cookies: chocolate and vanilla"
  ]) {
    expect(redactSensitiveText(safe)).toBe(safe);
  }
});

// GROWS THE RUN, NOT THE REPEAT COUNT — and that distinction is the whole test.
//
// `growthPerDoubling` below enlarges its input by repeating a fixed unit, so the
// NUMBER of runs grows and no single unbroken run ever gets longer. The
// quadratic this rule was restructured to avoid is PER RUN, O(run²):
// `[^\s;,=]+` followed by a literal `=` backtracks across one run at every start
// position inside it. A harness that never grows a run cannot express that axis
// AT ANY SIZE.
//
// That is not a hypothetical. An adversarial reviewer installed the rejected
// naive pattern and ran the two assertions below it: they returned 1.97, 2.00
// and 1.87 — all green, WITH THE ReDoS IN PLACE. This file's own docs section on
// probes that pass for the wrong reason was committed in the same change as
// those assertions.
//
// THE DISCRIMINATING SHAPE HAS NO `=` IN THE HEADER VALUE AT ALL. That detail is
// load-bearing and a first attempt at this test got it wrong: `"Cookie: sid="`
// followed by a long run measures 1.960 against the naive pattern and PASSES,
// because `sid=` satisfies the literal immediately and the scan never has to
// fail — 0.04 ms against 228 ms for the shape below. Both assertions here
// therefore put the whole run AFTER the header separator and BEFORE any `=`.
// SIZES ARE CALIBRATED TO THE MACHINE, not fixed, and that is what makes this
// assertion honest in BOTH directions.
//
// Fixed at 8/16/32 KiB it failed CI at ratio well outside tolerance while the
// implementation was perfectly linear: on a fast, quiet runner the linear scan
// finishes those sizes in a fraction of a millisecond, and at that scale timer
// resolution and JIT noise dominate the ratio. A test that can fail when nothing
// is wrong is exactly as useless as one that cannot fail when something is —
// this file already had the second kind, and replacing it with the first would
// be no improvement.
//
// So: grow the smallest size until it is comfortably above timer noise, then
// measure across three doublings from there. The two cases separate themselves
// without a threshold change.
//
//  - A LINEAR implementation is fast, so calibration keeps doubling and ends up
//    measuring at sizes where the numbers are solid. Cheap either way.
//  - A QUADRATIC one is already far above the floor at the smallest size, so
//    calibration stops immediately and the assertion fails at small sizes and
//    therefore FAST — measured at ~29s against a mutant carrying the naive
//    pattern. A test that can only fail by timing out reports its budget rather
//    than a duration.

function runLengthInput(prefix: string, kib: number): string {
  return prefix + "x".repeat(kib * 1024 - prefix.length);
}

function runLengthGrowthPerDoubling(prefix: string): number {
  let baseKib = RUN_GROWTH_MIN_KIB;
  while (
    baseKib < RUN_GROWTH_MAX_BASE_KIB
    && fastestMillis(runLengthInput(prefix, baseKib), 3) < RUN_GROWTH_FLOOR_MS
  ) {
    baseKib *= 2;
  }

  const times = [baseKib, baseKib * 2, baseKib * 4].map((kib) =>
    fastestMillis(runLengthInput(prefix, kib), 5)
  );
  const ratios = times.slice(1).map((time, index) => time / times[index]);
  return ratios.reduce((total, ratio) => total + ratio, 0) / ratios.length;
}

test("the cookie rule stays linear as a single unbroken RUN grows", () => {
  // Request direction: the header value is one enormous token carrying no `=`.
  expect(runLengthGrowthPerDoubling("cookie=")).toBeLessThan(2.8);
  // Response direction, same axis — the attribute path must not reintroduce it.
  expect(runLengthGrowthPerDoubling("Set-Cookie: ")).toBeLessThan(2.8);
});

test("the cookie rule stays linear on a cookie-dense single line", () => {
  // WHAT THESE TWO ACTUALLY GUARD, stated accurately because the comment that
  // stood here claimed they guarded the inner scan and they do not. Repeating a
  // fixed unit grows the NUMBER of runs, not their LENGTH, so these exercise the
  // OUTER regex — how many start positions it must consider, and whether a match
  // consumes to end-of-line instead of being re-entered. That is a real property
  // worth pinning. It is not the per-run quadratic, which the test above pins.
  //
  // Kept honest by measurement: with the naive inner pattern installed, both of
  // these return ~2.0 and PASS. Neither can detect that defect.
  expect(growthPerDoubling("Cookie: sid=a; b=c; ", "")).toBeLessThan(2.8);
  // NOTE: this one never triggers the cookie rule at all — no `:` or `=` follows
  // the literal, so the outer regex never matches and the input is returned
  // unchanged. It is retained as a guard on the LITERAL-SCAN cost of adding a
  // second `cookie`-keyed pattern to a file full of them, and it is labelled so
  // nobody reads it as cookie-redaction coverage.
  expect(redactSensitiveText("cookiecookiecookie")).toBe("cookiecookiecookie");
  expect(growthPerDoubling("cookiecookiecookie", "")).toBeLessThan(2.8);
});

test("newline-separated cookie control: identical bytes, bounded rescans", () => {
  // The PAIR is the signal. If a future change makes the cookie rule rescan to
  // end-of-line from every start position, the single-line shape above goes
  // quadratic while this one stays flat. One timing alone cannot tell "the regex
  // got slow" from "the box got busy".
  expect(growthPerDoubling("Cookie: sid=a; b=c; ", "\n")).toBeLessThan(2.8);
});

// ---------------------------------------------------------------------------
// Adversarial-review findings, round 1. Every case below LEAKED at ebfa05d.

test("a request Cookie header has no attributes, so no pair is exempt", () => {
  // RFC 6265 §4.2.1: `cookie-string = cookie-pair *( ";" SP cookie-pair )`.
  // `Path`, `Domain`, `Expires`, `Max-Age`, `SameSite` are RESPONSE attributes
  // and mean nothing in a request, so in a request header those are ordinary
  // cookie NAMES chosen by the application and their values are credentials.
  // The first version of this rule could not tell the two headers apart -- it
  // starts matching at the `cookie` substring -- so a request cookie inherited
  // the response header's exemptions and walked straight through.
  const cases = [
    `Cookie: sid=1; path=/${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; domain=${COOKIE_CREDENTIAL}.example`,
    `Cookie: sid=1; expires=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; max-age=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; samesite=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; secure=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; httponly=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; priority=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; version=${COOKIE_CREDENTIAL}`,
    `Cookie: sid=1; partitioned=${COOKIE_CREDENTIAL}`,
    // Casing and the `=` separator reach the same detection, so pin them too.
    `cookie: sid=1; PATH=/${COOKIE_CREDENTIAL}`,
    `COOKIE=sid=1; Path=/${COOKIE_CREDENTIAL}`,
    `HTTP_COOKIE=sid=1; domain=${COOKIE_CREDENTIAL}.example`,
    `{"headers":{"cookie":"sid=1; path=/${COOKIE_CREDENTIAL}"}}`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(COOKIE_CREDENTIAL);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("Set-Cookie attribute exemptions are narrow enough to exclude a credential", () => {
  // The exemption's VALUE shapes were measured far looser than the guard needed
  // to be: `expires` accepted any run of up to 32 alphanumerics, which is
  // exactly the shape of a session id, and `domain` was length-unbounded and
  // accepted an 87-character JWT-shaped token. 12 of 14 attribute-named probes
  // preserved a synthetic credential.
  const jwtShaped = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJTWU5USDAwMDAifQ.SYNTHsignature0000notreal";
  const cases = [
    `Set-Cookie: sid=1; Expires=${COOKIE_CREDENTIAL}`,
    `Set-Cookie: sid=1; Expires=SYNTHETICSESSIONID000000000000AB`,
    `Set-Cookie: sid=1; Domain=${jwtShaped}`,
    `Set-Cookie: sid=1; Max-Age=${COOKIE_CREDENTIAL}`,
    `Set-Cookie: sid=1; SameSite=${COOKIE_CREDENTIAL}`,
    // The opening pair is the cookie in a Set-Cookie too, so an attribute name
    // in first position is never exempt.
    `Set-Cookie: path=/${COOKIE_CREDENTIAL}`,
    `Set-Cookie: domain=${COOKIE_CREDENTIAL}.example`,
    // A valueless flag ahead of the cookie must not spend the opening-pair
    // protection: pairs are counted, not tokens.
    `Set-Cookie: Secure; path=/${COOKIE_CREDENTIAL}`,
    `Set-Cookie: HttpOnly; Secure; domain=${COOKIE_CREDENTIAL}.example`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(COOKIE_CREDENTIAL);
    expect(redacted).not.toContain(jwtShaped);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }

  // ...and the exemption must still WORK, or the guard above would have been
  // bought by deleting the feature. These are real attribute values.
  const attributed = redactSensitiveText(
    `Set-Cookie: sid=${COOKIE_CREDENTIAL}; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Max-Age=3600; Domain=example.test; Path=/admin; SameSite=Lax; Priority=High; HttpOnly; Secure`
  );
  expect(attributed).not.toContain(COOKIE_CREDENTIAL);
  for (const survivor of ["Expires=Wed, 09 Jun 2027 10:18:14 GMT", "Max-Age=3600", "Domain=example.test", "Path=/admin", "SameSite=Lax", "Priority=High", "HttpOnly", "Secure"]) {
    expect(attributed).toContain(survivor);
  }
});

test("masking a cookie does not destroy the structure around it", () => {
  // Replacing everything after `=` swallowed the closing quotes and brackets of
  // a cookie logged inside JSON, so the line stopped being parseable. Not a
  // leak, but it contradicts this rule's own invariant that output differs from
  // input only where a value was masked -- and destroying context is the defect
  // this file already had to fix once on the authorization side.
  const input = `{"set-cookie": ["a=1", "sid=${COOKIE_CREDENTIAL}"]}`;
  const redacted = redactSensitiveText(input);
  expect(redacted).not.toContain(COOKIE_CREDENTIAL);
  // Count QUOTES, not brackets: `[REDACTED]` contains a `]` of its own, so a
  // bracket count compares two different things and is not a structure check.
  // The marker carries no quote, so the quote count is a clean invariant.
  expect(redacted.split('"').length).toBe(input.split('"').length);
  expect(redacted.endsWith('"]}')).toBe(true);
  expect(redacted).toBe('{"set-cookie": ["a=[REDACTED]", "sid=[REDACTED]"]}');
  expect(redactSensitiveText(redacted)).toBe(redacted);
});

test("positive control: the round-1 assertions can fail", () => {
  // Each assertion above is an ABSENCE claim, so each needs proof the literal is
  // findable when nothing masks it.
  const jwtShaped = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJTWU5USDAwMDAifQ.SYNTHsignature0000notreal";
  expect(redactSensitiveText(`The log mentioned ${COOKIE_CREDENTIAL} in passing.`)).toContain(COOKIE_CREDENTIAL);
  expect(redactSensitiveText(`The log mentioned ${jwtShaped} in passing.`)).toContain(jwtShaped);
  expect(redactSensitiveText("The log mentioned SYNTHETICSESSIONID000000000000AB in passing.")).toContain("SYNTHETICSESSIONID000000000000AB");
});

test("a cookie value that is entirely delimiters is still masked", () => {
  // A dangling delimiter is not a tidy edge case, it is a leak. `AUTH=",<cred>`
  // tokenises to `AUTH="` — the comma is a pair separator — and leaving that
  // token untouched left an OPEN QUOTE in the line. The generic `*AUTH*` rule
  // downstream pairs `(["'])…\2`, so it mis-paired across to the next field's
  // quote or declined to match, and the credential printed with NO marker. The
  // same input was masked before the cookie rule existed, so the rule was making
  // the line worse. Found by adversarial review, 13 hits in a 300,000-case sweep.
  const cases = [
    `cookie:AUTH=",${COOKIE_CREDENTIAL}`,
    `Set-Cookie: AUTH=",${COOKIE_CREDENTIAL}`,
    `Cookie:TOKEN="\tpassword="${COOKIE_CREDENTIAL}"`,
    `Cookie: sid="`,
    `Cookie: a=']}`,
    `Set-Cookie: sid=";`
  ] as const;

  for (const input of cases) {
    const redacted = redactSensitiveText(input);
    expect(redacted).not.toContain(COOKIE_CREDENTIAL);
    // Idempotence broke here too — `api_key="; session="` masked to
    // `api_key="[REDACTED]"` and then to `api_key=[REDACTED]"` on the next pass.
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }

  expect(redactSensitiveText(`Set-Cookie: api_key="; session="`)).toBe(
    redactSensitiveText(redactSensitiveText(`Set-Cookie: api_key="; session="`))
  );

  // The JSON structure this re-emission exists for must survive the fix — the
  // cheaper repair (dropping quotes from the closer set) closes the leak but
  // gives this back, so it is pinned rather than assumed.
  expect(redactSensitiveText(`{"set-cookie": ["a=1", "sid=${COOKIE_CREDENTIAL}"]}`))
    .toBe('{"set-cookie": ["a=[REDACTED]", "sid=[REDACTED]"]}');

  // Positive control: the literal is findable when nothing masks it.
  expect(redactSensitiveText(`log mentioned ${COOKIE_CREDENTIAL} once`)).toContain(COOKIE_CREDENTIAL);
});

// ---------------------------------------------------------------------------
// ESCAPED-QUOTE TERMINATOR — todos d841b3e1.
//
// THIS AXIS DID NOT EXIST IN THIS FILE BEFORE THIS COMMIT, which is why a suite
// carrying 21 `digest` fixtures never found the defect. Measured on the corpus
// at 06cc7de: escaped quotes 0 occurrences, `hawk` 0 occurrences — so no amount
// of adding cases along the EXISTING axes could have expressed the shape. The
// tests below introduce the axis rather than extending the list.

// Synthetic, never-issued. Deliberately matches NO provider-prefix rule in
// src/redaction.ts (not sk-, gsk_, csk-, AKIA) so that a pass here can only come
// from the structural authorization handling under test.
//
// THAT PROPERTY IS THE POINT AND IT IS EASY TO LOSE. Probing this same defect
// with an `sk-`-prefixed canary returns "redacted" from the provider-prefix rule
// while the structural rule is still broken — the probe passes for the wrong
// reason. That is exactly how a sibling implementation was read as clean on
// shapes it in fact leaks on.
const ESCAPED_QUOTE_CANARY = "QQZZSYNTHETICCANARY0000NOTACREDENTIAL9999";

const AUTHORIZATION_SCHEMES = [
  ["Basic", `Basic ${ ESCAPED_QUOTE_CANARY }`],
  ["Bearer", `Bearer ${ ESCAPED_QUOTE_CANARY }`],
  // RFC 7616 Digest and Hawk carry QUOTED PARAMETERS natively. That is the whole
  // reachability argument: one ordinary `JSON.stringify(req.headers)` already
  // produces the escaped-quote shape for them, with no double encoding and no
  // attacker shaping the input.
  ["Digest", `Digest username="u", realm="r", nonce="n", uri="/", qop=auth, response="${ ESCAPED_QUOTE_CANARY }", opaque="o"`],
  ["Hawk", `Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="x", mac="${ ESCAPED_QUOTE_CANARY }"`]
] as const;

test("a JSON-serialized headers object does not leak the credential past an escaped quote", () => {
  for (const [scheme, value] of AUTHORIZATION_SCHEMES) {
    // The ordinary log call: JSON.stringify(req.headers). Built with a real
    // serializer, not hand-written, so the escaping is the runtime's.
    const input = JSON.stringify({ headers: { authorization: value } });
    const redacted = redactSensitiveText(input);

    expect(redacted, `${ scheme } leaked through a JSON-serialized headers object`)
      .not.toContain(ESCAPED_QUOTE_CANARY);
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});

test("the marker never appears beside a surviving credential", () => {
  // The specific pathology this task exists to remove, asserted directly rather
  // than as a consequence: before the fix the Digest and Hawk rows above came
  // back as `"authorization":"[REDACTED]"u\", response=\"<cred>\""` — a marker
  // that tells the next reader the line is clean, next to the credential. A
  // plain gap is bad; a gap wearing a marker is worse, because it stops the
  // reader looking.
  for (const [scheme, value] of AUTHORIZATION_SCHEMES) {
    const redacted = redactSensitiveText(JSON.stringify({ headers: { authorization: value } }));
    const leaked = redacted.includes(ESCAPED_QUOTE_CANARY);
    expect(leaked && redacted.includes("[REDACTED]"), `${ scheme } printed a marker beside a surviving credential`)
      .toBe(false);
  }
});

test("escaped-quote coverage does not depend on the credential matching a provider prefix", () => {
  // POSITIVE CONTROL FOR THE CONTROL. If this canary ever starts matching a
  // provider-prefix rule, every assertion above would pass without the
  // structural rule working at all. Pin the property: in bare prose, where no
  // structural rule applies, the canary must survive.
  expect(redactSensitiveText(`build id ${ ESCAPED_QUOTE_CANARY } is public`))
    .toContain(ESCAPED_QUOTE_CANARY);
});

test("escaped quotes in ordinary non-credential JSON are preserved byte for byte", () => {
  // NEGATIVE CONTROL. A change that masks everything scores zero leaks and is a
  // different defect. Legitimate structure carrying escaped quotes must come
  // back unchanged.
  for (const safe of [
    String.raw`{"user":"bob","note":"he said \"hello\" loudly"}`,
    String.raw`{"path":"C:\\Users\\bob","ok":true}`,
    String.raw`{"msg":"quote \" inside","level":"info"}`
  ]) {
    expect(redactSensitiveText(safe)).toBe(safe);
  }

  // The neighbouring-field guard, asserted as the file's own design states it
  // rather than as "byte-identical". An explicit non-secret status IS masked —
  // `authorization=denied` becomes `authorization=[REDACTED]` — while the audit
  // fields beside it survive. Over-redaction that DELETES a neighbour is the
  // failure this protects against, and this file has had to fix it once.
  //
  // Written down because the first version of this test asserted byte-identity
  // and failed: measured on both base and patched, the outputs are IDENTICAL, so
  // the test was wrong about the design and the code was right. Pinning the
  // wrong property here would have made a future correct change look like a
  // regression.
  for (const [input, survivors] of [
    [`authorization=denied user=bob reason=scope`, ["user=bob", "reason=scope"]],
    [`authorization=allowed user=alice`, ["user=alice"]]
  ] as const) {
    const redacted = redactSensitiveText(input);
    for (const survivor of survivors) {
      expect(redacted, `over-redaction deleted a neighbouring audit field: ${ survivor }`).toContain(survivor);
    }
  }
});

test("the escape-aware value body cannot be driven exponential by a run of backslashes", () => {
  // THE OBVIOUS FIX IS A ReDoS AND THIS IS WHAT PINS THE SHIPPED ONE.
  //
  // `(?:\\.|(?!\2)[^\r\n])*` lets a backslash be consumed by EITHER branch, so a
  // run of N backslashes has exponentially many parses. They are only explored
  // when the quoted branch must FAIL — which is precisely the generic key rules,
  // whose closing quote is required (`\2`, not `\2?`).
  //
  // Measured on this box against a mutant carrying the ambiguous body:
  // 0.25 / 0.57 / 1.54 / 3.96 / 10.35 / 27.33 ms at N = 18/20/22/24/26/28,
  // roughly 1.6^N, while the shipped disjoint body stayed flat at ~0.001 ms.
  // This file has already shipped two quadratic rules; a third arriving through
  // the fix for a leak would be a poor trade.
  //
  // The assertion is an absolute budget rather than a growth ratio because the
  // exponential separates by orders of magnitude, not by a slope — and because
  // the ratio-based tests in this file are the source of every flake in it.
  const adversarial = (n: number) => `API_TOKEN:"` + "\\".repeat(n) + "\nX";

  // Calibration guard: prove the input actually reaches the rule, so a budget
  // met by an input the regex never touches cannot pass for coverage.
  expect(redactSensitiveText(`API_TOKEN:"${ ESCAPED_QUOTE_CANARY }"`)).not.toContain(ESCAPED_QUOTE_CANARY);

  const started = process.hrtime.bigint();
  for (const n of [24, 28, 32, 40, 64, 128]) {
    redactSensitiveText(adversarial(n));
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  // The ambiguous body needs ~27 ms for N=28 ALONE and doubles every two
  // backslashes, so it cannot complete N=40 let alone N=128 inside this budget.
  // The disjoint body completes the whole sweep in well under a millisecond.
  expect(elapsedMs).toBeLessThan(1000);
});

test("every rule that models a quoted value captures the quote as group 2", () => {
  // The shared value body carries `\2`, so it is only correct while the opening
  // quote is group 2 in every pattern that embeds it. That invariant is
  // currently true by construction and would break silently — the rule would
  // simply stop matching, and a redaction rule that stops matching fails OPEN.
  // Asserted here rather than left to be discovered by a leak.
  const quoted = [
    `{"headers":{"authorization":"Basic ${ ESCAPED_QUOTE_CANARY }"}}`,
    `{"signature":"${ ESCAPED_QUOTE_CANARY }"}`,
    `{"API_TOKEN":"${ ESCAPED_QUOTE_CANARY }"}`,
    `{"api_key":"${ ESCAPED_QUOTE_CANARY }"}`,
    `API_TOKEN="${ ESCAPED_QUOTE_CANARY }"`,
    `api_key="${ ESCAPED_QUOTE_CANARY }"`,
    `{"cookie":"sid=${ ESCAPED_QUOTE_CANARY }"}`
  ];

  for (const input of quoted) {
    const redacted = redactSensitiveText(input);
    expect(redacted, `group-2 invariant broken for: ${ input }`).not.toContain(ESCAPED_QUOTE_CANARY);
    // The surrounding quote must be re-emitted, not swallowed — a rule that
    // matched but dropped the quote would also pass the leak assertion.
    expect(redactSensitiveText(redacted)).toBe(redacted);
  }
});
