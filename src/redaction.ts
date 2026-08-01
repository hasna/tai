type SecretReplacement = string | ((substring: string, ...args: any[]) => string);

const NON_SECRET_AUTHORIZATION_VALUES = new Set([
  "absent",
  "allow",
  "allowed",
  "anonymous",
  "denied",
  "forbidden",
  "invalid",
  "missing",
  "none",
  "unauthorized"
]);

const AUTHORIZATION_PARAMETER_PATTERN = /(?:^|[\s,])[A-Za-z_][A-Za-z0-9_.-]{0,32}=(?!=)(?=\S)/;

// Applied to ONE Digest header value at a time by redactDigestResponse, never
// to the whole input. Scoping it that way is what keeps the scan linear — see
// the note above the Digest entry in SECRET_PATTERNS.
const DIGEST_RESPONSE_PATTERN = /(\bresponse\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2?|[^\s'",]+)/gi;

const SECRET_PATTERNS: Array<[RegExp, SecretReplacement]> = [
  [/\b(sk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_OPENAI_KEY]"],
  [/\b(gsk_[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_GROQ_KEY]"],
  [/\b(csk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_CEREBRAS_KEY]"],
  [/\b(AKIA[0-9A-Z]{16})\b/g, "[REDACTED_AWS_KEY]"],
  // Digest auth stores its credential proof in a quoted `response=` parameter.
  // Mask it before the broader Authorization rule below replaces the scheme
  // token; otherwise the line can still print a marker while the response
  // survives beside it.
  //
  // THIS RULE WAS A ReDoS UNTIL THIS COMMIT, and the shape it shipped in is
  // worth keeping written down because it reads as harmless:
  //
  //   ...Digest\s+[^\r\n]*?\bresponse\s*=
  //
  // The lazy `[^\r\n]*?` rescans to END-OF-LINE from every position where
  // `authorization...Digest` matches. Many matches on one line is O(n^2); a
  // newline bounds each rescan, so ordinary multi-line log text stayed linear
  // and the defect never showed up in normal use. Measured on station02
  // (loadavg 1.23), repeated `Authorization: Digest ` on a single line:
  // 10.2 / 40.1 / 159.4 / 635.9 ms at 16/32/64/128 KiB — 3.94x, 3.97x, 3.99x
  // per doubling. The identical bytes newline-separated: 2.9 ms at 128 KiB.
  //
  // The cost is the SCAN DISTANCE, not the number of matches. The control that
  // settles that: a 128 KiB single line carrying 3971 `Digest` occurrences whose
  // scan terminates immediately (`Digest response=x `) runs in 0.5 ms, while
  // 5957 occurrences whose scan runs to end-of-line take 636.1 ms.
  //
  // Reachable from two call sites, which is what makes it a ReDoS rather than a
  // slow function: agentic.ts bounds shell output at maxBuffer 128 KiB (its
  // `.slice(0, 12000)` runs AFTER redaction and so bounds nothing), and
  // mcp/index.ts passes caller-supplied tool text with no bound at all. The
  // runtime is single-threaded, so this blocks the event loop.
  //
  // THE FIX IS A RESTRUCTURE, NOT A BOUND. The obvious repair is to cap the
  // lazy scan — `[^\r\n]{0,256}?` — and the honest reason that was not chosen is
  // NOT that it stays quadratic. It does not: measured on the same box and the
  // same shape, the bounded form is 0.6 / 1.2 / 2.5 / 4.8 ms across
  // 16/32/64/128 KiB, 1.99x per doubling — linear, because the cap makes the
  // per-position scan a constant. (An earlier draft of this comment asserted
  // O(n*N) and was wrong; the measurement is recorded here rather than the
  // prediction.)
  //
  // The bound loses on the other axis instead, which is the one this file
  // cares about: a cap declines to look past N, so a `response=` sitting
  // further into a header is not seen by this rule at all. A Digest header
  // carries `nonce`, `uri`, `opaque` and `cnonce` ahead of `response`, none
  // bounded by the RFC. On the shapes tested, the broader Authorization rule
  // below happens to mask such a header anyway — but that makes a leak rule
  // depend on a different rule as its safety net, which is not a property to
  // rely on when the two are edited separately. The restructure carries no
  // ceiling, so no input that was redacted before stops being redacted, and it
  // is also about 2x faster than the bounded form (2.3 ms vs 4.8 ms at
  // 128 KiB). Instead the header value is captured whole and
  // scanned once: `[^\r\n]*` has nothing after it, so it never backtracks, and
  // because the match CONSUMES to end-of-line every later `authorization...
  // Digest` on that line falls inside it and is never retried as a fresh start
  // position. `response=` is then masked inside that one captured value, where
  // the scan is bounded by the header rather than by a magic number. No length
  // ceiling is introduced, so nothing that was redacted before stops being
  // redacted.
  [/(authorization[A-Za-z0-9_-]{0,32}['"]?\s*[:=]\s*Digest\s+)([^\r\n]*)/gi, redactDigestResponse],
  // Consume the scheme AND the credentials that follow it. Matching only
  // `Bearer` left `Authorization: Basic <base64>` to the generic key:value rule
  // below, which replaced the scheme and passed the payload through — and for
  // Basic auth that payload IS the credential, so the output read
  // `Authorization: [REDACTED] <base64>`: a secret wearing a marker that says
  // it was handled.
  //
  // Three things had to widen together, because fixing any one of them alone
  // leaves the identical `[REDACTED] <credential>` output one character away:
  //
  //  * `[:=]` — a header line uses `:`, an env dump or a query string uses `=`.
  //  * No `\b` before `authorization`. `_` IS a word character, so `\b` never
  //    matched inside `HTTP_AUTHORIZATION` or `proxy_authorization`. Dropping
  //    the anchor lets the match start at `authorization` and leaves the prefix
  //    outside the match, which produces the same output without it.
  //  * A trailing `[A-Za-z0-9_-]*` so that `authorization_header:` reaches its
  //    separator instead of stopping at the key.
  //
  // The prefix is deliberately NOT matched with a leading `[A-Za-z0-9_-]*`: a
  // star before the literal makes the scan quadratic on long inputs.
  //
  // TWO CORRECTIONS TO WHAT THIS COMMENT USED TO SAY, both measured on
  // station02 with the regexes read from source rather than retyped.
  //
  // 1. The sibling's quadratic is URL_USERINFO_PATTERN, NOT
  //    redactNamedAssignments. This comment used to cite iapp-sms as carrying
  //    a measured 8.4s/50k quadratic in redactNamedAssignments. Per-pattern at
  //    n=50000 on a single repeated character: URL_USERINFO_PATTERN 2947ms,
  //    NAMED_ASSIGNMENT_PATTERN 0.2ms. The difference is the ANCHOR, not the
  //    star: NAMED_ASSIGNMENT_PATTERN opens with (^|[^A-Za-z0-9_-]) so an
  //    unbroken alnum run has one viable start position, while
  //    URL_USERINFO_PATTERN opens with a bare [a-z] and retries everywhere.
  //    (8.4s was station01, 2.9s is station02 — quote the box with the number.)
  //
  // 2. THIS FILE WAS NOT EXEMPT. The trailing [A-Za-z0-9_-]* below had the same
  //    quadratic shape as the leading star this comment declines: 470ms at 50k
  //    on an authorization-dense run, 4.0x per doubling. It was only linear on
  //    an input with no `authorization` substring in it. iapp-sms bounded the
  //    identical run at 32; THIS COMMIT applies that same bound below, so the
  //    gap docs/redaction.md recorded is closed here rather than left open.
  //
  // Parameterized Authorization schemes (`MAC mac=...`, custom HMAC schemes,
  // and similar) are credential material even when their inner parameter name is
  // not on a generic sensitive-key list. Redact that value before the
  // field-preservation rule below has a chance to mask only the scheme token and
  // leave `sig=...` or `nonce=...` beside a marker. Explicit non-secret status
  // values such as `authorization=denied user=bob` keep their neighboring audit
  // fields.
  [/(authorization[A-Za-z0-9_-]{0,32}['"]?\s*[:=]\s*)([A-Za-z][A-Za-z0-9._-]*)(\s+)([^\r\n]*)/gi, redactParameterizedAuthorization],
  // Two further details, both found by adversarial review of the first attempt
  // at this rule and both measured:
  //
  //  * The closing quote is OPTIONAL (`\2?`). A log line truncated at a byte
  //    limit — syslog's 1024, journald, CloudWatch — arrives as
  //    `{"headers":{"authorization":"Basic <cred>` with no closing quote. When
  //    the quoted alternative required its backreference the rule declined, and
  //    a weaker downstream rule then printed the marker followed by the
  //    credential. Truncation is the normal state of a long log line, not an
  //    edge case.
  //  * The optional scheme token is NOT consumed when the token after it is
  //    itself a `key=value` pair. `authorization=denied user=bob reason=scope`
  //    otherwise had `user=bob` swallowed and DELETED — over-redaction that
  //    destroys an adjacent field rather than masking it. The lookahead tests
  //    for `=` followed by a non-`=`, which a real `key=value` has and base64
  //    padding (`…RA==`) does not.
  //
  // The trailing key run is BOUNDED at 32. Unbounded, it rescans the rest of the
  // input from every position the literal matches, which is quadratic on a line
  // full of repeated `HTTP_AUTHORIZATION_` tokens. A real key suffix is `_header`
  // or similar, so 32 costs nothing and keeps the scan linear.
  [/(authorization[A-Za-z0-9_-]{0,32}['"]?\s*[:=]\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2?|(?:[A-Za-z][A-Za-z0-9._-]*\s+(?![^\s'"]*=[^\s'"=]))?[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  // AWS SigV4 puts the signature in a trailing `Signature=` segment of the same
  // Authorization header. The rule above eats the scheme and the first
  // comma-delimited part, so without this the header came out as
  // `Authorization: [REDACTED] ... Signature=<live signature>` — a marker at the
  // front of a line whose end is still a credential, which is the same
  // misleading shape this file exists to remove rather than a mere gap.
  // The value class stops at `&`, `,` and `;` so that redacting a signature in a
  // query string does not swallow the unrelated parameters after it.
  [/(signature[A-Za-z0-9_-]{0,32}['"]?\s*[:=]\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2?|[^\s'"&,;]+)/gi, "$1$2[REDACTED]$2"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"]
];

export function redactSensitiveText(value: string): string {
  return SECRET_PATTERNS.reduce((text, entry) => applySecretPattern(text, entry), value);
}

function applySecretPattern(text: string, [pattern, replacement]: [RegExp, SecretReplacement]): string {
  return typeof replacement === "string" ? text.replace(pattern, replacement) : text.replace(pattern, replacement);
}

// Masks `response=` inside a SINGLE Digest header value. Splitting the rule
// this way is what removes the quadratic: the caller has already consumed the
// header to end-of-line, so this scan is bounded by one header rather than by
// the whole input, and it cannot be re-entered from a later start position on
// the same line.
//
// Applying it with `g` masks every `response=` in the value rather than only
// the first. That is intentionally wider than the pattern it replaces: a second
// Digest header sharing the line is covered without relying on the outer rule
// being re-entered, and over-masking a parameter literally named `response`
// inside an Authorization header is the cheap direction of that trade.
//
// A value with no `response=` comes back byte-identical, so this rule never
// alters a line it has nothing to say about, and the broader Authorization
// rules below still see exactly the text they saw before.
function redactDigestResponse(match: string, prefix: string, headerValue: string): string {
  return `${ prefix }${ headerValue.replace(DIGEST_RESPONSE_PATTERN, "$1$2[REDACTED]$2") }`;
}

function redactParameterizedAuthorization(
  match: string,
  prefix: string,
  scheme: string,
  spacer: string,
  rest: string
): string {
  if (!AUTHORIZATION_PARAMETER_PATTERN.test(rest)) {
    return match;
  }

  if (NON_SECRET_AUTHORIZATION_VALUES.has(scheme.toLowerCase())) {
    return `${ prefix }[REDACTED]${ spacer }${ rest }`;
  }

  return `${ prefix }[REDACTED]`;
}

export function stripHiddenReasoning(value: string): string {
  return value
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .replace(/```(?:reasoning|thoughts|thinking)[\s\S]*?```/gi, "")
    .trim();
}
