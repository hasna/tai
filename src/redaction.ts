const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\b(sk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_OPENAI_KEY]"],
  [/\b(gsk_[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_GROQ_KEY]"],
  [/\b(csk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_CEREBRAS_KEY]"],
  [/\b(AKIA[0-9A-Z]{16})\b/g, "[REDACTED_AWS_KEY]"],
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
  // star before the literal makes the scan quadratic on long inputs, and the
  // sibling redactor in iapp-sms already has a measured 8.4s/50k quadratic that
  // this must not reproduce here.
  [/(authorization[A-Za-z0-9_-]*['"]?\s*[:=]\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|(?:[A-Za-z][A-Za-z0-9._-]*\s+)?[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  // AWS SigV4 puts the signature in a trailing `Signature=` segment of the same
  // Authorization header. The rule above eats the scheme and the first
  // comma-delimited part, so without this the header came out as
  // `Authorization: [REDACTED] ... Signature=<live signature>` — a marker at the
  // front of a line whose end is still a credential, which is the same
  // misleading shape this file exists to remove rather than a mere gap.
  // The value class stops at `&`, `,` and `;` so that redacting a signature in a
  // query string does not swallow the unrelated parameters after it.
  [/(signature[A-Za-z0-9_-]*['"]?\s*[:=]\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"&,;]+)/gi, "$1$2[REDACTED]$2"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"]
];

export function redactSensitiveText(value: string): string {
  return SECRET_PATTERNS.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), value);
}

export function stripHiddenReasoning(value: string): string {
  return value
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .replace(/```(?:reasoning|thoughts|thinking)[\s\S]*?```/gi, "")
    .trim();
}
