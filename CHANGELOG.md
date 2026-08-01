# Changelog

All notable changes to `@hasna/tai` are documented in this file.

## 0.1.5 - 2026-08-01

Security release. **Every published version through 0.1.4 emits session cookies verbatim.**
`redactSensitiveText` had no cookie handling at all, so `Cookie: session=<value>` came out
byte-identical — and a session cookie is bearer authentication under a different header name,
so anything logging an HTTP request through this function emitted live sessions.

- **`Cookie:` and `Set-Cookie:` values are now redacted**, whatever the cookie is named.
  The rule keys on the header's *role* — a `;`-delimited list of `name=value` pairs — rather
  than on a list of cookie names, so `session`, `sid`, `PHPSESSID`, `JSESSIONID`,
  `connect.sid`, `laravel_session`, `__Host-*` and `__Secure-*` are covered because none of
  them is special. Measured against 0.1.4: 9 of 10 cookie shapes leaked.
- **A request `Cookie:` header takes no attribute exemption.** RFC 6265 §4.2.1 makes it pairs
  and nothing else, so `Path`, `Domain` and `Expires` there are ordinary application-chosen
  cookie names whose values are credentials.
- **`Set-Cookie` attribute exemptions are shape-checked and narrow.** The value shapes were
  themselves credential-shaped — `expires` accepted any run of up to 32 alphanumerics, which
  is precisely a 32-character session id, and `domain` was length-unbounded and matched an
  87-character JWT. Across 8,090 generated cookie shapes, 291 leaked before this and 2 do now.
- Set-Cookie attributes (`Path`, `Domain`, `Expires`, `Max-Age`, `SameSite`, `HttpOnly`,
  `Secure`) and whitespace-separated neighbouring log fields stay readable; a cookie logged
  inside JSON keeps its surrounding quotes and brackets.

**Known residuals are named rather than implied** — see `docs/redaction.md`: percent-encoded
and Unicode spellings of the header name, folded continuation lines, whitespace-separated
pairs carrying no semicolon, and a genuinely path- or hostname-shaped value in a `Set-Cookie`
`Path=`/`Domain=` slot.

## 0.1.3 - 2026-08-01

Security release. `redactSensitiveText` printed its `[REDACTED]` marker while leaving the
credential intact beside it, so output that looked redacted still carried the secret.

- Closes the misleading-marker class for authorization-style fields: the marker no longer
  replaces only the auth *scheme* (`Basic`, `Digest`, `MAC`, `Negotiate`) while the parameter
  carrying the credential survives. Measured against the published bundle, the leaking shapes
  were `authorization=Basic <v>`, `Authorization: Digest ... response=<v>`,
  `HTTP_AUTHORIZATION=MAC mac=<v>` and `proxy_authorization: MAC mac=<v>`.
- Also fixes truncated log lines and adjacent-field deletion in the same code path.

**Every previously published version leaks, and the earlier ones leak more.** 0.1.2 is not a
regression — it carried a partial fix and was the least affected of the three. Upgrade from
any version; do not treat 0.1.0 or 0.1.1 as a safe fallback.

**Known and NOT fixed here:** `Cookie:` and `Set-Cookie:` values are not redacted, in this
version or any earlier one. That is a separate change under its own review and is deliberately
not bundled into a security release.

## 0.1.0 - 2026-07-24

Initial public release.

- CLI `tai` with `propose`, `plan`, `classify`, and `run` commands, plus `--version`/`-v`.
- MCP server binary `tai-mcp`.
- SDK exports: `createTai`, `classifyCommand`, `redactSensitiveText`, `parseCommandProposal`,
  `planAgenticCommands`.
- Local-first provider routing (OpenAI-compatible endpoint, Groq and Cerebras fallbacks).
- Single source of truth for the version: `readPackageVersion()` resolves it from the shipped
  `package.json` for the CLI, the MCP `serverInfo`, and the SDK export, so no version literal is
  duplicated in source.
- Packaging fixes required for the first release: removed the `postinstall` hook that invoked
  `scripts/postinstall.ts`, a file excluded from the published tarball (it broke every install
  from the registry) and that only created an unused `~/.hasna/tai/` directory; declared
  `publishConfig.access: public` for this scoped package.
