# Changelog

All notable changes to `@hasna/tai` are documented in this file.

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
