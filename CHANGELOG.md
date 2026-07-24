# Changelog

All notable changes to `@hasna/tai` are documented in this file.

## 0.1.0 - 2026-07-24

Initial public release.

- CLI `tai` with `propose`, `plan`, `classify`, and `run` commands, plus `--version`/`-v`.
- MCP server binary `tai-mcp`.
- SDK exports: `createTai`, `classifyCommand`, `redactSensitiveText`, `parseCommandProposal`,
  `planAgenticCommands`.
- Local-first provider routing (OpenAI-compatible endpoint, Groq and Cerebras fallbacks).
- Packaging fixes required for the first release: removed the `postinstall` hook that invoked
  `scripts/postinstall.ts`, a file excluded from the published tarball (it broke every install
  from the registry) and that only created an unused `~/.hasna/tai/` directory; declared
  `publishConfig.access: public` for this scoped package.
