import { createRequire } from "node:module";

const PACKAGE_NAME = "@hasna/tai";

// `import.meta.url` points at this file in development and at the bundled entry point
// (`dist/index.js`, `dist/cli/index.js`, `dist/mcp/index.js`) in the published package,
// so the manifest sits one, two, or three levels up depending on the caller.
const MANIFEST_CANDIDATES = ["../package.json", "../../package.json", "../../../package.json"];

/**
 * Resolves the package version from the shipped package.json so the version literal
 * is never duplicated in source and cannot go stale between releases.
 */
export function readPackageVersion(): string {
  let requireFromHere: NodeRequire;
  try {
    requireFromHere = createRequire(import.meta.url);
  } catch {
    return "unknown";
  }

  for (const candidate of MANIFEST_CANDIDATES) {
    try {
      const manifest = requireFromHere(candidate) as { name?: string; version?: string };
      if (manifest.name === PACKAGE_NAME && typeof manifest.version === "string" && manifest.version.length > 0) {
        return manifest.version;
      }
    } catch {
      // Candidate path does not exist from this caller; try the next one.
    }
  }

  return "unknown";
}
