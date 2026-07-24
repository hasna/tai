import { describe, expect, test } from "bun:test";
import manifest from "../package.json";
import { readPackageVersion } from "../src/version";

describe("readPackageVersion", () => {
  test("resolves the real version from the shipped package.json", () => {
    expect(readPackageVersion()).toBe(manifest.version);
  });

  test("never falls back to the unknown sentinel in a normal checkout", () => {
    expect(readPackageVersion()).not.toBe("unknown");
  });

  test("returns a semver-shaped string", () => {
    expect(readPackageVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
