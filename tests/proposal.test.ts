import { expect, test } from "bun:test";
import { parseCommandProposal } from "../src/proposal";

test("parses fenced JSON command proposals", () => {
  const proposal = parseCommandProposal("```json\n{\"command\":\"ls -la\",\"summary\":\"List files\"}\n```");
  expect(proposal.command).toBe("ls -la");
  expect(proposal.summary).toBe("List files");
  expect(proposal.classification.risk).toBe("allow");
});

test("reclassifies provider proposals instead of trusting provider risk", () => {
  const proposal = parseCommandProposal("{\"command\":\"rm -rf dist\",\"summary\":\"remove build\",\"classification\":{\"risk\":\"allow\",\"reasons\":[],\"requiresOverride\":false}}");
  expect(proposal.classification.risk).toBe("block");
});

test("redacts provider-supplied env values", () => {
  const proposal = parseCommandProposal("{\"command\":\"env\",\"summary\":\"show env\",\"env\":{\"API_KEY\":\"sk-1234567890abcdef\"}}");
  expect(proposal.env?.API_KEY).toBe("[REDACTED_OPENAI_KEY]");
});
