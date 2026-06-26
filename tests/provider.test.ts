import { expect, test } from "bun:test";
import { createTai } from "../src/sdk";
import { ProviderRouter } from "../src/providers/router";
import type { Provider, ProviderRequest, ProviderResponse } from "../src/types";

class FakeProvider implements Provider {
  constructor(
    readonly name: string,
    readonly model: string,
    private readonly isAvailable: boolean,
    private readonly text: string
  ) {}

  available(): boolean {
    return this.isAvailable;
  }

  async complete(_request: ProviderRequest): Promise<ProviderResponse> {
    return { text: this.text, provider: this.name, model: this.model };
  }
}

test("routes to the first available provider", async () => {
  const router = new ProviderRouter([
    new FakeProvider("missing", "none", false, "{}"),
    new FakeProvider("fake", "test", true, "{\"command\":\"pwd\",\"summary\":\"Show cwd\"}")
  ]);

  const response = await router.complete({ messages: [] });
  expect(response.provider).toBe("fake");
});

test("SDK proposes with fake provider", async () => {
  const tai = createTai({
    providers: [new FakeProvider("fake", "test", true, "{\"command\":\"pwd\",\"summary\":\"Show cwd\"}")]
  });

  const proposal = await tai.propose("where am I?");
  expect(proposal.command).toBe("pwd");
  expect(proposal.classification.risk).toBe("allow");
});
