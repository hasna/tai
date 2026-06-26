import { OpenAICompatibleProvider } from "./openai-compatible";
import type { Provider, ProviderRequest, ProviderResponse } from "../types";

export class ProviderRouter implements Provider {
  readonly name = "router";
  readonly model = "first-available";

  constructor(private readonly providers: Provider[]) {}

  available(): boolean {
    return this.providers.length > 0;
  }

  async complete(request: ProviderRequest): Promise<ProviderResponse> {
    const errors: string[] = [];

    for (const provider of this.providers) {
      if (!(await provider.available())) {
        continue;
      }
      try {
        return await provider.complete(request);
      } catch (error) {
        errors.push(`${ provider.name }: ${ error instanceof Error ? error.message : String(error) }`);
      }
    }

    throw new Error(`No provider completed the request.${ errors.length ? ` ${ errors.join(" | ") }` : "" }`);
  }
}

export function createDefaultProviders(env: NodeJS.ProcessEnv = process.env): Provider[] {
  return [
    new OpenAICompatibleProvider({
      name: "local",
      baseUrl: env.TAI_LOCAL_BASE_URL ?? "http://localhost:11434/v1",
      model: env.TAI_LOCAL_MODEL
    }),
    new OpenAICompatibleProvider({
      name: "groq",
      baseUrl: env.TAI_GROQ_BASE_URL ?? "https://api.groq.com/openai/v1",
      model: env.TAI_GROQ_MODEL,
      apiKey: env.GROQ_API_KEY
    }),
    new OpenAICompatibleProvider({
      name: "cerebras",
      baseUrl: env.TAI_CEREBRAS_BASE_URL ?? "https://api.cerebras.ai/v1",
      model: env.TAI_CEREBRAS_MODEL,
      apiKey: env.CEREBRAS_API_KEY
    })
  ];
}
