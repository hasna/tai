import type { Provider, ProviderRequest, ProviderResponse } from "../types";

interface OpenAICompatibleProviderOptions {
  name: string;
  baseUrl: string;
  model?: string;
  apiKey?: string;
}

export class OpenAICompatibleProvider implements Provider {
  readonly name: string;
  readonly model: string;
  private readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(options: OpenAICompatibleProviderOptions) {
    this.name = options.name;
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.model = options.model ?? "";
    this.apiKey = options.apiKey;
  }

  available(): boolean {
    if (!this.model) {
      return false;
    }
    if (this.name === "local") {
      return true;
    }
    return Boolean(this.apiKey);
  }

  async complete(request: ProviderRequest): Promise<ProviderResponse> {
    const response = await fetch(`${ this.baseUrl }/chat/completions`, {
      method: "POST",
      signal: request.signal,
      headers: {
        "content-type": "application/json",
        ...(this.apiKey ? { authorization: `Bearer ${ this.apiKey }` } : {})
      },
      body: JSON.stringify({
        model: this.model,
        messages: request.messages,
        temperature: 0,
        stream: false
      })
    });

    if (!response.ok) {
      throw new Error(`${ this.name } provider failed: ${ response.status } ${ response.statusText }`);
    }

    const json = await response.json() as { choices?: Array<{ message?: { content?: string } }> };
    const text = json.choices?.[0]?.message?.content;
    if (!text) {
      throw new Error(`${ this.name } provider returned no content.`);
    }

    return { text, provider: this.name, model: this.model };
  }
}
