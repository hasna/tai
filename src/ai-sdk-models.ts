import { createCerebras } from "@ai-sdk/cerebras";
import { createGroq } from "@ai-sdk/groq";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModel } from "ai";

export interface AiSdkModelCandidate {
  provider: "local" | "groq" | "cerebras";
  modelId: string;
  model: LanguageModel;
}

export function createAiSdkModelCandidates(env: NodeJS.ProcessEnv = process.env): AiSdkModelCandidate[] {
  const candidates: AiSdkModelCandidate[] = [];

  if (env.TAI_LOCAL_MODEL) {
    const local = createOpenAICompatible({
      name: env.TAI_LOCAL_PROVIDER_NAME ?? "local-openai-compatible",
      baseURL: env.TAI_LOCAL_BASE_URL ?? "http://localhost:11434/v1",
      apiKey: env.TAI_LOCAL_API_KEY
    });
    candidates.push({ provider: "local", modelId: env.TAI_LOCAL_MODEL, model: local(env.TAI_LOCAL_MODEL) });
  }

  if (env.GROQ_API_KEY && env.TAI_GROQ_MODEL) {
    const groq = createGroq({
      apiKey: env.GROQ_API_KEY,
      baseURL: env.TAI_GROQ_BASE_URL
    });
    candidates.push({ provider: "groq", modelId: env.TAI_GROQ_MODEL, model: groq(env.TAI_GROQ_MODEL) });
  }

  if (env.CEREBRAS_API_KEY && env.TAI_CEREBRAS_MODEL) {
    const cerebras = createCerebras({
      apiKey: env.CEREBRAS_API_KEY,
      baseURL: env.TAI_CEREBRAS_BASE_URL
    });
    candidates.push({ provider: "cerebras", modelId: env.TAI_CEREBRAS_MODEL, model: cerebras(env.TAI_CEREBRAS_MODEL) });
  }

  return candidates;
}

export function resolveAiSdkModel(env: NodeJS.ProcessEnv = process.env): AiSdkModelCandidate | undefined {
  return createAiSdkModelCandidates(env)[0];
}
