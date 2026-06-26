import { formatCommandPreview, parseCommandProposal } from "./proposal";
import { ProviderRouter, createDefaultProviders } from "./providers/router";
import { classifyCommand } from "./safety";
import { formatAgenticPlan } from "./agentic-plan";
import { planAgenticCommands } from "./agentic";
import { createAiSdkModelCandidates } from "./ai-sdk-models";
import type { LanguageModel } from "ai";
import type { AgenticCommandPlan, CommandProposal, Provider, TaiOptions } from "./types";

const SYSTEM_PROMPT = [
  "You turn natural-language terminal requests into one safe shell command.",
  "Return only JSON with keys command and summary.",
  "Do not include hidden reasoning, chain-of-thought, markdown, or explanations.",
  "Prefer read-only inspection commands. Do not invent credentials or destructive commands."
].join(" ");

export interface TaiClient {
  propose(request: string, signal?: AbortSignal): Promise<CommandProposal>;
  plan(request: string, signal?: AbortSignal): Promise<AgenticCommandPlan>;
  preview(request: string, signal?: AbortSignal): Promise<string>;
  previewPlan(request: string, signal?: AbortSignal): Promise<string>;
  classify(command: string): ReturnType<typeof classifyCommand>;
}

export function createTai(options: TaiOptions = {}): TaiClient {
  const providers: Provider[] = options.providers ?? createDefaultProviders(options.env);
  const router = new ProviderRouter(providers);

  return {
    async propose(request, signal) {
      const response = await router.complete({
        signal,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: `cwd: ${ options.cwd ?? process.cwd() }\nrequest: ${ request }` }
        ]
      });
      return parseCommandProposal(response.text);
    },
    async plan(request, signal) {
      const models = resolvePlanningModels(options);
      if (models.length === 0) {
        throw new Error("No AI SDK model configured. Set TAI_LOCAL_MODEL, or configure GROQ_API_KEY + TAI_GROQ_MODEL, or CEREBRAS_API_KEY + TAI_CEREBRAS_MODEL.");
      }

      const errors: string[] = [];
      for (const model of models) {
        try {
          return await planAgenticCommands({
            model,
            request,
            signal,
            cwd: options.cwd,
            env: options.env,
            maxSteps: options.maxAgentSteps
          });
        } catch (error) {
          errors.push(error instanceof Error ? error.message : String(error));
        }
      }

      throw new Error(`No AI SDK model completed the plan. ${ errors.join(" | ") }`);
    },
    async preview(request, signal) {
      return formatCommandPreview(await this.propose(request, signal));
    },
    async previewPlan(request, signal) {
      return formatAgenticPlan(await this.plan(request, signal));
    },
    classify(command) {
      return classifyCommand(command);
    }
  };
}

function resolvePlanningModels(options: TaiOptions): LanguageModel[] {
  if (options.aiModels?.length) {
    return options.aiModels;
  }
  if (options.aiModel) {
    return [options.aiModel];
  }
  return createAiSdkModelCandidates(options.env).map((candidate) => candidate.model);
}
