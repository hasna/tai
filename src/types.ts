export type RiskLevel = "allow" | "confirm" | "block";

export interface CommandClassification {
  risk: RiskLevel;
  reasons: string[];
  requiresOverride: boolean;
}

export interface CommandProposal {
  command: string;
  summary: string;
  cwd?: string;
  env?: Record<string, string>;
  classification: CommandClassification;
}

export interface AgenticCommandStep {
  command: string;
  summary: string;
  classification: CommandClassification;
}

export interface AgenticCommandPlan {
  objective: string;
  summary: string;
  steps: AgenticCommandStep[];
  requiresConfirmation: boolean;
  blocked: boolean;
  notes: string[];
}

export interface ProviderMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ProviderRequest {
  messages: ProviderMessage[];
  signal?: AbortSignal;
}

export interface ProviderResponse {
  text: string;
  provider: string;
  model: string;
}

export interface Provider {
  name: string;
  model: string;
  available(): boolean | Promise<boolean>;
  complete(request: ProviderRequest): Promise<ProviderResponse>;
}

export interface TaiOptions {
  providers?: Provider[];
  aiModel?: import("ai").LanguageModel;
  aiModels?: import("ai").LanguageModel[];
  maxAgentSteps?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}
