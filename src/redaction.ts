const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\b(sk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_OPENAI_KEY]"],
  [/\b(gsk_[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_GROQ_KEY]"],
  [/\b(csk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED_CEREBRAS_KEY]"],
  [/\b(AKIA[0-9A-Z]{16})\b/g, "[REDACTED_AWS_KEY]"],
  [/(Authorization:\s*Bearer\s+)[^\s'"]+/gi, "$1[REDACTED]"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?\s*=\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"],
  [/((?:api|access|secret|token|password|passwd|pwd)[_-]?key?['"]?\s*:\s*)(?:(["'])(?:(?!\2)[^\r\n])*\2|[^\s'"]+)/gi, "$1$2[REDACTED]$2"]
];

export function redactSensitiveText(value: string): string {
  return SECRET_PATTERNS.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), value);
}

export function stripHiddenReasoning(value: string): string {
  return value
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .replace(/```(?:reasoning|thoughts|thinking)[\s\S]*?```/gi, "")
    .trim();
}
