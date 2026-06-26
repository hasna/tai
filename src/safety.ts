import type { CommandClassification } from "./types";

const READ_ONLY = new Set([
  "bat",
  "cat",
  "cut",
  "df",
  "du",
  "grep",
  "head",
  "jq",
  "ls",
  "md5sum",
  "nl",
  "pwd",
  "rg",
  "sed",
  "sha1sum",
  "sha256sum",
  "sort",
  "stat",
  "tail",
  "tree",
  "uname",
  "wc",
  "which"
]);

const SENSITIVE_PATH_PATTERN = /(?:^|[\s:/"'`])(?:\.env(?:\.[^\s]*)?|id_rsa|id_ed25519|credentials|secrets?|token|keychain|\.aws\/credentials|\.config\/gh|\.npmrc|\.netrc)(?:$|[\s/"'`])/i;

const CONFIRM_PATTERNS: Array<[RegExp, string]> = [
  [/\bgit\s+(?:add|commit|checkout|switch|merge|rebase|cherry-pick|stash|tag|branch\s+(?!-+(?:list|show-current)\b)|remote|fetch|pull|push)\b/i, "git operation that may change local or remote state"],
  [/\b(?:bun|npm|pnpm|yarn|pip|pipx|uv|cargo|go|gem|brew|apt|dnf|yum)\s+(?:add|install|remove|update|upgrade|run|exec|x)\b/i, "package manager or executable package operation"],
  [/\b(?:curl|wget|scp|rsync|ssh|ftp|nc|ncat|telnet)\b/i, "network operation"],
  [/(?:^|[;&|]\s*)(?:mkdir|touch|cp|mv|tee|chmod|chown|ln|truncate)\b/i, "filesystem write or metadata change"],
  [/>|>>|\b(?:sed|perl)\b.+\s-i\b/i, "file write or in-place edit"],
  [/\b(?:kill|pkill|killall|launchctl|systemctl|service)\b/i, "process or service control"],
  [/\b(?:docker|podman|kubectl|helm|terraform|pulumi)\b/i, "infrastructure or container operation"]
];

const BLOCK_PATTERNS: Array<[RegExp, string]> = [
  [SENSITIVE_PATH_PATTERN, "possible credential disclosure"],
  [/\$\(|`|<\(|>\(/, "shell expansion can hide side effects"],
  [/\b(?:awk|perl|python|python3|ruby|node|bash|sh|zsh)\b.*\b(?:system|exec|spawn|eval|child_process)\b/i, "interpreter command can execute side effects"],
  [/\bfind\b.*(?:-exec|-delete|-execdir|-ok|-okdir)\b/i, "find action can mutate files or execute commands"],
  [/\brm\s+(?:-[^\s]*[rf][^\s]*|--recursive|--force)/i, "destructive recursive or forced remove"],
  [/\bsudo\b|\bsu\s+-?\b/i, "privilege escalation"],
  [/\b(?:git\s+push\b.*--force|git\s+push\b.*\+|git\s+reset\s+--hard|git\s+clean\s+-[^\s]*f)/i, "destructive git operation"],
  [/\b(?:npm|bun|pnpm|yarn)\s+publish\b|\b(?:gh|npm)\s+release\b|\b(?:vercel|netlify|wrangler)\s+deploy\b/i, "publish or deploy operation"],
  [/\b(?:cat|grep|rg|sed|awk)\b.*(?:\.env|id_rsa|id_ed25519|credentials|secrets?|token|keychain)/i, "possible credential disclosure"],
  [/\b(?:curl|wget)\b.*(?:\.env|id_rsa|id_ed25519|credentials|secrets?|token)/i, "possible credential exfiltration"]
];

export function classifyCommand(command: string): CommandClassification {
  const trimmed = command.trim();
  const reasons: string[] = [];

  for (const [pattern, reason] of BLOCK_PATTERNS) {
    if (pattern.test(trimmed)) {
      reasons.push(reason);
    }
  }

  if (reasons.length > 0) {
    return { risk: "block", reasons, requiresOverride: true };
  }

  for (const [pattern, reason] of CONFIRM_PATTERNS) {
    if (pattern.test(trimmed)) {
      reasons.push(reason);
    }
  }

  if (reasons.length > 0) {
    return { risk: "confirm", reasons, requiresOverride: false };
  }

  const first = firstCommand(trimmed);
  if (first === "git" && isReadOnlyGit(trimmed)) {
    return { risk: "allow", reasons: ["read-only git inspection command"], requiresOverride: false };
  }

  if (first && READ_ONLY.has(first) && !/[;&|]\s*(?:rm|mv|cp|curl|wget|chmod|chown|sudo|tee)\b/i.test(trimmed)) {
    return { risk: "allow", reasons: ["read-only inspection command"], requiresOverride: false };
  }

  return { risk: "confirm", reasons: ["unrecognized command requires confirmation"], requiresOverride: false };
}

function firstCommand(command: string): string | undefined {
  const match = command.match(/^\s*(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?<cmd>[a-z0-9._/-]+)/i);
  return match?.groups?.cmd?.split("/").pop();
}

function isReadOnlyGit(command: string): boolean {
  if (/[;&|]/.test(command)) {
    return false;
  }

  return /^\s*git\s+(?:status|log|show|diff|ls-files|ls-tree|rev-parse|remote\s+-v|branch\s+(?:--list|-l|--show-current)?|describe|blame|grep)\b/i.test(command);
}
