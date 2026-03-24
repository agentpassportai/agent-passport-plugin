import type { PassportActionInput, PassportDecision } from "../engine.js";

const DANGEROUS_PATTERNS = ["rm -rf", "mkfs", "dd if=", "shutdown", "reboot"];

export function destructiveShellRule(input: PassportActionInput): PassportDecision | null {
  const haystack = `${input.action} ${input.target ?? ""}`.toLowerCase();
  if (!DANGEROUS_PATTERNS.some((pattern) => haystack.includes(pattern))) return null;

  return {
    outcome: "deny",
    severity: "high",
    category: "exec",
    reason: "The requested action matches a destructive shell pattern.",
    matchedRule: "destructive-shell"
  };
}
