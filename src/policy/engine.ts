import { destructiveShellRule } from "./rules/destructive-shell.js";
import { externalCommsRule } from "./rules/external-comms.js";
import { privateNetworkRule } from "./rules/private-network.js";

export type PassportDecision = {
  outcome: "allow" | "deny" | "require_consent";
  severity: "low" | "medium" | "high";
  category: string;
  reason: string;
  matchedRule: string;
};

export type PassportActionInput = {
  action: string;
  target: string | null;
};

const rules = [
  destructiveShellRule,
  externalCommsRule,
  privateNetworkRule,
];

export function evaluateAction(input: PassportActionInput): PassportDecision {
  for (const rule of rules) {
    const match = rule(input);
    if (match) return match;
  }

  return {
    outcome: "require_consent",
    severity: "medium",
    category: "unknown",
    reason: "Action did not match a trusted-safe rule, so consent is required by default.",
    matchedRule: "default-require-consent"
  };
}
