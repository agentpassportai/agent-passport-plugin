import type { PassportDecision } from "./engine.js";

const PROMPT_INJECTION_PATTERNS = [
  /ignore (?:all |any |the )?(?:previous|prior) (?:instructions|rules|messages)/i,
  /system prompt/i,
  /developer message/i,
  /tool call/i,
  /curl\s+\S+\s*\|\s*(?:bash|sh)\b/i,
  /wget\s+\S+.*(?:bash|sh)\b/i,
  /powershell(?:\.exe)?\s+-enc\b/i,
  /base64\s+-d\b/i,
  /copy and paste (?:this|the) command/i,
  /please run (?:this|the following) command/i
];

export function evaluateInboundDispatch(input: {
  channel?: string | null;
  sessionKey?: string | null;
  senderId?: string | null;
  isGroup?: boolean;
  content?: string | null;
  body?: string | null;
}): PassportDecision {
  const haystack = `${input.content ?? ""}\n${input.body ?? ""}`;

  if (PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(haystack))) {
    return {
      outcome: "allow",
      severity: "high",
      category: "inboundPromptRisk",
      reason: "Inbound dispatch content contains prompt-injection or operator-manipulation markers and should be audited before the agent acts on it.",
      matchedRule: "before-dispatch-prompt-risk"
    };
  }

  if (input.isGroup) {
    return {
      outcome: "allow",
      severity: "medium",
      category: "inboundGroupDispatch",
      reason: "Group-channel inbound dispatch is a higher prompt-injection surface and is being audited with elevated priority.",
      matchedRule: "before-dispatch-group"
    };
  }

  if (!input.sessionKey?.trim()) {
    return {
      outcome: "allow",
      severity: "medium",
      category: "inboundRouting",
      reason: "Inbound dispatch arrived without a canonical session key, so Passport is recording it as a routing-sensitive audit event.",
      matchedRule: "before-dispatch-missing-session"
    };
  }

  return {
    outcome: "allow",
    severity: "low",
    category: "inboundDispatch",
    reason: "Inbound dispatch metadata is being recorded through the canonical before_dispatch hook.",
    matchedRule: "before-dispatch-default"
  };
}
