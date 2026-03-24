import type { PassportDecision } from "./engine.js";

const EXTERNAL_ACTION_MARKERS = [
  "send message",
  "post comment",
  "send email",
  "publish",
  "tweet",
  "post to",
  "reply"
];

export function evaluateOutboundCommunication(input: {
  to?: string | null;
  content?: string | null;
  target?: string | null;
}): PassportDecision {
  const haystack = `${input.to ?? ""} ${input.target ?? ""} ${input.content ?? ""}`.toLowerCase();

  if (EXTERNAL_ACTION_MARKERS.some((pattern) => haystack.includes(pattern))) {
    return {
      outcome: "require_consent",
      severity: "high",
      category: "externalMessaging",
      reason: "Outbound communication matched a high-risk external action marker and requires explicit consent.",
      matchedRule: "external-comms-marker"
    };
  }

  return {
    outcome: "require_consent",
    severity: "high",
    category: "externalMessaging",
    reason: "Outbound communication is consent-gated by default in Agent Passport v1.",
    matchedRule: "external-comms-default"
  };
}
