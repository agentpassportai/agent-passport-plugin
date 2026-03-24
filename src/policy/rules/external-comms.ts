import type { PassportActionInput, PassportDecision } from "../engine.js";

const EXTERNAL_ACTION_MARKERS = ["send message", "post comment", "send email", "publish", "tweet", "post to"];

export function externalCommsRule(input: PassportActionInput): PassportDecision | null {
  const haystack = `${input.action} ${input.target ?? ""}`.toLowerCase();
  if (!EXTERNAL_ACTION_MARKERS.some((pattern) => haystack.includes(pattern))) return null;

  return {
    outcome: "require_consent",
    severity: "high",
    category: "externalMessaging",
    reason: "External communication should require explicit consent in v1.",
    matchedRule: "external-comms"
  };
}
