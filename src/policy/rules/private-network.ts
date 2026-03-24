import type { PassportActionInput, PassportDecision } from "../engine.js";

const PRIVATE_NETWORK_MARKERS = [
  "127.0.0.1",
  "localhost",
  "10.",
  "172.16.",
  "172.17.",
  "172.18.",
  "172.19.",
  "172.20.",
  "192.168.",
  "intranet",
  ".local"
];

export function privateNetworkRule(input: PassportActionInput): PassportDecision | null {
  const haystack = `${input.action} ${input.target ?? ""}`.toLowerCase();
  if (!PRIVATE_NETWORK_MARKERS.some((pattern) => haystack.includes(pattern))) return null;

  return {
    outcome: "deny",
    severity: "high",
    category: "privateNetworkAccess",
    reason: "Private-network or loopback access is denied by default in v1.",
    matchedRule: "private-network"
  };
}
