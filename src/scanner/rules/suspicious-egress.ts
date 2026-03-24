import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType } from "./shared.js";

const SUSPICIOUS_EGRESS_PATTERNS = [
  /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s"')>]*)?/gi,
  /https?:\/\/(?:pastebin\.com|webhook\.site|transfer\.sh|ngrok\.io|discord(?:app)?\.com\/api\/webhooks|raw\.githubusercontent\.com)[^\s"')>]*/gi,
  /nc\s+-e\s+|bash\s+-i\s*>\&\s*\/dev\/tcp/gi
];

export const suspiciousEgressRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    for (const pattern of SUSPICIOUS_EGRESS_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `suspicious-egress:${file.relativePath}`,
        category: "suspicious-egress",
        severity: "high",
        signalType: inferSignalType(file.relativePath),
        title: "Suspicious egress destination or reverse-shell pattern found",
        summary: "The package references direct IP egress, webhook exfiltration endpoints, or reverse-shell style networking.",
        recommendation: "Block until each destination is reviewed and justified. Unknown webhook or IP egress is a bad smell.",
        evidence: matches.slice(0, 4).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
