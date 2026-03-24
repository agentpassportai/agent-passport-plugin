import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";

const PERSISTENCE_PATTERNS = [
  /systemctl\s+enable\s+/gi,
  /systemctl\s+(?:start|restart)\s+[\w.-]+/gi,
  /crontab\s+-[elr]|crontab\s+[^\n]+/gi,
  /(?:\/etc\/cron\.(?:d|daily|hourly|weekly|monthly)|~\/\.config\/autostart|~\/Library\/LaunchAgents|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)/gi,
  /(?:>>|tee\s+-a)\s+(?:~\/\.(?:bashrc|zshrc|profile)|\/etc\/(?:profile|bash\.bashrc))/gi
];

export const persistenceAutorunRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (isScannerImplementationFile(file.relativePath)) continue;
    for (const pattern of PERSISTENCE_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `persistence-autorun:${file.relativePath}`,
        category: "persistence-autorun",
        severity: inferSignalType(file.relativePath) === "documentation" ? "medium" : "high",
        signalType: inferSignalType(file.relativePath),
        title: "Persistence or autorun behavior referenced",
        summary: "This package references startup persistence, cron installation, service enablement, or shell-profile modification that could make it stick around after install.",
        recommendation: "Treat as high risk until each persistence mechanism is justified, narrowly scoped, and removable.",
        evidence: matches.slice(0, 4).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
