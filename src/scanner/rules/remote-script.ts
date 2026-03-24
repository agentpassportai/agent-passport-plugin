import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";

const REMOTE_EXEC_PATTERNS = [
  /curl\s+[^\n|]+\|\s*(?:bash|sh|zsh)/gi,
  /wget\s+[^\n|]+-O-?\s*\|\s*(?:bash|sh|zsh)/gi,
  /bash\s*<\(\s*curl[^)]*\)/gi,
  /sh\s*<\(\s*curl[^)]*\)/gi,
  /Invoke-WebRequest[^\n]*\|[^\n]*(?:iex|Invoke-Expression)/gi
];

export const remoteScriptRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (isScannerImplementationFile(file.relativePath)) continue;
    for (const pattern of REMOTE_EXEC_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `remote-script-execution:${file.relativePath}`,
        category: "remote-script-execution",
        severity: "high",
        signalType: inferSignalType(file.relativePath),
        title: "Remote script execution pattern found",
        summary: "This package contains a command that downloads remote content and pipes it straight into a shell or eval path.",
        recommendation: "Block or quarantine until the command is replaced with a reviewed, pinned, non-piped install path.",
        evidence: matches.slice(0, 3).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
