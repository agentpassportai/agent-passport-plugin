import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";

const STAGED_PAYLOAD_PATTERNS = [
  /(?:curl|wget)[^\n]+(?:-o|--output)\s+(?:\/tmp\/|\.\/|\$\{?TMPDIR\}?|\$\(mktemp\)|%TEMP%)[^\n]+(?:&&|;)[^\n]*(?:chmod\s+\+x|bash|sh|zsh|\.\/)/gi,
  /(?:mktemp|New-TemporaryFile)[^\n]*(?:&&|;)[^\n]*(?:curl|wget|Invoke-WebRequest)[^\n]*(?:&&|;)[^\n]*(?:chmod\s+\+x|Start-Process|bash|sh|zsh|\.\/)/gi,
  /(?:curl|wget|Invoke-WebRequest)[^\n]+(?:tar\s+-[xvzf]+|unzip\s+)[^\n]+(?:&&|;)[^\n]*(?:\.\/|bash|sh|zsh|node\s+)/gi
];

export const stagedPayloadRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (isScannerImplementationFile(file.relativePath)) continue;
    for (const pattern of STAGED_PAYLOAD_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `staged-payload:${file.relativePath}`,
        category: "staged-payload",
        severity: inferSignalType(file.relativePath) === "documentation" ? "medium" : "high",
        signalType: inferSignalType(file.relativePath),
        title: "Secondary payload download-and-execute pattern found",
        summary: "This package appears to download a file or archive, make it runnable or unpack it, and then execute the next stage.",
        recommendation: "Block until the downloaded payload is pinned, reviewed, and separated from automatic execution.",
        evidence: matches.slice(0, 3).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
