import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType } from "./shared.js";

const SOCIAL_ENGINEERING_PATTERNS = [
  /copy\s+and\s+paste\s+this\s+command/gi,
  /run\s+this\s+command\s+first/gi,
  /disable\s+(?:security|protections?|warnings?)/gi,
  /ignore\s+(?:the\s+)?warnings?/gi,
  /open\s+(?:a\s+)?terminal\s+and\s+run/gi
];

export const promptShellRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (!/\.(?:md|txt|ya?ml|json|sh|bash|zsh|ps1|js|ts|mjs|cjs)$/i.test(file.relativePath)) continue;
    for (const pattern of SOCIAL_ENGINEERING_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `prompt-directed-shell-execution:${file.relativePath}`,
        category: "prompt-directed-shell-execution",
        severity: "medium",
        signalType: inferSignalType(file.relativePath),
        title: "Prompt-instruction to run shell commands found",
        summary: "The package documentation or scripts explicitly instruct the operator to run commands in a way that could bypass normal review.",
        recommendation: "Review every operator-run command manually and avoid copy-paste execution of unpinned shell snippets.",
        evidence: matches.slice(0, 4).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
