import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType } from "./shared.js";
import {
  isMarkdownLikePath,
  isSocialEngineeringInstruction,
  markdownSnippet,
  parseMarkdownDocument
} from "./markdown.js";

const SOCIAL_ENGINEERING_PATTERNS = [
  /copy\s+and\s+paste\s+this\s+command/gi,
  /run\s+this\s+command\s+first/gi,
  /run\s+the\s+(?:setup|install|bootstrap|init)\s+script/gi,
  /paste\s+the\s+following\s+command/gi,
  /disable\s+(?:security|protections?|warnings?)/gi,
  /ignore\s+(?:the\s+)?warnings?/gi,
  /open\s+(?:a\s+)?terminal\s+and\s+run/gi,
  /this\s+command\s+is\s+safe\s+to\s+run/gi,
  /recommended\s+to\s+run\s+as\s+root/gi
];

export const promptShellRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (!/\.(?:md|txt|ya?ml|json|sh|bash|zsh|ps1|js|ts|mjs|cjs)$/i.test(file.relativePath)) continue;

    const evidence: Array<{ filePath: string; line: number; snippet: string }> = [];
    const seen = new Set<string>();
    const addEvidence = (item: { filePath: string; line: number; snippet: string }) => {
      const key = `${item.filePath}:${item.line}:${item.snippet}`;
      if (seen.has(key)) return;
      seen.add(key);
      evidence.push(item);
    };

    for (const pattern of SOCIAL_ENGINEERING_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      for (const match of matches.slice(0, 2)) {
        addEvidence(evidenceFromMatch(file, match.index ?? 0, match[0].length));
      }
    }

    if (isMarkdownLikePath(file.relativePath)) {
      const document = parseMarkdownDocument(file.content);
      for (const block of document.codeBlocks) {
        if (!isSocialEngineeringInstruction(block.content)) continue;
        addEvidence({
          filePath: file.relativePath,
          line: block.startLine,
          snippet: markdownSnippet(block.content)
        });
      }
    }

    if (!evidence.length) continue;

    findings.push({
      id: `prompt-directed-shell-execution:${file.relativePath}`,
      category: "prompt-directed-shell-execution",
      severity: "medium",
      signalType: inferSignalType(file.relativePath),
      title: "Prompt-instruction to run shell commands found",
      summary: "The package documentation or scripts explicitly instruct the operator to run commands in a way that could bypass normal review.",
      recommendation: "Review every operator-run command manually and avoid copy-paste execution of unpinned shell snippets.",
      evidence: evidence.slice(0, 4)
    });
  }

  return findings;
};
