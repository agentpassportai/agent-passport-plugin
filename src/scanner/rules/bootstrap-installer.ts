import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";
import {
  isInstallHeading,
  isMarkdownLikePath,
  isSocialEngineeringInstruction,
  isSuspiciousInstallCommand,
  markdownSnippet,
  parseMarkdownDocument
} from "./markdown.js";

const SCRIPT_MARKERS = [
  /\b(?:preinstall|postinstall)\b/gi,
  /\b(?:install\.sh|bootstrap\.sh|setup\.sh|init\.sh)\b/gi,
  /chmod\s+\+x\s+[^\n]*(?:install|bootstrap|setup|init)/gi,
  /run\s+(?:the\s+)?(?:install|bootstrap|setup|init)\s+script/gi,
  /(?:launchctl|systemctl|crontab|schtasks|update-rc\.d|rc-update|LaunchAgents|CurrentVersion\\Run)/gi
];

function getNearestHeadingBefore(headings: Array<{ line: number; text: string }>, line: number) {
  let nearest: { line: number; text: string } | null = null;
  for (const heading of headings) {
    if (heading.line >= line) break;
    nearest = heading;
  }
  return nearest;
}

export const bootstrapInstallerRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (isScannerImplementationFile(file.relativePath)) continue;
    for (const pattern of SCRIPT_MARKERS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `bootstrap-installer:${file.relativePath}`,
        category: "bootstrap-installer",
        severity: file.relativePath.endsWith("package.json") ? "high" : "medium",
        signalType: inferSignalType(file.relativePath),
        title: "Bootstrap or installer script behavior referenced",
        summary: "This package includes install/bootstrap behavior that deserves review before enablement.",
        recommendation: "Require manual review of every install/bootstrap step and verify it is necessary, local, and pinned.",
        evidence: matches.slice(0, 3).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }

    if (!isMarkdownLikePath(file.relativePath)) continue;

    const document = parseMarkdownDocument(file.content);
    const installHeadings = document.headings.filter((heading) => isInstallHeading(heading.text));
    const suspiciousBlocks = document.codeBlocks.filter((block) => {
      if (!isSuspiciousInstallCommand(block.content)) return false;
      const heading = getNearestHeadingBefore(document.headings, block.startLine);
      return !heading || isInstallHeading(heading.text);
    });

    const installEvidence = [
      ...installHeadings.slice(0, 2).map((heading) => ({
        filePath: file.relativePath,
        line: heading.line,
        snippet: markdownSnippet(`${"#".repeat(heading.depth)} ${heading.text}`)
      })),
      ...suspiciousBlocks.slice(0, 2).map((block) => ({
        filePath: file.relativePath,
        line: block.startLine,
        snippet: markdownSnippet(block.content)
      }))
    ];

    if (installHeadings.length && suspiciousBlocks.length) {
      const strongestBlock = suspiciousBlocks.find((block) => isSuspiciousInstallCommand(block.content)) ?? suspiciousBlocks[0]!;
      findings.push({
        id: `bootstrap-installer:${file.relativePath}:docs`,
        category: "bootstrap-installer",
        severity: isSuspiciousInstallCommand(strongestBlock.content) ? "high" : "medium",
        signalType: inferSignalType(file.relativePath),
        title: "Documentation-driven install chain found",
        summary: "This documentation uses install, bootstrap, or setup sections to direct the operator toward executable shell steps.",
        recommendation: "Treat the documentation as part of the executable trust surface. Review every install step, pin every remote dependency, and avoid copy-paste execution of unreviewed setup commands.",
        evidence: installEvidence.slice(0, 4)
      });
    } else if (installHeadings.length && isSocialEngineeringInstruction(file.content)) {
      const heading = installHeadings[0]!;
      findings.push({
        id: `bootstrap-installer:${file.relativePath}:prompt`,
        category: "prompt-directed-shell-execution",
        severity: "medium",
        signalType: inferSignalType(file.relativePath),
        title: "Documentation nudges the operator into running setup commands",
        summary: "This documentation combines install/setup language with instructions that could push an operator into executing commands before review.",
        recommendation: "Manually inspect each setup instruction and avoid trust decisions based only on the surrounding prose.",
        evidence: [
          {
            filePath: file.relativePath,
            line: heading.line,
            snippet: markdownSnippet(`${"#".repeat(heading.depth)} ${heading.text}`)
          }
        ]
      });
    }
  }

  return findings;
};
