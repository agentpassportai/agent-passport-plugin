import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";

const SCRIPT_MARKERS = [
  /\b(?:preinstall|postinstall)\b/gi,
  /\b(?:install\.sh|bootstrap\.sh|setup\.sh|init\.sh)\b/gi,
  /chmod\s+\+x\s+[^\n]*(?:install|bootstrap|setup|init)/gi,
  /run\s+(?:the\s+)?(?:install|bootstrap|setup|init)\s+script/gi
];

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
  }

  return findings;
};
