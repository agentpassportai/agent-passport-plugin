import type { ScannerFinding, ScannerRule } from "../types.js";
import { clipSnippet, inferSignalType } from "./shared.js";

const LIFECYCLE_HOOKS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack"
]);

const SUSPICIOUS_COMMAND_PATTERNS = [
  /(?:curl|wget|Invoke-WebRequest)/i,
  /(?:bash|sh|zsh|powershell|pwsh)\s+-c/i,
  /(?:iex|Invoke-Expression)\b/i,
  /\bnode\s+-e\b/i,
  /\bpython(?:3)?\s+-c\b/i,
  /(?:chmod\s+\+x|\.\/|\/tmp\/|mktemp)/i,
  /(?:systemctl\s+enable|crontab\s+|LaunchAgents|CurrentVersion\\Run)/i
];

export const manifestLifecycleRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (!file.relativePath.endsWith("package.json")) continue;

    let parsed: any;
    try {
      parsed = JSON.parse(file.content);
    } catch {
      continue;
    }

    const scripts = parsed?.scripts;
    if (!scripts || typeof scripts !== "object") continue;

    const suspiciousHooks = Object.entries(scripts)
      .filter(([name, command]) => LIFECYCLE_HOOKS.has(name) && typeof command === "string")
      .filter(([, command]) => SUSPICIOUS_COMMAND_PATTERNS.some((pattern) => pattern.test(command)));

    if (!suspiciousHooks.length) continue;

    findings.push({
      id: `manifest-lifecycle:${file.relativePath}`,
      category: "manifest-lifecycle",
      severity: "high",
      signalType: inferSignalType(file.relativePath),
      title: "Suspicious package lifecycle hook found",
      summary: "This package.json runs suspicious commands during install or packaging lifecycle hooks, which can trigger automatically during normal package operations.",
      recommendation: "Treat lifecycle hooks as code execution. Review each hook manually and remove any fetch, eval, shell, or persistence behavior before trust or install.",
      evidence: suspiciousHooks.slice(0, 4).map(([name, command]) => ({
        filePath: file.relativePath,
        line: 1,
        snippet: clipSnippet(`\"${name}\": ${JSON.stringify(command)}`)
      }))
    });
  }

  return findings;
};
