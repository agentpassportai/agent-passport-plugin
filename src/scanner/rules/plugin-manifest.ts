import type { ScannerFinding, ScannerRule } from "../types.js";
import { clipSnippet, inferSignalType } from "./shared.js";

const RISKY_CATEGORY_KEYS = [
  "exec",
  "externalMessaging",
  "privateNetworkAccess",
  "fileDelete",
  "configMutation",
  "pluginInstall"
] as const;

export const pluginManifestRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (!file.relativePath.endsWith("openclaw.plugin.json")) continue;

    let parsed: any;
    try {
      parsed = JSON.parse(file.content);
    } catch {
      continue;
    }

    const issues: string[] = [];
    const evidence: Array<{ filePath: string; line: number; snippet: string }> = [];

    if (parsed?.configSchema?.properties?.defaultPolicy?.default === "allow") {
      issues.push("defaultPolicy defaults to allow");
      evidence.push({
        filePath: file.relativePath,
        line: 1,
        snippet: clipSnippet('"defaultPolicy": { "default": "allow" }')
      });
    }

    const categories = parsed?.configSchema?.properties?.categories?.properties;
    if (categories && typeof categories === "object") {
      for (const key of RISKY_CATEGORY_KEYS) {
        const entry = categories[key];
        if (entry?.default === "allow") {
          issues.push(`category ${key} defaults to allow`);
          evidence.push({
            filePath: file.relativePath,
            line: 1,
            snippet: clipSnippet(`"${key}": { "default": "allow" }`)
          });
        }
      }
    }

    if (parsed?.configSchema?.properties?.audit?.properties?.enabled?.default === false) {
      issues.push("audit is disabled by default");
      evidence.push({
        filePath: file.relativePath,
        line: 1,
        snippet: clipSnippet('"audit": { "properties": { "enabled": { "default": false } } }')
      });
    }

    if (!issues.length) continue;

    findings.push({
      id: `plugin-manifest-risk:${file.relativePath}`,
      category: "plugin-manifest-risk",
      severity: issues.length >= 4 ? "high" : issues.length >= 2 ? "medium" : "low",
      signalType: inferSignalType(file.relativePath),
      title: "Plugin manifest ships risky trust defaults",
      summary: "This OpenClaw plugin manifest enables permissive defaults on high-risk surfaces or weakens audit posture, which raises the trust bar before install.",
      recommendation: "Review the manifest defaults before trusting the plugin. Prefer require-consent, deny, or audit-forward defaults on risky surfaces.",
      evidence: evidence.slice(0, 4)
    });
  }

  return findings;
};
