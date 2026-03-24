import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { bootstrapInstallerRule } from "./rules/bootstrap-installer.js";
import { credentialHarvestRule } from "./rules/credential-harvest.js";
import { promptShellRule } from "./rules/prompt-shell.js";
import { remoteScriptRule } from "./rules/remote-script.js";
import { suspiciousEgressRule } from "./rules/suspicious-egress.js";
import { persistenceAutorunRule } from "./rules/persistence-autorun.js";
import { stagedPayloadRule } from "./rules/staged-payload.js";
import { manifestLifecycleRule } from "./rules/manifest-lifecycle.js";
import { pluginManifestRule } from "./rules/plugin-manifest.js";
import { buildReport } from "./report.js";
import type { ScannerFile, ScannerReport, ScannerRule, ScannerTargetKind, ScannerTargetType } from "./types.js";

const DEFAULT_MAX_FILES = 200;
const DEFAULT_MAX_BYTES = 256_000;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "coverage", ".next"]);
const ALLOWED_EXTENSIONS = new Set([".md", ".txt", ".json", ".yaml", ".yml", ".sh", ".bash", ".zsh", ".ps1", ".js", ".ts", ".mjs", ".cjs"]);
const SPECIAL_FILENAMES = new Set(["SKILL.md", "README", "README.md", "package.json", "openclaw.plugin.json"]);
const SKIP_FILES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"]);
const SCANNER_RULES: ScannerRule[] = [
  remoteScriptRule,
  stagedPayloadRule,
  bootstrapInstallerRule,
  manifestLifecycleRule,
  pluginManifestRule,
  persistenceAutorunRule,
  credentialHarvestRule,
  suspiciousEgressRule,
  promptShellRule
];

function shouldScanFile(path: string) {
  const filename = path.split("/").pop() ?? path;
  if (SKIP_FILES.has(filename)) return false;
  if (SPECIAL_FILENAMES.has(filename)) return true;
  const dot = filename.lastIndexOf(".");
  if (dot === -1) return false;
  return ALLOWED_EXTENSIONS.has(filename.slice(dot).toLowerCase());
}

function detectTargetKind(files: ScannerFile[], targetPath: string, targetType: ScannerTargetType): ScannerTargetKind {
  const names = new Set(files.map((file) => file.relativePath.split("/").pop() ?? file.relativePath));
  const hasSkill = names.has("SKILL.md");
  const hasPluginManifest = names.has("openclaw.plugin.json");
  const hasPackageManifest = names.has("package.json");

  if (hasSkill && (hasPluginManifest || hasPackageManifest)) return "hybrid";
  if (hasPluginManifest) return "plugin";
  if (hasSkill) return "skill";
  if (hasPackageManifest) return "package";

  const basename = targetPath.split("/").pop() ?? targetPath;
  if (targetType === "file") {
    if (basename === "SKILL.md") return "skill";
    if (basename === "openclaw.plugin.json") return "plugin";
    if (basename === "package.json") return "package";
  }

  return "unknown";
}

function buildFingerprint(files: ScannerFile[], targetType: ScannerTargetType) {
  const hash = createHash("sha256");
  hash.update(`targetType:${targetType}\n`);
  for (const file of [...files].sort((a, b) => a.relativePath.localeCompare(b.relativePath))) {
    hash.update(`file:${file.relativePath}\n`);
    hash.update(file.content);
    hash.update("\n---\n");
  }
  return `sha256:${hash.digest("hex")}`;
}

async function collectFiles(rootPath: string, targetPath: string, maxFiles: number, maxBytes: number, files: ScannerFile[]) {
  if (files.length >= maxFiles) return;
  const targetStat = await stat(targetPath);

  if (targetStat.isDirectory()) {
    const entries = await readdir(targetPath, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
      await collectFiles(rootPath, resolve(targetPath, entry.name), maxFiles, maxBytes, files);
    }
    return;
  }

  if (!targetStat.isFile() || !shouldScanFile(targetPath) || targetStat.size > maxBytes) return;
  const content = await readFile(targetPath, "utf8");
  files.push({
    absolutePath: targetPath,
    relativePath: relative(rootPath, targetPath) || targetPath.split("/").pop() || targetPath,
    content
  });
}

export async function scanPath(targetPath: string, options?: { maxFiles?: number; maxBytes?: number }): Promise<ScannerReport> {
  const scannedPath = resolve(targetPath);
  const targetStat = await stat(scannedPath);
  const targetType: ScannerTargetType = targetStat.isDirectory() ? "directory" : "file";
  const rootPath = targetType === "directory" ? scannedPath : resolve(scannedPath, "..");
  const files: ScannerFile[] = [];

  await collectFiles(rootPath, scannedPath, options?.maxFiles ?? DEFAULT_MAX_FILES, options?.maxBytes ?? DEFAULT_MAX_BYTES, files);

  const findings = SCANNER_RULES.flatMap((rule) => rule({ rootPath, targetType, files }));
  const uniqueFindings = Array.from(new Map(findings.map((finding) => [finding.id, finding])).values());
  const targetKind = detectTargetKind(files, scannedPath, targetType);
  const fingerprint = buildFingerprint(files, targetType);

  return buildReport({
    scannedPath,
    fingerprint,
    targetType,
    targetKind,
    fileCount: files.length,
    filesScanned: files.map((file) => file.relativePath),
    findings: uniqueFindings
  });
}
