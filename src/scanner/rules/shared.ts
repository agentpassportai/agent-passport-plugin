import type { ScannerFile, ScannerSeverity, ScannerSignalType } from "../types.js";

export function isScannerImplementationFile(relativePath: string) {
  return relativePath.startsWith("src/scanner/");
}

export function inferSignalType(relativePath: string): ScannerSignalType {
  const lower = relativePath.toLowerCase();
  if (lower.endsWith(".md") || lower.endsWith(".txt")) return "documentation";
  if (lower.endsWith("package.json") || lower.endsWith("openclaw.plugin.json") || lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".json")) {
    return "config";
  }
  return "executable";
}

export function getLineNumber(content: string, index: number) {
  if (index <= 0) return 1;
  return content.slice(0, index).split(/\r?\n/).length;
}

export function clipSnippet(input: string, max = 180) {
  const normalized = input.replace(/\s+/g, " ").trim();
  return normalized.length <= max ? normalized : `${normalized.slice(0, max - 1)}…`;
}

export function evidenceFromMatch(file: ScannerFile, matchIndex: number, matchLength: number) {
  const start = Math.max(0, file.content.lastIndexOf("\n", matchIndex) + 1);
  const nextNewline = file.content.indexOf("\n", matchIndex + matchLength);
  const end = nextNewline === -1 ? file.content.length : nextNewline;
  return {
    filePath: file.relativePath,
    line: getLineNumber(file.content, matchIndex),
    snippet: clipSnippet(file.content.slice(start, end))
  };
}

export function severityWeight(severity: ScannerSeverity) {
  switch (severity) {
    case "high":
      return 6;
    case "medium":
      return 3;
    case "low":
    default:
      return 1;
  }
}
