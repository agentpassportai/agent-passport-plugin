import { clipSnippet } from "./shared.js";

export type MarkdownHeading = {
  line: number;
  depth: number;
  text: string;
};

export type MarkdownCodeBlock = {
  startLine: number;
  endLine: number;
  language: string;
  content: string;
};

export type MarkdownDocument = {
  headings: MarkdownHeading[];
  codeBlocks: MarkdownCodeBlock[];
};

const HEADING_RE = /^(#{1,6})\s+(.+?)\s*$/;
const FENCE_RE = /^\s{0,3}([`~]{3,})([^`]*)?$/;

const INSTALL_HEADING_PATTERNS = [
  /\binstall(?:ation)?\b/i,
  /\bsetup\b/i,
  /\bbootstrap\b/i,
  /\binit(?:ial(?:ize|isation|ization)|ialize|ialisation)?\b/i,
  /\bquickstart\b/i,
  /\bgetting started\b/i,
  /\bfirst run\b/i,
  /\bonboarding\b/i
];

const SHELL_LANGUAGES = new Set([
  "sh",
  "bash",
  "zsh",
  "shell",
  "console",
  "cmd",
  "bat",
  "powershell",
  "pwsh",
  "ps1"
]);

export function parseMarkdownDocument(content: string): MarkdownDocument {
  const headings: MarkdownHeading[] = [];
  const codeBlocks: MarkdownCodeBlock[] = [];
  const lines = content.split(/\r?\n/);

  let activeFence: { marker: string; startLine: number; language: string; content: string[] } | null = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;

    if (activeFence) {
      const trimmed = line.trimStart();
      const marker = activeFence.marker[0];
      const closing = trimmed.match(new RegExp(`^${escapeRegex(marker)}{${activeFence.marker.length},}\\s*$`));
      if (closing) {
        codeBlocks.push({
          startLine: activeFence.startLine,
          endLine: lineNumber,
          language: activeFence.language,
          content: activeFence.content.join("\n")
        });
        activeFence = null;
      } else {
        activeFence.content.push(line);
      }
      continue;
    }

    const headingMatch = line.match(HEADING_RE);
    if (headingMatch) {
      headings.push({
        line: lineNumber,
        depth: headingMatch[1].length,
        text: headingMatch[2]?.trim() ?? ""
      });
      continue;
    }

    const fenceMatch = line.match(FENCE_RE);
    if (fenceMatch) {
      const marker = fenceMatch[1];
      const language = (fenceMatch[2] ?? "").trim().split(/\s+/)[0]?.toLowerCase() ?? "";
      activeFence = {
        marker,
        startLine: lineNumber,
        language,
        content: []
      };
    }
  }

  if (activeFence) {
    codeBlocks.push({
      startLine: activeFence.startLine,
      endLine: lines.length,
      language: activeFence.language,
      content: activeFence.content.join("\n")
    });
  }

  return { headings, codeBlocks };
}

export function isMarkdownLikePath(relativePath: string) {
  return /\.(?:md|markdown|txt)$/i.test(relativePath) || /(?:^|\/)(?:README|SKILL)\b/i.test(relativePath);
}

export function isInstallHeading(text: string) {
  return INSTALL_HEADING_PATTERNS.some((pattern) => pattern.test(text));
}

export function isShellLikeLanguage(language: string) {
  return SHELL_LANGUAGES.has(language.toLowerCase());
}

export function isSuspiciousInstallCommand(text: string) {
  return [
    /(?:curl|wget|Invoke-WebRequest)[^\n|]+\|\s*(?:bash|sh|zsh|powershell|pwsh|iex)/i,
    /(?:curl|wget|Invoke-WebRequest)[^\n]+(?:-o|--output)\s+[^\n]*(?:&&|;)\s*(?:chmod\s+\+x|(?:\.\/|bash|sh|zsh|powershell|pwsh))/i,
    /\b(?:bash|sh|zsh)\s*<\(\s*(?:curl|wget)\b/i,
    /\b(?:bash|sh|zsh|powershell|pwsh)\s+-c\b/i,
    /\b(?:npm|pnpm|yarn|bun)\s+run\s+(?:install|bootstrap|setup|init|prepare)\b/i,
    /\b(?:install|bootstrap|setup|init)\.sh\b/i,
    /\b(?:chmod\s+\+x\s+\S+|\.\/\S+)\b/i,
    /Invoke-WebRequest[^\n]*(?:iex|Invoke-Expression|Start-Process)/i,
    /(?:certutil\s+-urlcache|bitsadmin|mshta|regsvr32|rundll32)\b/i
  ].some((pattern) => pattern.test(text));
}

export function isSocialEngineeringInstruction(text: string) {
  return [
    /copy\s+and\s+paste\s+this\s+command/i,
    /run\s+this\s+command\s+first/i,
    /disable\s+(?:security|protections?|warnings?)/i,
    /ignore\s+(?:the\s+)?warnings?/i,
    /open\s+(?:a\s+)?terminal\s+and\s+run/i,
    /recommended\s+to\s+run\s+as\s+root/i
  ].some((pattern) => pattern.test(text));
}

export function markdownSnippet(text: string, max = 180) {
  return clipSnippet(text, max);
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
