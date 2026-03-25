import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

type PassportAuditRuntimeConfig = {
  enabled: boolean;
  path?: string;
};

const DEFAULT_AUDIT_CONFIG: PassportAuditRuntimeConfig = {
  enabled: true
};

const SENSITIVE_KEY_PATTERN = /(content|message|snippet|stdout|stderr|payload|body|prompt|authorization|cookie|token|secret|password|api[_-]?key|credential)/i;
const SECRET_VALUE_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bBearer\s+[A-Za-z0-9._-]{12,}\b/gi,
  /\bx-api-key\b\s*[:=]\s*[^\s,]+/gi
];

let runtimeAuditConfig: PassportAuditRuntimeConfig = { ...DEFAULT_AUDIT_CONFIG };

export function configureAuditRuntime(config?: Partial<PassportAuditRuntimeConfig> | null) {
  runtimeAuditConfig = {
    ...DEFAULT_AUDIT_CONFIG,
    enabled: config?.enabled ?? DEFAULT_AUDIT_CONFIG.enabled,
    path: config?.path?.trim() || undefined
  };
}

function getAuditPath() {
  const explicit = runtimeAuditConfig.path?.trim();
  if (explicit) return resolve(explicit);
  const ledgerDir = process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
  return resolve(ledgerDir, "audit.jsonl");
}

function redactSecrets(input: string) {
  let output = input;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    output = output.replace(pattern, "[redacted]");
  }
  return output;
}

function sanitizeAuditValue(value: unknown, key?: string, depth = 0): unknown {
  if (depth > 6) return "[truncated]";
  if (value == null || typeof value === "number" || typeof value === "boolean") return value;

  if (typeof value === "string") {
    const redacted = redactSecrets(value);
    if (key && SENSITIVE_KEY_PATTERN.test(key)) {
      return `[redacted:${redacted.length} chars]`;
    }
    return redacted.length <= 240 ? redacted : `${redacted.slice(0, 240)}...[truncated ${redacted.length - 240} chars]`;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeAuditValue(entry, key, depth + 1));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
        entryKey,
        sanitizeAuditValue(entryValue, entryKey, depth + 1)
      ])
    );
  }

  return String(value);
}

export async function appendAuditRecord(record: unknown, auditPath = getAuditPath()) {
  if (!runtimeAuditConfig.enabled) return;
  await mkdir(dirname(auditPath), { recursive: true });
  const payload = sanitizeAuditValue(record) as object;
  await appendFile(auditPath, JSON.stringify({ ts: new Date().toISOString(), ...(payload ?? {}) }) + "\n", "utf8");
}
