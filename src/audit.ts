import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

function getAuditPath() {
  const ledgerDir = process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
  return resolve(ledgerDir, "audit.jsonl");
}

export async function appendAuditRecord(record: unknown, auditPath = getAuditPath()) {
  await mkdir(dirname(auditPath), { recursive: true });
  await appendFile(auditPath, JSON.stringify({ ts: new Date().toISOString(), ...((record as object) ?? {}) }) + "\n", "utf8");
}
