import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { PassportScanDecision, PassportScanReview } from "./review.js";
import type { ScannerReport } from "./scanner/types.js";

export type PassportPluginInstallRecord = {
  id: string;
  pluginId: string;
  pluginName: string;
  sourcePath: string;
  manifestPath: string;
  fingerprint: string;
  targetKind: ScannerReport["targetKind"];
  verdict: ScannerReport["verdict"];
  recommendationAction: ScannerReport["packageRecommendation"]["action"];
  reviewDecision?: PassportScanDecision;
  reviewId?: string;
  installCommand: string;
  linked: boolean;
  pinned: boolean;
  installedAt: string;
  enabledAt?: string;
};

export type PassportPluginInstallStore = {
  installs: PassportPluginInstallRecord[];
};

const storeLocks = new Map<string, Promise<unknown>>();

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getStorePath() {
  return resolve(getLedgerDir(), "plugin-installs.json");
}

async function ensureParent(path: string) {
  await mkdir(dirname(path), { recursive: true });
}

async function writeStoreAtomically(store: PassportPluginInstallStore, storePath: string) {
  await ensureParent(storePath);
  const tmpPath = `${storePath}.tmp`;
  await writeFile(tmpPath, JSON.stringify(store, null, 2) + "\n", "utf8");
  await rename(tmpPath, storePath);
}

async function withStoreLock<T>(storePath: string, fn: () => Promise<T>): Promise<T> {
  const previous = storeLocks.get(storePath) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolveLock) => {
    release = resolveLock;
  });

  storeLocks.set(storePath, previous.then(() => current));

  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (storeLocks.get(storePath) === current) {
      storeLocks.delete(storePath);
    }
  }
}

export async function loadPluginInstallStore(storePath = getStorePath()): Promise<PassportPluginInstallStore> {
  try {
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PassportPluginInstallStore>;
    return {
      installs: Array.isArray(parsed.installs) ? parsed.installs : []
    };
  } catch {
    return { installs: [] };
  }
}

export async function listPluginInstalls(input?: { pluginId?: string; sourcePath?: string; storePath?: string }) {
  const store = await loadPluginInstallStore(input?.storePath);
  return store.installs
    .filter((record) => !input?.pluginId || record.pluginId === input.pluginId)
    .filter((record) => !input?.sourcePath || record.sourcePath === input.sourcePath)
    .sort((a, b) => Date.parse(b.installedAt) - Date.parse(a.installedAt));
}

export async function getLatestPluginInstall(input: { pluginId?: string; sourcePath?: string; storePath?: string }) {
  const records = await listPluginInstalls(input);
  return records[0] ?? null;
}

export async function recordPluginInstall(input: {
  pluginId: string;
  pluginName: string;
  sourcePath: string;
  manifestPath: string;
  report: ScannerReport;
  scanReview?: PassportScanReview | null;
  installCommand: string;
  linked: boolean;
  pinned: boolean;
  enabledAt?: string;
  storePath?: string;
}) {
  const storePath = input.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const store = await loadPluginInstallStore(storePath);
    const record: PassportPluginInstallRecord = {
      id: `appi_${Math.random().toString(36).slice(2, 10)}`,
      pluginId: input.pluginId,
      pluginName: input.pluginName,
      sourcePath: input.sourcePath,
      manifestPath: input.manifestPath,
      fingerprint: input.report.fingerprint,
      targetKind: input.report.targetKind,
      verdict: input.report.verdict,
      recommendationAction: input.report.packageRecommendation.action,
      reviewDecision: input.scanReview?.decision,
      reviewId: input.scanReview?.id,
      installCommand: input.installCommand,
      linked: input.linked,
      pinned: input.pinned,
      installedAt: new Date().toISOString(),
      enabledAt: input.enabledAt
    };

    store.installs = [
      ...store.installs.filter((existing) => !(existing.pluginId === record.pluginId && existing.sourcePath === record.sourcePath)),
      record
    ];

    await writeStoreAtomically(store, storePath);
    return record;
  });
}

export async function markPluginEnabled(input: { pluginId: string; enabledAt?: string; storePath?: string }) {
  const storePath = input.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const store = await loadPluginInstallStore(storePath);
    const target = [...store.installs].sort((a, b) => Date.parse(b.installedAt) - Date.parse(a.installedAt)).find((record) => record.pluginId === input.pluginId);
    if (!target) return null;
    const enabledAt = input.enabledAt ?? new Date().toISOString();
    store.installs = store.installs.map((record) => record.id === target.id ? { ...record, enabledAt } : record);
    await writeStoreAtomically(store, storePath);
    return { ...target, enabledAt };
  });
}

export async function pruneMissingPluginInstalls(input?: { storePath?: string }) {
  const storePath = input?.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const store = await loadPluginInstallStore(storePath);
    const kept: PassportPluginInstallRecord[] = [];
    const removed: PassportPluginInstallRecord[] = [];

    for (const record of store.installs) {
      try {
        await stat(record.sourcePath);
        kept.push(record);
      } catch {
        removed.push(record);
      }
    }

    if (removed.length) {
      await writeStoreAtomically({ installs: kept }, storePath);
    }

    return { kept, removed };
  });
}
