import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export type PassportRereviewSeenEntry = {
  pluginId: string;
  fingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type PassportRereviewState = {
  seen: PassportRereviewSeenEntry[];
};

const storeLocks = new Map<string, Promise<unknown>>();

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getStorePath() {
  return resolve(getLedgerDir(), "rereview-state.json");
}

async function ensureParent(path: string) {
  await mkdir(dirname(path), { recursive: true });
}

async function writeStoreAtomically(store: PassportRereviewState, storePath: string) {
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

export async function loadRereviewState(storePath = getStorePath()): Promise<PassportRereviewState> {
  try {
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PassportRereviewState>;
    return {
      seen: Array.isArray(parsed.seen) ? parsed.seen : []
    };
  } catch {
    return { seen: [] };
  }
}

export async function updateRereviewState(input: {
  active: Array<{ pluginId: string; fingerprint: string }>;
  storePath?: string;
}) {
  const storePath = input.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const state = await loadRereviewState(storePath);
    const now = new Date().toISOString();
    const existing = new Map(state.seen.map((entry) => [`${entry.pluginId}:${entry.fingerprint}`, entry]));
    const activeKeys = new Set(input.active.map((entry) => `${entry.pluginId}:${entry.fingerprint}`));

    const seen = input.active.map((entry) => {
      const key = `${entry.pluginId}:${entry.fingerprint}`;
      const prior = existing.get(key);
      return prior
        ? { ...prior, lastSeenAt: now }
        : { pluginId: entry.pluginId, fingerprint: entry.fingerprint, firstSeenAt: now, lastSeenAt: now };
    });

    const newlySeen = seen.filter((entry) => !existing.has(`${entry.pluginId}:${entry.fingerprint}`));
    const resolved = state.seen.filter((entry) => !activeKeys.has(`${entry.pluginId}:${entry.fingerprint}`));

    await writeStoreAtomically({ seen }, storePath);
    return { seen, newlySeen, resolved };
  });
}
