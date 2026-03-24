import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const KNOWN_CHANNEL_PREFIXES = new Set([
  "telegram",
  "signal",
  "discord",
  "whatsapp",
  "slack",
  "imessage",
  "line",
  "irc",
  "googlechat"
]);

export type PassportConsentGrant = {
  key: string;
  scope: "outbound-message";
  target: string;
  reason?: string;
  grantedAt: string;
  expiresAt: string;
};

export type PassportConsentRequest = {
  id: string;
  target: string;
  action: "message_sending" | "message.send" | "sessions_send";
  reason?: string;
  requestedAt: string;
  status: "pending" | "approved" | "denied";
  reviewedAt?: string;
  reviewNote?: string;
  approvedGrantKey?: string;
};

export type PassportConsentStore = {
  grants: PassportConsentGrant[];
  requests: PassportConsentRequest[];
};

const storeLocks = new Map<string, Promise<unknown>>();

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getStorePath() {
  return resolve(getLedgerDir(), "consents.json");
}

async function ensureParent(path: string) {
  await mkdir(dirname(path), { recursive: true });
}

function cloneStore(store: PassportConsentStore): PassportConsentStore {
  return {
    grants: store.grants.map((grant) => ({ ...grant })),
    requests: store.requests.map((request) => ({ ...request }))
  };
}

async function writeConsentStoreAtomically(store: PassportConsentStore, storePath: string) {
  await ensureParent(storePath);
  const tmpPath = `${storePath}.tmp`;
  await writeFile(tmpPath, JSON.stringify(store, null, 2) + "\n", "utf8");
  await rename(tmpPath, storePath);
}

async function withStoreLock<T>(storePath: string, fn: () => Promise<T>): Promise<T> {
  const previous = storeLocks.get(storePath) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
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

export async function loadConsentStore(storePath = getStorePath()): Promise<PassportConsentStore> {
  try {
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PassportConsentStore>;
    return {
      grants: Array.isArray(parsed.grants) ? parsed.grants : [],
      requests: Array.isArray(parsed.requests) ? parsed.requests : []
    };
  } catch {
    return { grants: [], requests: [] };
  }
}

export async function saveConsentStore(store: PassportConsentStore, storePath = getStorePath()) {
  await withStoreLock(storePath, async () => {
    await writeConsentStoreAtomically(store, storePath);
  });
}

async function mutateConsentStore<T>(
  mutator: (store: PassportConsentStore) => Promise<{ store: PassportConsentStore; result: T }> | { store: PassportConsentStore; result: T },
  storePath = getStorePath()
): Promise<T> {
  return withStoreLock(storePath, async () => {
    const current = await loadConsentStore(storePath);
    const { store, result } = await mutator(cloneStore(current));
    await writeConsentStoreAtomically(store, storePath);
    return result;
  });
}

export async function grantConsent(input: {
  target: string;
  ttlMinutes: number;
  reason?: string;
  storePath?: string;
}) {
  return mutateConsentStore((store) => {
    const now = Date.now();
    const expiresAt = new Date(now + input.ttlMinutes * 60_000).toISOString();
    const target = normalizeTarget(input.target);
    const aliases = expandTargetAliases(input.target);
    const aliasKeys = new Set(Array.from(aliases, (alias) => `outbound-message:${alias}`));
    const key = `outbound-message:${target}`;

    store.grants = store.grants.filter((grant) => !aliasKeys.has(grant.key) && Date.parse(grant.expiresAt) > now);

    const grant: PassportConsentGrant = {
      key,
      scope: "outbound-message",
      target,
      reason: input.reason,
      grantedAt: new Date(now).toISOString(),
      expiresAt
    };

    store.grants.push(grant);
    return { store, result: grant };
  }, input.storePath);
}

export async function revokeConsent(target: string, storePath?: string) {
  return mutateConsentStore((store) => {
    const aliasKeys = new Set(Array.from(expandTargetAliases(target), (alias) => `outbound-message:${alias}`));
    const before = store.grants.length;
    store.grants = store.grants.filter((grant) => !aliasKeys.has(grant.key));
    return { store, result: { removed: before - store.grants.length } };
  }, storePath);
}

export async function listConsents(storePath?: string) {
  const now = Date.now();
  return mutateConsentStore((store) => {
    store.grants = store.grants.filter((grant) => Date.parse(grant.expiresAt) > now);
    return { store, result: store.grants };
  }, storePath);
}

export async function hasConsentForTarget(target: string, storePath?: string) {
  const aliasKeys = new Set(Array.from(expandTargetAliases(target), (alias) => `outbound-message:${alias}`));
  const grants = await listConsents(storePath);
  return grants.some((grant) => aliasKeys.has(grant.key));
}

export async function createConsentRequest(input: {
  target: string;
  action: PassportConsentRequest["action"];
  reason?: string;
  storePath?: string;
}) {
  return mutateConsentStore((store) => {
    const now = new Date().toISOString();
    const target = normalizeTarget(input.target);
    const aliasKeys = new Set(Array.from(expandTargetAliases(target), (alias) => `outbound-message:${alias}`));

    const activeGrant = store.grants.find(
      (grant) => Date.parse(grant.expiresAt) > Date.now() && aliasKeys.has(grant.key)
    );
    if (activeGrant) {
      const approved = [...store.requests]
        .reverse()
        .find((request) => request.status === "approved" && targetMatches(request.target, target));
      if (approved) {
        return { store, result: approved };
      }
    }

    const existing = store.requests.find(
      (request) => request.status === "pending" && request.action === input.action && targetMatches(request.target, target)
    );

    if (existing) {
      return { store, result: existing };
    }

    const request: PassportConsentRequest = {
      id: `apr_${Math.random().toString(36).slice(2, 10)}`,
      target,
      action: input.action,
      reason: input.reason,
      requestedAt: now,
      status: "pending"
    };

    store.requests.push(request);
    return { store, result: request };
  }, input.storePath);
}

export async function listConsentRequests(input?: {
  status?: PassportConsentRequest["status"] | "all";
  storePath?: string;
}) {
  const store = await loadConsentStore(input?.storePath);
  const status = input?.status ?? "all";
  if (status === "all") return store.requests;
  return store.requests.filter((request) => request.status === status);
}

export async function reviewConsentRequest(input: {
  requestId: string;
  decision: "approved" | "denied";
  ttlMinutes?: number;
  note?: string;
  storePath?: string;
}) {
  return mutateConsentStore((store) => {
    const request = store.requests.find((item) => item.id === input.requestId);
    if (!request) {
      return { store, result: { ok: false as const, error: `Request not found: ${input.requestId}` } };
    }

    request.status = input.decision;
    request.reviewedAt = new Date().toISOString();
    request.reviewNote = input.note;

    let grant: PassportConsentGrant | null = null;
    if (input.decision === "approved") {
      const now = Date.now();
      const target = normalizeTarget(request.target);
      const aliases = expandTargetAliases(request.target);
      const aliasKeys = new Set(Array.from(aliases, (alias) => `outbound-message:${alias}`));
      const key = `outbound-message:${target}`;

      store.grants = store.grants.filter((entry) => !aliasKeys.has(entry.key) && Date.parse(entry.expiresAt) > now);
      grant = {
        key,
        scope: "outbound-message",
        target,
        reason: input.note || request.reason,
        grantedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + (input.ttlMinutes ?? 60) * 60_000).toISOString()
      };
      store.grants.push(grant);
      request.approvedGrantKey = grant.key;
    }

    return {
      store,
      result: {
        ok: true as const,
        request: { ...request },
        grant
      }
    };
  }, input.storePath);
}

export function normalizeTarget(value: string) {
  return value.trim().toLowerCase();
}

function targetMatches(left: string, right: string) {
  const leftAliases = expandTargetAliases(left);
  const rightAliases = expandTargetAliases(right);
  for (const alias of leftAliases) {
    if (rightAliases.has(alias)) return true;
  }
  return false;
}

export function expandTargetAliases(value: string) {
  const normalized = normalizeTarget(value);
  const aliases = new Set<string>();
  if (!normalized) return aliases;

  aliases.add(normalized);

  if (normalized.startsWith("@")) {
    aliases.add(normalized.slice(1));
  }

  const colonIndex = normalized.indexOf(":");
  if (colonIndex > 0) {
    const prefix = normalized.slice(0, colonIndex);
    const rest = normalized.slice(colonIndex + 1);
    if (rest && KNOWN_CHANNEL_PREFIXES.has(prefix)) {
      aliases.add(rest);
      if (rest.startsWith("@")) aliases.add(rest.slice(1));
    }
  }

  return aliases;
}
