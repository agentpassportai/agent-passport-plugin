import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { PassportScanDecision, PassportScanReview } from "./review.js";

export type PassportSkillReviewRecord = {
  id: string;
  slug: string;
  skillDir: string;
  fingerprint: string;
  decision: PassportScanDecision;
  reviewId: string;
  recommendationAction: string;
  verdict: string;
  installedVersion?: string | null;
  createdAt: string;
};

export type PassportSkillReviewLedger = {
  reviews: PassportSkillReviewRecord[];
};

const storeLocks = new Map<string, Promise<unknown>>();

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getStorePath() {
  return resolve(getLedgerDir(), "skill-reviews.json");
}

async function ensureParent(path: string) {
  await mkdir(dirname(path), { recursive: true });
}

async function writeStoreAtomically(store: PassportSkillReviewLedger, storePath: string) {
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

export async function loadSkillReviewLedger(storePath = getStorePath()): Promise<PassportSkillReviewLedger> {
  try {
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PassportSkillReviewLedger>;
    return {
      reviews: Array.isArray(parsed.reviews) ? parsed.reviews : []
    };
  } catch {
    return { reviews: [] };
  }
}

export async function listSkillReviewRecords(input?: { slug?: string; storePath?: string }) {
  const store = await loadSkillReviewLedger(input?.storePath);
  return store.reviews
    .filter((record) => !input?.slug || record.slug === input.slug)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export async function getLatestSkillReviewRecord(slug: string, storePath?: string) {
  const records = await listSkillReviewRecords({ slug, storePath });
  return records[0] ?? null;
}

export async function recordSkillReview(input: {
  slug: string;
  skillDir: string;
  installedVersion?: string | null;
  review: PassportScanReview;
  storePath?: string;
}) {
  const storePath = input.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const store = await loadSkillReviewLedger(storePath);
    const record: PassportSkillReviewRecord = {
      id: `apsk_${Math.random().toString(36).slice(2, 10)}`,
      slug: input.slug,
      skillDir: input.skillDir,
      fingerprint: input.review.fingerprint,
      decision: input.review.decision,
      reviewId: input.review.id,
      recommendationAction: input.review.recommendationAction,
      verdict: input.review.verdict,
      installedVersion: input.installedVersion ?? null,
      createdAt: input.review.createdAt
    };

    store.reviews = [
      ...store.reviews.filter((existing) => existing.slug !== input.slug),
      record
    ];

    await writeStoreAtomically(store, storePath);
    return record;
  });
}
