import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { ScannerReport } from "./scanner/types.js";

export type PassportScanDecision = "trust" | "review" | "block";

export type PassportScanReview = {
  id: string;
  fingerprint: string;
  scannedPath: string;
  targetKind: ScannerReport["targetKind"];
  verdict: ScannerReport["verdict"];
  recommendationAction: ScannerReport["packageRecommendation"]["action"];
  decision: PassportScanDecision;
  note?: string;
  createdAt: string;
};

export type PassportScanReviewStore = {
  reviews: PassportScanReview[];
};

const storeLocks = new Map<string, Promise<unknown>>();

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getStorePath() {
  return resolve(getLedgerDir(), "scan-reviews.json");
}

async function ensureParent(path: string) {
  await mkdir(dirname(path), { recursive: true });
}

async function writeStoreAtomically(store: PassportScanReviewStore, storePath: string) {
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

export async function loadScanReviewStore(storePath = getStorePath()): Promise<PassportScanReviewStore> {
  try {
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PassportScanReviewStore>;
    return {
      reviews: Array.isArray(parsed.reviews) ? parsed.reviews : []
    };
  } catch {
    return { reviews: [] };
  }
}

export async function listScanReviews(input?: { fingerprint?: string; decision?: PassportScanDecision; storePath?: string }) {
  const store = await loadScanReviewStore(input?.storePath);
  return store.reviews
    .filter((review) => !input?.fingerprint || review.fingerprint === input.fingerprint)
    .filter((review) => !input?.decision || review.decision === input.decision)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export async function getLatestScanReview(fingerprint: string, storePath?: string) {
  const reviews = await listScanReviews({ fingerprint, storePath });
  return reviews[0] ?? null;
}

export async function recordScanReview(input: {
  report: ScannerReport;
  decision: PassportScanDecision;
  note?: string;
  storePath?: string;
}) {
  const storePath = input.storePath ?? getStorePath();
  return withStoreLock(storePath, async () => {
    const store = await loadScanReviewStore(storePath);
    const createdAt = new Date().toISOString();
    const review: PassportScanReview = {
      id: `apsr_${Math.random().toString(36).slice(2, 10)}`,
      fingerprint: input.report.fingerprint,
      scannedPath: input.report.scannedPath,
      targetKind: input.report.targetKind,
      verdict: input.report.verdict,
      recommendationAction: input.report.packageRecommendation.action,
      decision: input.decision,
      note: input.note,
      createdAt
    };

    store.reviews = [
      ...store.reviews.filter((existing) => existing.fingerprint !== input.report.fingerprint),
      review
    ];

    await writeStoreAtomically(store, storePath);
    return review;
  });
}
