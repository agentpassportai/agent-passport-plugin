import { getLatestScanReview, type PassportScanDecision } from "./review.js";
import { listPluginInstalls, pruneMissingPluginInstalls } from "./install-ledger.js";
import { scanPath } from "./scanner/index.js";
import { updateRereviewState } from "./rereview-state.js";

export type PassportRereviewItem = {
  pluginId: string;
  pluginName: string;
  sourcePath: string;
  recordedFingerprint: string;
  currentFingerprint: string;
  recordedRecommendation: string;
  currentRecommendation: string;
  currentReviewDecision: PassportScanDecision | null;
  reason: string;
};

export type PassportMissingInstallRecord = {
  pluginId: string;
  pluginName: string;
  sourcePath: string;
  recordedFingerprint: string;
  installedAt: string;
};

export async function listPluginsNeedingRereview(): Promise<PassportRereviewItem[]> {
  const installs = await listPluginInstalls();
  const latestByPluginId = new Map<string, (typeof installs)[number]>();
  for (const record of installs) {
    if (!latestByPluginId.has(record.pluginId)) {
      latestByPluginId.set(record.pluginId, record);
    }
  }

  const results: PassportRereviewItem[] = [];

  for (const record of latestByPluginId.values()) {
    const currentReport = await scanPath(record.sourcePath);
    const currentReview = await getLatestScanReview(currentReport.fingerprint);
    const driftChanged = currentReport.fingerprint !== record.fingerprint;
    const needsRereview = driftChanged && currentReview?.decision !== "trust";
    if (!needsRereview) continue;
    results.push({
      pluginId: record.pluginId,
      pluginName: record.pluginName,
      sourcePath: record.sourcePath,
      recordedFingerprint: record.fingerprint,
      currentFingerprint: currentReport.fingerprint,
      recordedRecommendation: record.recommendationAction,
      currentRecommendation: currentReport.packageRecommendation.action,
      currentReviewDecision: currentReview?.decision ?? null,
      reason: "Recorded install fingerprint drifted and the new fingerprint is not explicitly trusted."
    });
  }

  return results.sort((a, b) => a.pluginId.localeCompare(b.pluginId));
}

export async function sweepRereviewQueue() {
  const cleanup = await pruneMissingPluginInstalls();
  const queue = await listPluginsNeedingRereview();
  const state = await updateRereviewState({
    active: queue.map((item) => ({ pluginId: item.pluginId, fingerprint: item.currentFingerprint }))
  });

  const newlyEntered = queue.filter((item) =>
    state.newlySeen.some((seen) => seen.pluginId === item.pluginId && seen.fingerprint === item.currentFingerprint)
  );
  const resolved = state.resolved;
  const skippedMissing = cleanup.removed.map((record) => ({
    pluginId: record.pluginId,
    pluginName: record.pluginName,
    sourcePath: record.sourcePath,
    recordedFingerprint: record.fingerprint,
    installedAt: record.installedAt
  } satisfies PassportMissingInstallRecord));

  return {
    queue,
    newlyEntered,
    resolved,
    skippedMissing,
    summary: {
      queueCount: queue.length,
      newCount: newlyEntered.length,
      resolvedCount: resolved.length,
      skippedMissingCount: skippedMissing.length
    }
  };
}

export async function buildDriftAlerts() {
  const result = await sweepRereviewQueue();
  return {
    alert: result.summary.newCount > 0,
    newlyEntered: result.newlyEntered,
    resolved: result.resolved,
    skippedMissing: result.skippedMissing,
    summary: result.summary,
    nextCommand: "/passport workspace-state"
  };
}
