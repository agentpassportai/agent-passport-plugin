import { getLatestScanReview, type PassportScanDecision } from "./review.js";
import { listPluginInstalls } from "./install-ledger.js";
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
  const queue = await listPluginsNeedingRereview();
  const state = await updateRereviewState({
    active: queue.map((item) => ({ pluginId: item.pluginId, fingerprint: item.currentFingerprint }))
  });

  const newlyEntered = queue.filter((item) =>
    state.newlySeen.some((seen) => seen.pluginId === item.pluginId && seen.fingerprint === item.currentFingerprint)
  );
  const resolved = state.resolved;

  return {
    queue,
    newlyEntered,
    resolved,
    summary: {
      queueCount: queue.length,
      newCount: newlyEntered.length,
      resolvedCount: resolved.length
    }
  };
}

export async function buildDriftAlerts() {
  const result = await sweepRereviewQueue();
  return {
    alert: result.summary.newCount > 0,
    newlyEntered: result.newlyEntered,
    resolved: result.resolved,
    summary: result.summary,
    nextCommand: "/passport workspace-state"
  };
}
