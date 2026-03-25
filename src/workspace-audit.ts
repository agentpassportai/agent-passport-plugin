import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { listPluginInstalls, type PassportPluginInstallRecord } from "./install-ledger.js";
import { getLatestScanReview, type PassportScanDecision } from "./review.js";
import { scanPath } from "./scanner/index.js";
import type { ScannerReport, ScannerTargetKind } from "./scanner/types.js";
import { getLatestSkillReviewRecord, type PassportSkillReviewRecord } from "./skill-review-ledger.js";

type WorkspaceAuditKind = "plugin" | "skill";

type TrackedSkillLock = {
  version: 1;
  skills: Record<string, { version?: string; installedAt?: number }>;
};

type TrackedSkillOrigin = {
  version: 1;
  registry: string;
  slug: string;
  installedVersion: string;
  installedAt: number;
};

export type WorkspaceAuditOptions = {
  workspaceRoot?: string;
  ledgerDir?: string;
  includePlugins?: boolean;
  includeSkills?: boolean;
  maxItems?: number;
};

export type WorkspaceAuditItem = {
  id: string;
  kind: WorkspaceAuditKind;
  name: string;
  path: string;
  fingerprint: string | null;
  targetKind: ScannerTargetKind | null;
  status: string;
  verdict: ScannerReport["verdict"] | null;
  recommendation: ScannerReport["packageRecommendation"]["action"] | null;
  score: number;
  priority: number;
  signals: {
    documentation: number;
    config: number;
    executable: number;
    categories: string[];
  };
  summary: string;
  topRisks: string[];
  remediationTargets: string[];
  recommendedActions: string[];
  reviewDecision: PassportScanDecision | null;
  baselineFingerprint: string | null;
  driftChanged: boolean;
  tracked: boolean;
  installedVersion: string | null;
  installedAt: string | null;
  notes: string[];
};

export type WorkspaceAuditCounts = {
  total: number;
  plugins: number;
  skills: number;
  dangerous: number;
  suspicious: number;
  blocked: number;
  reviewRequired: number;
  trusted: number;
  missing: number;
  drifted: number;
  credentialHeavy: number;
  egressHeavy: number;
  persistenceHeavy: number;
  installChainHeavy: number;
  docChainHeavy: number;
  runtimeHeavy: number;
};

export type WorkspaceAuditResult = {
  workspaceRoot: string;
  ledgerDir: string;
  scannedAt: string;
  counts: WorkspaceAuditCounts;
  items: WorkspaceAuditItem[];
  highRiskItems: WorkspaceAuditItem[];
  nextSteps: string[];
};

function resolveWorkspaceRoot(explicit?: string) {
  const configured = explicit?.trim() || process.env.OPENCLAW_WORKSPACE_DIR?.trim();
  if (configured) return resolve(configured);

  let current = resolve(process.cwd());
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(resolve(current, ".clawhub", "lock.json")) || existsSync(resolve(current, "AGENTS.md"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return process.cwd();
}

function resolveLedgerDir(workspaceRoot: string, explicit?: string) {
  return resolve(explicit?.trim() || process.env.AGENT_PASSPORT_LEDGER_DIR?.trim() || resolve(workspaceRoot, ".openclaw", "agent-passport"));
}

function skillLockPath(workspaceRoot: string) {
  return resolve(workspaceRoot, ".clawhub", "lock.json");
}

function skillOriginPath(workspaceRoot: string, slug: string) {
  return resolve(workspaceRoot, "skills", slug, ".clawhub", "origin.json");
}

function skillReviewStorePath(ledgerDir: string) {
  return resolve(ledgerDir, "skill-reviews.json");
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return null;
  }
}

async function readTrackedSkillLock(workspaceRoot: string): Promise<TrackedSkillLock> {
  const parsed = await readJson<Partial<TrackedSkillLock>>(skillLockPath(workspaceRoot));
  if (parsed && parsed.version === 1 && parsed.skills && typeof parsed.skills === "object") {
    return {
      version: 1,
      skills: parsed.skills as TrackedSkillLock["skills"]
    };
  }
  return { version: 1, skills: {} };
}

async function readTrackedSkillOrigin(workspaceRoot: string, slug: string): Promise<TrackedSkillOrigin | null> {
  const parsed = await readJson<Partial<TrackedSkillOrigin>>(skillOriginPath(workspaceRoot, slug));
  if (
    parsed?.version === 1
    && typeof parsed.registry === "string"
    && typeof parsed.slug === "string"
    && typeof parsed.installedVersion === "string"
    && typeof parsed.installedAt === "number"
  ) {
    return parsed as TrackedSkillOrigin;
  }
  return null;
}

function latestInstallByPluginId(installs: PassportPluginInstallRecord[]) {
  const latestByPluginId = new Map<string, PassportPluginInstallRecord>();
  for (const record of installs) {
    if (!latestByPluginId.has(record.pluginId)) {
      latestByPluginId.set(record.pluginId, record);
    }
  }
  return [...latestByPluginId.values()];
}

function countSignals(report: ScannerReport) {
  return {
    documentation: report.findings.filter((finding) => finding.signalType === "documentation").length,
    config: report.findings.filter((finding) => finding.signalType === "config").length,
    executable: report.findings.filter((finding) => finding.signalType === "executable").length,
    categories: [...new Set(report.findings.map((finding) => finding.category))].sort()
  };
}

function hasCategory(report: ScannerReport, category: string) {
  return report.findings.some((finding) => finding.category === category);
}

function deriveRemediationTargets(report: ScannerReport, kind: WorkspaceAuditKind) {
  const targets = new Set<string>();
  const categories = new Set(report.findings.map((finding) => finding.category));

  if (categories.has("credential-harvest")) {
    targets.add("browser profiles and cookies");
    targets.add("SSH keys");
    targets.add("cloud credentials");
    targets.add("wallets");
    targets.add("API tokens");
  }
  if (categories.has("suspicious-egress")) {
    targets.add("egress destinations and webhooks");
    targets.add("proxy and firewall allowlists");
  }
  if (categories.has("persistence-autorun")) {
    targets.add("cron jobs and startup services");
    targets.add("shell profiles and LaunchAgents");
  }
  if (categories.has("manifest-lifecycle")) {
    targets.add("package lifecycle hooks");
  }
  if (categories.has("remote-script-execution") || categories.has("bootstrap-installer") || categories.has("prompt-directed-shell-execution")) {
    targets.add("install instructions");
    targets.add("temporary payloads and bootstrap scripts");
  }
  if (kind === "skill" && (categories.has("remote-script-execution") || categories.has("bootstrap-installer") || categories.has("prompt-directed-shell-execution"))) {
    targets.add("SKILL.md and README install guidance");
  }
  if (kind === "plugin" && categories.has("plugin-manifest-risk")) {
    targets.add("plugin trust defaults");
    targets.add("audit posture");
  }

  return [...targets];
}

function deriveRecommendedActions(report: ScannerReport, status: string, kind: WorkspaceAuditKind, driftChanged: boolean) {
  const actions: string[] = [];
  const escapedPath = report.scannedPath.includes(" ") ? `"${report.scannedPath}"` : report.scannedPath;

  if (driftChanged) {
    actions.push(`Re-review the current artifact at ${escapedPath}.`);
  }
  if (status === "blocked") {
    actions.push("Keep this artifact blocked until the current content is reviewed again.");
  } else if (status === "rereview-required") {
    actions.push("Re-trust the current fingerprint only after an explicit human review.");
  } else if (status === "dangerous-unreviewed") {
    actions.push("Block by default unless you intentionally want to override this exact fingerprint.");
  } else if (status === "needs-review" || status === "unreviewed") {
    actions.push("Review before trust.");
  }

  if (kind === "skill") {
    actions.push("Audit the workspace skill install guidance and any copy-paste shell steps.");
  } else {
    actions.push("Audit the plugin lifecycle, runtime hooks, and install/update behavior.");
  }

  return actions;
}

function summarizeNotes(report: ScannerReport, kind: WorkspaceAuditKind) {
  const notes: string[] = [...report.kindSensitiveNotes];
  if (kind === "skill") {
    notes.push("Skill trust should be treated as operator guidance plus executable install surface.");
  } else {
    notes.push("Plugin trust should be treated as packaged runtime behavior plus manifest defaults.");
  }
  return [...new Set(notes)].slice(0, 5);
}

function determinePluginStatus(report: ScannerReport, reviewDecision: PassportScanDecision | null, driftChanged: boolean) {
  if (reviewDecision === "block") return "blocked";
  if (driftChanged && reviewDecision !== "trust") return "rereview-required";
  if (reviewDecision === "trust") return driftChanged ? "drift-trusted" : "trusted";
  if (reviewDecision === "review") return "reviewed";
  if (report.packageRecommendation.action === "block-package") return "dangerous-unreviewed";
  if (report.packageRecommendation.action === "review-before-trust") return "needs-review";
  return "unreviewed";
}

function determineSkillStatus(report: ScannerReport, reviewDecision: PassportScanDecision | null, driftChanged: boolean) {
  if (reviewDecision === "block") return "blocked";
  if (driftChanged && reviewDecision !== "trust") return "rereview-required";
  if (reviewDecision === "trust") return "trusted";
  if (reviewDecision === "review") return "reviewed";
  if (report.packageRecommendation.action === "block-package") return "dangerous-unreviewed";
  if (report.packageRecommendation.action === "review-before-trust") return "needs-review";
  return "unreviewed";
}

function computePriority(report: ScannerReport, status: string, driftChanged: boolean) {
  let priority = report.score;
  if (report.verdict === "dangerous") priority += 20;
  if (report.packageRecommendation.action === "block-package") priority += 14;
  if (report.packageRecommendation.action === "review-before-trust") priority += 8;
  if (driftChanged) priority += 10;
  if (status === "blocked") priority += 4;
  if (status === "rereview-required") priority += 8;
  if (hasCategory(report, "credential-harvest")) priority += 6;
  if (hasCategory(report, "suspicious-egress")) priority += 5;
  if (hasCategory(report, "persistence-autorun")) priority += 4;
  if (hasCategory(report, "manifest-lifecycle")) priority += 4;
  if (hasCategory(report, "remote-script-execution") || hasCategory(report, "bootstrap-installer")) priority += 4;
  return priority;
}

function buildItemBase(input: {
  kind: WorkspaceAuditKind;
  name: string;
  path: string;
  report: ScannerReport;
  reviewDecision: PassportScanDecision | null;
  baselineFingerprint: string | null;
  driftChanged: boolean;
  tracked: boolean;
  installedVersion: string | null;
  installedAt: string | null;
  status: string;
}) {
  const signals = countSignals(input.report);
  const remediationTargets = deriveRemediationTargets(input.report, input.kind);
  const notes = summarizeNotes(input.report, input.kind);
  const topRisks = input.report.topRisks.slice(0, 3).map((risk) => `${risk.title}: ${risk.summary}`);
  const recommendedActions = deriveRecommendedActions(input.report, input.status, input.kind, input.driftChanged);
  const priority = computePriority(input.report, input.status, input.driftChanged);

  return {
    id: `${input.kind}:${input.kind === "skill" ? input.name : input.name}`,
    kind: input.kind,
    name: input.name,
    path: input.path,
    fingerprint: input.report.fingerprint,
    targetKind: input.report.targetKind,
    status: input.status,
    verdict: input.report.verdict,
    recommendation: input.report.packageRecommendation.action,
    score: input.report.score,
    priority,
    signals,
    summary: input.report.summary,
    topRisks,
    remediationTargets,
    recommendedActions,
    reviewDecision: input.reviewDecision,
    baselineFingerprint: input.baselineFingerprint,
    driftChanged: input.driftChanged,
    tracked: input.tracked,
    installedVersion: input.installedVersion,
    installedAt: input.installedAt,
    notes
  } satisfies WorkspaceAuditItem;
}

async function buildPluginItem(record: PassportPluginInstallRecord, reviewStorePath: string) {
  try {
    const report = await scanPath(record.sourcePath);
    const currentReview = await getLatestScanReview(report.fingerprint, reviewStorePath);
    const driftChanged = report.fingerprint !== record.fingerprint;
    const status = determinePluginStatus(report, currentReview?.decision ?? null, driftChanged);

    return buildItemBase({
      kind: "plugin",
      name: record.pluginName,
      path: record.sourcePath,
      report,
      reviewDecision: currentReview?.decision ?? null,
      baselineFingerprint: record.fingerprint,
      driftChanged,
      tracked: true,
      installedVersion: null,
      installedAt: record.installedAt,
      status
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const missingReport: ScannerReport = {
      scannedPath: record.sourcePath,
      fingerprint: record.fingerprint,
      targetType: "file",
      targetKind: "unknown",
      fileCount: 0,
      filesScanned: [],
      verdict: "suspicious",
      score: 0,
      summary: `Plugin source could not be scanned: ${message}`,
      kindSensitiveNotes: [],
      findings: [],
      groupedFindings: [],
      topRisks: [],
      packageRecommendation: {
        action: "review-before-trust",
        reason: message
      },
      generatedAt: new Date().toISOString()
    };

    return buildItemBase({
      kind: "plugin",
      name: record.pluginName,
      path: record.sourcePath,
      report: missingReport,
      reviewDecision: null,
      baselineFingerprint: record.fingerprint,
      driftChanged: true,
      tracked: true,
      installedVersion: record.pluginId,
      installedAt: record.installedAt,
      status: "missing"
    });
  }
}

async function buildSkillItem(workspaceRoot: string, slug: string, lockEntry: { version?: string; installedAt?: number } | undefined, reviewStorePath: string) {
  const skillDir = resolve(workspaceRoot, "skills", slug);
  const origin = await readTrackedSkillOrigin(workspaceRoot, slug);
  const baseline = await getLatestSkillReviewRecord(slug, reviewStorePath);

  try {
    const report = await scanPath(skillDir);
    const currentReview = await getLatestScanReview(report.fingerprint, reviewStorePath);
    const driftChanged = baseline ? report.fingerprint !== baseline.fingerprint : false;
    const status = determineSkillStatus(report, currentReview?.decision ?? null, driftChanged);
    return buildItemBase({
      kind: "skill",
      name: slug,
      path: skillDir,
      report,
      reviewDecision: currentReview?.decision ?? null,
      baselineFingerprint: baseline?.fingerprint ?? null,
      driftChanged,
      tracked: Boolean(lockEntry || origin),
      installedVersion: origin?.installedVersion ?? lockEntry?.version ?? null,
      installedAt: origin?.installedAt ? new Date(origin.installedAt).toISOString() : (lockEntry?.installedAt ? new Date(lockEntry.installedAt).toISOString() : null),
      status
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const missingReport: ScannerReport = {
      scannedPath: skillDir,
      fingerprint: baseline?.fingerprint ?? `missing:${slug}`,
      targetType: "file",
      targetKind: "skill",
      fileCount: 0,
      filesScanned: [],
      verdict: "suspicious",
      score: 0,
      summary: `Skill source could not be scanned: ${message}`,
      kindSensitiveNotes: [],
      findings: [],
      groupedFindings: [],
      topRisks: [],
      packageRecommendation: {
        action: "review-before-trust",
        reason: message
      },
      generatedAt: new Date().toISOString()
    };

    return buildItemBase({
      kind: "skill",
      name: slug,
      path: skillDir,
      report: missingReport,
      reviewDecision: null,
      baselineFingerprint: baseline?.fingerprint ?? null,
      driftChanged: Boolean(baseline),
      tracked: Boolean(lockEntry || origin),
      installedVersion: origin?.installedVersion ?? lockEntry?.version ?? null,
      installedAt: origin?.installedAt ? new Date(origin.installedAt).toISOString() : (lockEntry?.installedAt ? new Date(lockEntry.installedAt).toISOString() : null),
      status: "missing"
    });
  }
}

function summarizeCounts(items: WorkspaceAuditItem[]): WorkspaceAuditCounts {
  return {
    total: items.length,
    plugins: items.filter((item) => item.kind === "plugin").length,
    skills: items.filter((item) => item.kind === "skill").length,
    dangerous: items.filter((item) => item.verdict === "dangerous").length,
    suspicious: items.filter((item) => item.verdict === "suspicious").length,
    blocked: items.filter((item) => item.status === "blocked").length,
    reviewRequired: items.filter((item) => item.status === "rereview-required" || item.status === "needs-review" || item.status === "dangerous-unreviewed").length,
    trusted: items.filter((item) => item.status === "trusted" || item.status === "drift-trusted").length,
    missing: items.filter((item) => item.status === "missing").length,
    drifted: items.filter((item) => item.driftChanged).length,
    credentialHeavy: items.filter((item) => item.remediationTargets.some((target) => /credential|wallet|ssh/i.test(target))).length,
    egressHeavy: items.filter((item) => item.remediationTargets.some((target) => /egress|webhook|firewall|proxy/i.test(target))).length,
    persistenceHeavy: items.filter((item) => item.remediationTargets.some((target) => /cron|startup|launchagents|shell profiles/i.test(target))).length,
    installChainHeavy: items.filter((item) => item.signals.categories.some((category) => ["remote-script-execution", "bootstrap-installer"].includes(category))).length,
    docChainHeavy: items.filter((item) => item.signals.documentation > 0 && item.signals.categories.some((category) => ["prompt-directed-shell-execution", "bootstrap-installer"].includes(category))).length,
    runtimeHeavy: items.filter((item) => item.signals.executable > 0 || item.signals.categories.some((category) => ["manifest-lifecycle", "staged-payload", "persistence-autorun"].includes(category))).length
  };
}

function summarizeNextSteps(items: WorkspaceAuditItem[]) {
  const nextSteps = new Set<string>();
  const highest = items.slice(0, 5);
  if (items.some((item) => item.remediationTargets.some((target) => /browser profiles and cookies/i.test(target)))) {
    nextSteps.add("Rotate browser/session credentials and re-authenticated tokens.");
  }
  if (items.some((item) => item.remediationTargets.some((target) => /SSH keys/i.test(target)))) {
    nextSteps.add("Rotate SSH keys and inspect authorized_keys changes.");
  }
  if (items.some((item) => item.remediationTargets.some((target) => /cloud credentials/i.test(target)))) {
    nextSteps.add("Rotate cloud/API credentials and verify access logs.");
  }
  if (items.some((item) => item.remediationTargets.some((target) => /wallets/i.test(target)))) {
    nextSteps.add("Review and rotate wallets or seed phrases on affected hosts.");
  }
  if (items.some((item) => item.remediationTargets.some((target) => /cron jobs and startup services|shell profiles/i.test(target)))) {
    nextSteps.add("Audit persistence surfaces such as cron, LaunchAgents, systemd, and shell profiles.");
  }
  if (items.some((item) => item.status === "rereview-required")) {
    nextSteps.add("Re-review drifted artifacts before any update or enable action.");
  }
  if (highest.length) {
    nextSteps.add(`Triage the top ${highest.length} items first: ${highest.map((item) => item.name).join(", ")}.`);
  }
  return [...nextSteps];
}

export async function buildWorkspaceAudit(input?: WorkspaceAuditOptions): Promise<WorkspaceAuditResult> {
  const workspaceRoot = resolveWorkspaceRoot(input?.workspaceRoot);
  const ledgerDir = resolveLedgerDir(workspaceRoot, input?.ledgerDir);
  const reviewStorePath = resolve(ledgerDir, "scan-reviews.json");
  const pluginInstallStorePath = resolve(ledgerDir, "plugin-installs.json");
  const skillReviewPath = skillReviewStorePath(ledgerDir);
  const items: WorkspaceAuditItem[] = [];

  if (input?.includePlugins !== false) {
    const latestInstalls = latestInstallByPluginId(await listPluginInstalls({ storePath: pluginInstallStorePath }));
    for (const record of latestInstalls) {
      items.push(await buildPluginItem(record, reviewStorePath));
    }
  }

  if (input?.includeSkills !== false) {
    const lock = await readTrackedSkillLock(workspaceRoot);
    const slugs = Object.keys(lock.skills).sort();
    for (const slug of slugs) {
      items.push(await buildSkillItem(workspaceRoot, slug, lock.skills[slug], skillReviewPath));
    }
  }

  items.sort((a, b) => b.priority - a.priority || a.name.localeCompare(b.name));
  const highRiskItems = items.slice(0, input?.maxItems ?? 10);
  return {
    workspaceRoot,
    ledgerDir,
    scannedAt: new Date().toISOString(),
    counts: summarizeCounts(items),
    items,
    highRiskItems,
    nextSteps: summarizeNextSteps(highRiskItems)
  };
}

export function formatWorkspaceAudit(result: WorkspaceAuditResult) {
  const lines = [
    "Workspace audit:",
    `- workspace root: ${result.workspaceRoot}`,
    `- items: ${result.counts.total}`,
    `- plugins: ${result.counts.plugins}`,
    `- skills: ${result.counts.skills}`,
    `- dangerous: ${result.counts.dangerous}`,
    `- review required: ${result.counts.reviewRequired}`,
    `- drifted: ${result.counts.drifted}`
  ];

  if (result.highRiskItems.length) {
    lines.push("", "Top items:");
    for (const item of result.highRiskItems) {
      lines.push(`- ${item.kind}:${item.name} [${item.status}] score=${item.score} verdict=${item.verdict}`);
      lines.push(`  ${item.summary}`);
      if (item.remediationTargets.length) {
        lines.push(`  remediation: ${item.remediationTargets.join(", ")}`);
      }
    }
  }

  if (result.nextSteps.length) {
    lines.push("", "Next steps:");
    for (const step of result.nextSteps) {
      lines.push(`- ${step}`);
    }
  }

  return lines.join("\n");
}
