import { randomBytes } from "node:crypto";
import { cp, mkdir, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { scanPath } from "./scanner/index.js";
import type { ScannerReport } from "./scanner/types.js";
import { buildSkillProvenanceRecord, buildSkillTrustTier, explainSkillInspectionLimitations, type SkillArtifactSourceKind, type SkillProvenanceRecord, type SkillTrustTierResult } from "./provenance.js";
import type { PassportScanDecision } from "./review.js";

export type SkillInspectionInput = {
  sourcePath: string;
  label?: string;
  quarantineRoot?: string;
  maxFiles?: number;
  maxBytes?: number;
  reviewDecision?: PassportScanDecision | null;
};

export type SkillInspectionStageResult = {
  sourcePath: string;
  absoluteSourcePath: string | null;
  sourceKind: SkillArtifactSourceKind;
  quarantineRoot: string;
  quarantinePath: string | null;
  stagedPath: string | null;
  supported: boolean;
  copied: boolean;
  reason: string;
  limitations: string[];
};

export type SkillInspectionResult = {
  stage: SkillInspectionStageResult;
  scan: ScannerReport | null;
  provenance: SkillProvenanceRecord;
  trustTier: SkillTrustTierResult;
  summary: string;
};

function getLedgerDir() {
  return process.env.AGENT_PASSPORT_LEDGER_DIR || resolve(process.cwd(), ".openclaw/agent-passport");
}

function getSkillInspectionRoot() {
  return resolve(getLedgerDir(), "skill-inspection");
}

function buildQuarantineRoot(input?: { quarantineRoot?: string }) {
  return resolve(input?.quarantineRoot ?? getSkillInspectionRoot(), "quarantine");
}

function buildReviewLabel(value: string) {
  const base = value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return base || "skill";
}

function expandLocalPath(path: string) {
  if (!path.startsWith("~")) return path;
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (!home) return path;
  if (path === "~") return home;
  if (path.startsWith("~/")) return resolve(home, path.slice(2));
  return path;
}

function classifySourcePath(sourcePath: string): SkillArtifactSourceKind {
  const trimmed = sourcePath.trim();
  if (!trimmed) return "remote-or-preinstall";
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(trimmed)) return "remote-or-preinstall";
  if (/^(?:git@|git\+|npm:|workspace:)/i.test(trimmed)) return "remote-or-preinstall";
  if (/^[a-zA-Z]:[\\/]/.test(trimmed) || /^\\\\/.test(trimmed)) return "local-path";
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("../") || trimmed.startsWith("~")) return "local-path";
  return "remote-or-preinstall";
}

function describeUnsupportedSource(sourcePath: string, sourceKind: SkillArtifactSourceKind) {
  if (sourceKind === "local-path") {
    return "Local skill artifact path is available for staging.";
  }

  if (/^file:\/\//i.test(sourcePath)) {
    return "This helper does not treat file:// URLs as a staging input. Materialize the local path first.";
  }

  return "Remote marketplace, git, and preinstall sources must be materialized as a local filesystem path before inspection.";
}

async function stageLocalArtifact(input: {
  sourcePath: string;
  quarantineRoot: string;
  label: string;
}) {
  const absoluteSourcePath = resolve(expandLocalPath(input.sourcePath));
  const info = await stat(absoluteSourcePath);
  const runId = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(4).toString("hex")}`;
  const reviewLabel = buildReviewLabel(input.label || basename(absoluteSourcePath));
  const quarantinePath = resolve(input.quarantineRoot, `${reviewLabel}-${runId}`, basename(absoluteSourcePath));

  await mkdir(resolve(quarantinePath, ".."), { recursive: true });
  await cp(absoluteSourcePath, quarantinePath, {
    recursive: info.isDirectory(),
    dereference: false,
    preserveTimestamps: true,
    force: true
  });

  return {
    sourcePath: input.sourcePath,
    absoluteSourcePath,
    sourceKind: "local-path" as const,
    quarantineRoot: input.quarantineRoot,
    quarantinePath: resolve(quarantinePath, ".."),
    stagedPath: quarantinePath,
    supported: true,
    copied: true,
    reason: "Local skill artifact staged into a quarantine review area before scanning.",
    limitations: explainSkillInspectionLimitations("local-path")
  };
}

export async function stageSkillArtifact(input: {
  sourcePath: string;
  label?: string;
  quarantineRoot?: string;
}): Promise<SkillInspectionStageResult> {
  const sourceKind = classifySourcePath(input.sourcePath);
  const quarantineRoot = buildQuarantineRoot(input);

  if (sourceKind !== "local-path") {
    return {
      sourcePath: input.sourcePath,
      absoluteSourcePath: null,
      sourceKind,
      quarantineRoot,
      quarantinePath: null,
      stagedPath: null,
      supported: false,
      copied: false,
      reason: describeUnsupportedSource(input.sourcePath, sourceKind),
      limitations: explainSkillInspectionLimitations(sourceKind)
    };
  }

  try {
    return await stageLocalArtifact({
      sourcePath: input.sourcePath,
      quarantineRoot,
      label: input.label ?? basename(expandLocalPath(input.sourcePath))
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      sourcePath: input.sourcePath,
      absoluteSourcePath: resolve(expandLocalPath(input.sourcePath)),
      sourceKind,
      quarantineRoot,
      quarantinePath: null,
      stagedPath: null,
      supported: false,
      copied: false,
      reason: `Failed to stage local skill artifact: ${message}`,
      limitations: explainSkillInspectionLimitations(sourceKind)
    };
  }
}

export async function inspectSkillArtifact(input: SkillInspectionInput): Promise<SkillInspectionResult> {
  const stage = await stageSkillArtifact({
    sourcePath: input.sourcePath,
    label: input.label,
    quarantineRoot: input.quarantineRoot
  });

  if (!stage.supported || !stage.stagedPath) {
    const trustTier = buildSkillTrustTier({
      sourceKind: stage.sourceKind,
      reviewDecision: input.reviewDecision ?? null
    });
    const provenance = buildSkillProvenanceRecord({
      sourceKind: stage.sourceKind,
      sourcePath: input.sourcePath,
      stagedPath: stage.stagedPath,
      scan: null,
      trustTier,
      reviewDecision: input.reviewDecision ?? null
    });

    return {
      stage,
      scan: null,
      provenance,
      trustTier,
      summary: stage.reason
    };
  }

  const scan = await scanPath(stage.stagedPath, {
    maxFiles: input.maxFiles,
    maxBytes: input.maxBytes
  });

  const trustTier = buildSkillTrustTier({
    sourceKind: stage.sourceKind,
    verdict: scan.verdict,
    recommendationAction: scan.packageRecommendation.action,
    reviewDecision: input.reviewDecision ?? null
  });

  const provenance = buildSkillProvenanceRecord({
    sourceKind: stage.sourceKind,
    sourcePath: input.sourcePath,
    stagedPath: stage.stagedPath,
    scan,
    trustTier,
    reviewDecision: input.reviewDecision ?? null
  });

  return {
    stage,
    scan,
    provenance,
    trustTier,
    summary: `${scan.targetKind} staged at ${stage.stagedPath} and scanned with recommendation ${scan.packageRecommendation.action}.`
  };
}
