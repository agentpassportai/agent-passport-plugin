import type { PassportScanDecision } from "./review.js";
import type { ScannerPackageRecommendation, ScannerReport, ScannerVerdict } from "./scanner/types.js";

export type SkillArtifactSourceKind = "local-path" | "remote-or-preinstall";

export type SkillTrustTier =
  | "unsupported-remote"
  | "quarantined"
  | "review-required"
  | "reviewed"
  | "trusted"
  | "blocked";

export type SkillTrustTierResult = {
  tier: SkillTrustTier;
  reason: string;
  requiresManualReview: boolean;
};

export type SkillProvenanceRecord = {
  sourceKind: SkillArtifactSourceKind;
  sourcePath: string;
  stagedPath: string | null;
  scannedPath: string | null;
  fingerprint: string | null;
  verdict: ScannerVerdict | null;
  recommendationAction: ScannerPackageRecommendation["action"] | null;
  reviewDecision: PassportScanDecision | null;
  trustTier: SkillTrustTier;
  reason: string;
  limitations: string[];
};

export function explainSkillInspectionLimitations(sourceKind: SkillArtifactSourceKind) {
  if (sourceKind === "remote-or-preinstall") {
    return [
      "Passport can only stage and scan local filesystem skill artifacts in this helper.",
      "Remote marketplace fetches, git sources, and other preinstall flows must be materialized locally before inspection."
    ];
  }

  return [
    "Passport stages the local artifact into a quarantine review area before scanning it.",
    "Trust still depends on operator review and later command/CLI integration."
  ];
}

export function buildSkillTrustTier(input: {
  sourceKind: SkillArtifactSourceKind;
  verdict?: ScannerVerdict | null;
  recommendationAction?: ScannerPackageRecommendation["action"] | null;
  reviewDecision?: PassportScanDecision | null;
}): SkillTrustTierResult {
  if (input.sourceKind !== "local-path") {
    return {
      tier: "unsupported-remote",
      reason: "This helper only stages and scans local filesystem skill artifacts.",
      requiresManualReview: true
    };
  }

  if (input.reviewDecision === "block") {
    return {
      tier: "blocked",
      reason: "An operator has explicitly blocked this skill fingerprint.",
      requiresManualReview: true
    };
  }

  if (input.reviewDecision === "trust") {
    return {
      tier: "trusted",
      reason: "An operator has explicitly trusted this skill fingerprint.",
      requiresManualReview: false
    };
  }

  if (input.reviewDecision === "review") {
    return {
      tier: "reviewed",
      reason: "An operator review exists, but the fingerprint is not explicitly trusted yet.",
      requiresManualReview: true
    };
  }

  if (input.recommendationAction === "block-package" || input.verdict === "dangerous") {
    return {
      tier: "review-required",
      reason: "The scanner recommends blocking this artifact until it is reviewed.",
      requiresManualReview: true
    };
  }

  if (input.recommendationAction === "review-before-trust") {
    return {
      tier: "review-required",
      reason: "The scanner requires review before trust for this artifact.",
      requiresManualReview: true
    };
  }

  return {
    tier: "quarantined",
    reason: "The local artifact has been staged and scanned, but no explicit trust decision has been recorded yet.",
    requiresManualReview: true
  };
}

export function buildSkillProvenanceRecord(input: {
  sourceKind: SkillArtifactSourceKind;
  sourcePath: string;
  stagedPath?: string | null;
  scan?: ScannerReport | null;
  trustTier: SkillTrustTierResult;
  reviewDecision?: PassportScanDecision | null;
}): SkillProvenanceRecord {
  return {
    sourceKind: input.sourceKind,
    sourcePath: input.sourcePath,
    stagedPath: input.stagedPath ?? null,
    scannedPath: input.scan?.scannedPath ?? input.stagedPath ?? null,
    fingerprint: input.scan?.fingerprint ?? null,
    verdict: input.scan?.verdict ?? null,
    recommendationAction: input.scan?.packageRecommendation.action ?? null,
    reviewDecision: input.reviewDecision ?? null,
    trustTier: input.trustTier.tier,
    reason: input.trustTier.reason,
    limitations: explainSkillInspectionLimitations(input.sourceKind)
  };
}
