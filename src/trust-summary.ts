import type { PassportScanDecision } from "./review.js";

export type ArtifactTrustTier = "blocked" | "trusted" | "reviewed" | "review-required" | "unreviewed";
export type ArtifactKind = "plugin" | "skill";

export type ArtifactTrustSummary = {
  tier: ArtifactTrustTier;
  reason: string;
  provenance: string;
  driftChanged: boolean;
  reviewBoundFingerprint: string | null;
};

function buildProvenance(input: {
  artifactKind: ArtifactKind;
  registry?: string | null;
  sourcePath?: string | null;
}) {
  if (input.artifactKind === "plugin") {
    return input.sourcePath
      ? `Local plugin source recorded in Passport install ledger: ${input.sourcePath}`
      : "Local plugin source recorded in Passport install ledger.";
  }

  if (input.registry?.trim()) {
    return `Installed workspace skill from registry ${input.registry.trim()} scanned from local filesystem.`;
  }

  return "Installed workspace skill scanned from local filesystem.";
}

export function buildArtifactTrustSummary(input: {
  artifactKind: ArtifactKind;
  reviewDecision?: PassportScanDecision | null;
  recommendationAction?: string | null;
  verdict?: string | null;
  driftChanged?: boolean;
  fingerprint?: string | null;
  registry?: string | null;
  sourcePath?: string | null;
}): ArtifactTrustSummary {
  const driftChanged = Boolean(input.driftChanged);
  const provenance = buildProvenance(input);
  const reviewBoundFingerprint = input.fingerprint ?? null;

  if (input.reviewDecision === "block") {
    return {
      tier: "blocked",
      reason: "An operator has explicitly blocked this fingerprint.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  if (driftChanged && input.reviewDecision !== "trust") {
    return {
      tier: "review-required",
      reason: "The current fingerprint drifted and needs explicit re-review before trust.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  if (input.reviewDecision === "trust") {
    return {
      tier: "trusted",
      reason: "An operator has explicitly trusted this fingerprint.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  if (input.reviewDecision === "review") {
    return {
      tier: "reviewed",
      reason: "An operator review exists, but this fingerprint is not explicitly trusted.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  if (input.recommendationAction === "block-package" || input.verdict === "dangerous") {
    return {
      tier: "review-required",
      reason: "The scanner recommends blocking this artifact until a human reviews it.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  if (input.recommendationAction === "review-before-trust") {
    return {
      tier: "review-required",
      reason: "The scanner requires review before this artifact should be trusted.",
      provenance,
      driftChanged,
      reviewBoundFingerprint
    };
  }

  return {
    tier: "unreviewed",
    reason: "The artifact is scanned locally, but no explicit review or trust decision is recorded.",
    provenance,
    driftChanged,
    reviewBoundFingerprint
  };
}
