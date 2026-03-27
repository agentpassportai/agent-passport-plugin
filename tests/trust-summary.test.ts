import assert from "node:assert/strict";
import test from "node:test";

import { buildArtifactTrustSummary } from "../src/trust-summary.js";

test("buildArtifactTrustSummary marks drifted untrusted artifacts as review-required", () => {
  const summary = buildArtifactTrustSummary({
    artifactKind: "plugin",
    reviewDecision: "review",
    recommendationAction: "allow",
    driftChanged: true,
    fingerprint: "abc123",
    sourcePath: "/tmp/plugin"
  });

  assert.equal(summary.tier, "review-required");
  assert.match(summary.reason, /re-review/i);
  assert.match(summary.provenance, /install ledger/i);
  assert.equal(summary.reviewBoundFingerprint, "abc123");
});

test("buildArtifactTrustSummary preserves trusted installed skill provenance", () => {
  const summary = buildArtifactTrustSummary({
    artifactKind: "skill",
    reviewDecision: "trust",
    recommendationAction: "allow",
    fingerprint: "skill-fp",
    registry: "clawhub"
  });

  assert.equal(summary.tier, "trusted");
  assert.match(summary.provenance, /registry clawhub/i);
  assert.equal(summary.reviewBoundFingerprint, "skill-fp");
});

test("buildArtifactTrustSummary escalates dangerous unreviewed artifacts", () => {
  const summary = buildArtifactTrustSummary({
    artifactKind: "skill",
    verdict: "dangerous",
    recommendationAction: "block-package"
  });

  assert.equal(summary.tier, "review-required");
  assert.match(summary.reason, /scanner recommends blocking/i);
});
