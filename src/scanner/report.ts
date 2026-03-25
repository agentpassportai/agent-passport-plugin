import type { ScannerExploitability, ScannerFinding, ScannerFindingGroup, ScannerPackageRecommendation, ScannerRecommendedAction, ScannerReport, ScannerSeverity, ScannerTargetKind, ScannerTopRisk, ScannerVerdict } from "./types.js";
import { severityWeight } from "./rules/shared.js";

function highestSeverity(findings: ScannerFinding[]): ScannerSeverity | null {
  if (findings.some((finding) => finding.severity === "high")) return "high";
  if (findings.some((finding) => finding.severity === "medium")) return "medium";
  if (findings.some((finding) => finding.severity === "low")) return "low";
  return null;
}

function dedupe<T>(values: T[]) {
  return Array.from(new Set(values));
}

function findingPriority(finding: ScannerFinding) {
  const severityRank = finding.severity === "high" ? 3 : finding.severity === "medium" ? 2 : 1;
  const signalRank = finding.signalType === "executable" ? 3 : finding.signalType === "config" ? 2 : 1;
  const categoryBonus = finding.category === "manifest-lifecycle"
    ? 3
    : finding.category === "bootstrap-installer"
      ? 3
    : finding.category === "staged-payload" || finding.category === "persistence-autorun"
      ? 2
    : 0;
  return severityRank * 10 + signalRank * 3 + categoryBonus;
}

function findingGroupKey(finding: ScannerFinding) {
  const filePath = finding.evidence[0]?.filePath ?? finding.id;
  if (filePath.endsWith("package.json") && ["manifest-lifecycle", "remote-script-execution", "bootstrap-installer"].includes(finding.category)) {
    return `${filePath}:install-chain`;
  }
  if ((filePath.endsWith(".sh") || filePath.endsWith(".bash") || filePath.endsWith(".zsh") || filePath.endsWith(".ps1"))
    && ["remote-script-execution", "bootstrap-installer"].includes(finding.category)) {
    return `${filePath}:installer-chain`;
  }
  if (["staged-payload", "persistence-autorun"].includes(finding.category)) {
    return `${filePath}:payload-persistence`;
  }
  return `${filePath}:${finding.category}`;
}

function selectRepresentativeFinding(findings: ScannerFinding[]) {
  return [...findings].sort((a, b) => findingPriority(b) - findingPriority(a))[0];
}

function summarizeGroup(findings: ScannerFinding[]) {
  const categories = dedupe(findings.map((finding) => finding.category));
  const signalTypes = dedupe(findings.map((finding) => finding.signalType));
  const filePaths = dedupe(findings.flatMap((finding) => finding.evidence.map((item) => item.filePath)));
  const primaryPath = filePaths[0] ?? "unknown file";

  if (primaryPath.endsWith("package.json") && categories.includes("manifest-lifecycle")) {
    return {
      title: "Suspicious lifecycle hook chain",
      summary: `${primaryPath} contains package lifecycle hooks that run suspicious install-time commands.`
    };
  }
  if (categories.includes("bootstrap-installer") && filePaths.some((filePath) => /\.(?:md|markdown|txt)$/i.test(filePath) || /(?:README|SKILL)\b/i.test(filePath))) {
    return {
      title: "Documentation-driven install chain",
      summary: `${primaryPath} uses install, setup, or bootstrap instructions to push executable shell steps into the trust flow.`
    };
  }
  if (categories.includes("remote-script-execution") && categories.includes("bootstrap-installer")) {
    return {
      title: "Installer executes remote code",
      summary: `${primaryPath} includes installer behavior that downloads or runs code directly.`
    };
  }
  if (categories.includes("staged-payload") && categories.includes("persistence-autorun")) {
    return {
      title: "Staged payload with persistence",
      summary: `${primaryPath} fetches or stages a payload, then tries to keep it resident.`
    };
  }
  if (categories.includes("plugin-manifest-risk")) {
    return {
      title: "Plugin manifest weakens trust defaults",
      summary: `${primaryPath} sets permissive defaults on risky plugin surfaces or weakens audit posture.`
    };
  }
  if (categories.includes("credential-harvest")) {
    if (categories.includes("suspicious-egress")) {
      return {
        title: "Credential harvest with exfiltration path",
        summary: `${primaryPath} references credential-bearing material and also points at suspicious outbound destinations.`
      };
    }
    return {
      title: "Credential-bearing material referenced",
      summary: `${primaryPath} references secrets or credential-bearing material that needs justification.`
    };
  }
  if (categories.includes("suspicious-egress")) {
    return {
      title: "Suspicious outbound destination referenced",
      summary: `${primaryPath} references suspicious outbound destinations or shell-style egress.`
    };
  }
  if (categories.includes("prompt-directed-shell-execution")) {
    return {
      title: "Operator prompted to run shell commands",
      summary: `${primaryPath} instructs the operator to run shell commands manually.`
    };
  }

  return {
    title: "Suspicious package pattern group",
    summary: `${primaryPath} contains related findings: ${categories.join(", ")}.`
  };
}

function inferExploitability(findings: ScannerFinding[]): { exploitability: ScannerExploitability; reason: string } {
  const categories = dedupe(findings.map((finding) => finding.category));
  const signalTypes = dedupe(findings.map((finding) => finding.signalType));

  if (signalTypes.every((signalType) => signalType === "documentation")) {
    if (categories.includes("prompt-directed-shell-execution") || categories.includes("bootstrap-installer") || categories.includes("staged-payload") || categories.includes("persistence-autorun")) {
      return {
        exploitability: "operator-assisted",
        reason: "The evidence relies on operator instructions or documented install-time behavior rather than automatic execution."
      };
    }
    return {
      exploitability: "reference-only",
      reason: "The evidence is documentation-only and does not appear to auto-execute on its own."
    };
  }

  if (signalTypes.includes("executable")) {
    return {
      exploitability: "auto-exec",
      reason: "The evidence includes executable behavior that can run directly during install or script execution."
    };
  }

  if (categories.includes("manifest-lifecycle")) {
    return {
      exploitability: "auto-exec",
      reason: "The package manifest wires risky commands into lifecycle hooks that can run automatically."
    };
  }

  if (categories.includes("plugin-manifest-risk")) {
    return {
      exploitability: "operator-assisted",
      reason: "The plugin manifest weakens trust defaults, but the risk comes from permissive governance posture rather than automatic payload execution."
    };
  }

  if (signalTypes.includes("config")) {
    return {
      exploitability: "operator-assisted",
      reason: "The evidence comes from configuration or manifest wiring that still depends on how the artifact is installed or trusted."
    };
  }

  return {
    exploitability: "operator-assisted",
    reason: "The evidence suggests risky behavior, but it likely still depends on operator action or follow-on execution."
  };
}

function inferRecommendedAction(findings: ScannerFinding[], exploitability: ScannerExploitability, targetKind: ScannerTargetKind): { recommendedAction: ScannerRecommendedAction; reason: string } {
  const categories = dedupe(findings.map((finding) => finding.category));
  const hasHighSeverity = findings.some((finding) => finding.severity === "high");
  const hasInstructionalInstallRisk = categories.includes("prompt-directed-shell-execution")
    || categories.includes("remote-script-execution")
    || categories.includes("bootstrap-installer");
  const hasPluginRuntimeRisk = categories.includes("manifest-lifecycle")
    || categories.includes("staged-payload")
    || categories.includes("persistence-autorun");
  const hasPluginGovernanceRisk = categories.includes("plugin-manifest-risk");

  if (exploitability === "auto-exec") {
    return {
      recommendedAction: "block",
      reason: targetKind === "plugin"
        ? "This plugin pattern can execute automatically through manifest or packaged runtime behavior, so blocking by default is safest."
        : "This pattern can execute automatically during install or script execution, so blocking by default is safest."
    };
  }

  if (exploitability === "operator-assisted") {
    if (targetKind === "skill" && hasInstructionalInstallRisk) {
      return {
        recommendedAction: "review",
        reason: "This skill relies on operator action, but the instructions are risky enough that it should be reviewed before trust."
      };
    }

    if (targetKind === "plugin" && hasInstructionalInstallRisk) {
      return {
        recommendedAction: "review",
        reason: "This plugin is being introduced through risky operator-run setup instructions, so it should be reviewed before trust even without packaged runtime execution."
      };
    }

    if (targetKind === "plugin" && hasPluginGovernanceRisk) {
      return {
        recommendedAction: "review",
        reason: "This plugin ships permissive trust defaults or weak audit defaults, so it should be reviewed before trust even without an auto-exec chain."
      };
    }

    return {
      recommendedAction: hasHighSeverity ? "review" : "monitor",
      reason: hasHighSeverity
        ? "This pattern depends on operator action, but the risk is strong enough to require review before trust."
        : "This pattern depends on operator action and can be monitored unless other signals escalate it."
    };
  }

  if (categories.includes("credential-harvest") || categories.includes("suspicious-egress")) {
    return {
      recommendedAction: "review",
      reason: targetKind === "skill"
        ? "Documentation-only references to secrets or suspicious destinations in a skill still deserve review before trust."
        : "Documentation-only references to secrets or suspicious destinations still deserve review before trust."
    };
  }

  if (targetKind === "plugin" && hasPluginRuntimeRisk) {
    return {
      recommendedAction: "review",
      reason: "This plugin shows packaged runtime or persistence signals that should be reviewed before trust, even without a clean auto-exec chain."
    };
  }

  return {
    recommendedAction: "monitor",
    reason: "This evidence is low-friction reference material and can be monitored unless stronger signals appear."
  };
}

function buildFindingGroups(findings: ScannerFinding[], targetKind: ScannerTargetKind): ScannerFindingGroup[] {
  const groups = new Map<string, ScannerFinding[]>();
  for (const finding of findings) {
    const key = findingGroupKey(finding);
    const bucket = groups.get(key) ?? [];
    bucket.push(finding);
    groups.set(key, bucket);
  }

  return Array.from(groups.entries())
    .map(([id, groupFindings]) => {
      const representative = selectRepresentativeFinding(groupFindings);
      const summary = summarizeGroup(groupFindings);
      const exploitability = inferExploitability(groupFindings);
      const recommendedAction = inferRecommendedAction(groupFindings, exploitability.exploitability, targetKind);
      return {
        id,
        title: summary.title,
        summary: summary.summary,
        categories: dedupe(groupFindings.map((finding) => finding.category)),
        signalTypes: dedupe(groupFindings.map((finding) => finding.signalType)),
        severity: representative.severity,
        exploitability: exploitability.exploitability,
        exploitabilityReason: exploitability.reason,
        recommendedAction: recommendedAction.recommendedAction,
        recommendedActionReason: recommendedAction.reason,
        representativeFindingId: representative.id,
        findingIds: groupFindings.map((finding) => finding.id),
        filePaths: dedupe(groupFindings.flatMap((finding) => finding.evidence.map((item) => item.filePath)))
      } satisfies ScannerFindingGroup;
    })
    .sort((a, b) => {
      const aRep = findings.find((finding) => finding.id === a.representativeFindingId);
      const bRep = findings.find((finding) => finding.id === b.representativeFindingId);
      return findingPriority(bRep ?? findings[0]!) - findingPriority(aRep ?? findings[0]!);
    });
}

function buildTopRisks(groupedFindings: ScannerFindingGroup[], limit = 3): ScannerTopRisk[] {
  return groupedFindings.slice(0, limit).map((group) => ({
    title: group.title,
    summary: group.summary,
    severity: group.severity,
    signalTypes: group.signalTypes,
    categories: group.categories,
    filePaths: group.filePaths,
    exploitability: group.exploitability,
    exploitabilityReason: group.exploitabilityReason,
    recommendedAction: group.recommendedAction,
    recommendedActionReason: group.recommendedActionReason,
    groupId: group.id
  }));
}

function kindLabel(targetKind: ScannerTargetKind) {
  if (targetKind === "skill") return "skill";
  if (targetKind === "plugin") return "plugin";
  if (targetKind === "package") return "package";
  if (targetKind === "hybrid") return "skill/package hybrid";
  return "artifact";
}

function safeSummary(targetKind: ScannerTargetKind) {
  if (targetKind === "skill") {
    return "No high-signal poisoned-skill indicators were found in the scanned files.";
  }
  if (targetKind === "plugin") {
    return "No high-signal poisoned-plugin indicators were found in the scanned files.";
  }
  if (targetKind === "hybrid") {
    return "No high-signal poisoned skill or plugin indicators were found in the scanned files.";
  }
  return "No high-signal poisoned-package indicators were found in the scanned files.";
}

function buildPackageRecommendation(groupedFindings: ScannerFindingGroup[], verdict: ScannerVerdict, targetKind: ScannerTargetKind): ScannerPackageRecommendation {
  const label = kindLabel(targetKind);

  if (verdict === "safe" || !groupedFindings.length) {
    return {
      action: "allow",
      reason: `No high-signal poisoned-${label.replace("/", " or ")} indicators were found, so this ${label} can be allowed.`
    };
  }

  const actions = groupedFindings.map((group) => group.recommendedAction);
  const blockingGroups = groupedFindings.filter((group) => group.recommendedAction === "block");
  const reviewGroups = groupedFindings.filter((group) => group.recommendedAction === "review");
  const monitorGroups = groupedFindings.filter((group) => group.recommendedAction === "monitor");
  const referenceOnlyReview = reviewGroups.length > 0 && reviewGroups.every((group) => group.exploitability === "reference-only");
  const operatorOnly = groupedFindings.length > 0 && groupedFindings.every((group) => group.exploitability === "operator-assisted");

  if (blockingGroups.length) {
    const blockingTitles = blockingGroups
      .slice(0, 2)
      .map((group) => group.title.toLowerCase());
    return {
      action: "block-package",
      reason: `At least one high-risk group should be blocked by default for this ${label} (${blockingTitles.join(", ")}).`
    };
  }

  if (referenceOnlyReview && verdict !== "dangerous") {
    const reviewTitles = reviewGroups
      .slice(0, 2)
      .map((group) => group.title.toLowerCase());
    return {
      action: "review-before-trust",
      reason: `This ${label} mainly contains documentation or reference-only risk signals, so it should be reviewed before trust (${reviewTitles.join(", ")}).`
    };
  }

  if (reviewGroups.length) {
    const reviewTitles = reviewGroups
      .slice(0, 2)
      .map((group) => group.title.toLowerCase());
    return {
      action: "review-before-trust",
      reason: `This ${label} has findings that need human review before trust (${reviewTitles.join(", ")}).`
    };
  }

  if (operatorOnly || monitorGroups.length) {
    return {
      action: "monitor",
      reason: `Current findings for this ${label} are operator-dependent or low-friction, so monitoring is enough unless stronger signals appear.`
    };
  }

  return {
    action: "review-before-trust",
    reason: `This ${label} is not clean enough to allow automatically, so review it before trust.`
  };
}

function buildKindSensitiveNotes(targetKind: ScannerTargetKind, groupedFindings: ScannerFindingGroup[]): string[] {
  const categories = new Set(groupedFindings.flatMap((group) => group.categories));
  const notes: string[] = [];

  if (targetKind === "skill") {
    notes.push("Skills have a larger operator-trust surface. Install steps, bootstrap commands, and copy-paste shell instructions matter more here than they would in a pure library.");
    if (categories.has("prompt-directed-shell-execution") || categories.has("remote-script-execution") || categories.has("bootstrap-installer")) {
      notes.push("This skill includes instruction or install-chain signals. Treat README or SKILL.md shell steps as part of the risk surface, not just documentation.");
    }
  } else if (targetKind === "plugin") {
    notes.push("Plugins have a larger runtime-trust surface. Packaged code, manifests, hooks, and persistence behavior matter more than README-only language.");
    if (categories.has("manifest-lifecycle") || categories.has("staged-payload") || categories.has("persistence-autorun")) {
      notes.push("This plugin shows packaged runtime or persistence-style signals. Review what can execute automatically, not just what the docs say.");
    }
    if (categories.has("plugin-manifest-risk")) {
      notes.push("This plugin manifest weakens trust or audit defaults. Review the governance posture it ships with, not just the code paths it exposes.");
    }
  } else if (targetKind === "package") {
    notes.push("Packages are judged mainly on lifecycle hooks, bootstrap behavior, staged payloads, and whether code can run automatically during install or setup.");
  } else if (targetKind === "hybrid") {
    notes.push("This artifact looks like a hybrid. Review both skill-style operator instructions and plugin/package-style runtime execution paths.");
  } else {
    notes.push("Artifact kind is unknown. Treat both operator instructions and packaged runtime behavior as part of the trust surface.");
  }

  if (!groupedFindings.length) {
    notes.push("No grouped risk narratives were found for this artifact type in the current scan.");
  } else if (groupedFindings.some((group) => group.recommendedAction === "block")) {
    notes.push("At least one grouped risk narrative reached a block-level recommendation for this artifact type.");
  } else if (groupedFindings.some((group) => group.recommendedAction === "review")) {
    notes.push("The strongest current signal is review-before-trust, not immediate blocking.");
  }

  return notes.slice(0, 3);
}

function findingScore(finding: ScannerFinding, targetKind: ScannerTargetKind) {
  let score = finding.category === "plugin-manifest-risk"
    ? (finding.severity === "high" ? 4 : finding.severity === "medium" ? 2 : 1)
    : severityWeight(finding.severity);
  if (finding.signalType === "documentation") {
    score = Math.max(1, Math.ceil(score / 2));
  }

  if (
    targetKind === "skill"
    && finding.signalType === "documentation"
    && ["prompt-directed-shell-execution", "remote-script-execution"].includes(finding.category)
  ) {
    score += 1;
  }

  if (
    targetKind === "plugin"
    && ["manifest-lifecycle", "staged-payload", "persistence-autorun"].includes(finding.category)
  ) {
    score += 1;
  }

  return Math.min(10, score);
}

function hasDangerousExecutionSignal(findings: ScannerFinding[]) {
  return findings.some((finding) => (
    finding.severity === "high"
    && finding.signalType !== "documentation"
    && finding.category !== "plugin-manifest-risk"
  ));
}

function signalCount(findings: ScannerFinding[], signalType: ScannerFinding["signalType"]) {
  return findings.filter((finding) => finding.signalType === signalType).length;
}

function allDocumentationSignals(findings: ScannerFinding[]) {
  return findings.length > 0 && findings.every((finding) => finding.signalType === "documentation");
}

export function summarizeVerdict(verdict: ScannerVerdict, findings: ScannerFinding[], targetKind: ScannerTargetKind) {
  if (!findings.length) {
    return safeSummary(targetKind);
  }

  const label = kindLabel(targetKind);

  const categories = Array.from(new Set(findings.map((finding) => finding.category))).slice(0, 5);
  const executableCount = signalCount(findings, "executable");
  const configCount = signalCount(findings, "config");
  const documentationCount = signalCount(findings, "documentation");
  const strongestSignals = [
    executableCount ? "executable" : null,
    configCount ? "config" : null,
    documentationCount ? "documentation" : null
  ].filter(Boolean).join(", ");

  if (verdict === "dangerous") {
    if (!hasDangerousExecutionSignal(findings) && documentationCount && !executableCount && !configCount) {
      return `Suspicious ${label} patterns found in documentation: ${categories.join(", ")}. This is documentation-heavy evidence, but still risky enough to review before trust or enablement.`;
    }
    return `High-risk ${label} patterns found: ${categories.join(", ")}. Strongest evidence comes from ${strongestSignals} signals. Treat as dangerous until reviewed.`;
  }

  return `Suspicious ${label} patterns found: ${categories.join(", ")}. Current evidence is mainly ${strongestSignals} signals. Review before trust or enablement.`;
}

export function buildReport(input: Omit<ScannerReport, "verdict" | "score" | "summary" | "kindSensitiveNotes" | "groupedFindings" | "topRisks" | "packageRecommendation" | "generatedAt">): ScannerReport {
  const score = Math.min(10, input.findings.reduce((sum, finding) => sum + findingScore(finding, input.targetKind), 0));
  const severity = highestSeverity(input.findings);
  const verdict: ScannerVerdict = !severity
    ? "safe"
    : hasDangerousExecutionSignal(input.findings) || (score >= 6 && !allDocumentationSignals(input.findings))
      ? "dangerous"
      : "suspicious";
  const groupedFindings = buildFindingGroups(input.findings, input.targetKind);
  const topRisks = buildTopRisks(groupedFindings);
  const packageRecommendation = buildPackageRecommendation(groupedFindings, verdict, input.targetKind);
  const kindSensitiveNotes = buildKindSensitiveNotes(input.targetKind, groupedFindings);

  return {
    ...input,
    verdict,
    score,
    summary: summarizeVerdict(verdict, input.findings, input.targetKind),
    kindSensitiveNotes,
    groupedFindings,
    topRisks,
    packageRecommendation,
    generatedAt: new Date().toISOString()
  };
}
