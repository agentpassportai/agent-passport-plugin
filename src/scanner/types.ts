export type ScannerSeverity = "low" | "medium" | "high";
export type ScannerVerdict = "safe" | "suspicious" | "dangerous";
export type ScannerSignalType = "executable" | "config" | "documentation";
export type ScannerExploitability = "auto-exec" | "operator-assisted" | "reference-only";
export type ScannerRecommendedAction = "block" | "review" | "monitor";

export type ScannerFinding = {
  id: string;
  category: string;
  severity: ScannerSeverity;
  signalType: ScannerSignalType;
  title: string;
  summary: string;
  recommendation: string;
  evidence: Array<{
    filePath: string;
    line: number;
    snippet: string;
  }>;
};

export type ScannerTargetType = "directory" | "file";
export type ScannerTargetKind = "plugin" | "skill" | "package" | "hybrid" | "unknown";

export type ScannerFindingGroup = {
  id: string;
  title: string;
  summary: string;
  categories: string[];
  signalTypes: ScannerSignalType[];
  severity: ScannerSeverity;
  exploitability: ScannerExploitability;
  exploitabilityReason: string;
  recommendedAction: ScannerRecommendedAction;
  recommendedActionReason: string;
  representativeFindingId: string;
  findingIds: string[];
  filePaths: string[];
};

export type ScannerTopRisk = {
  title: string;
  summary: string;
  severity: ScannerSeverity;
  signalTypes: ScannerSignalType[];
  categories: string[];
  filePaths: string[];
  exploitability: ScannerExploitability;
  exploitabilityReason: string;
  recommendedAction: ScannerRecommendedAction;
  recommendedActionReason: string;
  groupId: string;
};

export type ScannerPackageRecommendation = {
  action: "allow" | "monitor" | "review-before-trust" | "block-package";
  reason: string;
};

export type ScannerFile = {
  absolutePath: string;
  relativePath: string;
  content: string;
};

export type ScannerRuleContext = {
  rootPath: string;
  targetType: ScannerTargetType;
  files: ScannerFile[];
};

export type ScannerRule = (context: ScannerRuleContext) => ScannerFinding[];

export type ScannerReport = {
  scannedPath: string;
  fingerprint: string;
  targetType: ScannerTargetType;
  targetKind: ScannerTargetKind;
  fileCount: number;
  filesScanned: string[];
  verdict: ScannerVerdict;
  score: number;
  summary: string;
  kindSensitiveNotes: string[];
  findings: ScannerFinding[];
  groupedFindings: ScannerFindingGroup[];
  topRisks: ScannerTopRisk[];
  packageRecommendation: ScannerPackageRecommendation;
  generatedAt: string;
};
