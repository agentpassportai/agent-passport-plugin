import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createJiti } from "jiti";

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = dirname(here);
const fixturesRoot = join(projectRoot, "fixtures", "scanner");
const snapshotsRoot = join(projectRoot, "fixtures", "scanner-snapshots");
const updateSnapshots = process.argv.includes("--update-snapshots");
const jsonRequested = process.argv.includes("--json");
const failFast = process.argv.includes("--fail-fast");
const strictCategories = process.argv.includes("--strict-categories");
const summaryAliasRequested = process.argv.includes("--summary-only");
const quietAliasRequested = process.argv.includes("--quiet");
const summaryRequested = summaryAliasRequested || quietAliasRequested;
const noSummaryFooter = process.argv.includes("--no-summary-footer");
const countsRequested = process.argv.includes("--counts-only");
const listCases = process.argv.includes("--list-cases");
const help = process.argv.includes("--help") || process.argv.includes("-h");
const outputFlagIndex = process.argv.indexOf("--output");
const outputPath = outputFlagIndex >= 0 ? process.argv[outputFlagIndex + 1] : undefined;
const caseFlagIndex = process.argv.indexOf("--case");
const caseFilter = caseFlagIndex >= 0 ? process.argv[caseFlagIndex + 1] : undefined;
const formatFlagIndex = process.argv.indexOf("--format");
const formatValue = formatFlagIndex >= 0 ? process.argv[formatFlagIndex + 1] : undefined;

if (outputFlagIndex >= 0 && !outputPath) {
  console.error("Missing value for --output");
  process.exit(1);
}

if (caseFlagIndex >= 0 && !caseFilter) {
  console.error("Missing value for --case");
  process.exit(1);
}

if (formatFlagIndex >= 0 && !formatValue) {
  console.error("Missing value for --format");
  process.exit(1);
}

if (summaryAliasRequested && quietAliasRequested) {
  console.error("Redundant flags: --summary-only and --quiet are aliases. Use one or the other.");
  process.exit(1);
}

const validFormats = ["human", "summary", "counts", "json"];
if (formatValue && !validFormats.includes(formatValue)) {
  console.error(`Invalid value for --format: ${formatValue}. Expected one of: ${validFormats.join(", ")}`);
  process.exit(1);
}

if (formatValue && jsonRequested && formatValue !== "json") {
  console.error(`Conflicting flags: --json implies --format json, but --format ${formatValue} was also provided`);
  process.exit(1);
}

if (formatValue && summaryRequested && formatValue !== "summary") {
  console.error(`Conflicting flags: --summary-only/--quiet imply --format summary, but --format ${formatValue} was also provided`);
  process.exit(1);
}

if (formatValue && countsRequested && formatValue !== "counts") {
  console.error(`Conflicting flags: --counts-only implies --format counts, but --format ${formatValue} was also provided`);
  process.exit(1);
}

const format = formatValue ?? (jsonRequested ? "json" : countsRequested ? "counts" : summaryRequested ? "summary" : "human");
const jsonOutput = format === "json";
const summaryOnly = format === "summary";
const countsOnly = format === "counts";

if (noSummaryFooter && !summaryOnly) {
  console.error("--no-summary-footer only applies to --format summary (or its aliases --summary-only / --quiet)");
  process.exit(1);
}

function printInfo(message) {
  if (!jsonOutput) console.log(message);
}

function printProblem(message) {
  if (!jsonOutput) console.error(message);
}

const jiti = createJiti(import.meta.url, { interopDefault: true, esmResolve: true });
const { scanPath } = await jiti.import(join(projectRoot, "src/scanner/index.ts"));

function normalizeReport(caseName, report) {
  return {
    scannedPath: `<fixture:${caseName}>`,
    fingerprint: report.fingerprint,
    targetType: report.targetType,
    targetKind: report.targetKind,
    fileCount: report.fileCount,
    filesScanned: report.filesScanned,
    verdict: report.verdict,
    score: report.score,
    summary: report.summary,
    packageRecommendation: report.packageRecommendation,
    kindSensitiveNotes: report.kindSensitiveNotes,
    findings: report.findings,
    groupedFindings: report.groupedFindings,
    topRisks: report.topRisks
  };
}

function buildSnapshotMismatchHints(existing, serialized) {
  const expectedLines = existing.split("\n");
  const actualLines = serialized.split("\n");
  const max = Math.max(expectedLines.length, actualLines.length);

  for (let index = 0; index < max; index += 1) {
    if (expectedLines[index] !== actualLines[index]) {
      const expectedLine = expectedLines[index] ?? "<missing>";
      const actualLine = actualLines[index] ?? "<missing>";
      return [
        `snapshot first differs at line ${index + 1}`,
        `expected: ${expectedLine}`,
        `actual:   ${actualLine}`
      ];
    }
  }

  return ["snapshot mismatch detected but no differing line was isolated"];
}

async function assertSnapshot(caseName, report) {
  const normalized = normalizeReport(caseName, report);
  const snapshotPath = join(snapshotsRoot, `${caseName}.json`);
  const serialized = `${JSON.stringify(normalized, null, 2)}\n`;

  if (updateSnapshots) {
    await mkdir(snapshotsRoot, { recursive: true });
    await writeFile(snapshotPath, serialized, "utf8");
    return [];
  }

  try {
    const existing = await readFile(snapshotPath, "utf8");
    return existing === serialized
      ? []
      : [
          `snapshot mismatch for ${caseName} (${snapshotPath})`,
          ...buildSnapshotMismatchHints(existing, serialized)
        ];
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [`missing snapshot for ${caseName} (${snapshotPath}). Run npm run scan:regression:update`];
    }
    throw error;
  }
}

const allCases = [
  {
    name: "clean-plugin",
    path: join(fixturesRoot, "clean-plugin"),
    expect: {
      targetKind: "plugin",
      verdict: "safe",
      packageAction: "allow",
      includesCategories: [],
      exactCategories: []
    }
  },
  {
    name: "governance-risk-plugin",
    path: join(fixturesRoot, "governance-risk-plugin"),
    expect: {
      targetKind: "plugin",
      verdict: "suspicious",
      packageAction: "review-before-trust",
      includesCategories: ["plugin-manifest-risk"],
      exactCategories: ["plugin-manifest-risk"]
    }
  },
  {
    name: "runtime-risk-plugin",
    path: join(fixturesRoot, "runtime-risk-plugin"),
    expect: {
      targetKind: "plugin",
      verdict: "dangerous",
      packageAction: "block-package",
      includesCategories: ["staged-payload", "persistence-autorun"],
      exactCategories: ["persistence-autorun", "staged-payload"]
    }
  },
  {
    name: "docs-risk-plugin",
    path: join(fixturesRoot, "docs-risk-plugin"),
    expect: {
      targetKind: "plugin",
      verdict: "suspicious",
      packageAction: "review-before-trust",
      includesCategories: ["prompt-directed-shell-execution", "remote-script-execution"],
      exactCategories: ["bootstrap-installer", "prompt-directed-shell-execution", "remote-script-execution"]
    }
  },
  {
    name: "suspicious-skill",
    path: join(fixturesRoot, "suspicious-skill"),
    expect: {
      targetKind: "skill",
      verdict: "suspicious",
      packageAction: "review-before-trust",
      includesCategories: ["prompt-directed-shell-execution", "bootstrap-installer"],
      exactCategories: ["bootstrap-installer", "prompt-directed-shell-execution"]
    }
  }
];

if (listCases) {
  const payload = allCases.map((testCase) => ({
    name: testCase.name,
    targetKind: testCase.expect.targetKind,
    verdict: testCase.expect.verdict,
    packageAction: testCase.expect.packageAction,
    path: testCase.path
  }));

  if (jsonOutput) {
    console.log(JSON.stringify({ cases: payload }, null, 2));
  } else {
    for (const testCase of payload) {
      console.log(`${testCase.name} :: ${testCase.targetKind} / ${testCase.verdict} / ${testCase.packageAction}`);
    }
  }
  process.exit(0);
}

if (help) {
  const lines = [
    "Usage: node ./scripts/scanner-regression.mjs [options]",
    "",
    "Options:",
    "  --case <name>          Run only one fixture case",
    "  --list-cases           List available fixture cases and exit",
    "  --json                 Alias for --format json",
    "  --format <mode>        Output mode: human | summary | counts | json",
    "                         Conflicting alias + format combinations are rejected",
    "  --output <path>        Write JSON results to a file",
    "  --fail-fast            Stop on the first failing case",
    "  --strict-categories    Require exact category-set matches",
    "  --summary-only         Print one compact line per case",
    "  --quiet                Alias for --summary-only (do not combine both)",
    "  --no-summary-footer    Suppress trailing pass banner in summary mode only",
    "  --counts-only          Print only final pass/fail counts",
    "  --update-snapshots     Rewrite normalized snapshots",
    "  --help, -h             Show this help",
    "",
    `Available cases: ${allCases.map((testCase) => testCase.name).join(", ")}`
  ];

  if (jsonOutput) {
    console.log(JSON.stringify({
      usage: "node ./scripts/scanner-regression.mjs [options]",
      options: [
        { flag: "--case <name>", description: "Run only one fixture case" },
        { flag: "--list-cases", description: "List available fixture cases and exit" },
        { flag: "--json", description: "Alias for --format json" },
        { flag: "--format <mode>", description: "Output mode: human | summary | counts | json" },
        { flag: "flag conflicts", description: "Conflicting alias + format combinations are rejected" },
        { flag: "--output <path>", description: "Write JSON results to a file" },
        { flag: "--fail-fast", description: "Stop on the first failing case" },
        { flag: "--strict-categories", description: "Require exact category-set matches" },
        { flag: "--summary-only", description: "Print one compact line per case" },
        { flag: "--quiet", description: "Alias for --summary-only (do not combine both)" },
        { flag: "--no-summary-footer", description: "Suppress trailing pass banner in summary mode only" },
        { flag: "--counts-only", description: "Print only final pass/fail counts" },
        { flag: "--update-snapshots", description: "Rewrite normalized snapshots" },
        { flag: "--help, -h", description: "Show this help" }
      ],
      cases: allCases.map((testCase) => testCase.name),
      format,
      strictCategories,
      summaryOnly,
      noSummaryFooter,
      countsOnly
    }, null, 2));
  } else {
    console.log(lines.join("\n"));
  }
  process.exit(0);
}

const cases = caseFilter ? allCases.filter((testCase) => testCase.name === caseFilter) : allCases;

if (!cases.length) {
  console.error(`Unknown case '${caseFilter}'. Available cases: ${allCases.map((testCase) => testCase.name).join(", ")}`);
  process.exit(1);
}

let failures = 0;
const results = [];

for (const testCase of cases) {
  const report = await scanPath(testCase.path);
  const categories = [...new Set(report.findings.map((finding) => finding.category))].sort();
  const problems = [...await assertSnapshot(testCase.name, report)];

  if (report.targetKind !== testCase.expect.targetKind) {
    problems.push(`targetKind expected ${testCase.expect.targetKind} but got ${report.targetKind}`);
  }
  if (report.verdict !== testCase.expect.verdict) {
    problems.push(`verdict expected ${testCase.expect.verdict} but got ${report.verdict}`);
  }
  if (report.packageRecommendation.action !== testCase.expect.packageAction) {
    problems.push(`packageRecommendation.action expected ${testCase.expect.packageAction} but got ${report.packageRecommendation.action}`);
  }
  for (const category of testCase.expect.includesCategories) {
    if (!categories.includes(category)) {
      problems.push(`missing expected category ${category}`);
    }
  }
  if (strictCategories) {
    const expectedCategories = [...(testCase.expect.exactCategories ?? testCase.expect.includesCategories)].sort();
    if (JSON.stringify(categories) !== JSON.stringify(expectedCategories)) {
      problems.push(`categories expected exactly [${expectedCategories.join(", ")}] but got [${categories.join(", ")}]`);
    }
  }

  if (problems.length) {
    failures += 1;
    results.push({
      name: testCase.name,
      ok: false,
      targetKind: report.targetKind,
      verdict: report.verdict,
      packageAction: report.packageRecommendation.action,
      categories,
      summary: report.summary,
      recommendationReason: report.packageRecommendation.reason,
      problems
    });
    if (!countsOnly) printProblem(`FAIL ${testCase.name} :: ${report.targetKind} / ${report.verdict} / ${report.packageRecommendation.action}`);
    if (!summaryOnly && !countsOnly) {
      for (const problem of problems) printProblem(`  - ${problem}`);
      printProblem(`  categories: ${categories.join(", ") || "(none)"}`);
      printProblem(`  summary: ${report.summary}`);
      printProblem(`  recommendation: ${report.packageRecommendation.action} — ${report.packageRecommendation.reason}`);
    }
    if (failFast) break;
    continue;
  }

  results.push({
    name: testCase.name,
    ok: true,
    targetKind: report.targetKind,
    verdict: report.verdict,
    packageAction: report.packageRecommendation.action,
    categories,
    summary: report.summary,
    recommendationReason: report.packageRecommendation.reason,
    problems: []
  });
  if (!countsOnly) {
    printInfo(`PASS ${testCase.name} :: ${report.targetKind} / ${report.verdict} / ${report.packageRecommendation.action}`);
  }
}

const jsonPayload = JSON.stringify({
  ok: failures === 0,
  failures,
  format,
  caseFilter: caseFilter ?? null,
  updateSnapshots,
  failFast,
  strictCategories,
  summaryOnly,
  noSummaryFooter,
  countsOnly,
  results
}, null, 2);

if (outputPath) {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${jsonPayload}\n`, "utf8");
}

if (jsonOutput) {
  console.log(jsonPayload);
}

const passedCount = results.filter((result) => result.ok).length;
const totalCount = results.length;

if (failures) {
  if (countsOnly) {
    printProblem(`${passedCount} passed, ${failures} failed`);
  } else {
    printProblem(`\nscanner regression failed: ${failures} case(s)`);
  }
  process.exit(1);
}

if (outputPath && !jsonOutput) {
  printInfo(`\nscanner regression artifact written to ${outputPath}`);
}

if (countsOnly) {
  printInfo(`${passedCount} passed, 0 failed`);
} else if (!(summaryOnly && noSummaryFooter)) {
  printInfo("\nscanner regression passed");
}
