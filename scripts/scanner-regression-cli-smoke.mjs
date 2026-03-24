import { execFile } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = dirname(here);
const runnerPath = join(projectRoot, "scripts", "scanner-regression.mjs");

async function runCase(name, args, expectations = {}) {
  const {
    expectCode = 0,
    stdoutIncludes = [],
    stderrIncludes = [],
    stdoutExcludes = [],
    stderrExcludes = [],
    jsonStdout = false,
    validateJson
  } = expectations;

  let code = 0;
  let stdout = "";
  let stderr = "";

  try {
    const result = await execFileAsync(process.execPath, [runnerPath, ...args], {
      cwd: projectRoot,
      maxBuffer: 1024 * 1024
    });
    stdout = result.stdout ?? "";
    stderr = result.stderr ?? "";
  } catch (error) {
    code = typeof error?.code === "number" ? error.code : 1;
    stdout = error?.stdout ?? "";
    stderr = error?.stderr ?? "";
  }

  const problems = [];

  if (code !== expectCode) {
    problems.push(`expected exit ${expectCode}, got ${code}`);
  }

  for (const text of stdoutIncludes) {
    if (!stdout.includes(text)) problems.push(`stdout missing: ${text}`);
  }

  for (const text of stderrIncludes) {
    if (!stderr.includes(text)) problems.push(`stderr missing: ${text}`);
  }

  for (const text of stdoutExcludes) {
    if (stdout.includes(text)) problems.push(`stdout unexpectedly included: ${text}`);
  }

  for (const text of stderrExcludes) {
    if (stderr.includes(text)) problems.push(`stderr unexpectedly included: ${text}`);
  }

  if (jsonStdout) {
    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch (error) {
      problems.push(`stdout was not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (parsed && validateJson) {
      try {
        validateJson(parsed);
      } catch (error) {
        problems.push(error instanceof Error ? error.message : String(error));
      }
    }
  }

  return { name, ok: problems.length === 0, code, stdout, stderr, problems };
}

const artifactPath = join(projectRoot, "tmp", "scanner-regression-cli-smoke.json");

const checks = [
  () => runCase("help", ["--help"], {
    stdoutIncludes: ["Usage:", "--format <mode>", "Available cases:"],
    stderrExcludes: ["Error"]
  }),
  () => runCase("help-json", ["--help", "--json"], {
    jsonStdout: true,
    validateJson(payload) {
      if (payload.usage !== "node ./scripts/scanner-regression.mjs [options]") {
        throw new Error("json help usage did not match expected string");
      }
      if (!Array.isArray(payload.options) || payload.options.length === 0) {
        throw new Error("json help options were missing");
      }
      if (!Array.isArray(payload.cases) || !payload.cases.includes("clean-plugin")) {
        throw new Error("json help cases were missing clean-plugin");
      }
    }
  }),
  () => runCase("list-cases", ["--list-cases"], {
    stdoutIncludes: ["clean-plugin :: plugin / safe / allow", "suspicious-skill :: skill / suspicious / review-before-trust"]
  }),
  () => runCase("counts", ["--counts-only"], {
    stdoutIncludes: ["5 passed, 0 failed"],
    stdoutExcludes: ["PASS clean-plugin", "scanner regression passed"]
  }),
  () => runCase("json", ["--json"], {
    jsonStdout: true,
    validateJson(payload) {
      if (payload.ok !== true) throw new Error("json run did not report ok=true");
      if (payload.format !== "json") throw new Error("json run did not report format=json");
      if (!Array.isArray(payload.results) || payload.results.length !== 5) {
        throw new Error("json run did not return 5 results");
      }
    }
  }),
  async () => {
    await rm(artifactPath, { force: true });
    const result = await runCase("artifact-output", ["--output", artifactPath], {
      stdoutIncludes: [`scanner regression artifact written to ${artifactPath}`],
      stderrExcludes: ["FAIL"]
    });

    const problems = [...result.problems];
    try {
      const artifact = await readFile(artifactPath, "utf8");
      const payload = JSON.parse(artifact);
      if (payload.ok !== true) problems.push("artifact json did not report ok=true");
      if (!Array.isArray(payload.results) || payload.results.length !== 5) {
        problems.push("artifact json did not contain 5 results");
      }
      if (payload.format !== "human") problems.push(`artifact json expected format human but got ${payload.format}`);
    } catch (error) {
      problems.push(`artifact output validation failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await rm(artifactPath, { force: true });
    }

    return { ...result, ok: problems.length === 0, problems };
  },
  () => runCase("conflict-json-format", ["--json", "--format", "counts"], {
    expectCode: 1,
    stderrIncludes: ["Conflicting flags: --json implies --format json"]
  }),
  () => runCase("redundant-summary-aliases", ["--summary-only", "--quiet"], {
    expectCode: 1,
    stderrIncludes: ["Redundant flags: --summary-only and --quiet are aliases"]
  }),
  () => runCase("invalid-no-summary-footer", ["--format", "counts", "--no-summary-footer"], {
    expectCode: 1,
    stderrIncludes: ["--no-summary-footer only applies to --format summary"]
  })
];

const results = [];
for (const check of checks) {
  results.push(await check());
}

const failures = results.filter((result) => !result.ok);
for (const result of results) {
  if (result.ok) {
    console.log(`PASS ${result.name}`);
    continue;
  }

  console.error(`FAIL ${result.name}`);
  for (const problem of result.problems) {
    console.error(`  - ${problem}`);
  }
  if (result.stderr.trim()) {
    console.error("  stderr:");
    for (const line of result.stderr.trim().split("\n")) {
      console.error(`    ${line}`);
    }
  }
  if (result.stdout.trim()) {
    console.error("  stdout:");
    for (const line of result.stdout.trim().split("\n")) {
      console.error(`    ${line}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`scanner regression CLI smoke failed (${failures.length}/${results.length})`);
  process.exit(1);
}

console.log(`scanner regression CLI smoke passed (${results.length}/${results.length})`);
