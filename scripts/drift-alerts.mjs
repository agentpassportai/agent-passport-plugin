#!/usr/bin/env node
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url, { interopDefault: true, esmResolve: true });
const { buildDriftAlerts, sweepRereviewQueue } = await jiti.import("../src/rereview.ts");

function printHelp() {
  console.log(`Agent Passport drift alerts CLI

Usage:
  node ./scripts/drift-alerts.mjs [--mode alerts|sweep] [--format human|json]

Options:
  --mode <value>    alerts (default) or sweep
  --format <value>  human (default) or json
  --help            Show this help

Exit codes:
  0   Success, no new alerts
  10  Success, new alerts detected (alerts mode only)
  1   Error
`);
}

function parseArgs(argv) {
  const args = [...argv];
  let mode = "alerts";
  let format = "human";

  while (args.length) {
    const arg = args.shift();
    if (arg === "--help" || arg === "-h") return { help: true, mode, format };
    if (arg === "--mode") {
      mode = args.shift() ?? "";
      continue;
    }
    if (arg?.startsWith("--mode=")) {
      mode = arg.slice("--mode=".length);
      continue;
    }
    if (arg === "--format") {
      format = args.shift() ?? "";
      continue;
    }
    if (arg?.startsWith("--format=")) {
      format = arg.slice("--format=".length);
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  if (mode !== "alerts" && mode !== "sweep") throw new Error(`Invalid --mode: ${mode}`);
  if (format !== "human" && format !== "json") throw new Error(`Invalid --format: ${format}`);
  return { help: false, mode, format };
}

function formatAlertsHuman(result) {
  if (!result.alert) {
    return `Agent Passport drift alerts: no new re-review entries. Queue=${result.summary.queueCount}, resolved=${result.summary.resolvedCount}. Review: ${result.nextCommand ?? "/passport workspace-state"}`;
  }
  return [
    "Agent Passport drift alerts:",
    `- alert: yes`,
    `- new entries: ${result.summary.newCount}`,
    `- queue count: ${result.summary.queueCount}`,
    `- resolved since last sweep: ${result.summary.resolvedCount}`,
    `- review with: ${result.nextCommand ?? "/passport workspace-state"}`,
    "",
    "Newly entered:",
    ...result.newlyEntered.map((item) => `- ${item.pluginId}: ${item.reason}`)
  ].join("\n");
}

function formatSweepHuman(result) {
  if (!result.summary.queueCount) {
    return "Agent Passport drift sweep: queue empty. Nothing new, nothing unresolved. Review: /passport workspace-state";
  }
  return [
    "Agent Passport drift sweep:",
    `- queue count: ${result.summary.queueCount}`,
    `- newly entered: ${result.summary.newCount}`,
    `- resolved since last sweep: ${result.summary.resolvedCount}`,
    `- review with: /passport workspace-state`,
    ...(result.newlyEntered.length ? ["", "Newly entered:", ...result.newlyEntered.map((item) => `- ${item.pluginId}: ${item.reason}`)] : []),
    ...(result.resolved.length ? ["", "Resolved since last sweep:", ...result.resolved.map((item) => `- ${item.pluginId} @ ${item.fingerprint}`)] : []),
    ...(result.queue.length ? ["", "Current queue:", ...result.queue.map((item) => `- ${item.pluginId}: ${item.reason}`)] : [])
  ].join("\n");
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    process.exit(0);
  }

  const result = options.mode === "alerts" ? await buildDriftAlerts() : await sweepRereviewQueue();

  if (options.format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(options.mode === "alerts" ? formatAlertsHuman(result) : formatSweepHuman(result));
  }

  if (options.mode === "alerts" && result.alert) {
    process.exit(10);
  }
  process.exit(0);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
