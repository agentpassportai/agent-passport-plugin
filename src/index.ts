import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { ReplyPayload } from "openclaw/plugin-sdk";
import { DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS } from "openclaw/plugin-sdk/approval-runtime";
import { createOperatorApprovalsGatewayClient } from "openclaw/plugin-sdk/gateway-runtime";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Type } from "@sinclair/typebox";
import { evaluateAction } from "./policy/engine.js";
import { evaluateInboundDispatch } from "./policy/inbound-dispatch.js";
import { evaluateOutboundCommunication } from "./policy/outbound-comms.js";
import { appendAuditRecord, configureAuditRuntime } from "./audit.js";
import { scanPath } from "./scanner/index.js";
import type { ScannerFinding, ScannerReport } from "./scanner/types.js";
import { getLatestScanReview, listScanReviews, recordScanReview, type PassportScanDecision, type PassportScanReview } from "./review.js";
import { getLatestPluginInstall, listPluginInstalls, markPluginEnabled, recordPluginInstall } from "./install-ledger.js";
import { getLatestSkillReviewRecord, recordSkillReview } from "./skill-review-ledger.js";
import { buildDriftAlerts, listPluginsNeedingRereview, sweepRereviewQueue } from "./rereview.js";
import { inspectSkillArtifact } from "./skill-inspection.js";
import { buildArtifactTrustSummary } from "./trust-summary.js";
import { buildWorkspaceAudit, formatWorkspaceAudit, type WorkspaceAuditOptions } from "./workspace-audit.js";
import {
  createConsentRequest,
  expandTargetAliases,
  grantConsent,
  hasConsentForTarget,
  listConsentRequests,
  listConsents,
  revokeConsent,
  reviewConsentRequest,
  type PassportConsentRequest
} from "./consent.js";

type PassportMode = "audit" | "warn" | "enforce";
type TrustedPathScope = "all" | "message_sending" | "message.send" | "sessions_send";
type GuardedScope = Exclude<TrustedPathScope, "all">;

type TrustedTargetRule = {
  target: string;
  paths: TrustedPathScope[];
  note?: string;
};

type PassportPluginConfig = {
  mode?: PassportMode;
  pathModes?: Partial<Record<GuardedScope, PassportMode>>;
  trustedTargets?: string[];
  trustedTargetRules?: TrustedTargetRule[];
  consentTtlMinutes?: number;
  audit?: {
    enabled?: boolean;
    path?: string;
  };
};

type LoadedPluginConfig = {
  mode: PassportMode;
  pathModes: Partial<Record<GuardedScope, PassportMode>>;
  trustedTargets: string[];
  trustedTargetRules: TrustedTargetRule[];
  consentTtlMinutes: number;
  audit: {
    enabled: boolean;
    path?: string;
  };
};

type NativeApprovalSeverity = "info" | "warning" | "critical";
type NativeApprovalResolution = "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled";
type NativeApprovalGatewayClient = Awaited<ReturnType<typeof createOperatorApprovalsGatewayClient>>;
type NativeApprovalGatewayResult = {
  approvalId?: string;
  resolution: NativeApprovalResolution;
  routeAvailable: boolean;
  error?: string;
};

const GUARDED_SCOPES: GuardedScope[] = ["message_sending", "message.send", "sessions_send"];
const TELEGRAM_NAMESPACE = "passport";
const OPTIONAL_MUTATING_TOOL = { optional: true } as const;
const EARLY_SECURITY_HOOK_PRIORITY = 100;
const NATIVE_PLUGIN_APPROVAL_COMMAND_HINT = "Reply with: /approve <id> allow-once|allow-always|deny";

function getPluginConfig(raw: Record<string, unknown> | undefined): LoadedPluginConfig {
  const auditConfig = raw?.audit && typeof raw.audit === "object"
    ? raw.audit as { enabled?: unknown; path?: unknown }
    : undefined;
  const trustedTargets = Array.isArray(raw?.trustedTargets)
    ? raw.trustedTargets.filter((x): x is string => typeof x === "string").map((x) => x.trim().toLowerCase())
    : [];

  const trustedTargetRules = Array.isArray(raw?.trustedTargetRules)
    ? raw.trustedTargetRules.flatMap((value) => {
        if (!value || typeof value !== "object") return [];
        const target = typeof value.target === "string" ? value.target.trim().toLowerCase() : "";
        if (!target) return [];
        const paths = Array.isArray(value.paths)
          ? value.paths.filter(
              (path: unknown): path is TrustedPathScope =>
                typeof path === "string" && ["all", "message_sending", "message.send", "sessions_send"].includes(path)
            )
          : ["all"];
        return [{
          target,
          paths: paths.length ? paths : ["all"],
          note: typeof value.note === "string" ? value.note : undefined
        } satisfies TrustedTargetRule];
      })
    : [];

  const pathModes = raw?.pathModes && typeof raw.pathModes === "object"
    ? Object.fromEntries(
        Object.entries(raw.pathModes).flatMap(([scope, mode]) => {
          if (!GUARDED_SCOPES.includes(scope as GuardedScope)) return [];
          if (mode !== "audit" && mode !== "warn" && mode !== "enforce") return [];
          return [[scope, mode]];
        })
      ) as Partial<Record<GuardedScope, PassportMode>>
    : {};

  return {
    mode: raw?.mode === "audit" || raw?.mode === "warn" || raw?.mode === "enforce" ? raw.mode : "warn",
    pathModes,
    trustedTargets,
    trustedTargetRules,
    consentTtlMinutes: typeof raw?.consentTtlMinutes === "number" && raw?.consentTtlMinutes > 0 ? Math.floor(raw.consentTtlMinutes) : 60,
    audit: {
      enabled: typeof auditConfig?.enabled === "boolean" ? auditConfig.enabled : true,
      path: typeof auditConfig?.path === "string" ? auditConfig.path : undefined
    }
  };
}

function shouldGateMessageTool(params: Record<string, unknown>) {
  const action = String(params.action ?? "").toLowerCase();
  return action === "send";
}

function shouldGateSessionSend(toolName: string) {
  return toolName === "sessions_send";
}

function normalizeTarget(value: unknown) {
  return String(value ?? "").trim().toLowerCase();
}

function targetMatches(target: string, candidate: string) {
  const targetAliases = expandTargetAliases(target);
  const candidateAliases = expandTargetAliases(candidate);
  for (const alias of targetAliases) {
    if (candidateAliases.has(alias)) return true;
  }
  return false;
}

function getTrustedMatch(target: string, scope: TrustedPathScope, pluginCfg: LoadedPluginConfig) {
  if (!target) return null;

  for (const rule of pluginCfg.trustedTargetRules) {
    if (!rule.paths.includes("all") && !rule.paths.includes(scope)) continue;
    if (targetMatches(target, rule.target)) {
      return {
        matchedRule: "trusted-target-rule",
        reason: rule.note || `Target matched trustedTargetRules for ${scope}.`
      };
    }
  }

  for (const targetEntry of pluginCfg.trustedTargets) {
    if (targetMatches(target, targetEntry)) {
      return {
        matchedRule: "trusted-target",
        reason: "Target matched trustedTargets allowlist after alias normalization."
      };
    }
  }

  return null;
}

function getModeForScope(scope: GuardedScope, pluginCfg: LoadedPluginConfig) {
  return pluginCfg.pathModes[scope] ?? pluginCfg.mode;
}

function buildDecisionText(prefix: string, matchedRule: string, mode: string, requestId?: string) {
  const requestSuffix = requestId ? ` requestId=${requestId}.` : "";
  return `${prefix} (${matchedRule}, mode=${mode}).${requestSuffix}`;
}

function approvalSeverityForDecision(decision: ReturnType<typeof evaluateOutboundCommunication>): NativeApprovalSeverity {
  if (decision.outcome === "deny") return "critical";
  if (decision.severity === "high" || decision.severity === "medium") return "warning";
  return "info";
}

function buildNativeApprovalDescription(input: {
  scope: GuardedScope;
  target: string;
  decision: ReturnType<typeof evaluateOutboundCommunication>;
  consentTtlMinutes: number;
}) {
  const { scope, target, decision, consentTtlMinutes } = input;
  const actionLabel = scope === "message_sending" ? `an outbound message to ${target}` : `${scope} to ${target}`;
  const allowOnceLabel = scope === "message_sending"
    ? "Allow once permits only this outbound message."
    : "Allow once permits only this tool call.";
  return [
    `Agent Passport paused ${actionLabel}.`,
    decision.reason,
    allowOnceLabel,
    `Allow always creates a Passport consent grant for ${consentTtlMinutes} minute${consentTtlMinutes === 1 ? "" : "s"}.`
  ].join("\n");
}

function buildNativeApprovalNote(resolution: NativeApprovalResolution, consentTtlMinutes: number) {
  return resolution === "allow-once"
    ? "Approved once via native plugin approval."
    : resolution === "allow-always"
      ? `Approved via native plugin approval; Passport TTL=${consentTtlMinutes}m.`
      : `Denied via native plugin approval (${resolution}).`;
}

function normalizeNativeApprovalResolution(value: unknown): NativeApprovalResolution {
  switch (value) {
    case "allow-once":
    case "allow-always":
    case "deny":
    case "timeout":
    case "cancelled":
      return value;
    default:
      return "timeout";
  }
}

export function isForwardedNativePluginApprovalMessage(content: string | null | undefined) {
  const text = String(content ?? "").trim();
  if (!text) return false;

  if (
    text.includes("Plugin approval required")
    && text.includes("\nTitle: ")
    && text.includes("\nID: ")
    && text.includes(`\n${NATIVE_PLUGIN_APPROVAL_COMMAND_HINT}`)
  ) {
    return true;
  }

  if (/^✅ Plugin approval (allowed once|allowed always|denied)\./.test(text) && text.includes(" ID: ")) {
    return true;
  }

  return /^⏱️ Plugin approval expired\. ID: /.test(text);
}

async function persistNativeApprovalResolution(input: {
  requestId: string;
  resolution: NativeApprovalResolution;
  decision: ReturnType<typeof evaluateOutboundCommunication>;
  scope: GuardedScope;
  pluginCfg: LoadedPluginConfig;
  auditRecord: Record<string, unknown>;
  approvalMode: "native-requireApproval" | "native-gateway-plugin-approval";
  gatewayApprovalId?: string;
}) {
  try {
    const result = await reviewConsentRequest({
      requestId: input.requestId,
      decision: input.resolution === "allow-once" || input.resolution === "allow-always" ? "approved" : "denied",
      grantMode: input.resolution === "allow-always" ? "ttl" : "none",
      ttlMinutes: input.pluginCfg.consentTtlMinutes,
      note: buildNativeApprovalNote(input.resolution, input.pluginCfg.consentTtlMinutes)
    });

    await appendAuditRecord({
      ...input.auditRecord,
      decision: input.decision,
      scope: input.scope,
      mode: "enforce",
      globalMode: input.pluginCfg.mode,
      effectiveMode: "enforce",
      consentRequestId: input.requestId,
      approvalMode: input.approvalMode,
      approvalState: "resolved",
      approvalResolution: input.resolution,
      gatewayApprovalId: input.gatewayApprovalId,
      reviewResult: result
    });

    return result;
  } catch (error) {
    await appendAuditRecord({
      ...input.auditRecord,
      decision: input.decision,
      scope: input.scope,
      mode: "enforce",
      globalMode: input.pluginCfg.mode,
      effectiveMode: "enforce",
      consentRequestId: input.requestId,
      approvalMode: input.approvalMode,
      approvalState: "resolution-error",
      approvalResolution: input.resolution,
      gatewayApprovalId: input.gatewayApprovalId,
      error: error instanceof Error ? error.message : String(error)
    });
    return null;
  }
}

function getMessageSendingTurnSource(input: {
  event: { metadata?: Record<string, unknown> };
  ctx: { channelId: string; accountId?: string; conversationId?: string };
}) {
  const metadata = input.event.metadata && typeof input.event.metadata === "object"
    ? input.event.metadata
    : {};
  const threadId = typeof metadata.threadId === "string" || typeof metadata.threadId === "number"
    ? metadata.threadId
    : undefined;

  return {
    turnSourceChannel: input.ctx.channelId,
    turnSourceTo: input.ctx.conversationId,
    turnSourceAccountId: input.ctx.accountId,
    turnSourceThreadId: threadId
  };
}

export async function requestNativePluginApprovalDecision(input: {
  config: Parameters<typeof createOperatorApprovalsGatewayClient>[0]["config"];
  pluginId: string;
  title: string;
  description: string;
  severity: NativeApprovalSeverity;
  turnSourceChannel?: string;
  turnSourceTo?: string;
  turnSourceAccountId?: string;
  turnSourceThreadId?: string | number;
}, deps?: {
  createGatewayClient?: typeof createOperatorApprovalsGatewayClient;
}) {
  const createGatewayClient = deps?.createGatewayClient ?? createOperatorApprovalsGatewayClient;
  let client: NativeApprovalGatewayClient | null = null;

  try {
    client = await createGatewayClient({
      config: input.config,
      clientDisplayName: "Agent Passport approvals"
    });
    client.start();

    const requestResult = await client.request<{
      id?: string;
      decision?: NativeApprovalResolution | null;
    }>("plugin.approval.request", {
      pluginId: input.pluginId,
      title: input.title,
      description: input.description,
      severity: input.severity,
      timeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS,
      twoPhase: true,
      ...(input.turnSourceChannel ? { turnSourceChannel: input.turnSourceChannel } : {}),
      ...(input.turnSourceTo ? { turnSourceTo: input.turnSourceTo } : {}),
      ...(input.turnSourceAccountId ? { turnSourceAccountId: input.turnSourceAccountId } : {}),
      ...(input.turnSourceThreadId !== undefined ? { turnSourceThreadId: input.turnSourceThreadId } : {})
    }, {
      expectFinal: false,
      timeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS + 10_000
    });

    const approvalId = typeof requestResult?.id === "string" ? requestResult.id : undefined;
    if (!approvalId) {
      return {
        resolution: "cancelled",
        routeAvailable: false,
        error: "gateway did not return a plugin approval id"
      } satisfies NativeApprovalGatewayResult;
    }

    if (Object.prototype.hasOwnProperty.call(requestResult ?? {}, "decision")) {
      if (requestResult?.decision === null) {
        return {
          approvalId,
          resolution: "cancelled",
          routeAvailable: false
        } satisfies NativeApprovalGatewayResult;
      }

      return {
        approvalId,
        resolution: normalizeNativeApprovalResolution(requestResult?.decision),
        routeAvailable: true
      } satisfies NativeApprovalGatewayResult;
    }

    const waitResult = await client.request<{ decision?: NativeApprovalResolution }>("plugin.approval.waitDecision", { id: approvalId }, {
      timeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS + 10_000
    });

    return {
      approvalId,
      resolution: normalizeNativeApprovalResolution(waitResult?.decision),
      routeAvailable: true
    } satisfies NativeApprovalGatewayResult;
  } catch (error) {
    return {
      resolution: "cancelled",
      routeAvailable: false,
      error: error instanceof Error ? error.message : String(error)
    } satisfies NativeApprovalGatewayResult;
  } finally {
    await client?.stopAndWait({ timeoutMs: 1_000 }).catch(() => void 0);
  }
}

export async function handleNativeMessageSendingApproval(input: {
  config: Parameters<typeof createOperatorApprovalsGatewayClient>[0]["config"];
  pluginId: string;
  logger: {
    info?: (message: string) => void;
    warn: (message: string) => void;
  };
  event: {
    to: string;
    content: string;
    metadata?: Record<string, unknown>;
  };
  ctx: {
    channelId: string;
    accountId?: string;
    conversationId?: string;
  };
  target: string;
  decision: ReturnType<typeof evaluateOutboundCommunication>;
  pluginCfg: LoadedPluginConfig;
  auditRecord: Record<string, unknown>;
}, deps?: {
  createGatewayClient?: typeof createOperatorApprovalsGatewayClient;
}) {
  const request = await createConsentRequest({
    target: input.target,
    action: "message_sending",
    reason: input.decision.reason
  });

  await appendAuditRecord({
    ...input.auditRecord,
    decision: input.decision,
    scope: "message_sending",
    mode: "enforce",
    globalMode: input.pluginCfg.mode,
    effectiveMode: "enforce",
    consentRequestId: request.id,
    approvalMode: "native-gateway-plugin-approval",
    approvalState: "requested"
  });

  const gatewayResult = await requestNativePluginApprovalDecision({
    config: input.config,
    pluginId: input.pluginId,
    title: "Agent Passport approval required",
    description: buildNativeApprovalDescription({
      scope: "message_sending",
      target: input.target,
      decision: input.decision,
      consentTtlMinutes: input.pluginCfg.consentTtlMinutes
    }),
    severity: approvalSeverityForDecision(input.decision),
    ...getMessageSendingTurnSource({
      event: input.event,
      ctx: input.ctx
    })
  }, deps);

  if (!gatewayResult.routeAvailable) {
    await appendAuditRecord({
      ...input.auditRecord,
      decision: input.decision,
      scope: "message_sending",
      mode: "enforce",
      globalMode: input.pluginCfg.mode,
      effectiveMode: "enforce",
      consentRequestId: request.id,
      approvalMode: "native-gateway-plugin-approval",
      approvalState: "manual-fallback-pending",
      approvalResolution: gatewayResult.resolution,
      gatewayApprovalId: gatewayResult.approvalId,
      error: gatewayResult.error
    });

    const errorSuffix = gatewayResult.error ? ` (${gatewayResult.error})` : "";
    input.logger.warn(
      `agent-passport: native approval routing unavailable for ${input.target}; request ${request.id} remains pending for manual /passport approve${errorSuffix}`
    );

    return {
      allowed: false,
      requestId: request.id,
      gatewayApprovalId: gatewayResult.approvalId,
      resolution: gatewayResult.resolution,
      routeAvailable: false
    };
  }

  await persistNativeApprovalResolution({
    requestId: request.id,
    resolution: gatewayResult.resolution,
    decision: input.decision,
    scope: "message_sending",
    pluginCfg: input.pluginCfg,
    auditRecord: input.auditRecord,
    approvalMode: "native-gateway-plugin-approval",
    gatewayApprovalId: gatewayResult.approvalId
  });

  return {
    allowed: gatewayResult.resolution === "allow-once" || gatewayResult.resolution === "allow-always",
    requestId: request.id,
    gatewayApprovalId: gatewayResult.approvalId,
    resolution: gatewayResult.resolution,
    routeAvailable: true
  };
}

export async function buildNativeToolApprovalRequirement(input: {
  scope: Exclude<GuardedScope, "message_sending">;
  target: string;
  decision: ReturnType<typeof evaluateOutboundCommunication>;
  pluginCfg: LoadedPluginConfig;
  auditRecord: Record<string, unknown>;
}) {
  const request = await createConsentRequest({
    target: input.target,
    action: input.scope,
    reason: input.decision.reason
  });

  await appendAuditRecord({
    ...input.auditRecord,
    decision: input.decision,
    scope: input.scope,
    mode: "enforce",
    globalMode: input.pluginCfg.mode,
    effectiveMode: "enforce",
    consentRequestId: request.id,
    approvalMode: "native-requireApproval",
    approvalState: "requested"
  });

  return {
    requireApproval: {
      title: "Agent Passport approval required",
      description: buildNativeApprovalDescription({
        scope: input.scope,
        target: input.target,
        decision: input.decision,
        consentTtlMinutes: input.pluginCfg.consentTtlMinutes
      }),
      severity: approvalSeverityForDecision(input.decision),
      timeoutBehavior: "deny" as const,
      onResolution: async (resolution: NativeApprovalResolution) => {
        await persistNativeApprovalResolution({
          requestId: request.id,
          resolution,
          decision: input.decision,
          scope: input.scope,
          pluginCfg: input.pluginCfg,
          auditRecord: input.auditRecord,
          approvalMode: "native-requireApproval"
        });
      }
    }
  };
}

function summarizeRequest(request: PassportConsentRequest) {
  return [
    `- ${request.id}`,
    `  action: ${request.action}`,
    `  target: ${request.target}`,
    `  status: ${request.status}`,
    request.reason ? `  reason: ${request.reason}` : null,
    `  requestedAt: ${request.requestedAt}`
  ].filter(Boolean).join("\n");
}

function buildRequestButtons(requests: PassportConsentRequest[]) {
  return {
    blocks: requests.flatMap((request) => ([
      { type: "text" as const, text: `${request.id} • ${request.action} • ${request.target}` },
      {
        type: "buttons" as const,
        buttons: [
          { label: `Approve ${request.id.slice(-4)}`, value: `approve:${request.id}`, style: "success" as const },
          { label: `Deny ${request.id.slice(-4)}`, value: `deny:${request.id}`, style: "danger" as const }
        ]
      }
    ]))
  };
}

function parseInteractivePayload(payload: string | undefined) {
  const parts = String(payload ?? "").split(":").filter(Boolean);
  if (parts[0] === TELEGRAM_NAMESPACE) parts.shift();
  const action = parts[0] ?? "";
  const requestId = parts[1] ?? "";
  const target = parts.slice(1).join(":");
  return { action, requestId, target };
}

function jsonToolResult<TDetails>(details: TDetails) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(details, null, 2) }],
    details
  };
}

type PluginApprovalForwardingSummary = {
  status: "disabled" | "configured" | "misconfigured";
  enabled: boolean;
  mode: "session" | "targets" | "both";
  usesSessionRoute: boolean;
  explicitTargetCount: number;
  agentFilterCount: number;
  sessionFilterCount: number;
  reason: string;
};

export function summarizePluginApprovalForwardingConfig(config: Parameters<typeof createOperatorApprovalsGatewayClient>[0]["config"]): PluginApprovalForwardingSummary {
  const pluginApprovals = config.approvals?.plugin;
  const enabled = pluginApprovals?.enabled === true;
  const mode = pluginApprovals?.mode === "targets" || pluginApprovals?.mode === "both"
    ? pluginApprovals.mode
    : "session";
  const usesSessionRoute = mode === "session" || mode === "both";
  const explicitTargetCount = Array.isArray(pluginApprovals?.targets)
    ? pluginApprovals.targets.filter(
        (target): target is { channel: string; to: string } =>
          Boolean(target)
          && typeof target === "object"
          && typeof target.channel === "string"
          && typeof target.to === "string"
      ).length
    : 0;
  const agentFilterCount = Array.isArray(pluginApprovals?.agentFilter)
    ? pluginApprovals.agentFilter.filter((value): value is string => typeof value === "string" && value.trim().length > 0).length
    : 0;
  const sessionFilterCount = Array.isArray(pluginApprovals?.sessionFilter)
    ? pluginApprovals.sessionFilter.filter((value): value is string => typeof value === "string" && value.trim().length > 0).length
    : 0;

  if (!enabled) {
    return {
      status: "disabled",
      enabled,
      mode,
      usesSessionRoute,
      explicitTargetCount,
      agentFilterCount,
      sessionFilterCount,
      reason: "approvals.plugin.enabled is false"
    };
  }

  if (!usesSessionRoute && explicitTargetCount === 0) {
    return {
      status: "misconfigured",
      enabled,
      mode,
      usesSessionRoute,
      explicitTargetCount,
      agentFilterCount,
      sessionFilterCount,
      reason: "approvals.plugin.mode=targets requires at least one approvals.plugin.targets entry"
    };
  }

  return {
    status: "configured",
    enabled,
    mode,
    usesSessionRoute,
    explicitTargetCount,
    agentFilterCount,
    sessionFilterCount,
    reason: usesSessionRoute
      ? "origin-session forwarding is enabled"
      : `${explicitTargetCount} explicit forwarding target${explicitTargetCount === 1 ? "" : "s"} configured`
  };
}

async function buildRequestsReply(status: PassportConsentRequest["status"] | "all" = "pending"): Promise<ReplyPayload> {
  const requests = await listConsentRequests({ status });
  if (!requests.length) {
    return {
      text: `Agent Passport requests (${status}): none.`,
      interactive: status === "pending" ? {
        blocks: [{ type: "buttons", buttons: [{ label: "Refresh", value: "requests" }] }]
      } : undefined
    };
  }

  const limited = requests.slice(-5).reverse();
  const text = [`Agent Passport requests (${status}, newest first):`, ...limited.map((request) => summarizeRequest(request))].join("\n\n");
  return {
    text,
    interactive: status === "pending" ? buildRequestButtons(limited.filter((request) => request.status === "pending")) : undefined
  };
}

async function buildStatusReply(
  pluginCfg: LoadedPluginConfig,
  runtimeConfig: Parameters<typeof createOperatorApprovalsGatewayClient>[0]["config"]
): Promise<ReplyPayload> {
  const grants = await listConsents();
  const pendingRequests = await listConsentRequests({ status: "pending" });
  const reviews = await listScanReviews();
  const installs = await listPluginInstalls();
  const rereviewQueue = await listPluginsNeedingRereview();
  const skillRereviewQueue = await listSkillsNeedingRereview();
  const skills = await listSkillStates();
  const pluginApprovalForwarding = summarizePluginApprovalForwardingConfig(runtimeConfig);
  const pathLines = GUARDED_SCOPES.map((scope) => `- ${scope}: ${getModeForScope(scope, pluginCfg)}`);
  return {
    text: [
      "Agent Passport status:",
      `- default mode: ${pluginCfg.mode}`,
      ...pathLines,
      "- inbound dispatch audit: enabled via before_dispatch",
      `- plugin approval forwarding: ${pluginApprovalForwarding.status}`,
      `- plugin approval forwarding mode: ${pluginApprovalForwarding.mode}`,
      `- plugin approval session route: ${pluginApprovalForwarding.usesSessionRoute ? "yes" : "no"}`,
      `- plugin approval explicit targets: ${pluginApprovalForwarding.explicitTargetCount}`,
      `- plugin approval filters: agent=${pluginApprovalForwarding.agentFilterCount}, session=${pluginApprovalForwarding.sessionFilterCount}`,
      `- plugin approval forwarding note: ${pluginApprovalForwarding.reason}`,
      `- active grants: ${grants.length}`,
      `- pending requests: ${pendingRequests.length}`,
      `- reviewed artifacts: ${reviews.length}`,
      `- recorded plugin installs: ${installs.length}`,
      `- tracked skills: ${skills.length}`,
      `- plugin re-review queue: ${rereviewQueue.length}`,
      `- skill re-review queue: ${skillRereviewQueue.length}`,
      `- consent TTL minutes: ${pluginCfg.consentTtlMinutes}`,
      `- audit enabled: ${pluginCfg.audit.enabled ? "yes" : "no"}`,
      `- audit path: ${pluginCfg.audit.path ?? ".openclaw/agent-passport/audit.jsonl"}`
    ].join("\n"),
    interactive: pendingRequests.length
      ? { blocks: [{ type: "buttons", buttons: [{ label: `Review ${pendingRequests.length} pending`, value: "requests", style: "primary" }] }] }
      : undefined
  };
}

function formatFinding(finding: ScannerFinding) {
  const evidence = finding.evidence.slice(0, 2).map((item) => `    - ${item.filePath}:${item.line} — ${item.snippet}`);
  return [
    `- ${finding.category} [${finding.severity}; ${finding.signalType}]`,
    `  ${finding.summary}`,
    `  Recommendation: ${finding.recommendation}`,
    ...evidence
  ].join("\n");
}

function summarizeSignalCounts(findings: ScannerFinding[]) {
  const counts = {
    executable: 0,
    config: 0,
    documentation: 0
  };
  for (const finding of findings) {
    counts[finding.signalType] += 1;
  }
  return counts;
}

function getFindingPriority(finding: ScannerFinding) {
  const severityRank = finding.severity === "high" ? 3 : finding.severity === "medium" ? 2 : 1;
  const signalRank = finding.signalType === "executable" ? 3 : finding.signalType === "config" ? 2 : 1;
  const categoryBonus = finding.category === "manifest-lifecycle"
    ? 3
    : finding.category === "staged-payload" || finding.category === "persistence-autorun"
      ? 2
      : 0;
  return severityRank * 10 + signalRank * 3 + categoryBonus;
}

function selectFindingsForReply(report: ScannerReport) {
  const grouped = report.groupedFindings ?? [];
  const groupedRepresentatives = grouped
    .map((group) => report.findings.find((finding) => finding.id === group.representativeFindingId))
    .filter((finding): finding is ScannerFinding => Boolean(finding))
    .sort((a, b) => getFindingPriority(b) - getFindingPriority(a));

  const executableOrConfig = groupedRepresentatives.filter((finding) => finding.signalType !== "documentation");
  if (!executableOrConfig.length) return groupedRepresentatives.slice(0, 6);

  const documentation = groupedRepresentatives.filter((finding) => finding.signalType === "documentation");
  return [...executableOrConfig.slice(0, 5), ...documentation.slice(0, 1)].slice(0, 6);
}

function buildNarrativeHighlights(report: ScannerReport) {
  return (report.groupedFindings ?? [])
    .slice(0, 3)
    .map((group) => `- ${group.summary} (${group.signalTypes.join(", ")}; ${group.exploitability}; action=${group.recommendedAction})`);
}

function kindLabelForReply(targetKind: ScannerReport["targetKind"]) {
  if (targetKind === "skill") return "skill";
  if (targetKind === "plugin") return "plugin";
  if (targetKind === "package") return "package";
  if (targetKind === "hybrid") return "hybrid";
  return "artifact";
}

function decisionSummary(decision: PassportScanDecision) {
  if (decision === "trust") return "trusted";
  if (decision === "block") return "blocked";
  return "marked for review";
}

function buildPreflightDecision(input: { report: ScannerReport; scanReview?: PassportScanReview | null }) {
  const { report, scanReview } = input;
  const recommendation = report.packageRecommendation.action;
  const reviewDecision = scanReview?.decision ?? null;

  if (reviewDecision === "block") {
    return {
      allowed: false,
      disposition: "deny" as const,
      reason: "This artifact was explicitly blocked by an operator review decision."
    };
  }

  if (recommendation === "block-package") {
    if (reviewDecision === "trust") {
      return {
        allowed: true,
        disposition: "allow-with-override" as const,
        reason: "This artifact was scanner-blocked by default, but an explicit trust override exists for this exact fingerprint."
      };
    }
    return {
      allowed: false,
      disposition: "deny" as const,
      reason: "Scanner recommendation is block-package. Install or enable should stay blocked unless an explicit trust override is recorded for this exact fingerprint."
    };
  }

  if (recommendation === "review-before-trust") {
    if (reviewDecision === "trust") {
      return {
        allowed: true,
        disposition: "allow" as const,
        reason: "Scanner required review before trust, and an explicit trust decision exists for this exact fingerprint."
      };
    }
    if (reviewDecision === "review") {
      return {
        allowed: true,
        disposition: "allow-with-review" as const,
        reason: "Scanner required review before trust, and an explicit human review decision exists for this exact fingerprint."
      };
    }
    return {
      allowed: false,
      disposition: "needs-review" as const,
      reason: "Scanner requires explicit review before trust. Record /passport review <path> or /passport trust <path> before install or enable."
    };
  }

  if (reviewDecision === "trust") {
    return {
      allowed: true,
      disposition: "allow" as const,
      reason: "Artifact is scanner-allowed and has an explicit trust decision recorded."
    };
  }

  if (reviewDecision === "review") {
    return {
      allowed: true,
      disposition: "allow-with-review" as const,
      reason: "Artifact is scanner-allowed, and a review decision is already recorded for this exact fingerprint."
    };
  }

  return {
    allowed: true,
    disposition: recommendation === "monitor" ? "allow-with-review" as const : "allow" as const,
    reason: recommendation === "monitor"
      ? "Scanner posture is monitor. Install or enable can proceed, but keep this artifact under review."
      : "Scanner posture is allow. Install or enable can proceed unless a later review blocks it."
  };
}

function buildSuggestedReviewCommands(report: ScannerReport) {
  const escapedPath = report.scannedPath.includes(" ") ? `"${report.scannedPath}"` : report.scannedPath;
  const commands = report.packageRecommendation.action === "allow"
    ? [`/passport trust ${escapedPath}`]
    : report.packageRecommendation.action === "block-package"
      ? [`/passport block ${escapedPath}`, `/passport review ${escapedPath}`]
      : [`/passport review ${escapedPath}`, `/passport trust ${escapedPath}`];
  return commands.map((command) => `- ${command}`);
}

function buildScanReply(report: ScannerReport, scanReview?: PassportScanReview | null) {
  const signalCounts = summarizeSignalCounts(report.findings);
  const label = kindLabelForReply(report.targetKind);
  const highlightedFindings = selectFindingsForReply(report);
  const findings = report.findings.length
    ? highlightedFindings.map((finding) => formatFinding(finding)).join("\n\n")
    : "- No high-signal poisoned-package indicators were found in the scanned files.";
  const narrativeHighlights = buildNarrativeHighlights(report);
  const topRisks = (report.topRisks ?? []).slice(0, 3).map((risk, index) => `- ${index + 1}. ${risk.title} [${risk.exploitability}; ${risk.recommendedAction}]: ${risk.summary}`);
  const kindSensitiveNotes = (report.kindSensitiveNotes ?? []).slice(0, 3).map((note) => `- ${note}`);
  const suggestedCommands = !scanReview ? buildSuggestedReviewCommands(report) : [];
  const suppressedCount = Math.max(0, report.groupedFindings.length - highlightedFindings.length);

  return [
    `Agent Passport scan: ${report.scannedPath}`,
    `- fingerprint: ${report.fingerprint}`,
    `- verdict: ${report.verdict}`,
    `- recommended ${label} action: ${report.packageRecommendation.action}`,
    `- ${label} action reason: ${report.packageRecommendation.reason}`,
    ...(scanReview ? [`- current review state: ${decisionSummary(scanReview.decision)} at ${scanReview.createdAt}`] : []),
    `- score: ${report.score}/10`,
    `- target type: ${report.targetType}`,
    `- detected kind: ${report.targetKind}`,
    `- files scanned: ${report.fileCount}`,
    `- signals: executable=${signalCounts.executable}, config=${signalCounts.config}, documentation=${signalCounts.documentation}`,
    `- summary: ${report.summary}`,
    ...(kindSensitiveNotes.length ? ["", `Why this matters for this ${label}:`, ...kindSensitiveNotes] : []),
    ...(topRisks.length ? ["", "Top risks:", ...topRisks] : []),
    ...(narrativeHighlights.length ? ["", "Risk story:", ...narrativeHighlights] : []),
    ...(suggestedCommands.length ? ["", "Suggested next step:", ...suggestedCommands] : []),
    "",
    "Findings:",
    findings,
    ...(suppressedCount > 0 ? ["", `- ${suppressedCount} additional lower-priority or documentation-heavy finding(s) suppressed in chat output.`] : [])
  ].join("\n");
}

function buildActionSpecificNextSteps(action: "install" | "enable" | "update", report: ScannerReport, scanReview?: PassportScanReview | null, driftChanged = false) {
  const escapedPath = report.scannedPath.includes(" ") ? `"${report.scannedPath}"` : report.scannedPath;
  if (driftChanged && action === "enable" && scanReview?.decision !== "trust") {
    return [
      `- Deny ${action} for now because the installed source fingerprint drifted.`,
      `- Re-scan the current source: /passport scan ${escapedPath}`,
      `- If this new fingerprint is acceptable, explicitly trust it: /passport trust ${escapedPath}`
    ];
  }
  if (scanReview?.decision === "block") {
    return [`- This ${action} attempt should stay denied until the artifact is re-reviewed.`, `- Re-scan after changes: /passport scan ${escapedPath}`];
  }
  if (report.packageRecommendation.action === "block-package" && scanReview?.decision !== "trust") {
    return [`- Deny ${action}.`, `- If you intentionally want to override for this exact fingerprint: /passport trust ${escapedPath}`];
  }
  if (report.packageRecommendation.action === "review-before-trust" && !scanReview) {
    return [`- Deny ${action} for now.`, `- Record review: /passport review ${escapedPath}`, `- Or explicitly trust: /passport trust ${escapedPath}`];
  }
  if (report.packageRecommendation.action === "review-before-trust" && scanReview?.decision === "review") {
    return [`- ${action[0].toUpperCase() + action.slice(1)} is allowed because a human review decision exists for this fingerprint.`];
  }
  if (report.packageRecommendation.action === "block-package" && scanReview?.decision === "trust") {
    return [`- ${action[0].toUpperCase() + action.slice(1)} is allowed only because an explicit trust override exists for this fingerprint.`];
  }
  return [`- ${action[0].toUpperCase() + action.slice(1)} can proceed under current Passport policy.`];
}

function buildAuthorizationReply(input: {
  action: "install" | "enable" | "update";
  report: ScannerReport;
  scanReview?: PassportScanReview | null;
  preflight: ReturnType<typeof buildPreflightDecision>;
  drift?: {
    changed: boolean;
    recordedFingerprint: string;
    currentFingerprint: string;
    recordedRecommendation: string;
    currentRecommendation: string;
    recordedVerdict: string;
    currentVerdict: string;
  } | null;
}) {
  const { action, report, scanReview, preflight, drift } = input;
  const nextSteps = buildActionSpecificNextSteps(action, report, scanReview, Boolean(drift?.changed));
  return [
    `Agent Passport authorization: ${action} ${report.scannedPath}`,
    `- allowed now: ${preflight.allowed ? "yes" : "no"}`,
    `- disposition: ${preflight.disposition}`,
    `- reason: ${preflight.reason}`,
    `- scanner recommendation: ${report.packageRecommendation.action}`,
    ...(scanReview ? [`- review state: ${decisionSummary(scanReview.decision)} at ${scanReview.createdAt}`] : ["- review state: none recorded for this fingerprint"]),
    ...(drift ? [
      `- install drift detected: ${drift.changed ? "yes" : "no"}`,
      ...(drift.changed ? [
        `- recorded fingerprint: ${drift.recordedFingerprint}`,
        `- current fingerprint: ${drift.currentFingerprint}`,
        `- recorded verdict/recommendation: ${drift.recordedVerdict} / ${drift.recordedRecommendation}`,
        `- current verdict/recommendation: ${drift.currentVerdict} / ${drift.currentRecommendation}`
      ] : [])
    ] : []),
    "",
    `Next step for ${action}:`,
    ...nextSteps,
    "",
    buildScanReply(report, scanReview)
  ].join("\n");
}

function clipOutput(text: string, maxChars = 1200) {
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n...[truncated]`;
}

function shellQuote(value: string) {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

async function resolvePluginManifestPath(targetPath: string) {
  const absolute = resolve(targetPath);
  const info = await stat(absolute);
  if (info.isDirectory()) return join(absolute, "openclaw.plugin.json");
  return absolute;
}

async function loadOpenClawPluginMetadata(targetPath: string) {
  const manifestPath = await resolvePluginManifestPath(targetPath);
  const raw = await readFile(manifestPath, "utf8");
  const manifest = JSON.parse(raw) as { id?: unknown; name?: unknown };
  const pluginId = typeof manifest.id === "string" ? manifest.id.trim() : "";
  if (!pluginId) {
    throw new Error(`Plugin manifest at ${manifestPath} is missing a valid id.`);
  }
  return {
    manifestPath,
    pluginId,
    pluginName: typeof manifest.name === "string" ? manifest.name : pluginId
  };
}

function buildRunReply(input: Awaited<ReturnType<typeof runArtifactAction>>) {
  const base = buildAuthorizationReply(input);
  if (!input.preflight.allowed) {
    return [
      base,
      "",
      "Execution: blocked by Passport policy.",
      `- command not run: ${input.command}`,
      `- cwd: ${input.cwd}`
    ].join("\n");
  }

  if (!input.executed) {
    return [
      base,
      "",
      "Execution: dry run only.",
      `- command not run: ${input.command}`,
      `- cwd: ${input.cwd}`
    ].join("\n");
  }

  return [
    base,
    "",
    `Execution: ${input.execution?.ok ? "succeeded" : "failed"}.`,
    `- command: ${input.command}`,
    `- cwd: ${input.cwd}`,
    `- exit code: ${input.execution?.exitCode ?? "null"}`,
    ...(input.execution?.stdout ? ["", "stdout:", clipOutput(input.execution.stdout)] : []),
    ...(input.execution?.stderr ? ["", "stderr:", clipOutput(input.execution.stderr)] : [])
  ].join("\n");
}

function buildPluginStateReply(input: Awaited<ReturnType<typeof buildPluginState>>) {
  if (!input.ok || !input.latestInstall || !input.drift) {
    return `Agent Passport plugin state failed for ${input.pluginId}: ${input.reason}`;
  }

  return [
    `Agent Passport plugin state: ${input.pluginId}`,
    `- state: ${input.state}`,
    `- reason: ${input.reason}`,
    `- plugin name: ${input.latestInstall.pluginName}`,
    `- source: ${input.latestInstall.sourcePath}`,
    `- install count: ${input.installCount}`,
    `- installed at: ${input.latestInstall.installedAt}`,
    `- enabled at: ${input.latestInstall.enabledAt ?? "not recorded"}`,
    `- recorded review: ${input.latestInstall.reviewDecision ?? "none"}`,
    `- current review: ${input.currentReview ? decisionSummary(input.currentReview.decision) : "none recorded for current fingerprint"}`,
    `- trust tier: ${input.trustSummary.tier}`,
    `- trust reason: ${input.trustSummary.reason}`,
    `- provenance: ${input.trustSummary.provenance}`,
    `- recorded fingerprint: ${input.drift.recordedFingerprint}`,
    `- current fingerprint: ${input.drift.currentFingerprint}`,
    `- drift changed: ${input.drift.changed ? "yes" : "no"}`,
    `- recorded verdict/recommendation: ${input.drift.recordedVerdict} / ${input.drift.recordedRecommendation}`,
    `- current verdict/recommendation: ${input.drift.currentVerdict} / ${input.drift.currentRecommendation}`,
    "",
    "Recommended next steps:",
    ...input.recommendedActions.map((action) => `- ${action}`)
  ].join("\n");
}

function summarizeWorkspaceStateCounts<T extends { state: string; ok?: boolean | null }>(items: T[]) {
  return {
    total: items.length,
    trusted: items.filter((item) => item.state === "trusted" || item.state === "trusted-enabled" || item.state === "trusted-installed").length,
    reviewed: items.filter((item) => item.state === "reviewed").length,
    blocked: items.filter((item) => item.state === "blocked").length,
    rereviewRequired: items.filter((item) => item.state === "rereview-required").length,
    needsReview: items.filter((item) => item.state === "needs-review" || item.state === "dangerous-unreviewed" || item.state === "unreviewed").length,
    missing: items.filter((item) => item.ok === false || item.state === "missing").length
  };
}

export async function buildWorkspaceState() {
  const pluginInstalls = await listPluginInstalls();
  const latestPluginIds = [...new Set(pluginInstalls.map((record) => record.pluginId))].sort();
  const pluginStates = await Promise.all(latestPluginIds.map(async (pluginId) => buildPluginState({ pluginId })));
  const skillStates = await listSkillStates();
  const pluginRereview = await listPluginsNeedingRereview();
  const skillRereview = await listSkillsNeedingRereview();

  return {
    plugins: {
      counts: summarizeWorkspaceStateCounts(pluginStates.map((item) => ({ state: item.state ?? "missing", ok: item.ok }))),
      items: pluginStates
    },
    skills: {
      counts: summarizeWorkspaceStateCounts(skillStates.map((item) => ({ state: item.state, ok: item.ok }))),
      items: skillStates
    },
    attention: {
      pluginRereview,
      skillRereview,
      pluginCount: pluginRereview.length,
      skillCount: skillRereview.length,
      total: pluginRereview.length + skillRereview.length
    }
  };
}

function buildWorkspaceStateReply(input: Awaited<ReturnType<typeof buildWorkspaceState>>) {
  const pluginAttention = input.plugins.items.filter((item) => !item.ok || item.state === "rereview-required" || item.state === "blocked" || item.state === "unreviewed");
  const skillAttention = input.skills.items.filter((item) => !item.ok || item.state === "rereview-required" || item.state === "blocked" || item.state === "dangerous-unreviewed" || item.state === "needs-review" || item.state === "unreviewed");
  const trustedPluginTierCount = input.plugins.items.filter((item) => item.ok && item.trustSummary.tier === "trusted").length;
  const reviewRequiredPluginTierCount = input.plugins.items.filter((item) => item.ok && item.trustSummary.tier === "review-required").length;
  const trustedSkillTierCount = input.skills.items.filter((item) => item.ok && item.trustSummary.tier === "trusted").length;
  const reviewRequiredSkillTierCount = input.skills.items.filter((item) => item.ok && item.trustSummary.tier === "review-required").length;

  const text = [
    "Agent Passport workspace state:",
    `- plugin installs tracked: ${input.plugins.counts.total}`,
    `- plugins trusted: ${input.plugins.counts.trusted}`,
    `- plugins reviewed: ${input.plugins.counts.reviewed}`,
    `- plugins blocked: ${input.plugins.counts.blocked}`,
    `- plugin trust tiers: trusted=${trustedPluginTierCount}, review-required=${reviewRequiredPluginTierCount}`,
    `- plugins needing attention: ${pluginAttention.length}`,
    `- skills tracked: ${input.skills.counts.total}`,
    `- skills trusted: ${input.skills.counts.trusted}`,
    `- skills reviewed: ${input.skills.counts.reviewed}`,
    `- skills blocked: ${input.skills.counts.blocked}`,
    `- skill trust tiers: trusted=${trustedSkillTierCount}, review-required=${reviewRequiredSkillTierCount}`,
    `- skills needing attention: ${skillAttention.length}`,
    `- total re-review queue: ${input.attention.total}`,
    "",
    ...(pluginAttention.length ? [
      "Plugins needing attention:",
      ...pluginAttention.slice(0, 10).map((item) => `- ${item.pluginId}: ${item.state}${item.ok ? ` [${item.trustSummary.tier}] (${item.reason})` : ""}`),
      ""
    ] : []),
    ...(skillAttention.length ? [
      "Skills needing attention:",
      ...skillAttention.slice(0, 10).map((item) => `- ${item.slug}: ${item.state}${item.installedVersion ? ` (${item.installedVersion})` : ""}${item.ok ? ` [${item.trustSummary.tier}]` : ""}`),
      ""
    ] : []),
    "Recommended next steps:",
    ...(input.attention.pluginCount ? ["- /passport rereview-queue"] : []),
    ...(input.attention.skillCount ? ["- /passport skills-rereview"] : []),
    ...(!input.attention.total ? ["- No immediate re-review work. Spot check with /passport skills or /passport plugin-state <id>."] : [])
  ].join("\n");

  const buttons: { label: string; value: string; style?: "primary" | "secondary" | "success" | "danger" }[][] = [];
  const topPlugin = pluginAttention.find((item) => item.ok && item.state === "rereview-required") ?? pluginAttention.find((item) => item.ok);
  const topSkill = skillAttention.find((item) => item.ok && item.state === "rereview-required") ?? skillAttention.find((item) => item.ok);

  buttons.push([{ label: "Refresh workspace", value: "workspace", style: "primary" }]);
  if (topPlugin?.ok) {
    buttons.push([
      { label: `View plugin ${topPlugin.pluginId}`, value: `plugin-state:${topPlugin.pluginId}`, style: "primary" },
      { label: `Review plugin ${topPlugin.pluginId}`, value: `review-plugin:${topPlugin.pluginId}` },
      { label: `Trust plugin ${topPlugin.pluginId}`, value: `trust-plugin:${topPlugin.pluginId}`, style: "success" },
      { label: `Block plugin ${topPlugin.pluginId}`, value: `block-plugin:${topPlugin.pluginId}`, style: "danger" }
    ]);
  }
  if (topSkill?.ok) {
    buttons.push([
      { label: `View skill ${topSkill.slug}`, value: `skill-state:${topSkill.slug}`, style: "primary" },
      { label: `Review skill ${topSkill.slug}`, value: `review-skill:${topSkill.slug}` },
      { label: `Trust skill ${topSkill.slug}`, value: `trust-skill:${topSkill.slug}`, style: "success" },
      { label: `Block skill ${topSkill.slug}`, value: `block-skill:${topSkill.slug}`, style: "danger" }
    ]);
  }

  return {
    text,
    interactive: buttons.length ? { blocks: buttons.map((row) => ({ type: "buttons" as const, buttons: row })) } : undefined
  };
}

function parsePositiveIntegerOption(value: string | number | undefined, label: string) {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return Math.floor(parsed);
}

function buildWorkspaceAuditOptions(input: {
  workspaceRoot?: string;
  ledgerDir?: string;
  includePlugins?: boolean;
  includeSkills?: boolean;
  pluginsOnly?: boolean;
  skillsOnly?: boolean;
  maxItems?: string | number;
}): WorkspaceAuditOptions {
  if (input.pluginsOnly && input.skillsOnly) {
    throw new Error("Choose either plugins-only or skills-only, not both.");
  }

  return {
    workspaceRoot: input.workspaceRoot?.trim() || undefined,
    ledgerDir: input.ledgerDir?.trim() || undefined,
    includePlugins: input.pluginsOnly ? true : (input.skillsOnly ? false : input.includePlugins),
    includeSkills: input.skillsOnly ? true : (input.pluginsOnly ? false : input.includeSkills),
    maxItems: parsePositiveIntegerOption(input.maxItems, "max-items")
  };
}

async function inspectSkillArtifactWithReview(input: Parameters<typeof inspectSkillArtifact>[0]) {
  const inspection = await inspectSkillArtifact(input);
  const currentReview = inspection.scan ? await getLatestScanReview(inspection.scan.fingerprint) : null;
  return { inspection, currentReview };
}

function buildSkillInspectionReply(input: {
  inspection: Awaited<ReturnType<typeof inspectSkillArtifact>>;
  currentReview: PassportScanReview | null;
}) {
  const { inspection, currentReview } = input;
  const commandPath = inspection.stage.absoluteSourcePath ?? inspection.stage.sourcePath;
  const nextSteps: string[] = [];

  if (inspection.stage.sourceKind !== "local-path") {
    nextSteps.push(`Materialize the skill artifact locally, then rerun /passport inspect-skill ${inspection.stage.sourcePath}.`);
  } else if (currentReview?.decision === "trust") {
    nextSteps.push("This fingerprint already has an explicit trust decision.");
  } else if (currentReview?.decision === "block") {
    nextSteps.push("Keep this fingerprint blocked until the staged contents are reviewed again.");
  } else {
    nextSteps.push(`Review the staged contents, then record /passport review ${commandPath}, /passport trust ${commandPath}, or /passport block ${commandPath}.`);
  }

  return [
    "Agent Passport skill inspection:",
    `- source: ${inspection.stage.sourcePath}`,
    ...(inspection.stage.absoluteSourcePath ? [`- absolute source: ${inspection.stage.absoluteSourcePath}`] : []),
    `- source kind: ${inspection.stage.sourceKind}`,
    `- supported: ${inspection.stage.supported ? "yes" : "no"}`,
    `- copied into quarantine: ${inspection.stage.copied ? "yes" : "no"}`,
    `- quarantine root: ${inspection.stage.quarantineRoot}`,
    ...(inspection.stage.quarantinePath ? [`- quarantine path: ${inspection.stage.quarantinePath}`] : []),
    ...(inspection.stage.stagedPath ? [`- staged path: ${inspection.stage.stagedPath}`] : []),
    `- trust tier: ${inspection.trustTier.tier}`,
    `- trust reason: ${inspection.trustTier.reason}`,
    ...(inspection.scan ? [
      `- scanner verdict/recommendation: ${inspection.scan.verdict} / ${inspection.scan.packageRecommendation.action}`,
      `- fingerprint: ${inspection.scan.fingerprint}`,
      `- current review: ${currentReview ? decisionSummary(currentReview.decision) : "none recorded for this fingerprint"}`
    ] : []),
    `- summary: ${inspection.summary}`,
    ...(inspection.provenance.limitations.length ? [
      "",
      "Limitations:",
      ...inspection.provenance.limitations.map((line) => `- ${line}`)
    ] : []),
    ...(nextSteps.length ? [
      "",
      "Next steps:",
      ...nextSteps.map((line) => `- ${line}`)
    ] : []),
    ...(inspection.scan ? ["", buildScanReply(inspection.scan, currentReview)] : [])
  ].join("\n");
}

async function buildArtifactPreflight(targetPath: string) {
  const report = await scanPath(targetPath);
  const scanReview = await getLatestScanReview(report.fingerprint);
  const preflight = buildPreflightDecision({ report, scanReview });
  return { report, scanReview, preflight };
}

async function buildArtifactAuthorization(input: { action: "install" | "enable" | "update"; targetPath: string }) {
  const result = await buildArtifactPreflight(input.targetPath);
  let drift: {
    changed: boolean;
    recordedFingerprint: string;
    currentFingerprint: string;
    recordedRecommendation: string;
    currentRecommendation: string;
    recordedVerdict: string;
    currentVerdict: string;
  } | null = null;

  if (input.action === "enable" || input.action === "update") {
    try {
      const metadata = await loadOpenClawPluginMetadata(input.targetPath);
      const record = await getLatestPluginInstall({ pluginId: metadata.pluginId });
      if (record) {
        drift = {
          changed: result.report.fingerprint !== record.fingerprint,
          recordedFingerprint: record.fingerprint,
          currentFingerprint: result.report.fingerprint,
          recordedRecommendation: record.recommendationAction,
          currentRecommendation: result.report.packageRecommendation.action,
          recordedVerdict: record.verdict,
          currentVerdict: result.report.verdict
        };

        if (drift.changed && result.scanReview?.decision !== "trust") {
          result.preflight = {
            allowed: false,
            disposition: "needs-review",
            reason: `Recorded install fingerprint for plugin ${metadata.pluginId} no longer matches this source path. Re-trust the new fingerprint before enable.`
          };
        }
      }
    } catch {
      // If we cannot derive plugin metadata here, fall back to plain artifact policy.
    }
  }

  return { action: input.action, ...result, drift };
}

async function resolveArtifactCommandCwd(targetPath: string) {
  const absolute = resolve(targetPath);
  try {
    const info = await stat(absolute);
    return info.isDirectory() ? absolute : dirname(absolute);
  } catch {
    return dirname(absolute);
  }
}

async function runShellCommand(command: string, cwd: string) {
  return await new Promise<{
    ok: boolean;
    exitCode: number | null;
    stdout: string;
    stderr: string;
  }>((resolvePromise) => {
    const child = spawn("/bin/sh", ["-lc", command], {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });

    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });

    child.on("close", (exitCode) => {
      resolvePromise({
        ok: exitCode === 0,
        exitCode,
        stdout,
        stderr
      });
    });

    child.on("error", (error) => {
      stderr += error instanceof Error ? error.message : String(error);
      resolvePromise({
        ok: false,
        exitCode: null,
        stdout,
        stderr
      });
    });
  });
}

async function runArtifactAction(input: {
  action: "install" | "enable" | "update";
  targetPath: string;
  command: string;
  dryRun?: boolean;
}) {
  const authorization = await buildArtifactAuthorization({ action: input.action, targetPath: input.targetPath });
  if (!authorization.preflight.allowed || input.dryRun) {
    return {
      ...authorization,
      executed: false,
      execution: null,
      command: input.command,
      cwd: await resolveArtifactCommandCwd(input.targetPath)
    };
  }

  const cwd = await resolveArtifactCommandCwd(input.targetPath);
  const execution = await runShellCommand(input.command, cwd);
  return {
    ...authorization,
    executed: true,
    execution,
    command: input.command,
    cwd
  };
}

async function installOpenClawPluginFromPath(input: {
  path: string;
  link?: boolean;
  pin?: boolean;
  enableAfterInstall?: boolean;
  dryRun?: boolean;
}) {
  const absolutePath = resolve(input.path);
  const metadata = await loadOpenClawPluginMetadata(absolutePath);
  const flags = [
    input.link ? "--link" : null,
    input.pin ? "--pin" : null
  ].filter(Boolean).join(" ");
  const installCommand = `openclaw plugins install ${flags ? `${flags} ` : ""}${shellQuote(absolutePath)}`;
  const installResult = await runArtifactAction({
    action: "install",
    targetPath: absolutePath,
    command: installCommand,
    dryRun: input.dryRun
  });

  let installRecord = null;
  if (installResult.executed && installResult.execution?.ok) {
    installRecord = await recordPluginInstall({
      pluginId: metadata.pluginId,
      pluginName: metadata.pluginName,
      sourcePath: absolutePath,
      manifestPath: metadata.manifestPath,
      report: installResult.report,
      scanReview: installResult.scanReview,
      installCommand,
      linked: Boolean(input.link),
      pinned: Boolean(input.pin)
    });
  }

  if (!input.enableAfterInstall) {
    return {
      pluginId: metadata.pluginId,
      pluginName: metadata.pluginName,
      install: installResult,
      installRecord,
      enable: null
    };
  }

  const enableCommand = `openclaw plugins enable ${shellQuote(metadata.pluginId)}`;
  const enableResult = await runArtifactAction({
    action: "enable",
    targetPath: absolutePath,
    command: enableCommand,
    dryRun: input.dryRun || !installResult.executed || !installResult.execution?.ok
  });

  let enabledRecord = null;
  if (enableResult.executed && enableResult.execution?.ok) {
    enabledRecord = await markPluginEnabled({ pluginId: metadata.pluginId });
  }

  return {
    pluginId: metadata.pluginId,
    pluginName: metadata.pluginName,
    install: installResult,
    installRecord,
    enable: enableResult,
    enabledRecord
  };
}

async function enableOpenClawPluginFromPath(input: {
  path: string;
  dryRun?: boolean;
}) {
  const absolutePath = resolve(input.path);
  const metadata = await loadOpenClawPluginMetadata(absolutePath);
  const enableCommand = `openclaw plugins enable ${shellQuote(metadata.pluginId)}`;
  const enableResult = await runArtifactAction({
    action: "enable",
    targetPath: absolutePath,
    command: enableCommand,
    dryRun: input.dryRun
  });
  const enabledRecord = enableResult.executed && enableResult.execution?.ok
    ? await markPluginEnabled({ pluginId: metadata.pluginId })
    : null;
  return {
    pluginId: metadata.pluginId,
    pluginName: metadata.pluginName,
    manifestPath: metadata.manifestPath,
    enable: enableResult,
    enabledRecord
  };
}

async function updateOpenClawPluginFromLedger(input: {
  pluginId: string;
  dryRun?: boolean;
}) {
  const record = await getLatestPluginInstall({ pluginId: input.pluginId });
  if (!record) {
    throw new Error(`No recorded Passport install found for plugin ${input.pluginId}.`);
  }

  const updateCommand = `openclaw plugins update ${shellQuote(record.pluginId)}`;
  const updateResult = await runArtifactAction({
    action: "update",
    targetPath: record.sourcePath,
    command: updateCommand,
    dryRun: input.dryRun
  });

  let updatedRecord = null;
  if (updateResult.executed && updateResult.execution?.ok) {
    updatedRecord = await recordPluginInstall({
      pluginId: record.pluginId,
      pluginName: record.pluginName,
      sourcePath: record.sourcePath,
      manifestPath: record.manifestPath,
      report: updateResult.report,
      scanReview: updateResult.scanReview,
      installCommand: updateCommand,
      linked: record.linked,
      pinned: record.pinned,
      enabledAt: record.enabledAt
    });
  }

  return {
    pluginId: record.pluginId,
    pluginName: record.pluginName,
    sourcePath: record.sourcePath,
    update: updateResult,
    updatedRecord
  };
}

function authorizeSkillUpdateState(state: Awaited<ReturnType<typeof buildSkillState>>) {
  if (!state.ok) {
    return {
      allowed: false,
      reason: state.reason ?? "Skill state is unavailable, so update should stay blocked."
    };
  }

  if (!state.tracked) {
    return {
      allowed: false,
      reason: "Skill is not tracked as a workspace ClawHub install, so Passport should not update it blindly."
    };
  }

  if (state.state === "trusted") {
    return {
      allowed: true,
      reason: "Skill is currently trusted for its installed fingerprint."
    };
  }

  if (state.state === "rereview-required") {
    return {
      allowed: false,
      reason: "Installed skill drifted since the last trusted review. Re-review and re-trust before update."
    };
  }

  if (state.state === "blocked") {
    return {
      allowed: false,
      reason: "Skill is explicitly blocked."
    };
  }

  return {
    allowed: false,
    reason: `Skill state is ${state.state}. Passport requires an explicit trust decision before update.`
  };
}

export async function updateOpenClawSkill(input: {
  slug: string;
  dryRun?: boolean;
}) {
  const slug = input.slug.trim();
  if (!slug) {
    throw new Error("Skill slug is required.");
  }

  const tracked = (await readTrackedSkillLock()).skills[slug] ?? null;
  const origin = await readTrackedSkillOrigin(slug);
  if (!tracked && !origin) {
    throw new Error(`Skill ${slug} is not tracked as a ClawHub-installed workspace skill.`);
  }

  const skillDir = resolveWorkspaceSkillDir(slug);
  const beforeState = await buildSkillState({ slug });
  const updateCommand = `openclaw skills update ${shellQuote(slug)}`;
  const authorization = authorizeSkillUpdateState(beforeState);

  if (input.dryRun || !authorization.allowed) {
    return {
      slug,
      skillDir,
      updateCommand,
      authorized: authorization.allowed,
      authorizationReason: authorization.reason,
      executed: false,
      execution: null,
      beforeState,
      afterState: null,
      drift: null
    };
  }

  const execution = await runShellCommand(updateCommand, getWorkspaceRoot());
  const afterState = execution.ok ? await buildSkillState({ slug }) : null;
  const drift = execution.ok ? await checkSkillDrift({ slug }) : null;

  return {
    slug,
    skillDir,
    updateCommand,
    authorized: authorization.allowed,
    authorizationReason: authorization.reason,
    executed: true,
    execution,
    beforeState,
    afterState,
    drift
  };
}

export async function updateAllOpenClawSkills(input?: {
  dryRun?: boolean;
}) {
  const slugs = await listTrackedSkillSlugs();
  const beforeStates = await Promise.all(slugs.map(async (slug) => [slug, await buildSkillState({ slug })] as const));
  const updateCommand = "openclaw skills update --all";
  const authorization = beforeStates
    .map(([slug, state]) => ({ slug, ...authorizeSkillUpdateState(state) }))
    .filter((item) => !item.allowed);

  if (input?.dryRun || authorization.length > 0) {
    return {
      slugs,
      updateCommand,
      authorized: authorization.length === 0,
      authorizationReason: authorization.length === 0
        ? "All tracked skills are currently trusted for their installed fingerprint."
        : `Blocked because ${authorization.length} tracked skill(s) are not trusted for update.`,
      blocked: authorization,
      executed: false,
      execution: null,
      beforeStates,
      afterStates: null,
      summary: {
        trackedCount: slugs.length,
        changedCount: 0,
        trustedCount: 0,
        reviewedCount: 0,
        blockedCount: 0,
        rereviewRequiredCount: 0,
        missingCount: beforeStates.filter(([, state]) => !state.ok || state.state === "missing").length
      }
    };
  }

  const execution = await runShellCommand(updateCommand, getWorkspaceRoot());
  const afterStates = execution.ok
    ? await Promise.all(slugs.map(async (slug) => [slug, await buildSkillState({ slug })] as const))
    : null;

  const beforeMap = new Map(beforeStates);
  const afterMap = new Map(afterStates ?? []);
  const changedCount = afterStates
    ? slugs.filter((slug) => {
        const before = beforeMap.get(slug);
        const after = afterMap.get(slug);
        return Boolean(before?.fingerprint && after?.fingerprint && before.fingerprint !== after.fingerprint);
      }).length
    : 0;

  const states = (afterStates ?? beforeStates).map(([, state]) => state);
  const summary = {
    trackedCount: slugs.length,
    changedCount,
    trustedCount: states.filter((state) => state.state === "trusted").length,
    reviewedCount: states.filter((state) => state.state === "reviewed").length,
    blockedCount: states.filter((state) => state.state === "blocked").length,
    rereviewRequiredCount: states.filter((state) => state.state === "rereview-required").length,
    missingCount: states.filter((state) => !state.ok || state.state === "missing").length
  };

  return {
    slugs,
    updateCommand,
    authorized: true,
    authorizationReason: "All tracked skills were trusted for update.",
    blocked: [],
    executed: true,
    execution,
    beforeStates,
    afterStates,
    summary
  };
}

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

function getWorkspaceRoot() {
  const explicit = process.env.OPENCLAW_WORKSPACE_DIR?.trim();
  if (explicit) return resolve(explicit);

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

function resolveWorkspaceSkillDir(slug: string) {
  return resolve(getWorkspaceRoot(), "skills", slug);
}

async function readTrackedSkillLock(): Promise<TrackedSkillLock> {
  try {
    const raw = JSON.parse(await readFile(resolve(getWorkspaceRoot(), ".clawhub", "lock.json"), "utf8")) as Partial<TrackedSkillLock>;
    return {
      version: 1,
      skills: raw.skills && typeof raw.skills === "object" ? raw.skills : {}
    };
  } catch {
    return { version: 1, skills: {} };
  }
}

async function readTrackedSkillOrigin(slug: string): Promise<TrackedSkillOrigin | null> {
  try {
    const raw = JSON.parse(await readFile(resolve(resolveWorkspaceSkillDir(slug), ".clawhub", "origin.json"), "utf8")) as Partial<TrackedSkillOrigin>;
    if (raw.version === 1 && typeof raw.registry === "string" && typeof raw.slug === "string" && typeof raw.installedVersion === "string" && typeof raw.installedAt === "number") {
      return raw as TrackedSkillOrigin;
    }
    return null;
  } catch {
    return null;
  }
}

async function listTrackedSkillSlugs() {
  const lock = await readTrackedSkillLock();
  return Object.keys(lock.skills).sort();
}

export async function checkSkillDrift(input: { slug: string }) {
  const slug = input.slug.trim();
  const baseline = await getLatestSkillReviewRecord(slug);
  const skillDir = resolveWorkspaceSkillDir(slug);
  const origin = await readTrackedSkillOrigin(slug);
  const tracked = (await readTrackedSkillLock()).skills[slug] ?? null;

  if (!baseline) {
    return {
      slug,
      ok: false,
      reason: "No Passport skill review baseline found for that slug.",
      skillDir,
      installedVersion: origin?.installedVersion ?? tracked?.version ?? null,
      baseline: null,
      currentReport: null,
      currentReview: null,
      drift: null
    };
  }

  const currentReport = await scanPath(skillDir);
  const currentReview = await getLatestScanReview(currentReport.fingerprint);
  const drift = {
    changed: currentReport.fingerprint !== baseline.fingerprint,
    recordedFingerprint: baseline.fingerprint,
    currentFingerprint: currentReport.fingerprint,
    recordedRecommendation: baseline.recommendationAction,
    currentRecommendation: currentReport.packageRecommendation.action,
    recordedVerdict: baseline.verdict,
    currentVerdict: currentReport.verdict
  };

  return {
    slug,
    ok: true,
    reason: drift.changed
      ? "Installed skill fingerprint drifted since the last Passport skill review."
      : "Installed skill fingerprint still matches the last Passport skill review.",
    skillDir,
    installedVersion: origin?.installedVersion ?? tracked?.version ?? null,
    baseline,
    currentReport,
    currentReview,
    drift
  };
}

export async function buildSkillState(input: { slug: string }) {
  const slug = input.slug.trim();
  const lock = await readTrackedSkillLock();
  const tracked = lock.skills[slug] ?? null;
  const skillDir = resolveWorkspaceSkillDir(slug);
  const origin = await readTrackedSkillOrigin(slug);
  const baseline = await getLatestSkillReviewRecord(slug);

  try {
    const report = await scanPath(skillDir);
    const scanReview = await getLatestScanReview(report.fingerprint);
    const drift = baseline ? {
      changed: report.fingerprint !== baseline.fingerprint,
      recordedFingerprint: baseline.fingerprint,
      currentFingerprint: report.fingerprint,
      recordedRecommendation: baseline.recommendationAction,
      currentRecommendation: report.packageRecommendation.action,
      recordedVerdict: baseline.verdict,
      currentVerdict: report.verdict
    } : null;
    let state = "unreviewed";
    const recommendedActions: string[] = [
      `/passport scan ${skillDir}`
    ];
    const trustSummary = buildArtifactTrustSummary({
      artifactKind: "skill",
      reviewDecision: scanReview?.decision ?? null,
      recommendationAction: report.packageRecommendation.action,
      verdict: report.verdict,
      driftChanged: drift?.changed ?? false,
      fingerprint: report.fingerprint,
      registry: origin?.registry ?? null,
      sourcePath: skillDir
    });

    if (drift?.changed && scanReview?.decision !== "trust") {
      state = "rereview-required";
      recommendedActions.push(`/passport review-skill ${slug}`);
      recommendedActions.push(`/passport trust-skill ${slug}`);
      recommendedActions.push(`/passport block-skill ${slug}`);
      recommendedActions.push(`/passport drift-skill ${slug}`);
    } else if (scanReview?.decision === "trust") {
      state = "trusted";
      recommendedActions.push(`/passport skill-state ${slug}`);
    } else if (scanReview?.decision === "review") {
      state = "reviewed";
      recommendedActions.push(`/passport trust-skill ${slug}`);
      recommendedActions.push(`/passport block-skill ${slug}`);
    } else if (scanReview?.decision === "block") {
      state = "blocked";
      recommendedActions.push(`/passport skill-state ${slug}`);
    } else if (report.packageRecommendation.action === "block-package") {
      state = "dangerous-unreviewed";
      recommendedActions.push(`/passport block-skill ${slug}`);
      recommendedActions.push(`/passport review-skill ${slug}`);
    } else {
      state = report.packageRecommendation.action === "review-before-trust" ? "needs-review" : "unreviewed";
      recommendedActions.push(`/passport review-skill ${slug}`);
      recommendedActions.push(`/passport trust-skill ${slug}`);
      recommendedActions.push(`/passport block-skill ${slug}`);
    }

    return {
      slug,
      ok: true,
      tracked: Boolean(tracked || origin),
      state,
      skillDir,
      installedVersion: origin?.installedVersion ?? tracked?.version ?? null,
      installedAt: origin?.installedAt ?? tracked?.installedAt ?? null,
      registry: origin?.registry ?? null,
      fingerprint: report.fingerprint,
      verdict: report.verdict,
      recommendation: report.packageRecommendation.action,
      currentReview: scanReview ?? null,
      trustSummary,
      baseline,
      drift,
      recommendedActions
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      slug,
      ok: false,
      tracked: Boolean(tracked || origin),
      state: "missing",
      skillDir,
      installedVersion: origin?.installedVersion ?? tracked?.version ?? null,
      installedAt: origin?.installedAt ?? tracked?.installedAt ?? null,
      registry: origin?.registry ?? null,
      fingerprint: null,
      verdict: null,
      recommendation: null,
      currentReview: null,
      trustSummary: buildArtifactTrustSummary({
        artifactKind: "skill",
        reviewDecision: null,
        recommendationAction: null,
        verdict: null,
        driftChanged: false,
        fingerprint: null,
        registry: origin?.registry ?? null,
        sourcePath: skillDir
      }),
      baseline,
      drift: null,
      recommendedActions: [],
      reason: message
    };
  }
}

function buildSkillStateReply(input: Awaited<ReturnType<typeof buildSkillState>>) {
  if (!input.ok) {
    return [
      `Agent Passport skill state: ${input.slug}`,
      `- state: ${input.state}`,
      `- tracked: ${input.tracked ? "yes" : "no"}`,
      `- skill dir: ${input.skillDir}`,
      `- installed version: ${input.installedVersion ?? "unknown"}`,
      `- reason: ${input.reason ?? "unavailable"}`
    ].join("\n");
  }

  return [
    `Agent Passport skill state: ${input.slug}`,
    `- state: ${input.state}`,
    `- tracked: ${input.tracked ? "yes" : "no"}`,
    `- skill dir: ${input.skillDir}`,
    `- installed version: ${input.installedVersion ?? "unknown"}`,
    `- installed at: ${input.installedAt ? new Date(input.installedAt).toISOString() : "unknown"}`,
    `- registry: ${input.registry ?? "unknown"}`,
    `- fingerprint: ${input.fingerprint}`,
    `- verdict/recommendation: ${input.verdict} / ${input.recommendation}`,
    `- current review: ${input.currentReview ? decisionSummary(input.currentReview.decision) : "none recorded for current fingerprint"}`,
    `- trust tier: ${input.trustSummary.tier}`,
    `- trust reason: ${input.trustSummary.reason}`,
    `- provenance: ${input.trustSummary.provenance}`,
    ...(input.baseline ? [
      `- last skill review fingerprint: ${input.baseline.fingerprint}`,
      `- last skill review decision: ${decisionSummary(input.baseline.decision)}`,
      `- skill drift changed: ${input.drift?.changed ? "yes" : "no"}`
    ] : ["- last skill review fingerprint: none recorded"]),
    ...(input.drift?.changed ? [
      `- recorded verdict/recommendation: ${input.drift.recordedVerdict} / ${input.drift.recordedRecommendation}`,
      `- current verdict/recommendation: ${input.drift.currentVerdict} / ${input.drift.currentRecommendation}`
    ] : []),
    "",
    "Recommended next steps:",
    ...input.recommendedActions.map((action) => `- ${action}`)
  ].join("\n");
}

async function listSkillStates() {
  const slugs = await listTrackedSkillSlugs();
  const results = [] as Awaited<ReturnType<typeof buildSkillState>>[];
  for (const slug of slugs) {
    results.push(await buildSkillState({ slug }));
  }
  return results;
}

export async function listSkillsNeedingRereview() {
  const states = await listSkillStates();
  return states
    .filter((item) => item.ok && item.state === "rereview-required" && item.drift)
    .map((item) => ({
      slug: item.slug,
      skillDir: item.skillDir,
      installedVersion: item.installedVersion,
      recordedFingerprint: item.drift!.recordedFingerprint,
      currentFingerprint: item.drift!.currentFingerprint,
      recordedRecommendation: item.drift!.recordedRecommendation,
      currentRecommendation: item.drift!.currentRecommendation,
      currentReviewDecision: item.currentReview?.decision ?? null,
      reason: "Installed skill fingerprint drifted and the new fingerprint is not explicitly trusted."
    }));
}

export async function applySkillDecision(input: {
  slug: string;
  decision: PassportScanDecision;
  senderId?: string;
  note?: string;
}) {
  const slug = input.slug.trim();
  const skillDir = resolveWorkspaceSkillDir(slug);
  const result = await applyScanDecision({
    targetPath: skillDir,
    decision: input.decision,
    senderId: input.senderId,
    note: input.note ?? `Recorded via skill slug ${slug}`
  });
  const origin = await readTrackedSkillOrigin(slug);
  await recordSkillReview({
    slug,
    skillDir,
    installedVersion: origin?.installedVersion ?? null,
    review: result.review
  });
  return result;
}

async function checkPluginInstallDrift(input: { pluginId: string }) {
  const record = await getLatestPluginInstall({ pluginId: input.pluginId });
  if (!record) {
    return {
      pluginId: input.pluginId,
      ok: false,
      reason: "No recorded Passport install found for that plugin id.",
      record: null,
      currentReport: null,
      currentReview: null,
      drift: null
    };
  }

  const currentReport = await scanPath(record.sourcePath);
  const currentReview = await getLatestScanReview(currentReport.fingerprint);
  const drift = {
    changed: currentReport.fingerprint !== record.fingerprint,
    recordedFingerprint: record.fingerprint,
    currentFingerprint: currentReport.fingerprint,
    recordedRecommendation: record.recommendationAction,
    currentRecommendation: currentReport.packageRecommendation.action,
    recordedVerdict: record.verdict,
    currentVerdict: currentReport.verdict
  };

  return {
    pluginId: record.pluginId,
    ok: true,
    reason: drift.changed
      ? "Source artifact fingerprint drifted since the recorded install."
      : "Source artifact fingerprint still matches the recorded install.",
    record,
    currentReport,
    currentReview,
    drift
  };
}

export async function applyPluginDecision(input: {
  pluginId: string;
  decision: PassportScanDecision;
  senderId?: string;
  note?: string;
}) {
  const pluginId = input.pluginId.trim();
  const record = await getLatestPluginInstall({ pluginId });
  if (!record) {
    throw new Error(`No recorded Passport install found for plugin ${pluginId}.`);
  }
  return await applyScanDecision({
    targetPath: record.sourcePath,
    decision: input.decision,
    senderId: input.senderId,
    note: input.note ?? `Recorded via plugin id ${pluginId}`
  });
}

export async function buildPluginState(input: { pluginId: string }) {
  const installs = await listPluginInstalls({ pluginId: input.pluginId });
  if (!installs.length) {
    return {
      pluginId: input.pluginId,
      ok: false,
      reason: "No recorded Passport install found for that plugin id.",
      latestInstall: null,
      installCount: 0,
      drift: null,
      currentReview: null,
      trustSummary: buildArtifactTrustSummary({
        artifactKind: "plugin",
        reviewDecision: null,
        recommendationAction: null,
        verdict: null,
        driftChanged: false,
        fingerprint: null,
        sourcePath: null
      }),
      state: null,
      recommendedActions: [] as string[]
    };
  }

  const driftCheck = await checkPluginInstallDrift({ pluginId: input.pluginId });
  if (!driftCheck.ok || !driftCheck.record || !driftCheck.currentReport) {
    return {
      pluginId: input.pluginId,
      ok: false,
      reason: driftCheck.reason,
      latestInstall: null,
      installCount: installs.length,
      drift: null,
      currentReview: null,
      trustSummary: buildArtifactTrustSummary({
        artifactKind: "plugin",
        reviewDecision: null,
        recommendationAction: null,
        verdict: null,
        driftChanged: false,
        fingerprint: null,
        sourcePath: null
      }),
      state: null,
      recommendedActions: [] as string[]
    };
  }

  const latestInstall = driftCheck.record;
  const currentReview = driftCheck.currentReview;
  const drift = driftCheck.drift!;
  const sourcePath = latestInstall.sourcePath;
  const trustSummary = buildArtifactTrustSummary({
    artifactKind: "plugin",
    reviewDecision: currentReview?.decision ?? null,
    recommendationAction: drift.currentRecommendation,
    verdict: drift.currentVerdict,
    driftChanged: drift.changed,
    fingerprint: drift.currentFingerprint,
    sourcePath
  });
  const recommendedActions: string[] = [];
  let state = "healthy";

  if (drift.changed && currentReview?.decision !== "trust") {
    state = "rereview-required";
    recommendedActions.push(`/passport scan ${sourcePath}`);
    recommendedActions.push(`/passport review-plugin ${input.pluginId}`);
    recommendedActions.push(`/passport trust-plugin ${input.pluginId}`);
    recommendedActions.push(`/passport block-plugin ${input.pluginId}`);
  } else if (drift.changed && currentReview?.decision === "trust") {
    state = "drift-trusted";
    recommendedActions.push(`/passport update-plugin ${input.pluginId} --dry-run`);
  } else if (currentReview?.decision === "block") {
    state = "blocked";
    recommendedActions.push(`/passport plugin-state ${input.pluginId}`);
  } else if (currentReview?.decision === "review") {
    state = "reviewed";
    recommendedActions.push(`/passport trust-plugin ${input.pluginId}`);
    recommendedActions.push(`/passport block-plugin ${input.pluginId}`);
  } else if (currentReview?.decision === "trust") {
    state = latestInstall.enabledAt ? "trusted-enabled" : "trusted-installed";
    if (!latestInstall.enabledAt) {
      recommendedActions.push(`/passport enable-plugin ${sourcePath} --dry-run`);
    }
    recommendedActions.push(`/passport update-plugin ${input.pluginId} --dry-run`);
  } else {
    state = "unreviewed";
    recommendedActions.push(`/passport review-plugin ${input.pluginId}`);
    recommendedActions.push(`/passport trust-plugin ${input.pluginId}`);
    recommendedActions.push(`/passport block-plugin ${input.pluginId}`);
  }

  recommendedActions.push(`/passport drift-plugin ${input.pluginId}`);

  return {
    pluginId: input.pluginId,
    ok: true,
    reason: driftCheck.reason,
    latestInstall,
    installCount: installs.length,
    drift,
    currentReview,
    trustSummary,
    state,
    recommendedActions
  };
}

async function applyScanDecision(input: {
  targetPath: string;
  decision: PassportScanDecision;
  note?: string;
  senderId?: string;
}) {
  const report = await scanPath(input.targetPath);
  const review = await recordScanReview({
    report,
    decision: input.decision,
    note: input.note
  });
  await appendAuditRecord({
    kind: "scan_review",
    senderId: input.senderId,
    targetPath: input.targetPath,
    review,
    report
  });
  return { report, review };
}

async function handleConsentRequired(input: {
  api: Parameters<NonNullable<ReturnType<typeof definePluginEntry>["register"]>>[0];
  scope: GuardedScope;
  target: string;
  decision: ReturnType<typeof evaluateOutboundCommunication>;
  pluginCfg: LoadedPluginConfig;
  auditRecord: Record<string, unknown>;
}) {
  const { api, scope, target, decision, pluginCfg, auditRecord } = input;
  const effectiveMode = getModeForScope(scope, pluginCfg);
  const request = await createConsentRequest({
    target,
    action: scope,
    reason: decision.reason
  });

  await appendAuditRecord({
    ...auditRecord,
    decision,
    scope,
    mode: effectiveMode,
    globalMode: pluginCfg.mode,
    effectiveMode,
    consentRequestId: request.id
  });

  if (effectiveMode === "audit") return;
  if (effectiveMode === "warn") {
    api.logger.warn?.(`agent-passport: ${scope} would require consent for ${target} (${decision.matchedRule}, request=${request.id})`);
    return;
  }

  if (scope === "message_sending") {
    return { cancel: true as const };
  }

  return {
    block: true,
    blockReason: buildDecisionText("Agent Passport blocked outbound action pending explicit consent", decision.matchedRule, effectiveMode, request.id)
  };
}

export default definePluginEntry({
  id: "agent-passport",
  name: "Agent Passport",
  description: "Scanner-first trust layer for poisoned skills, plugins, drift review, runtime policy checks, and audit logging in OpenClaw",
  register(api) {
    const currentConfig = () => {
      const cfg = getPluginConfig((api.pluginConfig ?? {}) as Record<string, unknown>);
      configureAuditRuntime(cfg.audit);
      return cfg;
    };

    currentConfig();

    api.on("before_dispatch", async (event, ctx) => {
      const decision = evaluateInboundDispatch({
        channel: event.channel ?? ctx.channelId,
        sessionKey: event.sessionKey ?? ctx.sessionKey,
        senderId: event.senderId ?? ctx.senderId,
        isGroup: event.isGroup,
        content: event.content,
        body: event.body
      });

      await appendAuditRecord({
        kind: "before_dispatch",
        event,
        context: ctx,
        decision
      });

      if (decision.severity === "high") {
        api.logger.warn?.(`agent-passport: inbound dispatch flagged ${decision.category} (${decision.matchedRule})`);
      } else if (decision.severity === "medium") {
        api.logger.info?.(`agent-passport: inbound dispatch audit raised ${decision.category} (${decision.matchedRule})`);
      }
    }, { priority: EARLY_SECURITY_HOOK_PRIORITY });

    api.on("message_sending", async (event, ctx) => {
      if (isForwardedNativePluginApprovalMessage(event.content)) {
        return;
      }

      const pluginCfg = currentConfig();
      const target = normalizeTarget(event.to);
      const trustedMatch = getTrustedMatch(target, "message_sending", pluginCfg);

      if (trustedMatch) {
        await appendAuditRecord({
          kind: "message_sending",
          channelId: ctx.channelId,
          conversationId: ctx.conversationId,
          event,
          decision: {
            outcome: "allow",
            severity: "low",
            category: "externalMessaging",
            reason: trustedMatch.reason,
            matchedRule: trustedMatch.matchedRule
          }
        });
        return;
      }

      if (await hasConsentForTarget(target)) {
        await appendAuditRecord({
          kind: "message_sending",
          channelId: ctx.channelId,
          conversationId: ctx.conversationId,
          event,
          decision: {
            outcome: "allow",
            severity: "low",
            category: "externalMessaging",
            reason: "Active consent grant found for outbound target.",
            matchedRule: "active-consent"
          }
        });
        return;
      }

      const decision = evaluateOutboundCommunication({
        to: event.to,
        content: event.content,
        target
      });

      if (getModeForScope("message_sending", pluginCfg) === "enforce" && (decision.outcome === "deny" || decision.outcome === "require_consent")) {
        const approvalResult = await handleNativeMessageSendingApproval({
          config: api.config,
          pluginId: api.id,
          logger: api.logger,
          event,
          ctx,
          target,
          decision,
          pluginCfg,
          auditRecord: {
            kind: "message_sending",
            channelId: ctx.channelId,
            conversationId: ctx.conversationId,
            event
          }
        });

        if (!approvalResult.allowed) {
          api.logger.info?.(`agent-passport: cancelled outbound send to ${event.to} via native message_sending approval (${approvalResult.resolution})`);
          return { cancel: true };
        }

        return;
      }

      const result = await handleConsentRequired({
        api,
        scope: "message_sending",
        target,
        decision,
        pluginCfg,
        auditRecord: {
          kind: "message_sending",
          channelId: ctx.channelId,
          conversationId: ctx.conversationId,
          event
        }
      });

      return result;
    }, { priority: EARLY_SECURITY_HOOK_PRIORITY });

    api.on("before_tool_call", async (event, ctx) => {
      const pluginCfg = currentConfig();
      const toolName = event.toolName;
      const params = event.params ?? {};

      if (toolName === "message" && shouldGateMessageTool(params)) {
        const target = normalizeTarget(params.target ?? params.to);
        const trustedMatch = getTrustedMatch(target, "message.send", pluginCfg);

        if (trustedMatch || await hasConsentForTarget(target)) {
          await appendAuditRecord({
            kind: "before_tool_call",
            toolName,
            event,
            context: ctx,
            decision: {
              outcome: "allow",
              severity: "low",
              category: "externalMessaging",
              reason: trustedMatch?.reason || "Active consent grant found for outbound target.",
              matchedRule: trustedMatch?.matchedRule || "active-consent"
            }
          });
          return;
        }

        const decision = evaluateOutboundCommunication({
          target,
          content: String(params.message ?? "")
        });

        if (getModeForScope("message.send", pluginCfg) === "enforce" && (decision.outcome === "deny" || decision.outcome === "require_consent")) {
          return buildNativeToolApprovalRequirement({
            scope: "message.send",
            target,
            decision,
            pluginCfg,
            auditRecord: { kind: "before_tool_call", toolName, event, context: ctx }
          });
        }

        return handleConsentRequired({
          api,
          scope: "message.send",
          target,
          decision,
          pluginCfg,
          auditRecord: { kind: "before_tool_call", toolName, event, context: ctx }
        });
      }

      if (shouldGateSessionSend(toolName)) {
        const target = normalizeTarget(params.sessionKey ?? params.label);
        const trustedMatch = getTrustedMatch(target, "sessions_send", pluginCfg);

        if (trustedMatch || await hasConsentForTarget(target)) {
          await appendAuditRecord({
            kind: "before_tool_call",
            toolName,
            event,
            context: ctx,
            decision: {
              outcome: "allow",
              severity: "low",
              category: "externalMessaging",
              reason: trustedMatch?.reason || "Active consent grant found for cross-session send.",
              matchedRule: trustedMatch?.matchedRule || "active-consent"
            }
          });
          return;
        }

        const decision = evaluateOutboundCommunication({
          target,
          content: String(params.message ?? "")
        });

        if (getModeForScope("sessions_send", pluginCfg) === "enforce" && (decision.outcome === "deny" || decision.outcome === "require_consent")) {
          return buildNativeToolApprovalRequirement({
            scope: "sessions_send",
            target,
            decision,
            pluginCfg,
            auditRecord: { kind: "before_tool_call", toolName, event, context: ctx }
          });
        }

        return handleConsentRequired({
          api,
          scope: "sessions_send",
          target,
          decision,
          pluginCfg,
          auditRecord: { kind: "before_tool_call", toolName, event, context: ctx }
        });
      }
    }, { priority: EARLY_SECURITY_HOOK_PRIORITY });

    api.registerCommand({
      name: "passport",
      description: "Review Agent Passport status and pending consent requests",
      acceptsArgs: true,
      handler: async (ctx) => {
        const pluginCfg = currentConfig();
        const tokens = (ctx.args?.trim() ?? "").split(/\s+/).filter(Boolean);
        const action = (tokens[0] ?? "status").toLowerCase();

        if (action === "status") {
          return buildStatusReply(pluginCfg, api.config);
        }

        if (action === "requests") {
          const status = (tokens[1] ?? "pending").toLowerCase();
          if (status === "pending" || status === "approved" || status === "denied" || status === "all") {
            return buildRequestsReply(status);
          }
          return { text: "Usage: /passport requests [pending|approved|denied|all]" };
        }

        if (action === "scan") {
          const targetPath = tokens.slice(1).join(" ").trim();
          if (!targetPath) return { text: "Usage: /passport scan <path>" };
          try {
            const report = await scanPath(targetPath);
            const scanReview = await getLatestScanReview(report.fingerprint);
            await appendAuditRecord({ kind: "command_scan_path", targetPath, senderId: ctx.senderId, report, scanReview });
            return { text: buildScanReply(report, scanReview) };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport scan failed: ${message}` };
          }
        }

        if (action === "preflight") {
          const targetPath = tokens.slice(1).join(" ").trim();
          if (!targetPath) return { text: "Usage: /passport preflight <path>" };
          try {
            const { report, scanReview, preflight } = await buildArtifactPreflight(targetPath);
            await appendAuditRecord({ kind: "command_preflight_artifact", targetPath, senderId: ctx.senderId, report, scanReview, preflight });
            return {
              text: [
                `Agent Passport preflight: ${report.scannedPath}`,
                `- allowed now: ${preflight.allowed ? "yes" : "no"}`,
                `- disposition: ${preflight.disposition}`,
                `- reason: ${preflight.reason}`,
                `- scanner recommendation: ${report.packageRecommendation.action}`,
                ...(scanReview ? [`- review state: ${decisionSummary(scanReview.decision)} at ${scanReview.createdAt}`] : ["- review state: none recorded for this fingerprint"]),
                "",
                buildScanReply(report, scanReview)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport preflight failed: ${message}` };
          }
        }

        if (action === "authorize") {
          const artifactAction = (tokens[1] ?? "").toLowerCase();
          const targetPath = tokens.slice(2).join(" ").trim();
          if ((artifactAction !== "install" && artifactAction !== "enable" && artifactAction !== "update") || !targetPath) {
            return { text: "Usage: /passport authorize <install|enable|update> <path>" };
          }
          try {
            const result = await buildArtifactAuthorization({ action: artifactAction as "install" | "enable" | "update", targetPath });
            await appendAuditRecord({ kind: "command_authorize_artifact", targetPath, senderId: ctx.senderId, ...result });
            return { text: buildAuthorizationReply(result) };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport authorize failed: ${message}` };
          }
        }

        if (action === "run") {
          const rawArgs = ctx.args?.trim() ?? "";
          const separator = rawArgs.indexOf(" -- ");
          if (separator === -1) {
            return { text: "Usage: /passport run <install|enable|update> <path> -- <command>" };
          }
          const left = rawArgs.slice(0, separator).trim().split(/\s+/).filter(Boolean);
          const command = rawArgs.slice(separator + 4).trim();
          const artifactAction = (left[1] ?? "").toLowerCase();
          const targetPath = left.slice(2).join(" ").trim();
          if ((artifactAction !== "install" && artifactAction !== "enable" && artifactAction !== "update") || !targetPath || !command) {
            return { text: "Usage: /passport run <install|enable|update> <path> -- <command>" };
          }
          try {
            const result = await runArtifactAction({
              action: artifactAction as "install" | "enable" | "update",
              targetPath,
              command
            });
            await appendAuditRecord({ kind: "command_run_artifact", senderId: ctx.senderId, targetPath, ...result });
            return { text: buildRunReply(result) };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport run failed: ${message}` };
          }
        }

        if (action === "install-plugin") {
          const argTokens = tokens.slice(1);
          const flags = new Set(argTokens.filter((token) => token.startsWith("--")));
          const targetPath = argTokens.filter((token) => !token.startsWith("--")).join(" ").trim();
          if (!targetPath) {
            return { text: "Usage: /passport install-plugin <local-path> [--link] [--pin] [--enable] [--dry-run]" };
          }
          try {
            const result = await installOpenClawPluginFromPath({
              path: targetPath,
              link: flags.has("--link"),
              pin: flags.has("--pin"),
              enableAfterInstall: flags.has("--enable"),
              dryRun: flags.has("--dry-run")
            });
            await appendAuditRecord({ kind: "command_install_openclaw_plugin", senderId: ctx.senderId, input: { targetPath, flags: [...flags] }, result });
            return {
              text: [
                `Agent Passport plugin install wrapper: ${targetPath}`,
                "",
                buildRunReply(result.install),
                ...(result.enable ? ["", `Enable step for ${result.pluginId}:`, "", buildRunReply(result.enable)] : [])
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport install-plugin failed: ${message}` };
          }
        }

        if (action === "enable-plugin") {
          const argTokens = tokens.slice(1);
          const flags = new Set(argTokens.filter((token) => token.startsWith("--")));
          const targetPath = argTokens.filter((token) => !token.startsWith("--")).join(" ").trim();
          if (!targetPath) {
            return { text: "Usage: /passport enable-plugin <local-path> [--dry-run]" };
          }
          try {
            const result = await enableOpenClawPluginFromPath({
              path: targetPath,
              dryRun: flags.has("--dry-run")
            });
            await appendAuditRecord({ kind: "command_enable_openclaw_plugin", senderId: ctx.senderId, input: { targetPath, flags: [...flags] }, result });
            return {
              text: [
                `Agent Passport plugin enable wrapper: ${result.pluginId}`,
                `- manifest: ${result.manifestPath}`,
                "",
                buildRunReply(result.enable)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport enable-plugin failed: ${message}` };
          }
        }

        if (action === "update-plugin") {
          const pluginId = tokens[1]?.trim();
          const dryRun = tokens.includes("--dry-run");
          if (!pluginId || pluginId.startsWith("--")) {
            return { text: "Usage: /passport update-plugin <pluginId> [--dry-run]" };
          }
          try {
            const result = await updateOpenClawPluginFromLedger({ pluginId, dryRun });
            await appendAuditRecord({ kind: "command_update_openclaw_plugin", senderId: ctx.senderId, input: { pluginId, dryRun }, result });
            return {
              text: [
                `Agent Passport plugin update wrapper: ${result.pluginId}`,
                `- source: ${result.sourcePath}`,
                "",
                buildRunReply(result.update)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport update-plugin failed: ${message}` };
          }
        }

        if (action === "update-skill") {
          const slug = tokens[1]?.trim();
          const dryRun = tokens.includes("--dry-run");
          if (!slug || slug.startsWith("--")) {
            return { text: "Usage: /passport update-skill <slug> [--dry-run]" };
          }
          try {
            const result = await updateOpenClawSkill({ slug, dryRun });
            await appendAuditRecord({ kind: "command_update_openclaw_skill", senderId: ctx.senderId, input: { slug, dryRun }, result });
            return {
              text: [
                `Agent Passport skill update wrapper: ${slug}`,
                `- skill dir: ${result.skillDir}`,
                `- command: ${result.updateCommand}`,
                `- authorized: ${result.authorized ? "yes" : "no"}`,
                `- authorization reason: ${result.authorizationReason}`,
                `- executed: ${result.executed ? "yes" : "no"}`,
                ...(result.execution ? [
                  `- success: ${result.execution.ok ? "yes" : "no"}`,
                  `- exit code: ${result.execution.exitCode ?? "null"}`
                ] : []),
                ...(result.afterState ? ["", buildSkillStateReply(result.afterState)] : [])
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport update-skill failed: ${message}` };
          }
        }

        if (action === "update-skills") {
          const dryRun = tokens.includes("--dry-run");
          try {
            const result = await updateAllOpenClawSkills({ dryRun });
            await appendAuditRecord({ kind: "command_update_all_openclaw_skills", senderId: ctx.senderId, input: { dryRun }, result });
            const states = result.afterStates ?? result.beforeStates;
            return {
              text: [
                "Agent Passport skills update wrapper:",
                `- command: ${result.updateCommand}`,
                `- authorized: ${result.authorized ? "yes" : "no"}`,
                `- authorization reason: ${result.authorizationReason}`,
                `- executed: ${result.executed ? "yes" : "no"}`,
                ...(result.execution ? [
                  `- success: ${result.execution.ok ? "yes" : "no"}`,
                  `- exit code: ${result.execution.exitCode ?? "null"}`
                ] : []),
                `- tracked skills: ${result.summary.trackedCount}`,
                `- changed skills: ${result.summary.changedCount}`,
                `- trusted: ${result.summary.trustedCount}`,
                `- reviewed: ${result.summary.reviewedCount}`,
                `- blocked: ${result.summary.blockedCount}`,
                `- re-review required: ${result.summary.rereviewRequiredCount}`,
                `- missing: ${result.summary.missingCount}`,
                ...(result.blocked.length ? ["", "Blocked skills:", ...result.blocked.map((item) => `- ${item.slug}: ${item.reason}`)] : []),
                "",
                "Skill states:",
                ...states.map(([slug, state]) => `- ${slug}: ${state.state}${state.installedVersion ? ` (${state.installedVersion})` : ""}`)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport update-skills failed: ${message}` };
          }
        }

        if (action === "installs") {
          const pluginId = tokens[1]?.trim();
          const installs = await listPluginInstalls({ pluginId: pluginId || undefined });
          if (!installs.length) {
            return { text: `Agent Passport installs${pluginId ? ` for ${pluginId}` : ""}: none recorded.` };
          }
          return {
            text: [
              `Agent Passport installs${pluginId ? ` for ${pluginId}` : ""}:`,
              ...installs.slice(0, 10).map((record) => [
                `- ${record.pluginId} (${record.pluginName})`,
                `  source: ${record.sourcePath}`,
                `  fingerprint: ${record.fingerprint}`,
                `  installedAt: ${record.installedAt}`,
                `  enabledAt: ${record.enabledAt ?? "not recorded"}`,
                `  review: ${record.reviewDecision ?? "none"}`,
                `  recommendation: ${record.recommendationAction}`
              ].join("\n"))
            ].join("\n\n")
          };
        }

        if (action === "skills") {
          const result = await listSkillStates();
          if (!result.length) {
            return { text: "Agent Passport skills: no tracked ClawHub skills found in this workspace." };
          }
          return {
            text: [
              "Agent Passport skills:",
              ...result.map((item) => [
                `- ${item.slug}`,
                `  state: ${item.state}`,
                `  version: ${item.installedVersion ?? "unknown"}`,
                `  verdict/recommendation: ${item.verdict ?? "unknown"} / ${item.recommendation ?? "unknown"}`,
                `  review: ${item.currentReview ? decisionSummary(item.currentReview.decision) : "none"}`,
                `  trust tier: ${item.trustSummary.tier}`,
                `  provenance: ${item.trustSummary.provenance}`
              ].join("\n"))
            ].join("\n\n")
          };
        }

        if (action === "workspace-state") {
          const result = await buildWorkspaceState();
          const reply = buildWorkspaceStateReply(result);
          await appendAuditRecord({ kind: "command_workspace_state", senderId: ctx.senderId, result });
          return reply;
        }

        if (action === "workspace-audit") {
          try {
            const maxIndex = tokens.indexOf("--max");
            if (maxIndex !== -1 && !tokens[maxIndex + 1]) {
              return { text: "Usage: /passport workspace-audit [--plugins-only|--skills-only] [--max <n>]" };
            }
            const auditOptions = buildWorkspaceAuditOptions({
              pluginsOnly: tokens.includes("--plugins-only"),
              skillsOnly: tokens.includes("--skills-only"),
              maxItems: maxIndex !== -1 ? tokens[maxIndex + 1] : undefined
            });
            const result = await buildWorkspaceAudit(auditOptions);
            await appendAuditRecord({ kind: "command_workspace_audit", senderId: ctx.senderId, input: auditOptions, result });
            return { text: formatWorkspaceAudit(result) };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport workspace-audit failed: ${message}` };
          }
        }

        if (action === "inspect-skill") {
          const argTokens = tokens.slice(1);
          const pathTokens: string[] = [];
          let label: string | undefined;
          let maxFiles: number | undefined;
          let maxBytes: number | undefined;

          try {
            for (let index = 0; index < argTokens.length; index += 1) {
              const token = argTokens[index];
              if (token === "--label") {
                label = argTokens[index + 1]?.trim();
                if (!label) throw new Error("Usage: /passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]");
                index += 1;
                continue;
              }
              if (token === "--max-files") {
                if (!argTokens[index + 1]) throw new Error("Usage: /passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]");
                maxFiles = parsePositiveIntegerOption(argTokens[index + 1], "max-files");
                index += 1;
                continue;
              }
              if (token === "--max-bytes") {
                if (!argTokens[index + 1]) throw new Error("Usage: /passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]");
                maxBytes = parsePositiveIntegerOption(argTokens[index + 1], "max-bytes");
                index += 1;
                continue;
              }
              pathTokens.push(token);
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport inspect-skill failed: ${message}` };
          }

          const sourcePath = pathTokens.join(" ").trim();
          if (!sourcePath) {
            return { text: "Usage: /passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]" };
          }

          try {
            const result = await inspectSkillArtifactWithReview({
              sourcePath,
              label,
              maxFiles,
              maxBytes
            });
            await appendAuditRecord({ kind: "command_inspect_skill_artifact", senderId: ctx.senderId, input: { sourcePath, label, maxFiles, maxBytes }, ...result });
            return { text: buildSkillInspectionReply(result) };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport inspect-skill failed: ${message}` };
          }
        }

        if (action === "skill-state") {
          const slug = tokens[1]?.trim();
          if (!slug) {
            return { text: "Usage: /passport skill-state <slug>" };
          }
          const result = await buildSkillState({ slug });
          await appendAuditRecord({ kind: "command_skill_state", senderId: ctx.senderId, input: { slug }, result });
          return { text: buildSkillStateReply(result) };
        }

        if (action === "drift-skill") {
          const slug = tokens[1]?.trim();
          if (!slug) {
            return { text: "Usage: /passport drift-skill <slug>" };
          }
          const result = await checkSkillDrift({ slug });
          await appendAuditRecord({ kind: "command_check_skill_drift", senderId: ctx.senderId, input: { slug }, result });
          if (!result.ok) {
            return { text: `Agent Passport skill drift check failed for ${slug}: ${result.reason}` };
          }
          return {
            text: [
              `Agent Passport skill drift check: ${slug}`,
              `- changed: ${result.drift?.changed ? "yes" : "no"}`,
              `- reason: ${result.reason}`,
              `- installed version: ${result.installedVersion ?? "unknown"}`,
              `- recorded fingerprint: ${result.drift?.recordedFingerprint}`,
              `- current fingerprint: ${result.drift?.currentFingerprint}`,
              `- recorded verdict/recommendation: ${result.drift?.recordedVerdict} / ${result.drift?.recordedRecommendation}`,
              `- current verdict/recommendation: ${result.drift?.currentVerdict} / ${result.drift?.currentRecommendation}`,
              `- current review state: ${result.currentReview ? decisionSummary(result.currentReview.decision) : "none recorded for current fingerprint"}`,
              "",
              buildScanReply(result.currentReport!, result.currentReview)
            ].join("\n")
          };
        }

        if (action === "skills-rereview") {
          const queue = await listSkillsNeedingRereview();
          if (!queue.length) {
            return { text: "Agent Passport skill re-review queue: empty." };
          }
          return {
            text: [
              "Agent Passport skill re-review queue:",
              ...queue.map((item) => [
                `- ${item.slug}`,
                `  skill dir: ${item.skillDir}`,
                `  version: ${item.installedVersion ?? "unknown"}`,
                `  recorded fingerprint: ${item.recordedFingerprint}`,
                `  current fingerprint: ${item.currentFingerprint}`,
                `  recorded recommendation: ${item.recordedRecommendation}`,
                `  current recommendation: ${item.currentRecommendation}`,
                `  current review: ${item.currentReviewDecision ?? "none"}`,
                `  reason: ${item.reason}`
              ].join("\n"))
            ].join("\n\n")
          };
        }

        if (action === "plugin-state") {
          const pluginId = tokens[1]?.trim();
          if (!pluginId) {
            return { text: "Usage: /passport plugin-state <pluginId>" };
          }
          const result = await buildPluginState({ pluginId });
          await appendAuditRecord({ kind: "command_plugin_state", senderId: ctx.senderId, input: { pluginId }, result });
          return { text: buildPluginStateReply(result) };
        }

        if (action === "drift-plugin") {
          const pluginId = tokens[1]?.trim();
          if (!pluginId) {
            return { text: "Usage: /passport drift-plugin <pluginId>" };
          }
          try {
            const result = await checkPluginInstallDrift({ pluginId });
            await appendAuditRecord({ kind: "command_check_plugin_drift", senderId: ctx.senderId, input: { pluginId }, result });
            if (!result.ok) {
              return { text: `Agent Passport drift check failed for ${pluginId}: ${result.reason}` };
            }
            return {
              text: [
                `Agent Passport drift check: ${pluginId}`,
                `- changed: ${result.drift?.changed ? "yes" : "no"}`,
                `- reason: ${result.reason}`,
                `- recorded fingerprint: ${result.drift?.recordedFingerprint}`,
                `- current fingerprint: ${result.drift?.currentFingerprint}`,
                `- recorded verdict/recommendation: ${result.drift?.recordedVerdict} / ${result.drift?.recordedRecommendation}`,
                `- current verdict/recommendation: ${result.drift?.currentVerdict} / ${result.drift?.currentRecommendation}`,
                `- current review state: ${result.currentReview ? decisionSummary(result.currentReview.decision) : "none recorded for current fingerprint"}`,
                "",
                buildScanReply(result.currentReport!, result.currentReview)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport drift-plugin failed: ${message}` };
          }
        }

        if (action === "rereview-queue") {
          const queue = await listPluginsNeedingRereview();
          if (!queue.length) {
            return { text: "Agent Passport re-review queue: empty." };
          }
          return {
            text: [
              "Agent Passport re-review queue:",
              ...queue.map((item) => [
                `- ${item.pluginId} (${item.pluginName})`,
                `  source: ${item.sourcePath}`,
                `  recorded fingerprint: ${item.recordedFingerprint}`,
                `  current fingerprint: ${item.currentFingerprint}`,
                `  recorded recommendation: ${item.recordedRecommendation}`,
                `  current recommendation: ${item.currentRecommendation}`,
                `  current review: ${item.currentReviewDecision ?? "none"}`,
                `  reason: ${item.reason}`
              ].join("\n"))
            ].join("\n\n")
          };
        }

        if (action === "drift-sweep") {
          const result = await sweepRereviewQueue();
          await appendAuditRecord({ kind: "command_drift_sweep", senderId: ctx.senderId, result });
          if (!result.summary.queueCount) {
            return { text: "Agent Passport drift sweep: queue empty. Nothing new, nothing unresolved. Review: /passport workspace-state" };
          }
          return {
            text: [
              "Agent Passport drift sweep:",
              `- queue count: ${result.summary.queueCount}`,
              `- newly entered: ${result.summary.newCount}`,
              `- resolved since last sweep: ${result.summary.resolvedCount}`,
              `- review with: /passport workspace-state`,
              ...(result.newlyEntered.length ? ["", "Newly entered:", ...result.newlyEntered.map((item) => `- ${item.pluginId}: ${item.reason}`)] : []),
              ...(result.resolved.length ? ["", "Resolved since last sweep:", ...result.resolved.map((item) => `- ${item.pluginId} @ ${item.fingerprint}`)] : []),
              ...(result.queue.length ? ["", "Current queue:", ...result.queue.map((item) => `- ${item.pluginId}: ${item.reason}`)] : [])
            ].join("\n")
          };
        }

        if (action === "drift-alerts") {
          const result = await buildDriftAlerts();
          await appendAuditRecord({ kind: "command_drift_alerts", senderId: ctx.senderId, result });
          if (!result.alert) {
            return { text: `Agent Passport drift alerts: no new re-review entries. Queue=${result.summary.queueCount}, resolved=${result.summary.resolvedCount}. Review: ${result.nextCommand}.` };
          }
          return {
            text: [
              "Agent Passport drift alerts:",
              `- alert: yes`,
              `- new entries: ${result.summary.newCount}`,
              `- queue count: ${result.summary.queueCount}`,
              `- resolved since last sweep: ${result.summary.resolvedCount}`,
              `- review with: ${result.nextCommand}`,
              "",
              "Newly entered:",
              ...result.newlyEntered.map((item) => `- ${item.pluginId}: ${item.reason}`)
            ].join("\n")
          };
        }

        if (action === "trust-skill" || action === "review-skill" || action === "block-skill") {
          const slug = tokens[1]?.trim();
          if (!slug) return { text: `Usage: /passport ${action} <slug>` };
          const decision = action.replace("-skill", "") as PassportScanDecision;
          try {
            const { report, review } = await applySkillDecision({
              slug,
              decision,
              senderId: ctx.senderId,
              note: `Recorded via /passport ${action}`
            });
            return {
              text: [
                `Recorded ${decisionSummary(review.decision)} for skill ${slug}.`,
                `- path: ${report.scannedPath}`,
                "",
                buildScanReply(report, review)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport ${action} failed: ${message}` };
          }
        }

        if (action === "trust-plugin" || action === "review-plugin" || action === "block-plugin") {
          const pluginId = tokens[1]?.trim();
          if (!pluginId) return { text: `Usage: /passport ${action} <pluginId>` };
          const decision = action.replace("-plugin", "") as PassportScanDecision;
          try {
            const { report, review } = await applyPluginDecision({
              pluginId,
              decision,
              senderId: ctx.senderId,
              note: `Recorded via /passport ${action}`
            });
            return {
              text: [
                `Recorded ${decisionSummary(review.decision)} for plugin ${pluginId}.`,
                `- path: ${report.scannedPath}`,
                "",
                buildScanReply(report, review)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport ${action} failed: ${message}` };
          }
        }

        if (action === "trust" || action === "review" || action === "block") {
          const targetPath = tokens.slice(1).join(" ").trim();
          if (!targetPath) return { text: `Usage: /passport ${action} <path>` };
          try {
            const { report, review } = await applyScanDecision({
              targetPath,
              decision: action,
              senderId: ctx.senderId,
              note: `Recorded via /passport ${action}`
            });
            return {
              text: [
                `Recorded ${decisionSummary(review.decision)} for ${report.scannedPath}.`,
                "",
                buildScanReply(report, review)
              ].join("\n")
            };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return { text: `Agent Passport ${action} failed: ${message}` };
          }
        }

        if (action === "approve" || action === "deny") {
          const requestId = tokens[1]?.trim();
          if (!requestId) return { text: `Usage: /passport ${action} <requestId>` };
          const result = await reviewConsentRequest({
            requestId,
            decision: action === "approve" ? "approved" : "denied",
            ttlMinutes: pluginCfg.consentTtlMinutes,
            note: `Reviewed via /passport ${action}`
          });
          await appendAuditRecord({ kind: "command_review_request", action, requestId, senderId: ctx.senderId, result });
          if (!result.ok) return { text: result.error };
          const updated = await buildRequestsReply("pending");
          return {
            text: `${action === "approve" ? "Approved" : "Denied"} ${requestId}.\n\n${updated.text}`,
            interactive: updated.interactive
          };
        }

        return {
          text: "Usage:\n/passport status\n/passport requests [pending|approved|denied|all]\n/passport scan <path>\n/passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]\n/passport preflight <path>\n/passport authorize <install|enable|update> <path>\n/passport run <install|enable|update> <path> -- <command>\n/passport install-plugin <local-path> [--link] [--pin] [--enable] [--dry-run]\n/passport enable-plugin <local-path> [--dry-run]\n/passport update-plugin <pluginId> [--dry-run]\n/passport update-skill <slug> [--dry-run]\n/passport update-skills [--dry-run]\n/passport installs [pluginId]\n/passport skills\n/passport workspace-state\n/passport workspace-audit [--plugins-only|--skills-only] [--max <n>]\n/passport skill-state <slug>\n/passport drift-skill <slug>\n/passport skills-rereview\n/passport trust-skill <slug>\n/passport review-skill <slug>\n/passport block-skill <slug>\n/passport plugin-state <pluginId>\n/passport trust-plugin <pluginId>\n/passport review-plugin <pluginId>\n/passport block-plugin <pluginId>\n/passport drift-plugin <pluginId>\n/passport rereview-queue\n/passport drift-sweep\n/passport drift-alerts\n/passport trust <path>\n/passport review <path>\n/passport block <path>\n/passport approve <requestId>\n/passport deny <requestId>"
        };
      }
    });

    api.registerCli((cli) => {
      cli.program
        .command("passport-audit")
        .description("Run the Agent Passport workspace incident-response audit")
        .option("--workspace-root <path>", "Override the workspace root to audit")
        .option("--ledger-dir <path>", "Override the Agent Passport ledger directory")
        .option("--plugins-only", "Audit recorded plugins only")
        .option("--skills-only", "Audit tracked skills only")
        .option("--max-items <count>", "Limit the number of top-ranked items shown")
        .option("--json", "Emit JSON instead of the human-readable summary")
        .action(async (options: {
          workspaceRoot?: string;
          ledgerDir?: string;
          pluginsOnly?: boolean;
          skillsOnly?: boolean;
          maxItems?: string;
          json?: boolean;
        }) => {
          currentConfig();
          const auditOptions = buildWorkspaceAuditOptions({
            workspaceRoot: options.workspaceRoot,
            ledgerDir: options.ledgerDir,
            pluginsOnly: options.pluginsOnly,
            skillsOnly: options.skillsOnly,
            maxItems: options.maxItems
          });
          const result = await buildWorkspaceAudit(auditOptions);
          await appendAuditRecord({ kind: "cli_workspace_audit", input: auditOptions, result });
          const output = options.json
            ? JSON.stringify(result, null, 2)
            : formatWorkspaceAudit(result);
          process.stdout.write(`${output}\n`);
        });

      cli.program
        .command("passport-inspect-skill <path>")
        .description("Stage a local skill artifact into Passport quarantine and scan it before trust")
        .option("--label <label>", "Override the quarantine label prefix")
        .option("--quarantine-root <path>", "Override the quarantine root directory")
        .option("--max-files <count>", "Limit the number of files scanned")
        .option("--max-bytes <count>", "Limit the maximum bytes scanned")
        .option("--json", "Emit JSON instead of the human-readable summary")
        .action(async (sourcePath: string, options: {
          label?: string;
          quarantineRoot?: string;
          maxFiles?: string;
          maxBytes?: string;
          json?: boolean;
        }) => {
          currentConfig();
          const result = await inspectSkillArtifactWithReview({
            sourcePath,
            label: options.label,
            quarantineRoot: options.quarantineRoot,
            maxFiles: parsePositiveIntegerOption(options.maxFiles, "max-files"),
            maxBytes: parsePositiveIntegerOption(options.maxBytes, "max-bytes")
          });
          await appendAuditRecord({ kind: "cli_inspect_skill_artifact", input: { sourcePath, ...options }, ...result });
          const output = options.json
            ? JSON.stringify(result, null, 2)
            : buildSkillInspectionReply(result);
          process.stdout.write(`${output}\n`);
        });
    }, { commands: ["passport-audit", "passport-inspect-skill"] });

    api.registerInteractiveHandler({
      channel: "telegram",
      namespace: TELEGRAM_NAMESPACE,
      handler: async (ctx) => {
        const pluginCfg = currentConfig();
        if (!ctx.auth.isAuthorizedSender) {
          await ctx.respond.reply({ text: "Not authorized." });
          return { handled: true };
        }

        const { action, requestId, target } = parseInteractivePayload(ctx.callback.payload);

        if (action === "workspace") {
          const result = await buildWorkspaceState();
          const reply = buildWorkspaceStateReply(result);
          await ctx.respond.editMessage({
            text: reply.text ?? "Agent Passport workspace state unavailable.",
            buttons: reply.interactive?.blocks.flatMap((block) => block.type === "buttons"
              ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
              : [])
          });
          return { handled: true };
        }

        if (action === "plugin-state" && target) {
          const result = await buildPluginState({ pluginId: target });
          await ctx.respond.editMessage({
            text: buildPluginStateReply(result),
            buttons: [[{ text: "Back to workspace", callback_data: "workspace" }]]
          });
          return { handled: true };
        }

        if (action === "skill-state" && target) {
          const result = await buildSkillState({ slug: target });
          await ctx.respond.editMessage({
            text: buildSkillStateReply(result),
            buttons: [[{ text: "Back to workspace", callback_data: "workspace" }]]
          });
          return { handled: true };
        }

        if (action === "requests") {
          const reply = await buildRequestsReply("pending");
          await ctx.respond.editMessage({
            text: reply.text ?? "Agent Passport requests: none.",
            buttons: reply.interactive?.blocks.flatMap((block) => block.type === "buttons"
              ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
              : [])
          });
          return { handled: true };
        }

        if ((action === "approve" || action === "deny") && requestId) {
          const result = await reviewConsentRequest({
            requestId,
            decision: action === "approve" ? "approved" : "denied",
            ttlMinutes: pluginCfg.consentTtlMinutes,
            note: `Reviewed via Telegram button by ${ctx.senderId ?? "unknown"}`
          });
          await appendAuditRecord({ kind: "interactive_review_request", action, requestId, senderId: ctx.senderId, result });
          if (!result.ok) {
            await ctx.respond.reply({ text: result.error });
            return { handled: true };
          }
          const updated = await buildRequestsReply("pending");
          await ctx.respond.editMessage({
            text: `${action === "approve" ? "Approved" : "Denied"} ${requestId}.\n\n${updated.text}`,
            buttons: updated.interactive?.blocks.flatMap((block) => block.type === "buttons"
              ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
              : [])
          });
          return { handled: true };
        }

        if (action === "status") {
          const reply = await buildStatusReply(pluginCfg, api.config);
          await ctx.respond.editMessage({
            text: reply.text ?? "Agent Passport status unavailable.",
            buttons: reply.interactive?.blocks.flatMap((block) => block.type === "buttons"
              ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
              : [])
          });
          return { handled: true };
        }

        if ((action === "review-plugin" || action === "trust-plugin" || action === "block-plugin") && target) {
          const decision = action.replace("-plugin", "") as PassportScanDecision;
          try {
            await applyPluginDecision({
              pluginId: target,
              decision,
              senderId: ctx.senderId,
              note: `Reviewed via Telegram button by ${ctx.senderId ?? "unknown"}`
            });
            const result = await buildWorkspaceState();
            const reply = buildWorkspaceStateReply(result);
            await ctx.respond.editMessage({
              text: reply.text ?? "Agent Passport workspace state unavailable.",
              buttons: reply.interactive?.blocks.flatMap((block) => block.type === "buttons"
                ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
                : [])
            });
            return { handled: true };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            await ctx.respond.reply({ text: `Agent Passport ${action} failed: ${message}` });
            return { handled: true };
          }
        }

        if ((action === "review-skill" || action === "trust-skill" || action === "block-skill") && target) {
          const decision = action.replace("-skill", "") as PassportScanDecision;
          try {
            await applySkillDecision({
              slug: target,
              decision,
              senderId: ctx.senderId,
              note: `Reviewed via Telegram button by ${ctx.senderId ?? "unknown"}`
            });
            const result = await buildWorkspaceState();
            const reply = buildWorkspaceStateReply(result);
            await ctx.respond.editMessage({
              text: reply.text ?? "Agent Passport workspace state unavailable.",
              buttons: reply.interactive?.blocks.flatMap((block) => block.type === "buttons"
                ? [block.buttons.map((button) => ({ text: button.label, callback_data: button.value }))]
                : [])
            });
            return { handled: true };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            await ctx.respond.reply({ text: `Agent Passport ${action} failed: ${message}` });
            return { handled: true };
          }
        }

        await ctx.respond.reply({ text: "Unknown Agent Passport action." });
        return { handled: true };
      }
    });

    api.registerTool({
      name: "agent_passport_status",
      label: "agent_passport_status",
      description: "Show Agent Passport mode and current policy defaults",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const pluginCfg = currentConfig();
        const grants = await listConsents();
        const pendingRequests = await listConsentRequests({ status: "pending" });
        return jsonToolResult({
                loaded: true,
                mode: pluginCfg.mode,
                pathModes: pluginCfg.pathModes,
                trustedTargets: pluginCfg.trustedTargets,
                trustedTargetRules: pluginCfg.trustedTargetRules,
                consentTtlMinutes: pluginCfg.consentTtlMinutes,
                activeConsentCount: grants.length,
                pendingConsentRequestCount: pendingRequests.length,
                guardedPaths: ["message_sending", "message(action=send)", "sessions_send"],
                auditedInboundPaths: ["before_dispatch"],
                reviewedArtifactCount: (await listScanReviews()).length,
                recordedPluginInstallCount: (await listPluginInstalls()).length,
                trackedSkillCount: (await listSkillStates()).length,
                pluginRereviewQueueCount: (await listPluginsNeedingRereview()).length,
                skillRereviewQueueCount: (await listSkillsNeedingRereview()).length,
                rereviewQueueCount: (await listPluginsNeedingRereview()).length + (await listSkillsNeedingRereview()).length
              });
      }
    });

    api.registerTool({
      name: "agent_passport_scan_path",
      label: "agent_passport_scan_path",
      description: "Scan a local skill, plugin, or package path for ClawHavoc-style poisoned-package indicators",
      parameters: Type.Object({
        path: Type.String(),
        maxFiles: Type.Optional(Type.Number({ minimum: 1 }))
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const report = await scanPath(params.path, { maxFiles: params.maxFiles ? Math.floor(params.maxFiles) : undefined });
        const scanReview = await getLatestScanReview(report.fingerprint);
        await appendAuditRecord({ kind: "tool_scan_path", input: params, report, scanReview });
        return jsonToolResult({ ...report, currentReview: scanReview });
      }
    });

    api.registerTool({
      name: "agent_passport_inspect_skill_artifact",
      label: "agent_passport_inspect_skill_artifact",
      description: "Stage a local skill artifact into Passport quarantine, scan it, and report provenance plus any existing review state for the resulting fingerprint",
      parameters: Type.Object({
        path: Type.String(),
        label: Type.Optional(Type.String()),
        quarantineRoot: Type.Optional(Type.String()),
        maxFiles: Type.Optional(Type.Number({ minimum: 1 })),
        maxBytes: Type.Optional(Type.Number({ minimum: 1 }))
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await inspectSkillArtifactWithReview({
          sourcePath: params.path,
          label: params.label,
          quarantineRoot: params.quarantineRoot,
          maxFiles: params.maxFiles ? Math.floor(params.maxFiles) : undefined,
          maxBytes: params.maxBytes ? Math.floor(params.maxBytes) : undefined
        });
        await appendAuditRecord({ kind: "tool_inspect_skill_artifact", input: params, ...result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_review_scan",
      label: "agent_passport_review_scan",
      description: "Record a trust, review, or block decision for a scanned artifact path",
      parameters: Type.Object({
        path: Type.String(),
        decision: Type.Union([
          Type.Literal("trust"),
          Type.Literal("review"),
          Type.Literal("block")
        ]),
        note: Type.Optional(Type.String())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await applyScanDecision({
          targetPath: params.path,
          decision: params.decision,
          note: params.note
        });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_review_skill",
      label: "agent_passport_review_skill",
      description: "Record a trust, review, or block decision for a tracked workspace skill by slug",
      parameters: Type.Object({
        slug: Type.String(),
        decision: Type.Union([
          Type.Literal("trust"),
          Type.Literal("review"),
          Type.Literal("block")
        ]),
        note: Type.Optional(Type.String())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await applySkillDecision({
          slug: params.slug,
          decision: params.decision,
          note: params.note
        });
        await appendAuditRecord({ kind: "tool_review_skill", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_review_plugin",
      label: "agent_passport_review_plugin",
      description: "Record a trust, review, or block decision for a Passport-recorded plugin by plugin id",
      parameters: Type.Object({
        pluginId: Type.String(),
        decision: Type.Union([
          Type.Literal("trust"),
          Type.Literal("review"),
          Type.Literal("block")
        ]),
        note: Type.Optional(Type.String())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await applyPluginDecision({
          pluginId: params.pluginId,
          decision: params.decision,
          note: params.note
        });
        await appendAuditRecord({ kind: "tool_review_plugin", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_preflight_artifact",
      label: "agent_passport_preflight_artifact",
      description: "Evaluate whether a scanned artifact should be allowed to install or enable right now, based on scanner posture and recorded review state",
      parameters: Type.Object({
        path: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await buildArtifactPreflight(params.path);
        await appendAuditRecord({ kind: "tool_preflight_artifact", input: params, ...result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_authorize_artifact_action",
      label: "agent_passport_authorize_artifact_action",
      description: "Authorize a specific artifact action such as install or enable using scanner posture plus recorded review state",
      parameters: Type.Object({
        action: Type.Union([
          Type.Literal("install"),
          Type.Literal("enable"),
          Type.Literal("update")
        ]),
        path: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await buildArtifactAuthorization({ action: params.action, targetPath: params.path });
        await appendAuditRecord({ kind: "tool_authorize_artifact", input: params, ...result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_run_artifact_action",
      label: "agent_passport_run_artifact_action",
      description: "Run an install or enable command only if Passport authorizes that artifact action first",
      parameters: Type.Object({
        action: Type.Union([
          Type.Literal("install"),
          Type.Literal("enable"),
          Type.Literal("update")
        ]),
        path: Type.String(),
        command: Type.String(),
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await runArtifactAction({
          action: params.action,
          targetPath: params.path,
          command: params.command,
          dryRun: params.dryRun
        });
        await appendAuditRecord({ kind: "tool_run_artifact", input: params, ...result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_install_openclaw_plugin",
      label: "agent_passport_install_openclaw_plugin",
      description: "Install a local OpenClaw plugin path only if Passport authorizes it first, with optional linked install and optional enable-after-install",
      parameters: Type.Object({
        path: Type.String(),
        link: Type.Optional(Type.Boolean()),
        pin: Type.Optional(Type.Boolean()),
        enableAfterInstall: Type.Optional(Type.Boolean()),
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await installOpenClawPluginFromPath(params);
        await appendAuditRecord({ kind: "tool_install_openclaw_plugin", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_enable_openclaw_plugin",
      label: "agent_passport_enable_openclaw_plugin",
      description: "Enable a local OpenClaw plugin path only if Passport authorizes it first",
      parameters: Type.Object({
        path: Type.String(),
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await enableOpenClawPluginFromPath(params);
        await appendAuditRecord({ kind: "tool_enable_openclaw_plugin", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_update_openclaw_plugin",
      label: "agent_passport_update_openclaw_plugin",
      description: "Update a Passport-recorded OpenClaw plugin only if Passport authorizes the update against the current recorded local source",
      parameters: Type.Object({
        pluginId: Type.String(),
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await updateOpenClawPluginFromLedger(params);
        await appendAuditRecord({ kind: "tool_update_openclaw_plugin", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_list_plugin_installs",
      label: "agent_passport_list_plugin_installs",
      description: "List Passport-recorded plugin installs for local OpenClaw plugin paths",
      parameters: Type.Object({
        pluginId: Type.Optional(Type.String())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await listPluginInstalls({ pluginId: params.pluginId });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_plugin_state",
      label: "agent_passport_plugin_state",
      description: "Return the combined install, drift, and review state for a Passport-recorded plugin",
      parameters: Type.Object({
        pluginId: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await buildPluginState({ pluginId: params.pluginId });
        await appendAuditRecord({ kind: "tool_plugin_state", input: params, result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_workspace_state",
      label: "agent_passport_workspace_state",
      description: "Return a combined workspace view across tracked plugins and skills, including attention queues",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await buildWorkspaceState();
        await appendAuditRecord({ kind: "tool_workspace_state", result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_workspace_audit",
      label: "agent_passport_workspace_audit",
      description: "Rank tracked plugins and skills for incident response after a ClawHavoc-style poisoning event",
      parameters: Type.Object({
        workspaceRoot: Type.Optional(Type.String()),
        ledgerDir: Type.Optional(Type.String()),
        includePlugins: Type.Optional(Type.Boolean()),
        includeSkills: Type.Optional(Type.Boolean()),
        maxItems: Type.Optional(Type.Number({ minimum: 1 }))
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const auditOptions = buildWorkspaceAuditOptions({
          workspaceRoot: params.workspaceRoot,
          ledgerDir: params.ledgerDir,
          includePlugins: params.includePlugins,
          includeSkills: params.includeSkills,
          maxItems: params.maxItems
        });
        const result = await buildWorkspaceAudit(auditOptions);
        await appendAuditRecord({ kind: "tool_workspace_audit", input: auditOptions, result });
        return jsonToolResult({ ...result, formatted: formatWorkspaceAudit(result) });
      }
    });

    api.registerTool({
      name: "agent_passport_check_plugin_drift",
      label: "agent_passport_check_plugin_drift",
      description: "Re-scan the last Passport-recorded local source for a plugin and compare it against the fingerprint captured at install time",
      parameters: Type.Object({
        pluginId: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await checkPluginInstallDrift({ pluginId: params.pluginId });
        await appendAuditRecord({ kind: "tool_check_plugin_drift", input: params, result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_skill_state",
      label: "agent_passport_skill_state",
      description: "Return the current install and review state for one tracked workspace skill",
      parameters: Type.Object({
        slug: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await buildSkillState({ slug: params.slug });
        await appendAuditRecord({ kind: "tool_skill_state", input: params, result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_list_skills_state",
      label: "agent_passport_list_skills_state",
      description: "List tracked workspace skills with Passport state summaries",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await listSkillStates();
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_check_skill_drift",
      label: "agent_passport_check_skill_drift",
      description: "Compare the current installed skill fingerprint against the last Passport-reviewed fingerprint for that skill slug",
      parameters: Type.Object({
        slug: Type.String()
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await checkSkillDrift({ slug: params.slug });
        await appendAuditRecord({ kind: "tool_check_skill_drift", input: params, result });
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_update_openclaw_skill",
      label: "agent_passport_update_openclaw_skill",
      description: "Run openclaw skills update for one tracked workspace skill, then return the resulting Passport state",
      parameters: Type.Object({
        slug: Type.String(),
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await updateOpenClawSkill({ slug: params.slug, dryRun: params.dryRun });
        await appendAuditRecord({ kind: "tool_update_openclaw_skill", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_update_all_openclaw_skills",
      label: "agent_passport_update_all_openclaw_skills",
      description: "Run openclaw skills update --all for tracked workspace skills, then return a Passport summary of resulting states",
      parameters: Type.Object({
        dryRun: Type.Optional(Type.Boolean())
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const result = await updateAllOpenClawSkills({ dryRun: params.dryRun });
        await appendAuditRecord({ kind: "tool_update_all_openclaw_skills", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_list_skills_rereview_queue",
      label: "agent_passport_list_skills_rereview_queue",
      description: "List tracked skills whose installed fingerprint drifted since the last Passport skill review and whose new fingerprint is not explicitly trusted",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await listSkillsNeedingRereview();
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_list_rereview_queue",
      label: "agent_passport_list_rereview_queue",
      description: "List Passport-recorded plugins whose source drifted and whose new fingerprint is not yet explicitly trusted",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await listPluginsNeedingRereview();
        return jsonToolResult(result);
      }
    });

    api.registerTool({
      name: "agent_passport_drift_sweep",
      label: "agent_passport_drift_sweep",
      description: "Sweep the re-review queue and report what newly entered or resolved since the last sweep",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await sweepRereviewQueue();
        await appendAuditRecord({ kind: "tool_drift_sweep", result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_drift_alerts",
      label: "agent_passport_drift_alerts",
      description: "Run a remembered-state drift sweep and return only whether new re-review alerts appeared, plus newly entered and resolved items",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const result = await buildDriftAlerts();
        await appendAuditRecord({ kind: "tool_drift_alerts", result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_list_scan_reviews",
      label: "agent_passport_list_scan_reviews",
      description: "List recorded scan-review decisions, optionally filtered by artifact fingerprint or decision",
      parameters: Type.Object({
        fingerprint: Type.Optional(Type.String()),
        decision: Type.Optional(Type.Union([
          Type.Literal("trust"),
          Type.Literal("review"),
          Type.Literal("block")
        ]))
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const reviews = await listScanReviews({
          fingerprint: params.fingerprint,
          decision: params.decision
        });
        return jsonToolResult(reviews);
      }
    });

    api.registerTool({
      name: "agent_passport_explain",
      label: "agent_passport_explain",
      description: "Explain how Agent Passport would classify a proposed action",
      parameters: Type.Object({
        action: Type.String(),
        target: Type.Optional(Type.String())
      }),
      async execute(_id, params) {
        const decision = evaluateAction({
          action: params.action,
          target: params.target ?? null
        });

        await appendAuditRecord({
          kind: "explain",
          input: params,
          decision
        });

        return jsonToolResult(decision);
      }
    });

    api.registerTool({
      name: "agent_passport_grant_consent",
      label: "agent_passport_grant_consent",
      description: "Grant temporary outbound-consent for a target",
      parameters: Type.Object({
        target: Type.String(),
        ttlMinutes: Type.Optional(Type.Number({ minimum: 1 })),
        reason: Type.Optional(Type.String())
      }),
      async execute(_id, params) {
        const pluginCfg = currentConfig();
        const grant = await grantConsent({
          target: params.target,
          ttlMinutes: params.ttlMinutes ?? pluginCfg.consentTtlMinutes,
          reason: params.reason
        });

        await appendAuditRecord({ kind: "grant_consent", grant });

        return jsonToolResult(grant);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_list_consents",
      label: "agent_passport_list_consents",
      description: "List active temporary consent grants",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        const grants = await listConsents();
        return jsonToolResult(grants);
      }
    });

    api.registerTool({
      name: "agent_passport_revoke_consent",
      label: "agent_passport_revoke_consent",
      description: "Revoke temporary outbound-consent for a target",
      parameters: Type.Object({
        target: Type.String()
      }),
      async execute(_id, params) {
        const result = await revokeConsent(params.target);
        await appendAuditRecord({ kind: "revoke_consent", target: params.target, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_request_consent",
      label: "agent_passport_request_consent",
      description: "Create or fetch a pending consent request for an outbound action",
      parameters: Type.Object({
        target: Type.String(),
        action: Type.Union([
          Type.Literal("message_sending"),
          Type.Literal("message.send"),
          Type.Literal("sessions_send")
        ]),
        reason: Type.Optional(Type.String())
      }),
      async execute(_id, params) {
        const request = await createConsentRequest(params);
        await appendAuditRecord({ kind: "request_consent", request });
        return jsonToolResult(request);
      }
    }, OPTIONAL_MUTATING_TOOL);

    api.registerTool({
      name: "agent_passport_list_requests",
      label: "agent_passport_list_requests",
      description: "List pending or historical consent requests",
      parameters: Type.Object({
        status: Type.Optional(Type.Union([
          Type.Literal("pending"),
          Type.Literal("approved"),
          Type.Literal("denied"),
          Type.Literal("all")
        ]))
      }, { additionalProperties: false }),
      async execute(_id, params) {
        const requests = await listConsentRequests({ status: params.status ?? "pending" });
        return jsonToolResult(requests);
      }
    });

    api.registerTool({
      name: "agent_passport_review_request",
      label: "agent_passport_review_request",
      description: "Approve or deny a pending consent request",
      parameters: Type.Object({
        requestId: Type.String(),
        decision: Type.Union([Type.Literal("approved"), Type.Literal("denied")]),
        ttlMinutes: Type.Optional(Type.Number({ minimum: 1 })),
        note: Type.Optional(Type.String())
      }),
      async execute(_id, params) {
        const pluginCfg = currentConfig();
        const result = await reviewConsentRequest({
          requestId: params.requestId,
          decision: params.decision,
          ttlMinutes: params.ttlMinutes ?? pluginCfg.consentTtlMinutes,
          note: params.note
        });
        await appendAuditRecord({ kind: "review_request", input: params, result });
        return jsonToolResult(result);
      }
    }, OPTIONAL_MUTATING_TOOL);
  }
});
