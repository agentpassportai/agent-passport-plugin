# Agent Passport v1 Build Plan

Status: draft
Date: 2026-03-23

## Goal
Ship a credible first version of Agent Passport as a native OpenClaw plugin without overclaiming runtime powers the current plugin surface does not clearly expose.

## Product thesis
Agent Passport should be the trust layer above OpenClaw runtime:
- consent gating
- outbound communication controls
- network safety policy
- inference governance
- auditability

## v1 scope

### In scope
- Native plugin package
- Config schema
- Decision engine
- Audit logging
- Explanation tools
- First real enforcement on one or two hookable surfaces
- Exec approval integration
- Outbound comms policy on supported paths
- Protected network wrapper / private-network denial policy

### Out of scope
- Universal interception of every tool and side effect
- Full enterprise dashboard
- Org-wide fleet policy sync
- Rich hosted compliance reporting
- Cross-framework trust SDK

## Workstreams

### 1. Hook verification
Goal: replace assumptions with exact runtime evidence.

Deliverable:
- verified hook/event list
- which hooks are notification-only vs block-capable
- exact surfaces Passport can own in v1

Done when:
- we have a short implementation note mapping each chosen v1 surface to a real SDK/runtime hook

### 2. Policy engine hardening
Goal: turn the starter rule engine into a usable policy core.

Deliverable:
- normalized action categories
- policy outcome enum: `allow | deny | require_consent`
- rule metadata including severity, rule id, explanation, remediation hint

Done when:
- example inputs across 8-10 action patterns return stable, understandable decisions

### 3. Audit trail
Goal: make every Passport decision reviewable.

Deliverable:
- local JSONL audit records
- stable schema for event type, decision, actor/session context, reason, rule hit
- simple query/read helper

Done when:
- a human can inspect recent Passport decisions without reading raw code

### 4. Outbound comms gating
Goal: make external comms the first clearly marketable enforcement surface.

Deliverable:
- consent-required policy for outbound send/post on supported surfaces
- clear operator explanation text
- audit record per outbound decision

Done when:
- Passport can gate at least one real outbound path end-to-end

### 5. Exec approval integration
Goal: make Passport augment the strongest existing core safety rail.

Deliverable:
- listen to exec approval lifecycle events
- attach Passport classification and rationale
- persist approval outcome in Passport audit trail

Done when:
- an exec approval request/resolution is reflected in Passport audit and explanation output

### 6. Safe network wrapper
Goal: enforce SSRF/private-network policy where Passport owns the request path.

Deliverable:
- wrapper or helper for outbound requests
- deny/gate local/private targets by policy
- explanation for why a target is blocked

Done when:
- a test request to localhost/private IP is denied with a useful reason

### 7. Provider governance
Goal: prove Passport can govern inference choices, not just side effects.

Deliverable:
- allow/deny model/provider rules
- inference audit records
- environment-specific restrictions where useful

Done when:
- Passport can block or flag a disallowed provider/model selection on a supported path

## Proposed milestone sequence

### Milestone 1 — package skeleton
- package manifest
- plugin manifest
- entrypoint
- starter policy engine
- starter audit writer

Status: done in draft form

### Milestone 2 — enforcement matrix and hook map
- exact runtime surface map
- choose first enforceable surfaces

### Milestone 3 — first real enforcement path
- outbound comms OR safe network wrapper
- end-to-end working demo

### Milestone 4 — exec approval integration
- approval lifecycle audit and explanation

### Milestone 5 — polish for publishability
- docs
- install instructions
- config examples
- package cleanup
- ClawHub packaging verification

## Success criteria for v1
- installs as a native OpenClaw plugin
- produces understandable policy decisions
- logs durable audit records
- gates at least one real sensitive action path
- integrates with at least one existing core approval/runtime surface
- can be explained honestly without hand-waving

## Biggest risk
The biggest risk is not technical difficulty. It is pretending the current SDK can do more universal interception than it really can.

## Correct strategy
Be narrow, sharp, and honest:
- enforce where real
- audit where adjacent
- propose core hook additions only after proving value
