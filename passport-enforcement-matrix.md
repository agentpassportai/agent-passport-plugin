# Agent Passport Enforcement Matrix

Status: draft
Date: 2026-03-23

## Summary

Agent Passport can be a real OpenClaw plugin now, but not yet a universal pre-action interceptor across every sensitive runtime path.

The strongest v1 position is:
- **enforce** on owned or clearly hookable surfaces
- **audit + explain** on adjacent surfaces
- **integrate with existing approvals** where core already owns the hard gate
- avoid pretending that one plugin can transparently intercept every dangerous action in the system without core changes

---

## Enforcement scale

- **Strong** — practical v1 enforcement path exists
- **Medium** — partial enforcement or wrapper-based enforcement exists
- **Weak** — mostly audit/explain today, needs core hook expansion for real enforcement

---

## Matrix

| Action surface | Interceptable now? | Enforcement level | Current mechanism / evidence | V1 plan | Main gap |
|---|---:|---|---|---|---|
| Outbound messaging / posting | Partial | Strong | Channel action gates and message lifecycle hooks exist; shipped code/examples reference `message_sending`, action gates, and channel-specific controls | Require consent for outbound sends on supported channel surfaces; log every outbound decision | No guaranteed single universal pre-send gate across every possible channel/tool path |
| Exec / shell commands | Partial | Medium | Core exec approvals system exists with `exec.approval.requested` and `exec.approval.resolved` events | Piggyback on core exec approvals: add Passport policy explanation, audit, rule tags, operator-facing reasoning | No documented public generic pre-exec plugin interceptor |
| Web fetch / SSRF / private-network access | Partial | Medium | SSRF guard helpers exist and guarded fetch patterns exist in plugin SDK/runtime | Enforce on Passport-owned tools and network wrappers; block private-network targets by policy where Passport owns request flow | No evidence of a universal pre-request interception layer for all plugins/tools |
| Provider/model selection and inference governance | Yes | Strong | Provider plugins have real runtime hooks (`resolveDynamicModel`, `prepareDynamicModel`, `wrapStreamFn`, etc.) | Restrict providers/models, attach policy metadata, audit inference decisions, deny disallowed providers | Covers inference governance, not general side effects |
| File writes / deletes / path traversal | Limited | Weak | No documented global filesystem interception hook found in current public plugin docs | Provide Passport-owned protected file tools and policy-test helpers; audit intent where visible | No universal pre-write/pre-delete hook |
| Plugin/package installs | Limited | Weak | Install paths exist, but no documented public pre-install interception hook found | Offer safer wrapper flow, policy checks, audit, and operator guidance | No generic install middleware surfaced in current SDK docs |
| Config mutation | Limited | Weak | Config load/write helpers exist, but not a clear generic policy interception hook before all config changes | Add policy-aware wrapper/admin tooling and audit for sensitive config changes | No universal pre-config-mutation gate found |
| Subagent spawning / background delegation | Yes | Strong | Typed events exist for `subagent_spawning`, `subagent_ended`, and delivery targeting | Audit and govern delegation patterns; require policy on risky subagent launches where hook coverage allows | Need precise event payload/ordering verification for hard enforcement |
| Conversation binding / approval-linked workflows | Yes | Medium | `onConversationBindingResolved(...)` exists | Use for policy state, trust state changes, approval-linked audit | Useful for workflow trust, not broad side-effect enforcement |
| Session/context lifecycle | Yes | Medium | Typed lifecycle hooks like `session_before_compact` and `context` are present in shipped code | Use for audit summarization, risk carry-forward, and policy state maintenance | Observability is stronger than hard blocking |

---

## What Agent Passport can credibly ship as v1

### 1. Outbound comms trust layer
- Require consent for outbound sending on supported paths
- Explain why a send/post is gated
- Maintain a durable audit trail

### 2. Exec approval intelligence layer
- Listen to exec approval lifecycle
- Attach Passport-style reasoning to approval requests
- Track policy hits and operator decisions
- Produce audit and reviewable history

### 3. Protected network access layer
- Provide Passport-owned safe network wrappers
- Deny or gate private-network / SSRF-like destinations
- Add policy packs for local/internal targets, metadata endpoints, and suspicious redirects

### 4. Inference governance layer
- Restrict model/provider choices
- Audit provider/model usage
- Enforce trust posture by environment or workspace

### 5. Audit and explanation layer
- Status, explain, and audit-search tools
- Decision history with clear rule attribution
- Operator-readable remediation guidance

---

## What should NOT be claimed in v1

Do not claim that Passport universally intercepts all of:
- filesystem writes/deletes
- all message sends in all paths
- all network requests from all plugins
- all config mutations
- all install actions

That claim would outrun the visible public SDK surface.

---

## Recommended v1 product wording

> Agent Passport is the trust layer for OpenClaw: consent gating, outbound communication controls, network safety policy, inference governance, and auditable agent decisions.

That is strong and true.

Avoid saying:

> Agent Passport intercepts every dangerous action everywhere.

Not true yet.

---

## Best implementation strategy

### Path A — realistic v1
Build Passport as a hybrid plugin that does:
- **enforcement** where hooks are real
- **wrapper enforcement** where Passport owns the action surface
- **audit/explain** where core currently owns the hard gate

This is the right move.

### Path B — future strengthening
After v1, propose a narrow OpenClaw core addition:
- generic pre-tool-execution hook
- generic action classification pipeline
- generic side-effect gate abstraction

If those land, Passport becomes dramatically stronger without ugly hacks.

---

## Immediate build priority

1. Outbound comms gating
2. Exec approval integration
3. Safe network wrapper / SSRF policy
4. Provider governance
5. Audit search + explanation UX

That is enough for a real first release.
