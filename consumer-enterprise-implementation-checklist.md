# Agent Passport v1.1 Implementation Checklist

Status: working plan
Date: 2026-03-23
Context: reshape the current live local draft from a narrow outbound-comms trust plugin into one shared core serving both consumer OpenClaw and enterprise NemoClaw markets.

## Problem Statement
The current Agent Passport draft proves a real but narrow enforcement path: consent-gated outbound comms on selected hook surfaces such as `message_sending`, `message.send`, and `sessions_send`. That is useful, but it is not yet the right product shape for the market pain now exposed by ClawHavoc. Consumers need simple protection from poisoned skills without losing their control chat. Enterprises need package governance, provenance, approval workflows, and runtime containment for NemoClaw deployments. If we keep the current shape, we risk overfitting to chat-path gating while underserving the more important install, review, and trust problems.

## Goals
1. Add a scanner-led product layer that can flag ClawHavoc-style poisoned skills and plugins before or during install/enable workflows.
2. Preserve one shared Passport engine for both consumer and enterprise lanes, with different defaults and UX rather than separate codebases.
3. Make control-plane chat surfaces safe by default: trusted or audit-only, never easy to brick.
4. Keep the currently proven consent/audit/runtime gating paths, but reposition them as runtime containment rather than the sole product headline.
5. Produce a v1.1 package that can be described honestly for both consumer OpenClaw and enterprise NemoClaw audiences.

## Non-Goals
1. Universal interception of every dangerous action in OpenClaw or NemoClaw. Current public hooks do not support that honestly.
2. Full enterprise fleet backend, centralized policy service, or multi-tenant admin console in this iteration.
3. Perfect malware detection. Scanner v1 should be rule-based and explicit about limitations.
4. Blocking Telegram or other control-plane chat surfaces by default. That is out of scope and actively harmful.
5. Universal pre-install middleware across all package/install paths unless a real hook is confirmed. Wrapper/guided workflow is acceptable for v1.

## User Stories
### Consumer lane
- As a home or prosumer OpenClaw user, I want Passport to scan a skill before I trust it so that I can avoid installing something malicious.
- As a home user, I want a simple verdict with plain-English findings so that I can decide quickly without reading shell scripts.
- As a user controlling my agent over Telegram or similar chat, I want Passport to never brick my main control lane so that I can recover from problems.
- As a cautious user, I want Passport to warn or gate risky runtime behavior if a bad skill slips through so that damage is reduced.

### Enterprise lane
- As a NemoClaw admin, I want to evaluate skills/plugins before deployment so that suspicious packages do not enter the environment unchecked.
- As an enterprise buyer, I want provenance, approval state, and change tracking so that package trust can be governed over time.
- As a security owner, I want auditable runtime policy decisions so that I can review what the system blocked, warned on, or allowed.
- As an admin, I want package updates to trigger review when meaningful risk changes occur so that trust does not silently drift.

## Current State Snapshot
What the current draft already has:
- Real plugin package shape and runtime load
- Consent request lifecycle
- Audit trail
- Path-scoped trust
- Runtime config with per-path modes
- Proven `sessions_send` consent/enforce path
- Telegram `/passport` command and interactive approval lane in draft form
- Hooked paths:
  - `message_sending`
  - `before_tool_call` for `message.send`
  - `before_tool_call` for `sessions_send`

What the current draft does not yet have:
- Skill/plugin scanner
- Threat-rule families for ClawHavoc-style packages
- Provenance or package review state
- Update drift review
- Package verdict reports
- Consumer vs enterprise policy presets
- Explicit no-enforcement defaults for control-plane chat in docs and config schema

## Requirements

## P0: Reshape the core product safely
### P0.1 Control-lane safety defaults
**Requirement**
The default configuration and README must make primary control lanes trusted or audit-only by default.

**Acceptance criteria**
- [ ] README explicitly states that Telegram/control-plane chat is not enforced by default.
- [ ] Example config ships with chat/control-lane trust or audit-only posture.
- [ ] No demo or docs position Telegram blocking as the hero use case.
- [ ] Config examples distinguish consumer-safe defaults from narrower enterprise runtime enforcement.

**Current file impact**
- `README.md`
- `openclaw.plugin.json`
- `src/index.ts` (default policy handling and any helper text)

### P0.2 Scanner MVP
**Requirement**
Passport must gain a local scanner that evaluates skill/plugin packages for ClawHavoc-style patterns.

**Acceptance criteria**
- [ ] New scanner module can inspect a path containing docs, manifests, and scripts.
- [ ] Scanner returns machine-readable findings with severity, category, evidence, and recommendation.
- [ ] Scanner can classify at least: remote-script-execution, bootstrap-installer, credential-harvest indicators, suspicious-egress, wallet-targeting indicators, prompt-directed-shell-execution.
- [ ] Scanner outputs a top-level verdict: `safe`, `suspicious`, or `dangerous`.
- [ ] Scanner runs locally without requiring a cloud backend.

**Proposed files**
- `src/scanner/index.ts`
- `src/scanner/types.ts`
- `src/scanner/report.ts`
- `src/scanner/rules/remote-script.ts`
- `src/scanner/rules/bootstrap-installer.ts`
- `src/scanner/rules/credential-harvest.ts`
- `src/scanner/rules/suspicious-egress.ts`
- `src/scanner/rules/prompt-shell.ts`

### P0.3 Scanner tools
**Requirement**
Expose scanner capability through Passport tools and command UX.

**Acceptance criteria**
- [ ] Tool `agent_passport_scan_path` exists and returns a structured report.
- [ ] Tool `agent_passport_explain_finding` exists or equivalent explanation output is included in the scan result.
- [ ] `/passport` help text includes scanner usage once implemented.
- [ ] Scan output is readable by both humans and automation.

**Proposed files**
- `src/index.ts`
- `README.md`

### P0.4 Threat taxonomy
**Requirement**
The scanner and runtime policy engine should share named threat categories aligned with the product story.

**Acceptance criteria**
- [ ] Threat categories are defined centrally.
- [ ] Audit records reference stable category names.
- [ ] README explains what the initial categories mean.
- [ ] Category names are reused in reports and future policy packs.

**Proposed categories**
- `remote-script-execution`
- `bootstrap-installer`
- `credential-harvest`
- `wallet-targeting`
- `suspicious-egress`
- `hidden-secondary-payload`
- `private-network-probe`
- `prompt-directed-shell-execution`
- `risky-update-drift`

### P0.5 Product repositioning
**Requirement**
The README and docs must describe Passport as a shared trust engine with two packaging lanes: consumer and enterprise.

**Acceptance criteria**
- [ ] README has separate sections for consumer OpenClaw and enterprise NemoClaw use.
- [ ] README clearly states what is proven now vs partial vs future.
- [ ] Outbound comms gating is described as one runtime containment path, not the sole headline.
- [ ] ClawHavoc-style poisoned package detection is introduced as a core motivation.

## P1: Make the product more enterprise-real
### P1.1 Provenance and review store
**Requirement**
Add persistent review state for scanned packages.

**Acceptance criteria**
- [ ] Passport stores package review records with path/source, version if available, hash or fingerprint, scan verdict, findings summary, reviewedAt, review status.
- [ ] Re-scan can detect meaningful drift from the prior approved state.
- [ ] Audit records can reference review IDs.

**Proposed file**
- `<ledger>/package-reviews.json`
- `src/reviews.ts`

### P1.2 Consumer and enterprise policy presets
**Requirement**
Provide explicit presets rather than forcing users to hand-build policy.

**Acceptance criteria**
- [ ] Consumer preset trusts control chat and emphasizes scanner + warnings.
- [ ] Enterprise preset emphasizes review, provenance, stricter runtime containment, and package governance.
- [ ] Presets are documented and reproducible.

### P1.3 Update drift review
**Requirement**
Package trust should not silently survive meaningful change.

**Acceptance criteria**
- [ ] Re-scan shows whether docs/scripts/domains changed materially.
- [ ] A previously approved package can become `re-review-required` when risk shape changes.
- [ ] Report explains why re-review was triggered.

## P2: Future considerations
- Universal install interception if a real core hook exists
- Enterprise policy distribution backend
- Fleet-wide review and approval sync
- Publisher verification and signed provenance
- Deeper runtime enforcement if generic pre-tool / pre-network hooks become available

## Implementation Checklist by Current File

### `src/index.ts`
- [ ] Keep current consent and audit flows.
- [ ] Add scanner tools registration.
- [ ] Add `/passport scan <path>` and possibly `/passport findings <id>` command flows.
- [ ] Keep current config reads live, not snapshotted.
- [ ] Ensure control-lane trust remains the default, not an afterthought.
- [ ] Avoid expanding Telegram blocking logic; keep Telegram as command/report surface.

### `openclaw.plugin.json`
- [ ] Extend config schema with scanner/reporting options if needed.
- [ ] Consider explicit consumer/enterprise mode or preset selector.
- [ ] Document control-plane safe defaults in schema/examples.

### `README.md`
- [ ] Rewrite opening sections around ClawHavoc and poisoned package defense.
- [ ] Split into Consumer lane / Enterprise lane / Shared engine.
- [ ] Add truthful “what v1.1 does” and “what it does not claim” section.
- [ ] Add examples of scan output and trust/review workflow.

### New scanner module
- [ ] Build rule engine.
- [ ] Add deterministic report output.
- [ ] Keep evidence snippets small and clear.
- [ ] Prefer obvious, explainable detections first.

### New review/provenance module
- [ ] Store package review records.
- [ ] Compute package fingerprint.
- [ ] Compare against prior review state.
- [ ] Mark re-review-required on meaningful changes.

## Suggested Phase Order
### Phase 1: Safe repositioning
- Rewrite README
- Lock in control-lane safe defaults
- Stop presenting Telegram enforcement as the hero story

### Phase 2: Scanner MVP
- Implement scanner types, rules, and report output
- Add scan tool(s)
- Add example reports

### Phase 3: Review state
- Add package review persistence
- Add drift detection / re-review-required state

### Phase 4: Dual-lane packaging
- Add consumer preset
- Add enterprise/NemoClaw preset
- Polish docs and examples for both markets

## Success Metrics
### Leading indicators
- Users can run a scan locally and get a verdict in one command
- README clearly separates consumer and enterprise value propositions
- No default config blocks the main control lane
- At least one realistic malicious-pattern fixture is classified as suspicious or dangerous
- At least one benign fixture is classified as safe

### Lagging indicators
- Passport can be described credibly as an anti-ClawHavoc trust layer without overstating coverage
- Enterprise/NemoClaw conversations can center on governance rather than chat friction
- Consumer demos emphasize “safe install” rather than “why did my chat get blocked?”

## Open Questions
### Blocking
- Do we have a real package-install interception hook anywhere in current OpenClaw/NemoClaw, or should v1.1 intentionally ship with scan/review wrapper workflows first?
- Which package formats must the scanner support first: skill directories, plugin packages, tarballs, or all three?

### Non-blocking
- Do we want one combined scan+review tool or separate tools for raw scan and approval state?
- Should enterprise review metadata live only locally in v1.1, or do we want a JSON export format designed now for later sync?
- Do we want `modePreset: consumer|enterprise` or just documented example configs first?

## Recommended Immediate Next Step
Implement Phase 1 and Phase 2 only:
1. rewrite README and product framing
2. add scanner MVP and scan tool
3. leave existing consent/runtime gating intact
4. do not expand Telegram enforcement

That gets Passport aligned with the market pain fast without pretending we already have universal interception.
