# Agent Passport

Status: draft release candidate  
Package: `@agentholdings/agent-passport`  
Plugin id: `agent-passport`

Agent Passport is a trust layer for OpenClaw packages and actions.

The core idea is simple:

**scan before trust. authorize before install, enable, or update where hooks exist. re-review when artifacts drift.**

This is the honest product shape now. Not a fake universal interceptor. Not a chat-locking demo. A real scanner-first trust layer with runtime containment on the surfaces Passport actually controls.

## Why this exists

ClawHavoc-style poisoned skills, plugins, and package flows are the real problem.

A dangerous artifact does not need to look like malware in the old sense. It can hide in:
- install instructions
- shell snippets in docs
- bootstrap scripts
- manifest defaults
- staged payloads
- suspicious egress or credential collection behavior

Agent Passport exists to make that reviewable before trust, then keep trust from quietly going stale after the artifact changes.

## What Agent Passport is

Agent Passport is one shared core with two packaging lanes.

### Consumer lane
For OpenClaw users who want help avoiding sketchy skills and plugins without bricking their control lane.

Priorities:
- plain-English scan results
- safe defaults
- lightweight review and trust decisions
- control chat stays trusted or audit-only by default
- optional runtime containment where Passport has real hooks

### Enterprise lane
For NemoClaw or managed deployments that need package governance, approvals, provenance, drift review, and runtime controls.

Priorities:
- artifact review workflows
- explicit trust state
- re-review on drift
- auditable authorization decisions
- runtime containment on supported surfaces

### Shared core
Both lanes use the same core ideas:
- fingerprint the artifact you reviewed
- bind review decisions to content, not just a path string
- do not let old trust silently survive meaningful drift
- separate scanner truth from runtime policy truth
- be honest about what Passport can and cannot intercept

## Hard product rules

These are non-negotiable.

- Do not block Telegram or the primary control lane by default.
- Do not pretend Passport intercepts every dangerous action in OpenClaw.
- Do not claim package trust based only on a file path.
- Do not let prior trust silently survive artifact drift.
- Do use real hook surfaces when enforcing policy.

## What is proven today

This draft already proves real product surface, not just theory.

### Scanner and review
- local artifact scanner with explainable findings
- artifact fingerprinting
- review decisions bound to exact fingerprint
- verdicts: `safe`, `suspicious`, `dangerous`
- recommendations such as `allow`, `review-before-trust`, and `block-package`

### Plugin governance
- local plugin install wrapper over real `openclaw plugins install`
- plugin enable wrapper over real `openclaw plugins enable`
- plugin update wrapper over real `openclaw plugins update`
- install ledger for recorded plugin source, fingerprint, recommendation, and review state
- drift-aware re-review for plugin enable and update
- plugin-level operator actions by plugin id

### Skill governance
- tracked workspace skill visibility based on real ClawHub metadata
- slug-level review actions for installed skills
- skill drift detection against the last Passport-reviewed fingerprint
- single-skill and workspace-wide skill update wrappers over real OpenClaw skill update flows
- skills re-review queue when installed contents drift

### Operator workflow
- single-item truth views for plugins and skills
- combined `/passport workspace-state` view across plugins and skills
- Telegram action buttons from the workspace view
- proactive drift sweep and drift alerts
- cron/shell-friendly alerts CLI

### Runtime containment already in draft
Passport also has a real runtime consent and audit lane on supported surfaces:
- `message_sending`
- `message.send`
- `sessions_send`

That matters. It is just no longer the whole headline.

## What Agent Passport does not claim

This draft does **not** honestly claim:
- universal pre-install interception
- universal pre-exec interception
- universal pre-network interception
- universal pre-file-write or pre-delete interception
- complete containment of every malicious plugin or skill path
- remote preinstall scanning of ClawHub content before OpenClaw fetches it

The right current claim is narrower and stronger:

**Agent Passport helps detect and constrain poisoned skills and plugins on the paths it can actually see and control.**

## Scanner model

The scanner is local, rule-based, and explainable on purpose.

That is a feature, not a compromise. Operators should be able to see why something was flagged.

### Current high-signal categories
- `remote-script-execution`
- `bootstrap-installer`
- `credential-harvest`
- `suspicious-egress`
- `prompt-directed-shell-execution`
- `manifest-lifecycle`
- `staged-payload`
- `persistence-autorun`

### Artifact-aware interpretation
The scanner distinguishes artifact shape and explains findings differently for:
- `skill`
- `plugin`
- `package`
- `hybrid`
- `unknown`

That means Passport can say more than “this looks bad.” It can explain why the signal matters for this kind of artifact.

### Example outcomes
- clean plugin → `allow`
- docs-risk plugin → `review-before-trust`
- suspicious skill → `review-before-trust`
- runtime-risk plugin → `block-package`

## Trust model

Trust follows content.

That means:
- scan an artifact
- compute fingerprint
- record `review`, `trust`, or `block`
- reuse that decision only for the same fingerprint
- if contents drift later, old trust no longer counts for the new fingerprint

This is why drift matters so much in Passport. “We reviewed it once” is not good enough if the thing changed.

## Plugin workflow

Plugins are the most complete lifecycle in the draft right now.

### Real plugin commands
- `/passport install-plugin <local-path> [--link] [--pin] [--enable] [--dry-run]`
- `/passport enable-plugin <local-path> [--dry-run]`
- `/passport update-plugin <pluginId> [--dry-run]`
- `/passport installs [pluginId]`
- `/passport plugin-state <pluginId>`
- `/passport trust-plugin <pluginId>`
- `/passport review-plugin <pluginId>`
- `/passport block-plugin <pluginId>`
- `/passport drift-plugin <pluginId>`
- `/passport rereview-queue`

### Plugin state model
Plugin views combine:
- latest recorded install
- current fingerprint
- current review state
- recorded vs current recommendation
- drift status
- recommended next actions

### Drift policy
If the current source fingerprint no longer matches the fingerprint captured at install time:
- prior trust is no longer enough for enable/update
- Passport moves the plugin into re-review flow
- new trust must be recorded for the new fingerprint

## Skill workflow

Skills are handled honestly. Not as fake plugin clones.

OpenClaw skills are ClawHub slug-based, not local-path plugin installs. So Passport currently focuses on installed-state truth, review state, and drift-aware re-review.

### Real skill commands
- `/passport skills`
- `/passport skill-state <slug>`
- `/passport trust-skill <slug>`
- `/passport review-skill <slug>`
- `/passport block-skill <slug>`
- `/passport drift-skill <slug>`
- `/passport skills-rereview`
- `/passport update-skill <slug> [--dry-run]`
- `/passport update-skills [--dry-run]`

### Skill truth model
For tracked skills, Passport can show:
- installed version
- workspace path
- current fingerprint
- current review state
- scanner verdict and recommendation
- last Passport-reviewed fingerprint
- whether the installed skill drifted and needs re-review

### Honest limitation
Passport does **not** yet claim remote preinstall scanning of ClawHub packages before fetch. The current promise is post-install truth, review, and drift governance for installed skills.

## Workspace operator view

`/passport workspace-state` is the top-level operator view.

It rolls up tracked plugins and tracked skills into one summary, then shows the items that currently need attention.

On Telegram it also supports lightweight interaction:
- refresh workspace
- inspect top plugin or skill detail
- review, trust, or block the top plugin or skill
- return to the workspace view after inspection

That gives Passport a real operator loop instead of a pile of disconnected commands.

## Example workflows

### 1. Clean plugin
Goal: install a local plugin that scans cleanly and keep the workflow honest.

```bash
/passport scan ./fixtures/scanner/clean-plugin
/passport install-plugin ./fixtures/scanner/clean-plugin --dry-run
```

Expected shape:
- verdict: `safe`
- recommendation: `allow`
- install wrapper shows the real `openclaw plugins install` command it would run
- if you trust and install it for real, Passport records the install fingerprint and can later detect drift

Why this matters:
- Passport stays out of the way when the artifact is boring and clean
- the install is still fingerprinted and recorded so trust has memory later

### 2. Suspicious skill
Goal: inspect an installed or local skill that looks sketchy, review it, and avoid fake certainty.

```bash
/passport scan ./fixtures/scanner/suspicious-skill
/passport review ./fixtures/scanner/suspicious-skill
```

Expected shape:
- verdict: usually `suspicious`
- recommendation: `review-before-trust`
- findings point at risky shell guidance, bootstrap steps, or other operator-trust issues
- `review` records that a human looked at this exact fingerprint
- `trust` is a stronger statement than `review` and should be used deliberately

Why this matters:
- many bad artifacts are dangerous because they trick the operator, not because they exploit a runtime hook
- Passport treats docs and setup instructions as part of the trust surface

### 3. Drift and re-review
Goal: show that prior trust does not silently survive artifact change.

Typical flow:

```bash
/passport plugin-state <pluginId>
/passport drift-plugin <pluginId>
/passport workspace-state
```

Expected shape after the source changes:
- plugin moves to `rereview-required`
- old trust is no longer enough for enable or update
- drift output shows recorded fingerprint vs current fingerprint
- workspace view surfaces the changed item and lets the operator inspect or act

If the operator decides the new fingerprint is acceptable:

```bash
/passport review-plugin <pluginId>
/passport trust-plugin <pluginId>
```

Why this matters:
- Passport trust follows content, not nostalgia
- this is the difference between a real governance loop and a one-time checkbox

## Drift and alerts

Passport includes a proactive drift layer.

### Commands
- `/passport drift-sweep`
- `/passport drift-alerts`

### CLI
```bash
npm run drift:alerts
npm run drift:sweep
npm run drift:alerts:json
node ./scripts/drift-alerts.mjs --mode alerts --format json
```

Exit codes:
- `0` = success, no new alerts
- `10` = success, new alerts detected
- `1` = error

Alerts-mode JSON includes:
- `alert`
- `newlyEntered`
- `resolved`
- `summary`
- `nextCommand: "/passport workspace-state"`

That makes Passport easy to wire into cron or shell automation without noisy repeated alerts.

## Install and local development

### Local plugin path
Install this draft from a local checkout with the real OpenClaw plugin command:

```bash
openclaw plugins install /path/to/agent-passport-plugin-v1 --link
openclaw plugins enable agent-passport
```

### Local verification
From the repo root:

```bash
npm run scan:regression
npm run drift:alerts:json
```

Those helper scripts and regression fixtures live in the source repo for development and validation. They are not part of the published package tarball.

## Commands

### Core
- `/passport status`
- `/passport requests [pending|approved|denied|all]`
- `/passport scan <path>`
- `/passport preflight <path>`
- `/passport authorize <install|enable|update> <path>`
- `/passport run <install|enable|update> <path> -- <command>`
- `/passport trust <path>`
- `/passport review <path>`
- `/passport block <path>`
- `/passport approve <requestId>`
- `/passport deny <requestId>`

### Plugins
- `/passport install-plugin <local-path> [--link] [--pin] [--enable] [--dry-run]`
- `/passport enable-plugin <local-path> [--dry-run]`
- `/passport update-plugin <pluginId> [--dry-run]`
- `/passport installs [pluginId]`
- `/passport plugin-state <pluginId>`
- `/passport trust-plugin <pluginId>`
- `/passport review-plugin <pluginId>`
- `/passport block-plugin <pluginId>`
- `/passport drift-plugin <pluginId>`
- `/passport rereview-queue`

### Skills
- `/passport skills`
- `/passport skill-state <slug>`
- `/passport trust-skill <slug>`
- `/passport review-skill <slug>`
- `/passport block-skill <slug>`
- `/passport drift-skill <slug>`
- `/passport skills-rereview`
- `/passport update-skill <slug> [--dry-run]`
- `/passport update-skills [--dry-run]`

### Workspace
- `/passport workspace-state`
- `/passport drift-sweep`
- `/passport drift-alerts`

## Tools
- `agent_passport_status`
- `agent_passport_scan_path`
- `agent_passport_explain`
- `agent_passport_grant_consent`
- `agent_passport_list_consents`
- `agent_passport_revoke_consent`
- `agent_passport_request_consent`
- `agent_passport_list_requests`
- `agent_passport_review_request`
- `agent_passport_review_scan`
- `agent_passport_preflight_artifact`
- `agent_passport_authorize_artifact_action`
- `agent_passport_run_artifact_action`
- `agent_passport_install_openclaw_plugin`
- `agent_passport_enable_openclaw_plugin`
- `agent_passport_update_openclaw_plugin`
- `agent_passport_list_plugin_installs`
- `agent_passport_plugin_state`
- `agent_passport_review_plugin`
- `agent_passport_check_plugin_drift`
- `agent_passport_list_rereview_queue`
- `agent_passport_workspace_state`
- `agent_passport_skill_state`
- `agent_passport_list_skills_state`
- `agent_passport_review_skill`
- `agent_passport_check_skill_drift`
- `agent_passport_update_openclaw_skill`
- `agent_passport_update_all_openclaw_skills`
- `agent_passport_list_skills_rereview_queue`
- `agent_passport_drift_sweep`
- `agent_passport_drift_alerts`
- `agent_passport_list_scan_reviews`

## Scanner regression fixtures

Regression fixtures live under `fixtures/scanner/`:
- `clean-plugin`
- `governance-risk-plugin`
- `runtime-risk-plugin`
- `docs-risk-plugin`
- `suspicious-skill`

Run the regression suite:

```bash
npm run scan:regression
```

Update snapshots:

```bash
npm run scan:regression:update
```

Run one case:

```bash
npm run scan:regression:case -- docs-risk-plugin
```

Machine-readable output:

```bash
npm run scan:regression:json
node ./scripts/scanner-regression.mjs --format json
```

Compact human output:

```bash
npm run scan:regression:summary
```

Counts output:

```bash
npm run scan:regression:counts
```

CLI smoke coverage:

```bash
npm run scan:regression:cli
```

This is the cheap drift alarm for scanner semantics. If scanner behavior moves, these cases should fail before docs and demos quietly drift apart.

## Recommended posture

### Consumer-safe default
- default mode: `warn` or `audit`
- control lane trusted or audit-only
- scanner and explanation first
- runtime containment as backup, not the headline

### Enterprise-leaning default
- scanner before trust or enable
- authorize before install, enable, or update where supported
- require re-review on meaningful drift
- keep auditable approval state
- use tighter runtime containment on supported non-control paths

## Near-term roadmap

1. keep improving docs and positioning around poisoned-package defense
2. preserve safe defaults for control lanes
3. continue hardening scanner semantics and report quality
4. tighten plugin and skill re-review workflows
5. add deeper provenance and publisher trust later
6. only claim broader interception when real hooks exist

## Bottom line

Agent Passport is no longer just an outbound-comms gate.

It is becoming a scanner-first trust layer for poisoned skills and plugins, with real review state, drift-aware re-review, honest install and update authorization where hooks exist, and runtime containment on the paths Passport can actually control.

That is the right story. And now the code is finally close enough to the story that the README can say it without bullshit.
