# Agent Passport

NPM package: `@agentholdings/agent-passport`  
ClawHub package: `agent-passport-plugin`  
Plugin id: `agent-passport`

Agent Passport is a trust layer for OpenClaw packages and actions.

**Scan before trust. Authorize before install, enable, or update where hooks exist. Re-review when artifacts drift.**

It is built to catch poisoned skills, plugins, and package updates before they quietly become trusted. Trust decisions are tied to the contents you reviewed, not just a name or path.

The three names are intentional:
- install from npm with `@agentholdings/agent-passport`
- find it on ClawHub as `agent-passport-plugin`
- enable or inspect it inside OpenClaw as `agent-passport`

ClawHub package names must match `package.json` and share a namespace with skill slugs. `agent-passport` was already taken there, so the ClawHub listing uses `agent-passport-plugin` while npm and the runtime plugin id stay cleaner for normal OpenClaw use.

Security scope and local state are documented in [SECURITY-SCOPE.md](./SECURITY-SCOPE.md).

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

Agent Passport is built around a few core ideas:
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

## What is available today

These parts are already implemented.

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
- local-first quarantine inspection helper for staging skill artifacts before trust
- slug-level review actions for installed skills
- skill drift detection against the last Passport-reviewed fingerprint
- single-skill and workspace-wide skill update wrappers over real OpenClaw skill update flows
- skills re-review queue when installed contents drift

### Operator workflow
- single-item truth views for plugins and skills
- combined `/passport workspace-state` view across plugins and skills
- ranked `/passport workspace-audit` incident-response view with remediation targets
- Telegram action buttons from the workspace view
- proactive drift sweep and drift alerts
- cron/shell-friendly alerts CLI

### Local state
Passport stores its review and operating state locally in the workspace unless configured otherwise:
- scan review decisions are fingerprint-bound
- plugin install records capture source path, manifest path, fingerprint, and review state
- skill review records capture slug, skill directory, fingerprint, and review state
- consent grants and requests are local and temporary
- drift queue state is local and used only to surface re-review work
- audit logs are local JSONL records and should be treated as sensitive operator data

### Runtime containment
Passport also has runtime consent and audit controls on supported surfaces:
- `message_sending`
- `message.send`
- `sessions_send`

## What Agent Passport does not claim

Agent Passport does **not** claim:
- universal pre-install interception
- universal pre-exec interception
- universal pre-network interception
- universal pre-file-write or pre-delete interception
- complete containment of every malicious plugin or skill path
- remote preinstall scanning of ClawHub content before OpenClaw fetches it

Current scope:

**Agent Passport helps detect and constrain poisoned skills and plugins on the paths it can actually see and control.**

## Scanner model

The scanner is local, rule-based, and explainable. Operators should be able to see why something was flagged.

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

That lets Passport explain why a signal matters for this kind of artifact instead of just saying something looks bad.

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

Plugins are the most complete lifecycle right now.

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

Skills are handled as skills, not treated like plugin clones.

OpenClaw skills are ClawHub slug-based, not local-path plugin installs. Passport focuses on installed-state truth, review state, and drift-aware re-review.

### Real skill commands
- `/passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]`
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

`/passport workspace-audit` is the incident-response view. It re-ranks tracked plugins and skills by risk, highlights remediation targets, and gives a concrete next-step list after a ClawHavoc-style event.

It rolls up tracked plugins and tracked skills into one summary, then shows the items that currently need attention.

On Telegram it also supports lightweight interaction:
- refresh workspace
- inspect top plugin or skill detail
- review, trust, or block the top plugin or skill
- return to the workspace view after inspection

That gives operators one place to inspect and act instead of bouncing between unrelated commands.

## Example workflows

### 1. Clean plugin
Install a local plugin that scans cleanly.

```bash
/passport scan /path/to/clean-plugin
/passport install-plugin /path/to/clean-plugin --dry-run
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
Inspect a skill that looks sketchy and review it before trusting it.

```bash
/passport scan /path/to/suspicious-skill
/passport review /path/to/suspicious-skill
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
Show that prior trust does not silently survive an artifact change.

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
openclaw passport-audit
openclaw passport-inspect-skill /path/to/skill
```

Use the in-product Passport commands above as the primary operator surface. The explicit OpenClaw CLI entrypoints are there for automation and shell-driven workflows.

## Install and local development

### Local plugin path
Install from a local checkout with the standard OpenClaw plugin command:

```bash
openclaw plugins install /path/to/agent-passport-plugin --link
openclaw plugins enable agent-passport
```

### Local verification
From the repo root, use `npm pack --dry-run` to confirm the published surface is clean before release.

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
- `/passport inspect-skill <path> [--label <label>] [--max-files <n>] [--max-bytes <n>]`
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
- `/passport workspace-audit [--plugins-only|--skills-only] [--max <n>]`
- `/passport drift-sweep`
- `/passport drift-alerts`

## Public Surface

The default public-facing story should stay read-only and review-oriented:
- scan, status, state, drift, and explain flows are the safest public entry points
- install, enable, update, trust, review, block, and consent-grant flows are explicit operator actions
- mutating flows are higher-risk and should be used deliberately, not treated as ambient assistant behavior

If you are documenting or publishing Passport on ClawHub, this distinction matters more than the command count.

## Tools
- `agent_passport_status`
- `agent_passport_scan_path`
- `agent_passport_inspect_skill_artifact`
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
- `agent_passport_workspace_audit`
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

## Recommended posture

- default mode: `warn` or `audit`
- keep the control lane trusted or audit-only
- put scanner output and explanation first
- use runtime containment as a supported backstop, not the headline

## Bottom line

Agent Passport is a scanner-first trust layer for poisoned skills and plugins, with review state, drift-aware re-review, install and update authorization where hooks exist, and runtime containment on the paths Passport can actually control.
