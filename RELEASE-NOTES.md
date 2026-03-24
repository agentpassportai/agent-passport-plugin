# Agent Passport 0.1.0

Initial draft release of Agent Passport as a native OpenClaw plugin.

## What is in this release
- scanner-first trust model for skills, plugins, and package-like artifacts
- fingerprint-bound review decisions
- plugin install, enable, and update wrappers on real OpenClaw commands
- skill state, review, drift, and update wrappers aligned to real OpenClaw skill flows
- drift-aware re-review queues for plugins and skills
- workspace-level operator view with Telegram actions for top attention items
- runtime consent and audit controls on supported message/session-send paths

## What this release does not claim
- universal interception of all dangerous actions
- remote preinstall scanning for every package source
- full runtime containment across all OpenClaw surfaces

## Positioning
Agent Passport is aimed at poisoned-package defense first:
- scan before trust
- authorize where hooks exist
- re-review when artifacts drift

Use the README for the current product story and workflow examples.
