# Agent Passport 0.1.0

First draft release of Agent Passport as a native OpenClaw plugin.

## Included in this release
- scanner-first trust for skills, plugins, and package-like artifacts
- review decisions bound to exact fingerprints
- plugin install, enable, and update wrappers over real OpenClaw commands
- skill state, review, drift, and update wrappers aligned with real OpenClaw skill flows
- re-review queues for drifted plugins and skills
- a workspace-level operator view with Telegram actions for the top items that need attention
- runtime consent and audit controls on supported message and session-send paths

## What it does not claim
- universal interception of all dangerous actions
- remote preinstall scanning for every package source
- full runtime containment across all OpenClaw surfaces

## Focus
Agent Passport starts with poisoned-package defense:
- scan before trust
- authorize where hooks exist
- re-review when artifacts drift

The README has the current product story and workflow examples.
