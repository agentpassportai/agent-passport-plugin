# Runnable + Consent Upgrade Notes

Status: draft
Date: 2026-03-23

## Step 1: make it runnable
Completed in draft-package terms:
- package metadata tightened
- manifest updated
- tsconfig added
- first enforcement vertical aligned to real hook contracts
- plugin tools added for status/explain/consent management

## Step 2: add consent mechanics
Completed in first-pass draft terms:
- local consent store added
- temporary grant / list / revoke tools added
- hook logic now checks trusted targets and active consent grants before blocking
- plugin modes now support `audit`, `warn`, and `enforce`

## What still counts as unfinished
- local install/load validation
- exact tool runtime verification against a live OpenClaw process
- operator UX for approvals beyond manual consent-grant tools
- richer target matching (channel-aware, thread-aware, identity-aware)
- consent prompts linked to an actual user-facing approval interaction

## Honest status
This is now beyond architecture. It is a plausible draft plugin package with:
- a real enforcement vertical
- real temporary consent mechanics
- real audit trail

But it is not yet proven by a live load test.
