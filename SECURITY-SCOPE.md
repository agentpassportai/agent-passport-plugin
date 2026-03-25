# Security Scope

Agent Passport is a scanner-first trust layer for OpenClaw. It is not a universal sandbox, and it does not claim to intercept every dangerous action.

## What It Stores Locally

By default, Passport keeps its state under `.openclaw/agent-passport/` in the active workspace unless the ledger directory is overridden by environment or plugin config.

Typical local records are:
- `scan-reviews.json` for fingerprint-bound trust, review, and block decisions
- `plugin-installs.json` for recorded plugin source, fingerprint, and install state
- `skill-reviews.json` for tracked skill review state
- `consents.json` for temporary outbound consent grants and requests
- `rereview-state.json` for drift queue tracking
- `audit.jsonl` for audit events when audit logging is enabled

These records are local operator state, not provenance.

## What It Enforces Today

Passport enforces consent checks on the hook surfaces it actually controls:
- `message_sending`
- `message.send`
- `sessions_send`

It also wraps explicit install, enable, update, review, trust, block, and drift workflows for local plugins and tracked workspace skills.

## What It Does Not Claim

Passport does not claim:
- universal pre-install interception
- universal pre-exec interception
- universal pre-network interception
- universal pre-file-write or pre-delete interception
- complete containment of every malicious plugin or skill path
- remote preinstall scanning of ClawHub content before OpenClaw fetches it

## Public Surface

The public, read-only surface is:
- scan
- status
- state
- drift inspection
- queue inspection
- explain-only policy views

Operator actions such as install, enable, update, trust, review, block, and consent grant are higher-risk and should be treated as explicit workflows, not ambient defaults.

## Handling Rule

The safe reading rule is simple: trust follows content, local state is fingerprint-bound, and anything that changes the artifact should trigger re-review.
