Agent Passport 0.1.2 cleans up the canonical release line after the ClawHub publish work.

This release keeps the canonical npm package identity as `@agentholdings/agent-passport`, preserves the runtime plugin id as `agent-passport`, and retains the ClawHub compatibility metadata added for publication. It also keeps the published artifact surface lean by excluding regression fixtures, helper scripts, and internal planning docs from the package tarball.

The product behavior is unchanged in intent: scanner-first trust, fingerprint-bound review, drift-aware rereview, and runtime policy checks only on the OpenClaw surfaces Passport actually controls.
