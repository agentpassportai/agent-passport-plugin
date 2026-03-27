Agent Passport 0.1.5 upgrades to OpenClaw `2026.3.24` and adds audit-first inbound dispatch classification.

This release updates the plugin's OpenClaw compatibility metadata and dependency to `2026.3.24`, then uses the new `before_dispatch` hook to record canonical inbound routing metadata and classify suspicious inbound content before normal delivery. Passport now raises audit severity for prompt-injection-shaped install instructions, copy-paste command chains, and group-routing cases while keeping the behavior honest: inbound handling is classified and logged, not blocked.

The release keeps the trust story narrow and explicit. Passport still enforces on the outbound and operator-controlled surfaces it already owns, and now audits inbound dispatch on OpenClaw `2026.3.24+` without claiming universal inbound interception. One practical note: OpenClaw `2026.3.24` raises the supported Node runtime floor upstream to `>=22.14.0`.
