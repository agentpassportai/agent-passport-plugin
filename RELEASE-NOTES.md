Agent Passport 0.1.4 promotes trust-tier and provenance information into the normal operator views and makes the runtime consent gate deterministic.

This release adds shared trust-summary logic for plugins and skills, exposes trust tier and provenance details in the standard plugin, skill, and workspace state outputs, and adds regression coverage for those summaries. It also registers the `message_sending` and `before_tool_call` enforcement hooks with explicit early priority so Passport's consent gate does not rely on default plugin ordering.

The scope is still intentionally narrow and honest: the release improves visibility and determinism on the surfaces Passport already controls, without claiming broader interception or remote marketplace preinstall scanning.
