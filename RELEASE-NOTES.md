Agent Passport 0.1.3 adds the first explicit incident-response and skill-quarantine operator surfaces on top of the scanner-first trust model.

This release adds a ranked workspace incident audit for tracked plugins and skills, local-first skill artifact inspection with quarantine staging and trust-tier reporting, and explicit OpenClaw CLI entrypoints for both flows. The normal `/passport` command surface and the plugin docs were updated to reflect those operator paths, and the public security scope now documents the quarantine review area as part of Passport's local state.

The release still keeps the trust boundary honest: skill inspection is local-first, not a claim of remote marketplace interception, and the new workspace audit is read-only reporting that feeds the existing review and trust workflows rather than bypassing them.
