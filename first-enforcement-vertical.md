# First Enforcement Vertical: Outbound Comms Gating

Status: draft
Date: 2026-03-23

## Why this vertical first
Outbound communication is the cleanest early trust surface:
- high user risk
- easy to explain
- commercially meaningful
- there is now visible hook support in the plugin surface

## Hooks used

### `message_sending`
Evidence from current SDK types:
- `PluginHookMessageSendingEvent = { to, content, metadata? }`
- `PluginHookMessageSendingResult = { content?, cancel? }`

Meaning:
- Passport can inspect outbound message text and target
- Passport can cancel the send

### `before_tool_call`
Evidence from current SDK types:
- `PluginHookBeforeToolCallEvent = { toolName, params, ... }`
- `PluginHookBeforeToolCallResult = { params?, block?, blockReason? }`

Meaning:
- Passport can block specific tool calls before execution
- Passport can return a human-readable reason

## Current draft enforcement

### Hook path 1 — channel send path
- Hook: `message_sending`
- Behavior: evaluates every outbound message and cancels by default in v1
- Current policy stance: outbound comms require consent by default

### Hook path 2 — message tool send path
- Hook: `before_tool_call`
- Target: `toolName === "message"` with `action === "send"`
- Behavior: block with explicit reason

### Hook path 3 — cross-session message path
- Hook: `before_tool_call`
- Target: `toolName === "sessions_send"`
- Behavior: block with explicit reason

## What this proves
- Passport can do real pre-send enforcement on at least one practical action class
- Passport can attach audit records to the decision
- Passport can return operator-readable block reasons on tool paths

## What this does not prove yet
- consent resolution flow
- target allowlists / trusted channels
- nuanced policy exceptions
- all outbound comms everywhere
- all channel-specific send paths

## Next improvements
1. add config-driven allowlists for trusted internal targets
2. add `audit` / `warn` / `enforce` modes for hooks
3. add `agent_passport_audit_search`
4. connect block decisions to an approval or consent workflow instead of hard blocking
5. add per-channel policy controls

## Honest current framing
This is a real first enforcement vertical, but still a narrow one. That is fine. Narrow and real beats broad and fake.
