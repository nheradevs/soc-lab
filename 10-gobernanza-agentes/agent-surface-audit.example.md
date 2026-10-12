# Agent surface audit (sanitized example)

Method: inventory from live configuration and running processes, not from memory; one row per tool with an explicit trust verdict; then permission gaps expressed as testable statements and re-verified by behavior.

## MCP servers

| Server | Transport | Reach | Credential exposure | Trust verdict | Decision |
|---|---|---|---|---|---|
| memory store | local stdio, user-owned binary | persistent memory files in user home | none in config | SELF, but it is the only MCP with WRITE power | allowed for the primary agent; DENIED for read-only/external subagents (memory-poisoning class: injected content must not persist as future "facts") |
| code intelligence | local stdio, third-party npm package | full project source (indexes it) | none | THIRD-PARTY (supply chain) | allowed; version-drift review added to the quarterly hygiene list |
| docs lookup | REMOTE HTTPS, unauthenticated | everything the agent SENDS in queries leaves the machine; responses enter context | no key = no credential risk, but query text is the leak surface | EXTERNAL - "trust in an MCP provider is a security decision" | allowed for the primary; `ask` for general-purpose subagents so child egress is human-visible |

## Subagent permissions (what an audit should confirm)

Healthy patterns found (keep them):
- Read-only mappers with `bash/edit/write/task` denied.
- Reviewer agents with deny-by-default (`"*": deny`) and narrow exceptions.
- One validator agent allowed to run exactly ONE literal command (least privilege made visible).
- The orchestrator's delegation surface is an explicit allowlist by agent name (never `"task": allow` as a wildcard).
- Built-in defaults already gate: external-directory access = ask, `*.env` reads = ask, subagents cannot interrogate the user directly (delegation stays under the primary agent).

Gaps found and fixed here:
- MCP tools were not addressed by any permission rule, so even deny-heavy subagents could still reach memory-write and remote-query tools. Fix: per-agent blocks appended (order matters: later rules win), e.g. `"engram_*": "deny"` / `"context7_*": "deny"` on read-only agents, `"context7_*": "ask"` on the general worker.
- Acceptance test was behavioral, not hopeful: a live read-only subagent was asked to call the now-denied tools and reported them unavailable/blocked.
- Residual risk recorded: agent definitions managed by an upstream framework can be REGENERATED and silently drop these blocks; the post-sync diff against a labeled backup is part of the maintenance routine.

## Reusable checklist

1. Enumerate MCP servers from config + processes; classify SELF / THIRD-PARTY-LOCAL / EXTERNAL.
2. For each: what enters (queries, source paths) and what leaves (network, disk writes, persistent state).
3. Compare against every agent definition: can a *read-only* or *externally-fed* agent reach any *write-capable* tool?
4. Encode the answers as permission rules; verify by triggering a denied call in a fresh child session.
5. Document the residual risks; set a cadence (MCP additions, tool versions, hook patterns rotate every 3-6 months).
