# 10-gobernanza-agentes - AI tooling governance

The honeypot watches attackers; this phase watches **the watcher**: the AI coding agent(s) that operate the lab over SSH and shell. An agent that can edit files, run commands and reach MCP servers is another system in the threat model - so it gets the same treatment as any other: persistent policy, least-privilege configuration, deterministic controls, code review and a threat model.

The practices here were distilled from security guidance for agentic coding tools (permissions modes, allow/ask/deny rules, hooks as deterministic gates, MCP trust, subagent scoping) and implemented on **OpenCode** (the lab uses OpenCode with a non-Anthropic model, so every concept was mapped to its equivalent, and two were found NOT to exist here - documented below).

## Controls implemented

| Layer | Mechanism | Where | What it stops |
|---|---|---|---|
| Policy (persistent) | `AGENTS.md` 7-part security policy (data classification, non-negotiables, deny list, approved deps, verification commands, closing checklist) | project root (local), template here: `agent-policy.example.md` | agent drift between sessions; secret leakage by default |
| Permissions (deterministic) | `permission` blocks: bash deny/ask patterns, `.env` family denied read+write, self-governance files (config, policy, plugins) ask-gated | project + global `opencode.json` | `rm -rf`-class commands, credential reads, agent weakening its own cage |
| Hooks (deterministic, content-level) | one plugin, three guards on `tool.execute.before`: bash-firewall, secrets-scanner, env-protector (incl. bash-string `.env` detection) | example here: `security-hooks.example.ts` | secrets in written content; `.env` via `cat`/`cp`/`tar`/interpreters (permissions cannot see command content) |
| Review | `/security-review` custom command (3-phase, confidence >= 80%, project-specific exclusions) | `.opencode/command/security-review.md` | AI-introduced regressions in infra code; it found 2 HIGH / 3 MEDIUM here, all remediated and verified |
| Threat model | STRIDE over the whole pipeline including the agent context window itself | internal `threat.md` (publication by decision) | design blind spots (top risk found: attacker-controlled log content as prompt-injection input) |
| Surface audit | MCP servers + subagent permissions mapped and scoped | sanitized: `agent-surface-audit.example.md` | unscoped third-party reach from read-only workers (memory poisoning / query egress) |

## Porting notes (concept -> OpenCode reality)

- Rule precedence is **order-based** (last match wins), not deny>ask>allow by type: the catch-all `"*"` goes first, exceptions after.
- Permission patterns for `read`/`edit` do **not** gate the `bash` tool - a `cat .env` bypasses them by design. Hooks close that gap (found via a live test, not theory).
- There is **no native OS sandbox** (`/sandbox`-style) in OpenCode today: isolation here is layers (policy, permissions, hooks) + running risky work inside a container when needed.
- Hooks are TypeScript `tool.execute.before` handlers: throwing blocks the call (exit-code semantics replaced by exceptions).
- Subagents inherit the same permission engine; per-agent blocks plus tool-name wildcards (`"mcpname_*": "deny"`) give per-agent MCP scoping.
- Attribution to the source course will be added to this file after the author has reviewed the implementation (his brand, his call).

## Findings-and-fixes summary (from `/security-review`, 2026-10-12)

2 HIGH, 3 MEDIUM, all closed with before/after evidence in the project tracker: TLS-verification leakage into the public Telegram leg (fixed + behaviorally verified), a re-bootstrap variant that bound monitoring to `0.0.0.0` with default credentials (single-source-of-truth fixed), dead decoy ports (removed, GCP rule synced, externally verified), unpinned bootstrap supply chain (pinned/verified), enrollment secret printed by an unquoted heredoc (fixed). The audit also corrected one imported-once-wrong recommendation (metadata token enforcement is platform-specific - verify hardening steps against the target cloud, not against another cloud's docs).

## Pre-push guard

`pre-push.example.sh` - machine-enforced secret scanning at push time (gitleaks when installed, pattern fallback always). Install: copy to `.git/hooks/pre-push` and `chmod +x`.
