# 10-gobernanza-agentes - AI tooling governance

The honeypot watches attackers; this phase watches **the watcher**: the AI coding agent that operates my lab over SSH and shell. An agent that can edit files, run commands and reach MCP servers is just another system in my threat model, so I gave it the same treatment as everything else: a policy, least-privilege config, deterministic controls, code review and its own threat model.

The practices here are adapted from Álvaro Chirou's course ["Claude Code Seguro: Programa con IA sin Riesgos de Seguridad"](https://www.udemy.com/course/claude-code-para-ciberseguridad-blinda-tu-codigo/) (Udemy). One honest wrinkle: I don't run Claude Code. I use OpenCode with a Qwen model, so every concept had to be mapped to its equivalent, and two things turned out not to work the same way here at all. Both are documented below because that mismatch was the real lesson.

## Controls implemented

| Layer | Mechanism | Where | What it stops |
|---|---|---|---|
| Policy (persistent) | `AGENTS.md` with a 7-part security policy: data classification, non-negotiables, deny list, approved deps, verification commands, closing checklist | project root (local copy), template here: `agent-policy.example.md` | agent drift between sessions; secret leakage by default |
| Permissions (deterministic) | `permission` blocks: bash deny/ask patterns, `.env` family denied for read AND write, self-governance files (the config, the policy, the plugins) gated behind approval | project + global `opencode.json` | `rm -rf`-class commands, credential reads, and the agent quietly loosening its own cage |
| Hooks (deterministic, content-level) | one plugin, three guards on `tool.execute.before`: bash-firewall, secrets-scanner, env-protector (including `.env` detection inside bash command strings) | example here: `security-hooks.example.ts` | secrets in written content; `.env` via `cat`/`cp`/`tar`/interpreters - permission patterns cannot see command content, the hooks can |
| Review | `/security-review` custom command: 3 phases, confidence >= 80%, exclusions for my documented decisions | `.opencode/command/security-review.md` | regressions in my own infra code. It found 2 HIGH and 3 MEDIUM real issues; all five were fixed and re-verified |
| Threat model | STRIDE over the whole pipeline, including the agent context window as its own trust boundary | internal `threat.md` | design blind spots. Top risk found: attacker-controlled log content as prompt-injection input |
| Surface audit | every MCP server and subagent mapped with a trust verdict, then scoped | sanitized: `agent-surface-audit.example.md` | read-only subagents reaching write-capable tools (memory poisoning) or egress-capable ones |

## Porting notes (concept -> OpenCode reality)

- Rule precedence is order-based (last match wins), not deny>ask>allow by type: the catch-all `"*"` goes first and exceptions after it. Easy to get backwards if you come from the course's syntax.
- Permission patterns for `read`/`edit` do not gate the `bash` tool. A `cat .env` bypasses them by design. I only found this by testing, and hooks close the gap. A config that looks secure and a config that is secure are different things.
- There is no native OS sandbox in OpenCode today. Isolation here is layers (policy, permissions, hooks) plus running risky work in a container when needed.
- Hooks are TypeScript `tool.execute.before` handlers: throwing an error blocks the call (no exit codes involved).
- Subagents share the same permission engine; per-agent blocks with tool-name wildcards (`"server_*": "deny"`) give per-agent MCP scoping.

## Findings and fixes (from my run of `/security-review`, 2026-10-12)

2 HIGH, 3 MEDIUM, all closed with before/after evidence: TLS verification leaking into the public Telegram leg (fixed, behaviorally verified), a bootstrap variant that bound monitoring to `0.0.0.0` with default credentials (replaced by a single source of truth), dead decoy ports (removed, GCP rule synced and externally verified), unpinned bootstrap installs (pinned or verified), and an enrollment secret printed by an unquoted heredoc (fixed). The same exercise corrected one of my own recommendations: metadata token enforcement (IMDSv2) is an AWS concept that does not exist in GCP. I had hardening steps "sounding right" until the platform docs said otherwise; the GCP-native fix was removing the service account from the honeypot VM instead. That one stayed in the record on purpose.

## Pre-push guard

`pre-push.example.sh` runs secret scanning at push time: gitleaks when installed, a pattern fallback always. Install: copy to `.git/hooks/pre-push` and `chmod +x`.
