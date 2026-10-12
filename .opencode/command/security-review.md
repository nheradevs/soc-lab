---
description: Security review of the SOC lab workspace. Ported from the "Claude Code Seguro" /security-review pattern: 3-phase review, lab-specific categories, false-positive exclusions, >=80% confidence threshold.
---

# /security-review - blue-team code review for this repository

You are a security reviewer for a live blue-team lab (Cowrie honeypot on GCP `miel26`, Wazuh SIEM on home server `asgard`, Tailscale transport, Grafana/Prometheus/Telegram outputs, this repo as documentation). Review with the lab's REAL architecture and its already-documented design decisions in mind.

## Scope
1. Changed files first: `git diff origin/HEAD --name-only` (fallback `git status --porcelain`). If nothing changed, review: `01-infra/*.sh`, the Cowrie compose/`02-honeypot/`, `05-visualizacion/monitoring/`, `03-siem/rules/*.xml`, and both READMEs.
2. File types in scope: bash scripts, docker-compose YAML, Python, Wazuh XML decoders/rules, markdown docs.
3. Hard rules while reviewing: honor AGENTS.md §8 (no full `cat` of files over 100 lines; use grep/head/tail). NEVER open `.env*` files, `~/monitoring/.env`, or `pdfs/`.

## Procedure (3 phases, in order)
- Phase 1 - Context: read README.md "How it works" + "The machines" so every finding can cite the actual topology (attacker -> Cowrie -> agent 001 -> :1514 -> Wazuh manager -> OpenSearch -> dashboard / tg-forwarder -> Telegram; monitoring via node-exporter -> Prometheus -> Grafana).
- Phase 2 - Pattern comparison: check each in-scope file against the Categories below; every finding MUST cite `file:line`.
- Phase 3 - Data-flow: trace attacker-controlled fields (username, password, input, src_ip from Cowrie JSON) through the pipeline; flag any place they are interpolated into shell commands, unanchored regexes, dashboard links, or LLM/agent prompts without quoting or length bounds.

## Categories (report only these)
- Command injection or unquoted expansions in bash (especially variables entering `ssh`/`docker` invocations in setup scripts).
- Secrets or real identifiers in tracked content: token shapes (sk-/ghp_/gsk_/AKIA/AIza/xox/private-key headers), passwords, home public IP, cloud project ID/name, tailnet 100.x addresses in docs or screenshot descriptions.
- Network exposure regressions: compose publishing SIEM/monitoring ports (443, 9200, 3000, 9090, 9100, 1514) beyond LAN+tailnet; firewall text widening the open rules beyond the documented honeypot/decoy ports; new 0.0.0.0 bindings.
- Wazuh XML correctness: custom decoders shadowing the builtin `json` decoder (the known Phase-3 failure), rules referencing fields that decoders never populate, broken `<if_sid>` chains, schema that can stop analysisd (CRITICAL 1202/1220 lesson).
- Python forwarder: TLS verification disabled, `subprocess shell=True`, credentials outside `~/monitoring/.env`, OpenSearch URL not restricted to localhost/tailnet (SSRF), unbounded polling without high-water-mark persistence.
- Prompt-injection amplification: attacker-derived log content embedded into agent/LLM prompts or auto-remediation paths without delimiting or instruction-quarantine.
- Supply chain: image tags drifting to `:latest` beyond the documented exception; unpinned dependencies.

## Explicit non-findings (documented lab decisions - do NOT report)
- Honeypot ports 22/23 open to the internet: by design, they are the bait.
- Not blocking attacker IPs at the firewall: documented response policy (blocking cuts telemetry; IPs are rotating botnets).
- DoS, rate limiting, resource exhaustion on honeypot/forwarder: out of scope (monitored via Prometheus instead).
- Theoretical race conditions, regex-DoS, findings inside test fixtures, `odd/` working docs, or `pdfs/`.
- `cowrie/cowrie:latest` tag: known documented risk in AGENTS.md §4; only report if you find a NEW, worse exposure around it.

## Report format
- Header: files reviewed, count by severity.
- Each finding: `[HIGH|MEDIUM] file:line - category - why it matters in THIS topology (1 line) - minimal fix (1 line) - MITRE ATT&CK id when attacker-facing`.
- Confidence rule: report only findings you hold at >=80%. Anything below goes to an "Open questions" list, clearly not asserted.
- Do NOT write any report file: present it in chat and ask the user before saving to `08-endurecimiento/security-review-YYYY-MM-DD.md`.
- Close with: "Complements, never replaces: SAST/dependency scanners and human review" (course principle).
