# Hardening: 2026-09-17 (post-incident)

Context: `06-observaciones/2026-09-16_ssh-bruteforce-martian-spoofing.md`.

## Response policy (decision, 2026-09-17)

**Do not block attacker IPs in the VPC firewall.** Rationale:

- The honeypot's value is TTP observation; blocking cuts off the feed.
- Attacker IPs are rotating botnet nodes (TechTies NYC / TECHOFF Amsterdam VPS); any block is temporary.
- Attacker containment is provided by the Cowrie container (fake services, no path out of the sandbox).
- No evidence of targeted interest in the operator. These are mass scanners.

**Accepted risk.** Self-DoS on the 1 GB e2-micro (the 2026-09-16 traffic spike nearly took telemetry down for 13.5 h).
**Primary mitigation.** Upgrade to **e2-small (2 GB)**, see below.

Isolation nuance: the *container* is a full sandbox, but the *VM host* is real:
real SSH (2222, key-only) and Tailscale toward the SIEM. Restricting 2222 closes
the only real door on the box.

## Already applied (lab side)

| Item | What | Verified |
|------|------|----------|
| wazuh-agent enabled | `systemctl enable wazuh-agent` on miel26. It was **not** enabled before the incident, so after a stop/reboot it never came back on its own. | Agent 001 active, keepalives normal, rule 503 present after reboot |
| Wazuh dashboard `run_as` fix (asgard) | `wazuh.yml`: `run_as: false` (run_as token carried `rbac_roles: []`, empty for the local user) | UI usable, no banner (see asgard Engram record `bugfix/wazuh-run-as-empty-rbac-roles`) |

## GCP console actions (status 2026-09-17)

### 1. Restrict ingress 2222 to the operator home IP, ✅ APPLIED & VERIFIED

**Why:** 2222 is the real SSH and is exposed to `0.0.0.0/0`; the lab's golden rule is that only the honeypot ports (22/23) should be public.

**Where:** GCP Console → **VPC network** → **Firewall** (miel26 project).

**Current state (2026-09-17):**

| Rule | Ports | Source | Role |
|------|-------|--------|------|
| `honeypot-inbound` | tcp:22, 23, 80, 445, **2222**, 3306, 3389 | 0.0.0.0/0 | honeypot decoy surface, also leaks 2222 |
| `cowrie-in-22` | tcp:22 | 0.0.0.0/0 | honeypot fake SSH |
| `ops-ssh-in-2222` | tcp:2222 | <operator home IP, redacted> | operator access (already correct) |

**Action.** Edit `honeypot-inbound` → remove `2222` from its ports (leave `tcp:22, 23, 80, 445, 3306, 3389`) → save. No new rule is needed: after this, 2222 is only reachable via `ops-ssh-in-2222` (home IP). GCP firewall is allow-union (no deny), so as long as `honeypot-inbound` carries 2222 from `0.0.0.0/0`, nothing else can close it.

**Before applying.** Confirm current access works: `ssh -p 2222 <user>@<miel26 external IP>` (currently `<honeypot public IP, redacted>`).
**After applying.** Run the same command again from the laptop; it must keep working.
Rules take effect in seconds; no VM restart needed.

**Verification (2026-09-17).** Home SSH from the laptop OK (via `ops-ssh-in-2222`); hairpin probe from miel26 to its own external IP:2222 → connection timeout (non-home source denied). Port closed to the internet, open to the operator.

**Dynamic-IP caveat.** If the ISP reassigns the home IP, SSH from home breaks until the rule is updated. Update path: `curl ifconfig.me` → edit the rule's source range.

**Escape hatch (so this can never fully lock out):** GCP Console → **Instances** → `miel26` → `⋮` → **Serial console**: works without the firewall. From the serial console (or any other device with console access) the rule can be corrected.

### 2. e2-micro → e2-small (2 GB), ✅ APPLIED & VERIFIED (2026-09-17 14:53 UTC)

**Why.** Primary mitigation for the accepted self-DoS risk.

**Where:** GCP Console → **Instances** → `miel26`.

**What:** Stop → **Change machine type** → `e2-small` (2 vCPU / 2 GB) → Start.
Downtime: a few minutes. After boot, confirm:

- `systemctl status wazuh-agent` → active (auto-start is now enabled)
- new alerts arriving in Wazuh for agent 001 (rule 503 on start)

**Verification (2026-09-17 14:53 UTC):** VM back up as e2-small (2 vCPU / 1964 MB), `wazuh-agent` active **and enabled**, Cowrie container up, Tailscale direct link to asgard healthy. Rule 503 "Wazuh agent started" received at 14:53:27 UTC, telemetry auto-recovered with no manual intervention (this is the first time the full stop→start cycle self-healed; before the incident the agent was not enabled).

**External IP note.** The previous external IP was ephemeral and was released when the VM was stopped. A static external IP **`<honeypot public IP, redacted>`** (`miel26-external-ip`, us-central1, Premium) is now attached, so the IP is stable across future stop/start cycles. Main README updated. (Side effect of the console flow: the VM's internal IP `<honeypot internal IP, redacted>` was also promoted to a static internal address, named `miel26-external`, misnamed but harmless.)

### 3. Instance hygiene, ✅ APPLIED & VERIFIED (2026-09-17 15:0x UTC)

**What:**

- **Deletion protection enabled** on miel26 (`gcloud compute instances update miel26 --deletion-protection` via Cloud Shell). Prevents accidental deletion from console/API.
- **Expired on-demand SSH keys removed** from instance metadata: leftover `google-ssh` on-demand keys from console "SSH in browser" sessions. Only the operator's persistent key remains.

**Verified.** Instance metadata `ssh-keys` attribute read from inside the VM now contains exactly one entry (the operator's persistent key); instance page shows Deletion protection = Enabled.

**Note:** `google-ssh` on-demand keys are session keys, GCP re-issues them automatically the next time "SSH in browser" is used with that account. Removal is hygiene, not a security control; the access control is the persistent key set + the 2222 firewall restriction above.

## Candidate next steps (lab side, not yet done)

- Lightweight resource monitor on miel26 (memory + conntrack table occupancy) with a Wazuh alert threshold, so the next traffic spike is visible before telemetry degrades.
- Decide miel26 Tailscale membership (open gap in main README): a deliberate honeypot target ideally should not share the analyst mesh.
