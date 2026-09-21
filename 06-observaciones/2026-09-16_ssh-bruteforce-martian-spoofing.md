# 2026-09-16 — SSH brute-force + martian spoofing campaign (miel26 self-DoS)

First large-scale campaign captured by the lab. Two attacker IPs ran an automated
SSH dropper/recon campaign against the honeypot, and the traffic surge coincided
with a **~14-hour telemetry blackout**: Wazuh agent 001 stopped reporting at
07:33:59 UTC and only recovered after a manual reboot at 21:32 UTC. During the
blackout the honeypot was attacked — and blind.

## Attackers

| Source IP | Cowrie events | Window (UTC) | Activity |
|-----------|--------------|--------------|----------|
| `109.160.32.48` | 1,137 | 09-16 06:56:09 → 07:13:56 | Scripted SSH brute-force (190 connections, 158 fake logins, 150 commands) + 85 kernel-dropped martian packets |
| `195.178.110.228` | 22 | from 09-16 06:57:17 | Same campaign window (session.connect/closed) + 2 martian packets |

Both IPs also spoofed the honeypot's Docker bridge IP (`172.17.0.2`) as source.

## Timeline (UTC, all 2026-09-16 unless noted)

| Time | Event |
|------|-------|
| 05:00–07:33 | Alert surge on agent 001: 15,131 alerts (10,049 in the 06:00 hour) |
| 06:56:09 | `109.160.32.48` starts scripted SSH campaign against fake SSH (`172.17.0.2:2222`) |
| 06:57:17 | Second source `195.178.110.228` joins |
| 07:06:31 | Kernel: `workqueue: update_balloon_size_func [virtio_balloon] hogged CPU` (GCP memory pressure during surge) |
| 07:13:56 | Last Cowrie event from `109.160.32.48` |
| 07:33:59 | **Last alert from agent 001** (rule 504, agent disconnected). Telemetry path (Tailscale :1514) dies |
| 08:00–20:59 | **Telemetry blackout** — zero alerts from agent 001; honeypot keeps running but is blind |
| 08:21:54 | First kernel martian log: `IPv4: martian source 172.17.0.2 from 109.160.32.48, on dev ens4` (continues, rate-limited) |
| 19:57:24 | Martian packets also observed from `195.178.110.228` |
| 21:26:12 | Last martian log; boot -1 ends (manual reboot) |
| 21:32:38 | New boot |
| 21:38:08 | First alert from agent 001 (rule 503, agent connected) after `systemctl enable --now wazuh-agent` |
| 09-17 02:26 | 0 martian lines on current boot; attacker IPs silent since reboot |

## TTPs

1. **Botnet-style SSH dropper recon** (`109.160.32.48`):
   connect → client.version/kex → login with arbitrary credentials (Cowrie fakes
   success) → run `uname -s -v -n -r -m` → close, ~every 4 seconds. Event mix:
   session.connect 190 / client.version 183 / client.kex 168 / login.success 158 /
   command.input 150 / session.params 150 / session.closed 138.
2. **Martian source spoofing**: packets arriving on the public interface `ens4`
   claiming source `172.17.0.2` (the honeypot's own Docker bridge IP). The kernel
   drops them as martians; 87 surviving log lines (85 × `109.160.32.48`,
   2 × `195.178.110.228`) plus interleaved raw frame dumps:
   `ll header: 42 01 0a 80 00 02 42 01 0a 80 00 01 08 00` (ethertype `0x0800`).

## Impact

- **Honeypot self-DoS / observability loss**: 13.5 hours with zero telemetry
  (07:33:59 → 21:38:08). Every attack in that window — including the entire
  spoofing campaign — is unobserved by design.
- The spoofing itself was dropped by the kernel (no direct impact evidenced),
  but it proves the attacker can inject packets into the honeypot's underlay.
- Contributing factor that lengthened the outage: `wazuh-agent` was **not
  enabled** after install, so nothing self-healed; a manual reboot was required.

## Analysis — evidence vs. hypothesis

**Confirmed by evidence:**
- The brute-force window, volumes, TTP commands, and both attacker IPs
  (OpenSearch, reproducible queries below).
- The agent outage window and the martian logs (manager API + kernel journal).
- The spoofing **stopped exactly at the reboot**; zero occurrences since
  (checked 09-17 02:26 UTC).

**Hypothesis (corrected):** an earlier working theory blamed the spoofing flood
for the telemetry loss. The timeline does not support that: the agent's last
alert (07:33:59) predates the first surviving martian log (08:21:54). The
better-supported reading is that the **05:00–07:33 traffic surge** (~15k alerts,
~200 rapid scripted SSH sessions, `virtio_balloon` CPU hog at 07:06 on a
1 GB e2-micro) broke the guest's Tailscale/telemetry path. No OOM-kill and no
`nf_conntrack: table full` lines were found in the pre-reboot kernel journal.

**Unresolved:**
- Exact root cause of the 07:34 telemetry death (candidates: resource
  exhaustion, conntrack pressure; no `conntrack` tool installed to measure).
- Why the spoofing stopped at the reboot (attacker withdrew vs. GCP-side
  filtering) — unknown.
- True spoofing rate: kernel log lines are rate-limited (~10 min apart).

## Evidence (reproducible)

OpenSearch (asgard, `admin`):

```bash
# Per-attacker volume + window + event mix
curl -sk -u 'admin:***' 'https://localhost:9200/wazuh-alerts-4.x-*/_search' \
  -H 'Content-Type: application/json' -d '{
  "size": 0, "track_total_hits": true,
  "query": {"term": {"data.src_ip": "109.160.32.48"}},
  "aggs": {"by_event": {"terms": {"field": "data.eventid"}},
           "min_ts": {"min": {"field": "@timestamp"}},
           "max_ts": {"max": {"field": "@timestamp"}}}'

# Agent 001 hourly activity on 09-16 (shows the 08:00–20:59 hole)
curl -sk -u 'admin:***' 'https://localhost:9200/wazuh-alerts-4.x-2026.09.16/_search' \
  -H 'Content-Type: application/json' -d '{
  "size": 0, "query": {"term": {"agent.id": "001"}},
  "aggs": {"por_hora": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}}'

# Agent outage bounds (last alert before / first after the reboot)
#   last  before: 2026-09-16T07:33:59.359Z (rule 504)
#   first after : 2026-09-16T21:38:08.189Z (rule 503)
# Agent state:    GET https://localhost:55000/agents?agents_list=001
#                 → lastKeepAlive 2026-09-17T02:27:10Z, status active
```

Kernel journal (miel26, pre-reboot boot `-1`):

```bash
sudo journalctl -b -1 -k | grep -i martian
# first: Sep 16 08:21:54 … martian source 172.17.0.2 from 109.160.32.48, on dev ens4
# last : Sep 16 21:26:12 …
sudo journalctl -b -1 -k | grep -ci martian   # 87 lines: 85 × 109.160.32.48, 2 × 195.178.110.228
sudo journalctl -b -1 -k --since "2026-09-16 07:00" --until "2026-09-16 09:00" | tail
# virtio_balloon CPU-hog line at 07:06:31
```

## Response / status

| Action | Status |
|--------|--------|
| Reboot miel26 + `systemctl enable --now wazuh-agent` | ✅ done 09-16 21:32–21:38 UTC; agent enabled, now auto-starts |
| Telemetry confirmed (rule 503 connected; alerts flowing) | ✅ done |
| Block attacker IPs at GCP VPC firewall | ⬜ → `08-endurecimiento/` |
| Restrict 2222 ingress to operator IP | ⬜ → `08-endurecimiento/` |
| Upgrade miel26 to e2-small (2 GB) to survive surges | ⬜ → `08-endurecimiento/` |
| Add conntrack accounting / memory monitoring on miel26 | ⬜ → `08-endurecimiento/` |
