# SOC lab monitoring — Prometheus + Grafana + Wazuh→Telegram forwarder

Infrastructure-health monitoring for the SOC lab. Covers:

- **Asgard** (SIEM/indexer host): disk, RAM, load — the indexer filling up
  would silently stop alert indexing, so this is the biggest blind spot.
- **miel26** (GCP honeypot, e2-small): up/down, RAM, conntrack — self-DoS
  watch under heavy attack.
- **Wazuh → Telegram forwarder**: the high-value events only (Cowrie fake
  logins, command input, agent events), NOT the ~10k alerts/day flood.

This is infra monitoring, not security visualization — the Wazuh dashboard
already covers security.

## Layout

```
monitoring/
├── docker-compose.yml            # 4 services, internal network
├── .env.example                  # template; real .env lives ONLY on asgard (chmod 600)
├── prometheus/
│   ├── prometheus.yml            # 2 scrape jobs: node-asgard, node-miel26
│   └── rules.yml                 # 5 alert rules (group lab-infra)
├── grafana/
│   ├── provisioning/             # datasource (uid: prometheus) + file provider
│   └── dashboards/lab-infra.json # "Lab infra health" dashboard
└── forwarder/
    ├── forwarder.py              # Python 3 stdlib only (urllib)
    └── Dockerfile                # python:3.12-slim
```

Services (all `restart: unless-stopped`): `node-exporter` (asgard metrics),
`prometheus` (30d retention), `grafana` (provisioned datasource + dashboard),
`tg-forwarder` (host network; no published ports).

## Accessing Grafana

Grafana is bound to `127.0.0.1:3000` on asgard. From your laptop:

```
ssh -N -L 3000:localhost:3000 asgard
```

Then open http://localhost:3000 — user `admin`, password is
`GRAFANA_ADMIN_PASSWORD` from `~/monitoring/.env` (chmod 600).
Sign-up is disabled. Prometheus is at `127.0.0.1:9090` the same way.

## miel26 exporter

`node-exporter` runs as a **standalone container on miel26**, published only
on the Tailscale IP:

```
-p 100.x.x.x:9100:9100   # NEVER 0.0.0.0 / public
```

It is not in this compose file. asgard scrapes it over the tailnet
(`100.x.x.x:9100` in `prometheus.yml`). Reason: the honeypot's only
network-reachable monitoring port is the tailnet interface — an attacker on
the public internet must not be able to read host metrics or kill the
exporter.

## How the forwarder works

Wazuh ≥ 4.8 removed `GET /alerts` from the manager API, so the forwarder
**polls the Wazuh indexer (OpenSearch) directly**:

1. `POST /wazuh-alerts-4.x-*/_search` (basic auth, indexer admin) —
   `@timestamp > high-water-mark AND rule.id IN RULES`, ascending, ≤500 docs.
2. Skips duplicates via an in-memory LRU of the last 500 processed event ids.
3. Applies a per `(src_ip, rule.id)` cooldown (`COOLDOWN_SECONDS`).
4. Formats the message (Telegram HTML, user values escaped) and sends it —
   or logs `WOULD SEND: ...` when `DRY_RUN=true` / no token (test mode).
5. Advances the high-water mark to the newest processed `@timestamp`
   (persisted atomically to `/state/hwm.json`). First run starts at
   `now - 120s` — no backfill, so an old restart never floods Telegram.

Telegram 429 → sleep 60s, retry once, then drop. Any other error → log,
sleep 15s, continue. SIGTERM → clean exit 0.

Forwarded rules (default):

| rule | meaning |
|------|---------|
| 100501 | Cowrie fake login |
| 100504 | Command typed in a fake session |
| 501 / 502 | Wazuh agent connect / event (miel26 agent liveness) |

## Tuning

Edit `~/monitoring/.env` on asgard, then
`docker compose up -d tg-forwarder` (re-reads env on recreate):

- `RULES=100501,100504,501,502` — comma-separated rule ids. Find more ids in
  the Wazuh dashboard (Rules) or in OpenSearch:
  `rule.id` in `wazuh-alerts-4.x-*`.
- `COOLDOWN_SECONDS=60` — silence per (source ip, rule). Raise it if a
  particular attacker pair is spamming.
- `POLL_INTERVAL=10` — seconds between polls.

## Enabling Telegram (T5)

1. Create a bot with @BotFather → token. Get your chat id (e.g. by messaging
   the bot and calling `https://api.telegram.org/bot<token>/getUpdates`).
2. On asgard: set `TG_BOT_TOKEN=...`, `TG_CHAT_ID=...`, `DRY_RUN=false` in
   `.env`.
3. `docker compose up -d tg-forwarder` and check
   `docker logs tg-forwarder --tail 30`.

## Security constraints

- No new port is bound to `0.0.0.0` or any public interface, on either host:
  - asgard: Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`,
    node-exporter `127.0.0.1:9100`; tg-forwarder uses host network with
    **no** published ports (egress only).
  - miel26: node-exporter `100.x.x.x:9100` (tailscale0 only).
- Secrets: the real `.env` exists only on asgard (`chmod 600`); the repo
  carries `.env.example` with placeholders only.
- `~/wazuh/` is read-only for this project.
