# 05-visualizacion

Grafana dashboard JSON exports and screenshots for the write-up.

## monitoring/

Prometheus + Grafana infra monitoring plus a Wazuh→Telegram alert forwarder
for the SOC lab: asgard health (disk/RAM/load), miel26 honeypot health
(up/RAM/conntrack), and filtered Telegram alerts for the high-value events
(Cowrie fake logins, command input, agent events).

See [monitoring/README.md](monitoring/README.md) for access (SSH tunnel),
forwarder tuning, and the security constraints.
