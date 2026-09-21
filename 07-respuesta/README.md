# 07-respuesta

Triage and response runbooks for the observed attacks (TheHive/Cortex if added later).

High-value Wazuh events (Cowrie fake logins / command input / agent events)
are forwarded to Telegram from asgard via `05-visualizacion/monitoring/`
(forwarder runs in DRY_RUN until a bot token + chat id are configured).
