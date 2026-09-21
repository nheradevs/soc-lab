# 03-siem

Wazuh tuning lives here:

- **ILM policy** — hot for 14 days, then delete. A home SSD must not fill up. Configure it in the Wazuh indexer ISM (Index Lifecycle Management).
- **Agent configuration** — enrollment plus the localfile pointing at the Cowrie logs.
- **Custom decoders/rules** — drop them in `rules/`.
- **Dashboard exports** — shared with 05-visualizacion.

## ILM intent (pseudocode)

```yaml
# ILM intent: keep wazuh-* hot for 14 days, then delete — no warm/cold phases.
# Adapt to the actual ISM API/CLI for the Wazuh version in use.
match:  "wazuh-*"
hot:    { max_age: 14d }
delete: { min_age: 14d }
```
