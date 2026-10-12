# 02-honeypot

Cowrie is a low-interaction honeypot: it serves fake login shells that record everything (usernames, passwords, commands, exfiltration attempts) with zero risk to real services.

> Deployed reality check (2026-10-12): this lab runs the **SSH and Telnet** modules only (container ports mapped to 22/23). Cowrie also offers HTTP, SMB, RDP and MySQL modules, but the decoy firewall ports previously opened for them were removed by the security review (nothing served them; enabling them later is a deliberate decision, not a leftover default).

## Why low-interaction

There is no real operating system inside to patch or to hand over to an attacker. The "honey" is the data, not a vulnerable box.

## What it captures

- Credential attempts per fake service (usernames and passwords)
- Commands typed in the fake shells
- Files uploaded or downloaded (exfiltration attempts)
- Source IPs, timestamps, and full session transcripts (in the `cowrie-data` docker volume)

## TODO

- [ ] Suricata on the VPS (later, if VPS RAM allows)
- [ ] canarytokens: fake AWS credentials file + fake credential doc
- [x] Wazuh agent localfile on the Cowrie logs + built-in Cowrie decoder check (done in Phase 3/5; the custom child-of-`json` decoder was retired for shadowing the builtin)
- [ ] Home-IP block on the honeypot ports verified
