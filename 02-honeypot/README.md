# 02-honeypot

Cowrie is a low-interaction honeypot: it serves fake login shells (SSH, Telnet, HTTP, SMB, RDP, MySQL) that record everything — usernames, passwords, commands, exfiltration attempts — with zero risk to real services.

## Why low-interaction

There is no real operating system inside to patch or to hand over to an attacker. The "honey" is the data, not a vulnerable box.

## What it captures

- Credential attempts per fake service (usernames and passwords)
- Commands typed in the fake shells
- Files uploaded or downloaded (exfiltration attempts)
- Source IPs, timestamps, and full session transcripts (in `cowrie-data/`)

## TODO

- [ ] Suricata on the VPS (later, if VPS RAM allows)
- [ ] canarytokens: fake AWS credentials file + fake credential doc
- [ ] Wazuh agent localfile on the Cowrie logs + built-in Cowrie decoder check
- [ ] Home-IP block on the honeypot ports verified
