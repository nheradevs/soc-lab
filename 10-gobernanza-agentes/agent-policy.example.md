# Instrucciones y Política de Seguridad del Agente - SOC Lab

> Política persistente para agentes de IA (opencode) que operan este repositorio.
> Estructura basada en el curso "Claude Code Seguro" (Álvaro Chirou): este archivo guía
> el comportamiento pero no lo enforcea; el enforcement por configuración se define en §9.
> Última revisión: 2026-10-12.

## 1. Descripción del proyecto y clasificación de datos

Laboratorio SOC blue-team real: honeypot Cowrie en GCP (`miel26`) → SIEM Wazuh 4.14.7
en `asgard` (ThinkPad always-on detrás de NAT) → dashboard, Grafana y alertas Telegram,
unidos por Tailscale. Fases 01–09 (infra → report).

Datos y su sensibilidad:

- **SECRETO**: tokens (bot de Telegram, API de Wazuh, admin de Grafana), contraseñas,
  IP pública del hogar, nombre/ID del proyecto cloud. Solo viven en `~/monitoring/.env`
  en asgard (chmod 600) o en el cofre del operador. Nunca en este repositorio.
- **CONFIDENCIAL**: user/password de víctimas capturadas por Cowrie (siempre enmascaradas,
  formato `p******`), direcciones tailnet (100.x.x.x), IPs internas.
- **PÚBLICO-DE-LAB**: IPs de atacantes, TTPs, reglas y detecciones.

Rigor esperado: **ALTO**. Ante cualquier conflicto entre seguridad y comodidad, elegir
siempre seguridad.

## 2. Reglas de seguridad no negociables

1. Cero secretos en código, commits, logs, screenshots o salidas del agente.
   Las plantillas usan placeholders (`<TOKEN>`).
2. Toda acción remota (SSH, API de GCP, cambios en asgard/miel26) requiere autorización
   explícita del usuario en la sesión, nombrando destino y operación. La autorización
   para trabajar localmente NO autoriza acciones remotas.
3. Por defecto, la inspección remota es de solo lectura; toda mutación remota se aprueba
   caso por caso.
4. Menor privilegio en todo: servicios, puertos, permisos del agente, herramientas MCP.
5. Scripts bash: `set -euo pipefail`, variables entre comillas, entradas validadas antes
   de usarse. Nunca `curl | bash`.
6. Ningún servicio del SIEM/monitoreo (443, 9200, 3000, 9090, 9100, 1514) expuesto fuera
   de la LAN y el tailnet. Prohibido publicar puertos Docker en `0.0.0.0` para esos
   servicios.
7. Logs y documentación no registran credenciales ni datos personales de víctimas.
8. Todo screenshot que se versione o publique pasa primero por el checklist de
   saneamiento de `README.md`.

## 3. Patrones prohibidos (deny list)

- Hardcodear tokens, contraseñas o API keys en cualquier archivo, incluidos tests.
- Commitear: `.env*` (excepto `.env.example`), `*.pem`, `*.key`, `client.keys`,
  `tailscaled.state`, o cualquier copia de `~/monitoring/.env`.
- `docker run/compose -p 0.0.0.0:...` para servicios del SIEM o del monitoreo.
- Deshabilitar la verificación TLS (`-k`, `verify=False`).
- Cambiar reglas de firewall/GCP, borrar volúmenes o ejecutar `rm -rf` fuera del
  workspace sin confirmación explícita del usuario.
- Introducir dependencias nuevas (imágenes, librerías) sin aprobación explícita.
- Leer archivos grandes sin filtrar (ver §8).

## 4. Herramientas y dependencias aprobadas

- Imágenes oficiales con tag fijo: `wazuh/wazuh-*:4.14.7`, `prom/prometheus`,
  `grafana/grafana`, `prom/node-exporter`.
- Honeypot: `cowrie/cowrie` - riesgo conocido: hoy usa `:latest`; fijar un tag estable
  al reanudar mantenimiento del honeypot.
- Forwarder: Python 3 + `requests` únicamente.
- Escaneo: `grep` y `gitleaks` (si está disponible). Ninguna herramienta nueva de
  seguridad sin aprobación.

## 5. Privacidad y cumplimiento

- Minimización: del ataque se conserva solo la evidencia necesaria para detectar y reportar.
- Credenciales de víctimas: enmascaradas SIEMPRE, también en issues o PRs. El patrón es
  la lección; la cadena completa, no.
- Las IPs de atacantes pueden quedar visibles (son el punto del lab). Las IPs e
  identidades propias, nunca.
- El honeypot es de baja interacción: no hay sistemas ni datos reales expuestos dentro.

## 6. Comandos de verificación (antes de cerrar una tarea que toca el repo)

```bash
# secretos conocidos
git ls-files | xargs grep -lnE 'ghp_[A-Za-z0-9]{36}|gsk_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|AIza[0-9A-Za-z_-]{35}' || echo OK
# .env en el staged
git status --porcelain | grep -E '\.env$' && echo "REVISAR" || echo OK
# sintaxis de scripts
bash -n 01-infra/*.sh
# compose modificado
docker compose -f <archivo> config -q
```

Reportar el resultado real de cada comando aplicable al cerrar la tarea.

## 7. Checklist previo a cerrar cualquier tarea

- [ ] Sin secretos incrustados; ningún `.env` en el staged.
- [ ] Si hubo acción remota: autorización explícita obtenida y destino/operación reportados.
- [ ] IPs y nombres propios saneados en todo documento o screenshot publicado.
- [ ] Dependencias nuevas: fuente confiable y tag fijo (o riesgo conocido documentado).
- [ ] Comandos de §6 ejecutados (los aplicables) con resultado reportado.
- [ ] README EN/ES actualizado si la tarea cambia comportamiento público del lab.

## 8. Reglas estrictas de lectura de archivos (anti-saturación de contexto)

- **PROHIBIDO**: `cat` de archivos de log, configuración o código de más de 100 líneas;
  leer archivos completos sin filtrar.
- **OBLIGATORIO**: logs → `tail -n 50`; errores → `grep -iE 'error|fail|exception'`;
  parámetros puntuales de config → `grep -A5 -B2 'parametro'`; estructura → `head -n 20`.
- **RAZÓN**: saturar la ventana de contexto (327k tokens) corta la ejecución del agente
  y pierde trabajo.

## 9. Gobernanza del agente (opencode)

Este archivo guía pero no bloquea. El enforcement por configuración vive en:

- **B**: bloque `permission` en `opencode.json` - patrones bash allow/ask/deny
  (precedencia deny > ask > allow), lectura de `.env` denegada, `external_directory`
  en `ask`, herramientas MCP acotadas por servidor/herramienta.
- **C**: plugin global con tres hooks defensivos sobre `tool.execute.before`
  (bash-firewall, secrets-scanner, env-protector): bloquean de forma determinística
  aunque el agente intente lo contrario. Máximo 5 hooks, una responsabilidad cada uno.
- **D/E**: comando `/security_review`, modelado STRIDE, auditoría de MCP y subagentes.

Roadmap completo y evidencia: `odd/tasks/ai-tooling-governance.md`.
