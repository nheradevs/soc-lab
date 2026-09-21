#!/usr/bin/env python3
"""SOC lab - Wazuh alert forwarder to Telegram.

Polls the Wazuh indexer (OpenSearch) for new alerts matching a small set of
high-value rules (Cowrie fake logins, command input, agent events), applies
per-(source, rule) cooldowns and deduplication, and forwards them to Telegram
as HTML messages.

Why OpenSearch and not the Wazuh manager API?
  Wazuh >= 4.8 removed the legacy GET /alerts manager-API endpoint. Alerts
  are indexed in OpenSearch under wazuh-alerts-4.x-*, so this forwarder
  queries the indexer directly with the indexer's admin credentials
  (OPENSEARCH_* env vars). The WAZUH_* env vars remain in .env for general
  Wazuh API access but are not used by this program.

Constraints:
  - Python 3 standard library only (urllib).
  - Runs with network_mode: host inside the asgard compose stack, so the
    indexer is reachable at https://localhost:9200 and outbound Telegram
    calls work without published ports.
  - DRY_RUN=true (default) logs "WOULD SEND: <message>" instead of calling
    Telegram - this is the safe test mode.

Robustness:
  - High-water mark persisted to /state/hwm.json (atomic tmp+rename);
    first run starts at now-120s (no backfill).
  - In-memory LRU set of the last 500 processed event ids (skips duplicates).
  - Any API/parse exception is logged with traceback, sleep 15s, continue.
  - Telegram 429: sleep 60s, retry once, then drop (never crash).
  - Clean SIGTERM handling (exit 0).
"""

import base64
import hashlib
import html
import json
import logging
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

# --- configuration (env) ------------------------------------------------------

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200").rstrip("/")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS", "")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
DRY_RUN = os.environ.get("DRY_RUN", "true").strip().lower() in ("1", "true", "yes", "on")
RULES = [r.strip() for r in os.environ.get("RULES", "100501,100504,501,502").split(",") if r.strip()]
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "60"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))

ALERT_INDEX = "wazuh-alerts-4.x-*"
PAGE_SIZE = 500
STATE_FILE = "/state/hwm.json"
DEDUP_CAPACITY = 500
INITIAL_LOOKBACK_SECONDS = 120  # first run only; no backfill
ERROR_RETRY_SECONDS = 15

log = logging.getLogger("tg-forwarder")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False  # self-signed indexer certs
_SSL_CTX.verify_mode = ssl.CERT_NONE

_STOP = False
_seen = OrderedDict()      # LRU set of processed event ids
_cooldown = {}             # (src_key, rule_id) -> monotonic time of last send


# --- helpers ------------------------------------------------------------------

def _handle_term(signum, _frame):
    global _STOP
    _STOP = True
    log.info("signal %s received; shutting down cleanly", signum)


def mask(secret):
    """Mask a secret for logs: keep first 2 chars, hide the rest."""
    if not secret:
        return "(empty)"
    return secret[:2] + "*" * max(len(secret) - 2, 4)


def parse_ts(ts):
    """Parse an ISO8601 UTC timestamp; None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_ts(ts):
    """Timestamp truncated to seconds, UTC, e.g. 2026-09-21T16:10:32."""
    dt = parse_ts(ts)
    if dt is None:
        return str(ts)[:19] if ts else "?"
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def esc(value):
    """HTML-escape a user-derived value (<, >, &)."""
    return html.escape("" if value is None else str(value), quote=False)


def dedup_key(index, doc_id, ts):
    return hashlib.sha1(f"{index}|{doc_id}|{ts}".encode("utf-8")).hexdigest()


def seen_add(key):
    """LRU membership test for processed events. True if new."""
    if key in _seen:
        _seen.move_to_end(key)
        return False
    _seen[key] = True
    while len(_seen) > DEDUP_CAPACITY:
        _seen.popitem(last=False)
    return True


def http_request(url, data=None, headers=None, timeout=30):
    """urllib request; returns (status, body_bytes). Raises on network errors."""
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def interruptible_sleep(seconds):
    end = time.monotonic() + seconds
    while not _STOP and time.monotonic() < end:
        time.sleep(1)


# --- state (high-water mark) ---------------------------------------------------

def load_hwm():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            ts = json.load(f).get("ts")
        if ts and parse_ts(ts):
            return ts
    except (OSError, ValueError):
        pass
    ts = datetime.now(timezone.utc) - timedelta(seconds=INITIAL_LOOKBACK_SECONDS)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def save_hwm(ts):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"ts": ts}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_FILE)


# --- indexer query --------------------------------------------------------------

def es_search(hwm_iso):
    """Fetch alerts with @timestamp strictly after hwm, matching RULES.

    Returns a list of (index, doc_id, source).
    """
    auth = base64.b64encode(f"{OPENSEARCH_USER}:{OPENSEARCH_PASS}".encode("utf-8")).decode()
    body = json.dumps({
        "size": PAGE_SIZE,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["rule", "data", "agent", "@timestamp"],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": hwm_iso}}},
                    {"terms": {"rule.id": RULES}},
                ]
            }
        },
    }).encode("utf-8")
    status, raw = http_request(
        f"{OPENSEARCH_URL}/{ALERT_INDEX}/_search",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        },
    )
    if status == 401:
        raise RuntimeError("OpenSearch 401 Unauthorized - check OPENSEARCH_USER/OPENSEARCH_PASS in .env")
    if status != 200:
        raise RuntimeError(f"OpenSearch HTTP {status}: {raw[:200]!r}")
    payload = json.loads(raw.decode("utf-8", "replace"))
    hits = payload.get("hits", {}).get("hits", [])
    return [(h.get("_index", ""), h.get("_id", ""), h.get("_source", {})) for h in hits]


# --- message building ------------------------------------------------------------

def build_message(src):
    """Build the Telegram HTML message for an alert; None if rule not formatted."""
    rule = src.get("rule") or {}
    rule_id = str(rule.get("id", ""))
    data = src.get("data") or {}
    agent = src.get("agent") or {}
    ts = esc(fmt_ts(src.get("@timestamp")))

    if rule_id == "100501":
        return (
            f"\U0001F3A3 Cowrie fake login (L{esc(rule.get('level', '?'))})\n"
            f"\U0001F310 {esc(data.get('src_ip', '?'))}\n"
            f"\U0001F464 {esc(data.get('username', '?'))} / {esc(data.get('password', ''))}\n"
            f"\U0001F4E1 {esc(data.get('protocol', '?'))} \u2192 port {esc(data.get('dst_port', '?'))}\n"
            f"\U0001F550 {ts} UTC"
        )
    if rule_id == "100504":
        cmd = data.get("input") or data.get("message") or ""
        return (
            f"\u2328\uFE0F Command in fake session\n"
            f"\U0001F310 {esc(data.get('src_ip', '?'))}\n"
            f"\U0001F4DD {esc(cmd)}\n"
            f"\U0001F550 {ts} UTC"
        )
    if rule_id in ("501", "502"):
        return (
            f"\U0001F493 Wazuh agent event\n"
            f"\U0001F916 {esc(agent.get('name', '?'))}\n"
            f"\U0001F4C4 {esc(rule.get('description', ''))}\n"
            f"\U0001F550 {ts} UTC"
        )
    return None


def send_telegram(text):
    """Send (or dry-run log) one message. Never raises."""
    if DRY_RUN or not TG_BOT_TOKEN:
        log.info("WOULD SEND: %s", text.replace("\n", " | "))
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TG_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    for attempt in (1, 2):
        try:
            status, body = http_request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if status == 200:
                log.info("sent Telegram message (%d chars)", len(text))
                return
            if status == 429:
                if attempt == 1:
                    log.warning("Telegram 429 rate limit; sleeping 60s and retrying once")
                    interruptible_sleep(60)
                    continue
                log.error("Telegram 429 on retry; dropping message")
                return
            log.error("Telegram HTTP %s: %s - dropping message", status, body[:200])
            return
        except Exception as e:  # network error etc.
            log.error("Telegram send failed (%s) - dropping message", e)
            return


# --- main loop --------------------------------------------------------------------

def poll_once(hwm):
    items = es_search(hwm)
    log.info("poll: %d matching alert(s) after %s", len(items), hwm)
    if len(items) >= PAGE_SIZE:
        log.warning("full page returned; the rest is picked up by the next poll")

    max_seen = None
    for index, doc_id, src in items:
        if _STOP:
            break
        ts = str(src.get("@timestamp", ""))
        if not seen_add(dedup_key(index, doc_id, ts)):
            log.debug("duplicate skipped: %s", doc_id)
            continue
        # Advance the watermark for every new alert consumed, whether it is
        # sent or suppressed (cooldown / unformatted rule). Suppressed alerts
        # already got their one allowed send; re-querying them forever would
        # grow the window past PAGE_SIZE and defeat the dedup LRU.
        dt, best = parse_ts(ts), parse_ts(max_seen)
        if dt is not None and (best is None or dt > best):
            max_seen = ts
        msg = build_message(src)
        if msg is None:
            continue
        data = src.get("data") or {}
        agent = src.get("agent") or {}
        src_key = data.get("src_ip") or agent.get("name") or "?"
        rule_id = str((src.get("rule") or {}).get("id", ""))
        cd_key = (src_key, rule_id)
        now = time.monotonic()
        last = _cooldown.get(cd_key)
        if last is not None and now - last < COOLDOWN_SECONDS:
            log.debug("cooldown active for %s (%.0fs remaining)", cd_key, COOLDOWN_SECONDS - (now - last))
            continue
        _cooldown[cd_key] = now
        send_telegram(msg)

    if max_seen:
        hwm = max_seen
        save_hwm(hwm)
        log.info("high-water mark advanced to %s", hwm)
    return hwm


def main():
    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)
    sys.stdout.reconfigure(line_buffering=True)

    class _UtcFormatter(logging.Formatter):
        def formatTime(self, record, datefmt=None):
            return datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_UtcFormatter("%(asctime)sZ %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    log.info(
        "starting forwarder: source=%s user=%s pass=%s rules=%s cooldown=%ss poll=%ss "
        "dry_run=%s tg_token=%s tg_chat=%s state=%s",
        OPENSEARCH_URL, OPENSEARCH_USER, mask(OPENSEARCH_PASS), ",".join(RULES),
        COOLDOWN_SECONDS, POLL_INTERVAL, DRY_RUN, mask(TG_BOT_TOKEN),
        "(set)" if TG_CHAT_ID else "(empty)", STATE_FILE,
    )
    if not OPENSEARCH_PASS:
        log.error("OPENSEARCH_PASS is empty - every poll will fail with 401; fix .env")

    hwm = load_hwm()
    log.info("high-water mark: %s (first-run lookback = %ds, no backfill)",
             hwm, INITIAL_LOOKBACK_SECONDS)

    while not _STOP:
        try:
            hwm = poll_once(hwm)
        except Exception:
            log.exception("poll error - sleeping %ds and continuing", ERROR_RETRY_SECONDS)
            interruptible_sleep(ERROR_RETRY_SECONDS)
        interruptible_sleep(POLL_INTERVAL)

    log.info("forwarder stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
