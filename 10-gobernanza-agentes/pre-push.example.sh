#!/usr/bin/env bash
# Pre-push secret gate. Install: cp to .git/hooks/pre-push && chmod +x.
# Emergency bypass: SKIP_SECRETS_GATE=1 git push (auditable by choice, not by accident).
set -euo pipefail
[ "${SKIP_SECRETS_GATE:-0}" = "1" ] && { echo "secrets gate SKIPPED by operator"; exit 0; }

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks protect --staged --redact || gitleaks detect --redact
else
  echo "gitleaks not installed: running pattern fallback"
  PATTERNS='ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|gsk_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
  HITS=$(git ls-files -z | xargs -0 grep -lInE "$PATTERNS" 2>/dev/null | grep -vE 'security-hooks|agent-policy|pre-push|README|\.example|\.disabled' || true)
  if [ -n "$HITS" ]; then
    echo "BLOCKED: secret-shaped strings found:"; echo "$HITS"; exit 1
  fi
fi

# .env hygiene: never allow real .env files in the tracked tree
if git ls-files | grep -qP '(^|/)\.env$|(^|/)\.env\.(?!example)[A-Za-z0-9_-]+$'; then
  echo "BLOCKED: tracked .env file(s) present"; exit 1
fi
echo "secrets gate: OK"
