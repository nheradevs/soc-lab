// security-hooks.ts - Deterministic defensive guards for OpenCode.
//
// Port of the three PreToolUse hooks from the course
// "Claude Code Seguro" (Álvaro Chirou), module 7:
//   - bash-firewall:  blocks destructive shell patterns
//   - secrets-scanner: blocks secret-like literals in commands and file writes
//   - env-protector:  keeps .env-family content out of the agent context,
//                     including via the BASH tool (the gap where file-path
//                     read/edit permissions do not apply to `cat .env`)
//
// Mechanism: `tool.execute.before` -> throwing an Error blocks the call.
// Design notes (course hygiene honored):
//   - One file, three single-responsibility guards, documented, versioned locally.
//   - Deterministic by design, but still NOT a security boundary against a
//     motivated attacker: it runs in the user's context and can be disabled.
//   - Patterns intentionally conservative on false positives: content-dumping
//     verbs are blocked; filename-only inspection (ls, git ls-files) is allowed.
//
// Written as plain JavaScript (valid inside .ts) so the exact shipped bytes
// can be unit-tested with plain node by renaming to .mjs. No type annotations
// or imports were used on purpose.

// --- Guard 1: bash-firewall (course: bash-firewall.sh) ---
const DENY_BASH = [
  "rm -rf",
  "rm -fr",
  "mkfs",
  "dd if=",
  "> /dev/sd",
  "shutdown",
  "reboot",
  "chmod 777 /",
  "chown -r",
  "chown -R",
  ":(){",
  "history -c",
];

// --- Guard 2: secrets-scanner (course: secrets-scanner.sh) + lab additions ---
const SECRET_PATTERNS = [
  /sk-[A-Za-z0-9]{20,}/,
  /ghp_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{22,}/,
  /gsk_[A-Za-z0-9]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(password|passwd|pwd|secret|token|api[_-]?key)["'\s]*[:=]\s*["'][^"'\s]{6,}["']/i,
];

// --- Guard 3: env-protector (course: env-protector.sh) + bash-string gap fix ---
// Protected path families (content-level; the opencode.json read/edit denies
// cover file-path tool gating; this closes the bash channel and adds depth).
const PROTECTED_PATH =
  /(\.env$|\.env\.[a-z0-9_-]+$|(^|\/)\.ssh\/|(^|\/)id_rsa|client\.keys$|tailscaled\.state$|credentials\.json$|(^|\/)\.aws\/credentials$|(^|\/)secrets\/|\.git-credentials$|(^|\/)\.netrc$)/i;
const ALLOWED_PATH = /\.env\.example$/i;

// Verbs that dump or copy file CONTENT (filename-level tools like ls/find/grep
// are intentionally NOT here to keep legitimate inspection friction-free).
const READISH =
  /\b(?:cat|head|tail|less|more|strings|base64|xxd|od|tee|cp|scp|rsync|tar|source)\b/;
// Dot-sourcing ("source .env" or ". .env"): the lone-dot form must be
// immediately followed by an .env-ish token to avoid matching `find . -name`.
const DOTSOURCE = /(?:^|[\s;&|])\.\s+\S*\.env(?!\.example)/;
const REDIRECT = /(>>?|\btee\b)[^|;&]*\.env/i;
// Interpreter exfil gap (found in review): `python -c open(".env").read()`
// has no content-dumping verb. Block interpreters invoked with eval flags
// when an .env-ish token is present, plus the dotenv dumpers.
const INTERPRETER = /\b(?:python[0-9.]*|perl|ruby|php|node(?:js)?)\b/;
const EVALFLAG = /(?:\s|^)(?:-c|-e|--eval|--code|-r)(?:\s|$)/;
const DOTENV = /\bdotenv\b/;
// Content-scan exclusion (NOT path protection): the test harness legitimately
// contains fake secret fixtures. Without this the scanner would block its own
// tests from being edited. Applies only to write/edit tool args, never bash.
const TESTFIXTURE_PATH = /(^|\/)odd\/tests\/|security-hooks\.test\.mjs$/;

function block(which, detail) {
  throw new Error(
    "[security-hooks] " + which + " blocked this action: " + detail,
  );
}

function envTokens(text) {
  // returns list of .env-ish path tokens found in a command, minus examples
  const matches = text.match(/[\w~/.-]*\.env(?:\.[a-zA-Z0-9_-]+)?/g) || [];
  return matches.filter((m) => !/\.env\.example$/i.test(m));
}

function scanSecrets(which, text) {
  for (const re of SECRET_PATTERNS) {
    if (re.test(text)) {
      block(which, "content matches secret pattern " + String(re).slice(0, 40));
    }
  }
}

function scanProtectedPath(which, path) {
  if (path && !ALLOWED_PATH.test(path) && PROTECTED_PATH.test(path)) {
    block(which, "protected path: " + path);
  }
}

export const SecurityHooks = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      const tool = String((input && input.tool) || "").toLowerCase();
      const args = (output && output.args) || {};

      if (tool === "bash") {
        const cmd = String(args.command || "");
        const low = cmd.toLowerCase();
        for (const p of DENY_BASH) {
          if (low.includes(p.toLowerCase())) {
            block("bash-firewall", "denylist pattern \"" + p + "\" in: " + cmd.slice(0, 160));
          }
        }
        const envs = envTokens(low);
        if (
          envs.length &&
          (READISH.test(low) ||
            REDIRECT.test(cmd) ||
            DOTSOURCE.test(low) ||
            (INTERPRETER.test(low) && EVALFLAG.test(low)) ||
            DOTENV.test(low))
        ) {
          block("env-protector", "bash would read/write .env content: " + cmd.slice(0, 160));
        }
        scanSecrets("secrets-scanner", cmd);
        return;
      }

      if (tool === "read") {
        scanProtectedPath("env-protector", String(args.filePath || args.path || ""));
        return;
      }

      if (tool === "write" || tool === "edit" || tool === "apply_patch" || tool === "multiedit") {
        scanProtectedPath("env-protector", String(args.filePath || args.path || ""));
        if (!TESTFIXTURE_PATH.test(String(args.filePath || args.path || ""))) {
          scanSecrets("secrets-scanner", JSON.stringify(args));
        }
        return;
      }
    },
  };
};

export default SecurityHooks;
