/**
 * MCP Shield — Policy Decision Engine
 * ===================================
 *
 * This is the security core. It is deliberately free of I/O, transport, and
 * VS Code dependencies so that:
 *
 *   1. Both proxies (stdio `gateway.ts` and HTTP `gateway-http.ts`) enforce the
 *      same rules from one implementation. Previously the two transports carried
 *      copy-pasted logic that had already drifted apart, which meant a rule
 *      fixed in one place stayed broken in the other.
 *   2. Every rule is testable as a pure function.
 *
 * Guiding principle: fail closed, and never let a usability escape hatch double
 * as the security off-switch. See `PolicyMode` for why that sentence exists.
 */

import * as path from "path";
import * as fs from "fs";
import { getToolCapabilities } from "./database";
import type { Policy, PolicyMode } from "./database";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Maps a severity onto a 0-100 score so the dashboard can rank events. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  LOW: 20,
  MEDIUM: 45,
  HIGH: 75,
  CRITICAL: 100,
};

/**
 * One rule violation. Findings are recorded even when the decision is ALLOWED
 * (Monitor mode), which is what lets a user answer "what would break if I
 * tightened this policy?" before actually tightening it.
 */
export interface PolicyFinding {
  /** Stable rule id, e.g. "R-PATH-ESCAPE". Dashboards may key off this. */
  rule: string;
  severity: Severity;
  message: string;
}

export interface PolicyDecision {
  decision: "ALLOWED" | "BLOCKED";
  /** Human-readable justification, surfaced in the audit log and the prompt. */
  reason: string;
  findings: PolicyFinding[];
  /** 0-100, from the highest-severity finding. */
  riskScore: number;
}

export type { PolicyMode };

// ─────────────────────────────────────────────────────────────────────────────
// Detection corpora
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Shell metacharacters that let one command become several.
 *
 * This is defence-in-depth only. The real fix belongs in the downstream MCP
 * server, which should never concatenate arguments into a shell string. We
 * cannot see how the target executes, so we reject the input shape instead.
 */
const SHELL_METACHARACTERS = /[;&|`$<>\n\r]|\$\(/;

/**
 * Tool-name tokens implying the tool executes something.
 *
 * We tokenize instead of regexing the raw name because `\b` does not match
 * between `run` and `_` — underscore is a word character — so the original
 * `/\brun\b/` silently failed to match `run_command`. Splitting on
 * non-alphanumerics handles snake_case, kebab-case and camelCase.
 */
const EXEC_TOOL_TOKENS = new Set([
  "run", "exec", "execute", "shell", "cmd", "command", "terminal", "console",
  "bash", "sh", "zsh", "fish", "powershell", "pwsh", "batch",
  "python", "python3", "node", "ruby", "perl", "php",
  "npm", "npx", "yarn", "pnpm", "pip", "cargo",
  "spawn", "fork", "subprocess", "eval", "script", "invoke",
  "compile", "make", "docker", "kubectl", "ssh", "sudo",
]);

/** Sensitive targets, blocked even when they sit inside an allowed root. */
const SENSITIVE_PATH_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "SSH key directory", re: /(?:^|[\\/])\.ssh[\\/]/i },
  { name: "SSH private key", re: /\bid_(?:rsa|dsa|ecdsa|ed25519)\b/i },
  { name: "Environment file", re: /(?:^|[\\/])\.env(?:\.[\w-]+)?(?:$|["'\s])/i },
  { name: "Credential store", re: /(?:^|[\\/])(?:\.netrc|\.npmrc|\.pypirc)(?:$|["'\s])/i },
  { name: "Private key material", re: /\.(?:pem|pfx|p12|keystore|jks)(?:$|["'\s])/i },
  { name: "Unix account database", re: /(?:^|[\\/])etc[\\/](?:passwd|shadow|sudoers)\b/i },
  { name: "Cloud credentials", re: /(?:^|[\\/])\.(?:aws|azure|gcloud|kube)[\\/]/i },
  { name: "OS credential vault", re: /(?:Login Data|Keychains|NTDS\.dit)(?:$|["'\s])/i },
];

/**
 * Credential shapes we refuse to let leave the machine in tool arguments.
 *
 * This is threat T-07 (secret exfiltration), the counterpart to domain
 * allowlisting: allowlisting controls *where* data may go, this controls *what*
 * may go anywhere at all. Patterns are anchored and length-bounded so ordinary
 * identifiers and git SHAs do not trip them.
 */
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key ID", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { name: "AWS secret access key", re: /aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/i },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "GitHub fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/ },
  { name: "OpenAI API key", re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { name: "Bearer token", re: /\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}\b/ },
  {
    name: "Assigned secret literal",
    re: /\b(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"][^'"\s]{16,}['"]/i,
  },
];

/**
 * Instruction-override phrases in tool *descriptions*.
 *
 * Kept byte-identical to the original scanner because the redaction output is
 * asserted by tests and displayed in the UI. Each match runs to the next
 * sentence terminator.
 */
const DESCRIPTION_INJECTION_REGEX =
  /(?:note\s+to\s+ai|ignore\s+previous|system\s+instruction|instead\s+of|always\s+read|secretly|covertly|you\s+must\s+first|before\s+doing|do\s+not\s+tell)[^.]*/gi;

/**
 * Broader corpus for scanning untrusted tool *output*.
 *
 * This closes the real T-01 gap. The original implementation only sanitized tool
 * descriptions, but indirect prompt injection overwhelmingly arrives inside
 * content the agent reads — a poisoned README, a issue comment, a web page —
 * not in the tool's own advertised description.
 */
const RESULT_INJECTION_REGEX = new RegExp(
  [
    "note\\s+to\\s+(?:ai|assistant|llm|model)",
    "ignore\\s+(?:all\\s+)?(?:previous|prior|above)\\s+(?:instructions?|prompts?)",
    "disregard\\s+(?:all\\s+)?(?:previous|prior|above)\\s+\\w+",
    "system\\s*(?:instruction|prompt|message)\\s*[:=]",
    "you\\s+are\\s+now\\s+(?:a|an|in)\\b",
    "new\\s+instructions?\\s*[:=]",
    "do\\s+not\\s+tell\\s+the\\s+user",
    "without\\s+(?:telling|informing|asking)\\s+the\\s+user",
    "</?(?:system|instructions?)>",
  ].join("|"),
  "gi"
);

/** Sensitive-file keywords advertised in a tool description. */
const SENSITIVE_DESCRIPTION_REGEX =
  /(?:\.ssh|id_rsa|passwd|shadow|\.env|credentials|private_key|\.key|\.pem)/gi;

/** Schemes that move data off the machine but are not http(s). */
const NON_HTTP_EGRESS_SCHEMES = /\b(?:ftps?|sftp|ws|wss|gopher|dict|smb|telnet):\/\//i;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function highestScore(findings: PolicyFinding[]): number {
  return findings.reduce((max, f) => Math.max(max, SEVERITY_WEIGHT[f.severity]), 0);
}

function worstSeverity(findings: PolicyFinding[]): Severity {
  return findings.reduce<Severity>(
    (worst, f) => (SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[worst] ? f.severity : worst),
    "LOW"
  );
}

function allow(reason: string, findings: PolicyFinding[] = []): PolicyDecision {
  return { decision: "ALLOWED", reason, findings, riskScore: highestScore(findings) };
}

function blockWith(finding: PolicyFinding, prior: PolicyFinding[] = []): PolicyDecision {
  const findings = [...prior, finding];
  return {
    decision: "BLOCKED",
    reason: finding.message,
    findings,
    riskScore: highestScore(findings),
  };
}

/** Tolerant parse for the TEXT columns that hold JSON string arrays. */
export function parseJsonList(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === "string");
  if (typeof raw !== "string" || raw.trim() === "") return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

/** Split a tool name into lowercase alphanumeric tokens. */
export function tokenizeToolName(name: string): string[] {
  return (name || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

/** Does the tool's name imply it executes commands or scripts? */
export function isExecutionTool(toolName: string): boolean {
  return tokenizeToolName(toolName).some((t) => EXEC_TOOL_TOKENS.has(t));
}

/**
 * Recursively collect every string in an arbitrary JSON value.
 *
 * Depth-bounded so a hostile server cannot stall the proxy with a deeply nested
 * payload, and it walks arrays as well as objects (the original only walked
 * enumerable object keys via `for..in`, which happens to cover arrays too, but
 * this is explicit about intent).
 */
export function collectStrings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 32 || out.length > 5000) return out;
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out, depth + 1);
  } else if (value && typeof value === "object") {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      collectStrings((value as Record<string, unknown>)[key], out, depth + 1);
    }
  }
  return out;
}

/**
 * Is `target` inside one of `allowedRoots`?
 *
 * The original used `resolved.startsWith(allowedRoot)`, a prefix-confusion bug:
 * allowlisting `/safe/dir` also permitted `/safe/dir-evil` and `/safe/dirsecrets`
 * because those strings share the prefix. `path.relative` is boundary-correct —
 * if the result starts with `..` or is absolute, the target escaped the root.
 *
 * We additionally canonicalize through `realpath` so a symlink planted inside an
 * allowed root cannot point outside it. For paths that do not exist yet (a file
 * about to be written) we canonicalize the nearest existing ancestor instead.
 */
export function isPathContained(target: string, allowedRoots: string[]): boolean {
  const canonicalize = (p: string): string => {
    const resolved = path.resolve(p);
    try {
      return fs.realpathSync.native(resolved);
    } catch {
      const parent = path.dirname(resolved);
      if (parent === resolved) return resolved;
      try {
        return path.join(fs.realpathSync.native(parent), path.basename(resolved));
      } catch {
        return resolved;
      }
    }
  };

  // Windows paths are case-insensitive, so a case-flipped path must not escape.
  const normalize = (p: string): string => (process.platform === "win32" ? p.toLowerCase() : p);

  const canonicalTarget = normalize(canonicalize(target));

  return allowedRoots.some((root) => {
    const canonicalRoot = normalize(canonicalize(root));
    const rel = path.relative(canonicalRoot, canonicalTarget);
    if (rel === "") return true; // the target is the root itself
    // `..` escapes the root; an absolute result means a different drive entirely.
    return !rel.startsWith("..") && !path.isAbsolute(rel);
  });
}

/** Heuristic: does this string look like a filesystem path worth gating? */
export function looksLikePath(value: string): boolean {
  if (!value || value.length > 4096) return false;
  if (/^[a-zA-Z]:[\\/]/.test(value)) return true; // Windows drive path
  if (/^\\\\[^\\]/.test(value)) return true; // UNC share
  if (/^~[\\/]/.test(value)) return true; // home-relative
  if (/^file:\/\//i.test(value)) return true;
  if (/^https?:\/\//i.test(value)) return false; // a URL, not a path
  return path.isAbsolute(value);
}

/** Expand `~` and `file://` so home-relative paths cannot dodge containment. */
export function expandHome(value: string): string {
  if (/^~[\\/]/.test(value)) {
    const home = process.env.HOME || process.env.USERPROFILE || "";
    if (home) return path.join(home, value.slice(2));
  }
  if (/^file:\/\//i.test(value)) {
    try {
      return decodeURIComponent(new URL(value).pathname.replace(/^\/([a-zA-Z]:)/, "$1"));
    } catch {
      return value;
    }
  }
  return value;
}

/**
 * Decode common encodings so `%2e%2e%2f` traversal is visible to the literal
 * `..` check. Used for *detection only* — the original string is always what
 * gets forwarded or reported.
 */
export function decodeForInspection(value: string): string {
  let decoded = value;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded.replace(/\\x2e/gi, ".").replace(/\\u002e/gi, ".");
}
