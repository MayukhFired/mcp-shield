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

// ─────────────────────────────────────────────────────────────────────────────
// Individual rules
// ─────────────────────────────────────────────────────────────────────────────

/** T-07: credential material present in outbound tool arguments. */
export function findSecrets(values: string[]): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  for (const value of values) {
    for (const { name, re } of SECRET_PATTERNS) {
      if (re.test(value)) {
        findings.push({
          rule: "R-SECRET-EXFIL",
          severity: "CRITICAL",
          message: `Credential material detected in tool arguments (${name}). MCP Shield blocks tool calls that carry secrets, to prevent exfiltration.`,
        });
        break; // one finding per value is enough
      }
    }
  }
  return findings;
}

/** Sensitive targets, flagged even when inside an allowed root. */
export function findSensitivePaths(values: string[]): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  for (const value of values) {
    if (!/[\\/]/.test(value) && !looksLikePath(value)) continue;
    for (const { name, re } of SENSITIVE_PATH_PATTERNS) {
      if (re.test(value)) {
        findings.push({
          rule: "R-SENSITIVE-PATH",
          severity: "HIGH",
          message: `Access to protected resource blocked: "${value}" matches a sensitive pattern (${name}).`,
        });
        break;
      }
    }
  }
  return findings;
}

/**
 * T-05: network egress control.
 *
 * Two behaviours, chosen by `denyUnlisted`:
 *   - false (default): only enforce when an allowlist exists. Preserves the
 *     original semantics so shielding a server does not immediately break it.
 *   - true: any URL whose host is not listed is blocked. This is the correct
 *     posture for a locked-down server, and the dashboard offers it explicitly
 *     because the default fails open by design.
 */
export function inspectUrls(
  value: string,
  allowedDomains: string[],
  denyUnlisted: boolean
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  // Non-HTTP schemes bypass any http(s)-shaped check, so name them explicitly.
  if (NON_HTTP_EGRESS_SCHEMES.test(value) && (allowedDomains.length > 0 || denyUnlisted)) {
    const scheme = value.match(NON_HTTP_EGRESS_SCHEMES)?.[0] ?? "unknown";
    findings.push({
      rule: "R-NET-SCHEME",
      severity: "HIGH",
      message: `Non-HTTP egress scheme blocked: "${scheme}" in "${value}". Only http(s) hosts can be allowlisted.`,
    });
    return findings;
  }

  const urlRegex = /https?:\/\/[^\s"'()<>]+/gi;
  const urls = value.match(urlRegex);
  if (!urls) return findings;

  for (const candidate of urls) {
    let hostname: string;
    try {
      hostname = new URL(candidate).hostname;
    } catch {
      findings.push({
        rule: "R-NET-MALFORMED",
        severity: "MEDIUM",
        message: `Malformed URL pattern detected in arguments: "${candidate}"`,
      });
      continue;
    }

    if (allowedDomains.length === 0) {
      if (denyUnlisted) {
        findings.push({
          rule: "R-NET-DENY",
          severity: "HIGH",
          message: `External URL access blocked: "${candidate}". No domains are allowlisted for this server and unlisted domains are denied.`,
        });
      }
      continue;
    }

    const isAllowed = allowedDomains.some((domain) => {
      const d = domain.trim().toLowerCase();
      const h = hostname.toLowerCase();
      if (d.startsWith("*.")) {
        const suffix = d.slice(2);
        // Wildcard matches the apex and any subdomain, but nothing that merely
        // ends with the same characters (`evilnpm.org` must not match `*.npm.org`).
        return h === suffix || h.endsWith("." + suffix);
      }
      return h === d;
    });

    if (!isAllowed) {
      findings.push({
        rule: "R-NET-DOMAIN",
        severity: "HIGH",
        message: `External URL access blocked: "${candidate}". Domain '${hostname}' is not in the allowed list: ${allowedDomains.join(", ")}`,
      });
    }
  }

  return findings;
}

/**
 * Scan untrusted text — a tool result — for instruction-override attempts.
 *
 * Returns the matches found and a redacted copy. The caller decides whether to
 * substitute the redacted version, because doing so alters data the agent asked
 * for and that tradeoff belongs to policy, not detection.
 */
export function scanTextForInjection(text: string): { matches: string[]; sanitized: string } {
  RESULT_INJECTION_REGEX.lastIndex = 0;
  const matches = text.match(RESULT_INJECTION_REGEX) || [];
  if (matches.length === 0) return { matches: [], sanitized: text };
  return {
    matches,
    sanitized: text.replace(
      RESULT_INJECTION_REGEX,
      "[REDACTED BY MCP SHIELD: instruction-override attempt detected in tool output]"
    ),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Evaluate a `tools/call` against a server's policy.
 *
 * Rule order is deliberate:
 *   0. Unshielded status  → explicit bypass, no inspection at all.
 *   1. Disabled tool list → the operator's hard denylist outranks everything.
 *   2. Read-only mode     → capability check, cache first then name heuristic.
 *   3. Argument scanning  → traversal, containment, shell metacharacters,
 *                           sensitive targets, secrets, network egress.
 *   4. Monitor downgrade  → findings recorded, call permitted.
 *
 * Step 4 runs *last* on purpose. The original code checked Permissive mode at
 * the top and returned before any scanner ran, so a user silencing prompts also
 * silenced detection. Now Monitor observes the full finding set.
 *
 * Within step 3, shell-metacharacter detection precedes sensitive-path
 * detection: for `run_command("cat /etc/passwd; rm -rf /")` the metacharacter is
 * the more precise and more urgent diagnosis.
 */
export async function evaluatePolicy(
  db: any,
  policy: Policy,
  toolName: string,
  toolArgs: unknown
): Promise<PolicyDecision> {
  // ── 0. Explicit bypass ───────────────────────────────────────────────────
  if (policy.status === "Unshielded") {
    return allow("Server status is set to Unshielded.");
  }

  const mode = (policy.mode || "Gated") as PolicyMode;
  const isMonitor = mode === "Monitor" || mode === "Permissive";
  const findings: PolicyFinding[] = [];

  /**
   * Record a violation. In Monitor mode we keep scanning and return null so the
   * caller continues; otherwise we stop here and block.
   */
  const violation = (finding: PolicyFinding): PolicyDecision | null => {
    if (isMonitor) {
      findings.push(finding);
      return null;
    }
    return blockWith(finding, findings);
  };

  // ── 1. Operator denylist ─────────────────────────────────────────────────
  // Blocked even in Monitor mode: this is an explicit, unambiguous instruction
  // from the operator, not a heuristic finding to be observed.
  const disabledTools = parseJsonList(policy.disabled_tools);
  if (disabledTools.includes(toolName)) {
    return blockWith({
      rule: "R-TOOL-DISABLED",
      severity: "CRITICAL",
      message: `Tool '${toolName}' is disabled in the security policy.`,
    });
  }

  // ── 2. Read-only enforcement (T-03) ──────────────────────────────────────
  if (policy.readonly === 1) {
    const capabilities = await getToolCapabilities(db, policy.server_id, toolName);

    if (capabilities.length > 0) {
      if (capabilities.includes("WRITE")) {
        const decided = violation({
          rule: "R-READONLY",
          severity: "HIGH",
          message: `Write operations are blocked on this server. Tool '${toolName}' is classified as write-capable.`,
        });
        if (decided) return decided;
      }
    } else {
      // No cached capability yet — no tools/list has passed through. Fall back
      // to name heuristics rather than failing open.
      const writeRegex =
        /write|delete|remove|update|create|execute|run|install|uninstall|post|put|patch|destroy|mkdir|rmdir|unlink/i;
      if (writeRegex.test(toolName)) {
        const decided = violation({
          rule: "R-READONLY",
          severity: "HIGH",
          message: `Write operations are blocked on this server. Tool '${toolName}' matches read-only restriction pattern.`,
        });
        if (decided) return decided;
      }
    }
  }

  // ── 3. Argument inspection ───────────────────────────────────────────────
  const argValues = collectStrings(toolArgs);

  // 3a. Traversal sequences (T-02), checked on a decoded copy so percent-encoded
  //     traversal is caught. The message reports the original value.
  for (const raw of argValues) {
    const probe = decodeForInspection(raw);
    if (probe.includes("..") && /[\\/]/.test(probe)) {
      const decided = violation({
        rule: "R-PATH-TRAVERSAL",
        severity: "CRITICAL",
        message: `Potential path traversal attempt detected in arguments: "${raw}"`,
      });
      if (decided) return decided;
    }
  }

  // 3b. Containment (T-02). An empty allowlist falls back to the proxy's working
  //     directory, which is the shielded project root.
  const configuredPaths = parseJsonList(policy.allowed_paths);
  const allowedRoots = configuredPaths.length > 0 ? configuredPaths : [process.cwd()];

  for (const raw of argValues) {
    if (!looksLikePath(raw)) continue;
    const candidate = expandHome(decodeForInspection(raw));
    if (!isPathContained(candidate, allowedRoots)) {
      const decided = violation({
        rule: "R-PATH-ESCAPE",
        severity: "HIGH",
        message: `Access to path outside authorized directories is blocked: "${raw}". Authorized directories: ${allowedRoots.join(", ")}`,
      });
      if (decided) return decided;
    }
  }

  // 3c. Shell metacharacters on execution-capable tools (T-04).
  if (isExecutionTool(toolName)) {
    for (const raw of argValues) {
      if (SHELL_METACHARACTERS.test(raw)) {
        const decided = violation({
          rule: "R-SHELL-METACHAR",
          severity: "CRITICAL",
          message: `Dangerous shell metacharacter detected in command tool arguments: "${raw}"`,
        });
        if (decided) return decided;
      }
    }
  }

  // 3d. Sensitive targets, even within an allowed root.
  for (const finding of findSensitivePaths(argValues)) {
    const decided = violation(finding);
    if (decided) return decided;
  }

  // 3e. Credential exfiltration (T-07). Defaults on; `!== 0` keeps policies
  //     written before this column existed protected rather than opted out.
  if (policy.block_secrets !== 0) {
    for (const finding of findSecrets(argValues)) {
      const decided = violation(finding);
      if (decided) return decided;
    }
  }

  // 3f. Network egress (T-05).
  const allowedDomains = parseJsonList(policy.allowed_domains);
  const denyUnlisted = policy.deny_unlisted_domains === 1;
  for (const raw of argValues) {
    for (const finding of inspectUrls(raw, allowedDomains, denyUnlisted)) {
      const decided = violation(finding);
      if (decided) return decided;
    }
  }

  // ── 4. Monitor downgrade ─────────────────────────────────────────────────
  if (isMonitor) {
    const label = mode === "Permissive" ? "Permissive" : "Monitor";
    if (findings.length > 0) {
      return allow(
        `${label} mode: ${findings.length} policy finding(s) recorded but the call was allowed. Highest severity: ${worstSeverity(findings)}.`,
        findings
      );
    }
    return allow(`${label} mode: no policy findings; call observed and allowed.`);
  }

  return allow("Passed all automated security rules.");
}

/**
 * Evaluate a non-tool resource access (`resources/read`).
 *
 * These methods were previously unguarded: only `tools/call` was intercepted, so
 * a server that exposed the filesystem as MCP *resources* bypassed path gating
 * entirely. The URI is checked with the same containment and sensitivity rules.
 */
export function evaluateResourceAccess(policy: Policy, uri: string): PolicyDecision {
  if (policy.status === "Unshielded") {
    return allow("Server status is set to Unshielded.");
  }

  const mode = (policy.mode || "Gated") as PolicyMode;
  const isMonitor = mode === "Monitor" || mode === "Permissive";
  const findings: PolicyFinding[] = [];

  const probe = decodeForInspection(uri);
  const target = expandHome(probe);

  if (probe.includes("..") && /[\\/]/.test(probe)) {
    findings.push({
      rule: "R-PATH-TRAVERSAL",
      severity: "CRITICAL",
      message: `Potential path traversal attempt detected in resource URI: "${uri}"`,
    });
  }

  for (const finding of findSensitivePaths([target])) {
    findings.push(finding);
  }

  // Only containment-check URIs that actually denote local files.
  if (looksLikePath(target) || /^file:/i.test(uri)) {
    const configuredPaths = parseJsonList(policy.allowed_paths);
    const allowedRoots = configuredPaths.length > 0 ? configuredPaths : [process.cwd()];
    if (!isPathContained(target, allowedRoots)) {
      findings.push({
        rule: "R-PATH-ESCAPE",
        severity: "HIGH",
        message: `Resource outside authorized directories is blocked: "${uri}". Authorized directories: ${allowedRoots.join(", ")}`,
      });
    }
  }

  if (findings.length === 0) {
    return allow("Resource URI passed all automated security rules.");
  }
  if (isMonitor) {
    const label = mode === "Permissive" ? "Permissive" : "Monitor";
    return allow(
      `${label} mode: ${findings.length} finding(s) recorded on resource read but access was allowed.`,
      findings
    );
  }
  // Report the worst finding as the reason rather than whichever ran first.
  const worst = findings.reduce((a, b) =>
    SEVERITY_WEIGHT[b.severity] > SEVERITY_WEIGHT[a.severity] ? b : a
  );
  return blockWith(worst, findings.filter((f) => f !== worst));
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool-definition analysis (runs on tools/list responses)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Classify a tool as READ or WRITE from its name and input schema (T-03).
 *
 * This is intentionally a heuristic and is documented as such in the threat
 * model. It exists so that read-only mode has something better than a name
 * regex to work with, and the result is cached in `tool_capabilities` the first
 * time a `tools/list` flows through the proxy.
 *
 * Known limitation worth stating out loud: a server that names a destructive
 * tool `get_status` defeats this. That is why read-only mode is a convenience
 * control and the *denylist* plus interactive approval are the real enforcement.
 */
export function classifyToolCapabilities(tool: any): string[] {
  const capabilities: string[] = [];
  const name = (tool.name || "").toLowerCase();

  const writeKeywords = [
    "write", "delete", "remove", "update", "create", "execute", "run",
    "install", "uninstall", "post", "put", "patch", "destroy", "mkdir",
    "rmdir", "unlink", "apply", "commit", "push", "save", "edit", "modify",
    "append", "set", "touch", "exec",
  ];

  const readKeywords = [
    "read", "get", "list", "describe", "view", "show", "info", "query",
    "explain", "check", "scan", "search", "find", "status", "audit",
  ];

  let isWrite = writeKeywords.some((kw) => name.includes(kw));

  // A write keyword appearing inside a read-prefixed name usually describes what
  // is being queried, not performed: `get_write_permissions` only reads.
  // `run`/`exec` are excluded from the override because they execute regardless.
  if (isWrite) {
    const hasReadPrefix = readKeywords.some((kw) => name.startsWith(kw));
    if (hasReadPrefix && !name.includes("run") && !name.includes("exec")) {
      isWrite = false;
    }
  }

  // Schema hint: a tool accepting content/text/code/value alongside a target is
  // almost certainly mutating, even when its name is neutral.
  if (tool.inputSchema && tool.inputSchema.properties) {
    const props = Object.keys(tool.inputSchema.properties).map((p) => p.toLowerCase());
    if (
      (props.includes("content") ||
        props.includes("text") ||
        props.includes("code") ||
        props.includes("value")) &&
      !readKeywords.some((kw) => name.includes(kw))
    ) {
      isWrite = true;
    }
  }

  capabilities.push(isWrite ? "WRITE" : "READ");
  return capabilities;
}

/** A smell found while inspecting an advertised tool definition. */
export interface ToolSmell {
  toolName: string;
  smellType: "PROMPT_INJECTION" | "PATH_TRAVERSAL";
  originalDescription: string;
  details: string;
}

export interface ToolScanResult {
  tools: any[];
  smells: ToolSmell[];
  capabilities: { toolName: string; capabilities: string[] }[];
}

/**
 * Inspect and sanitize an advertised tool list (T-01, first half).
 *
 * Pure function: it returns what it found and lets the caller persist. The
 * previous version wrote to SQLite from inside the map with floating unawaited
 * promises, which made it untestable without a database and meant write failures
 * surfaced as unhandled rejections.
 *
 * Only prompt-injection text is redacted. Sensitive-file references are reported
 * but left intact, because the description may be legitimately warning the user
 * about the tool's behaviour, and silently rewriting it would be misleading.
 */
export function analyzeToolList(tools: any[]): ToolScanResult {
  const smells: ToolSmell[] = [];
  const capabilities: { toolName: string; capabilities: string[] }[] = [];

  const scanned = tools.map((tool) => {
    capabilities.push({ toolName: tool.name, capabilities: classifyToolCapabilities(tool) });

    let description: string = tool.description || "";
    const original = description;
    let details = "";
    let smellType: "PROMPT_INJECTION" | "PATH_TRAVERSAL" | null = null;

    DESCRIPTION_INJECTION_REGEX.lastIndex = 0;
    const injectionMatches = description.match(DESCRIPTION_INJECTION_REGEX);
    if (injectionMatches) {
      smellType = "PROMPT_INJECTION";
      details += `Prompt injection patterns detected: "${injectionMatches.join(", ")}". `;
      description = description.replace(
        DESCRIPTION_INJECTION_REGEX,
        "[Description redacted by MCP Shield for prompt injection safety]"
      );
    }

    SENSITIVE_DESCRIPTION_REGEX.lastIndex = 0;
    const fileMatches = original.match(SENSITIVE_DESCRIPTION_REGEX);
    if (fileMatches) {
      // PATH_TRAVERSAL wins the label when both are present, matching the
      // original behaviour that the dashboard and tests expect.
      smellType = "PATH_TRAVERSAL";
      details += `Sensitive file references detected: "${fileMatches.join(", ")}". `;
    }

    if (smellType) {
      smells.push({
        toolName: tool.name,
        smellType,
        originalDescription: original,
        details: details.trim(),
      });
      return { ...tool, description };
    }

    return tool;
  });

  return { tools: scanned, smells, capabilities };
}
