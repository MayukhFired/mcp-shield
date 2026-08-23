import { open, Database } from "sqlite";
import sqlite3 from "sqlite3";

/**
 * Enforcement mode for a shielded server.
 *
 * `Permissive` is retained only so that databases written by earlier versions
 * keep loading; it is treated as an alias for `Monitor`. See the extended note
 * in `policy.ts` — the original `Permissive` mode skipped every scanner, which
 * meant the button users pressed to stop approval prompts also silently disabled
 * path gating, domain allowlisting and injection sanitization.
 */
export type PolicyMode = "Strict" | "Gated" | "Monitor" | "Permissive";

export interface Policy {
  server_id: string;
  mode: PolicyMode;
  readonly: number; // 1 = true, 0 = false
  allowed_paths: string; // JSON string array
  allowed_domains: string; // JSON string array
  disabled_tools: string; // JSON string array
  status: "Shielded" | "Unshielded";
  max_payload_kb: number; // 0 = disabled, >0 = max response size in KB
  /** 1 = block tool calls carrying credential-shaped strings (threat T-07). */
  block_secrets: number;
  /** 1 = block any URL whose host is not in allowed_domains. 0 = only block when the list is non-empty. */
  deny_unlisted_domains: number;
  /** 1 = scan tool *results* for prompt-injection payloads and redact them (threat T-01). */
  scan_results: number;
}

export interface AuditEntry {
  id?: number;
  timestamp: number;
  server_id: string;
  tool_name: string;
  arguments: string;
  decision: "ALLOWED" | "BLOCKED" | "WARNING";
  reason: string;
  response?: string;
  duration_ms?: number;
  /** 0-100, derived from the highest-severity policy finding. */
  risk_score?: number;
  /** JSON array of PolicyFinding objects, so the dashboard can show every rule hit. */
  findings?: string;
  /** Which JSON-RPC method was intercepted (tools/call, resources/read, ...). */
  method?: string;
}

export interface SecurityWarning {
  id?: number;
  timestamp: number;
  server_id: string;
  tool_name: string;
  smell_type:
    | "PROMPT_INJECTION"
    | "PATH_TRAVERSAL"
    | "SUSPICIOUS_SCHEMA"
    | "RESULT_INJECTION"
    | "SECRET_EXFIL"
    | "PAYLOAD_LIMIT";
  description: string;
  details: string;
  sanitized: number; // 1 = true, 0 = false
}

/**
 * A standing user decision that lets a specific tool skip the approval prompt.
 *
 * This exists to fix a UX-as-security problem: when *every* gated call raises a
 * blocking modal, users escape by loosening the whole policy. Letting them
 * approve one tool once — permanently or for a session — removes the incentive
 * to disable inspection wholesale.
 */
export interface ApprovalRule {
  server_id: string;
  tool_name: string;
  /** ALWAYS persists indefinitely; SESSION expires at `expires_at`. */
  scope: "ALWAYS" | "SESSION";
  created_at: number;
  /** Epoch ms after which a SESSION rule stops applying. 0 for ALWAYS. */
  expires_at: number;
}

export interface PendingApproval {
  id: string;
  timestamp: number;
  server_id: string;
  tool_name: string;
  arguments: string;
  status: "PENDING" | "APPROVED" | "DENIED";
}

// Opens the database with concurrency optimizations
export async function openDB(dbPath: string): Promise<Database> {
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database,
  });

  // Enable Write-Ahead Logging for concurrent read/write and set a busy timeout to handle locks gracefully
  await db.exec("PRAGMA busy_timeout = 10000;");
  await db.exec("PRAGMA journal_mode = WAL;");

  await initSchema(db);
  return db;
}

async function initSchema(db: Database): Promise<void> {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS policies (
      server_id TEXT PRIMARY KEY,
      mode TEXT NOT NULL DEFAULT 'Gated',
      readonly INTEGER NOT NULL DEFAULT 0,
      allowed_paths TEXT NOT NULL DEFAULT '[]',
      allowed_domains TEXT NOT NULL DEFAULT '[]',
      disabled_tools TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'Shielded',
      max_payload_kb INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      server_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      arguments TEXT NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT NOT NULL,
      response TEXT,
      duration_ms INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS security_warnings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      server_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      smell_type TEXT NOT NULL,
      description TEXT NOT NULL,
      details TEXT NOT NULL,
      sanitized INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS pending_approvals (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      server_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      arguments TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING'
    );

    CREATE TABLE IF NOT EXISTS tool_capabilities (
      server_id TEXT,
      tool_name TEXT,
      capabilities TEXT,
      PRIMARY KEY (server_id, tool_name)
    );

    CREATE TABLE IF NOT EXISTS approval_rules (
      server_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'ALWAYS',
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (server_id, tool_name)
    );

    -- The dashboard reads the newest audit rows constantly; without this index
    -- every 2-second refresh becomes a full table scan once the log grows.
    CREATE INDEX IF NOT EXISTS idx_audit_server_time
      ON audit_log (server_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_pending_status
      ON pending_approvals (status, timestamp);
  `);

  // ── Migrations ───────────────────────────────────────────────────────────
  // Additive-only. Each call is a no-op when the column already exists, so the
  // same code path works for a fresh database and one written by v0.1.0.
  await ensureColumn(db, "policies", "max_payload_kb", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(db, "policies", "block_secrets", "INTEGER NOT NULL DEFAULT 1");
  await ensureColumn(db, "policies", "deny_unlisted_domains", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(db, "policies", "scan_results", "INTEGER NOT NULL DEFAULT 1");
  await ensureColumn(db, "audit_log", "risk_score", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(db, "audit_log", "findings", "TEXT");
  await ensureColumn(db, "audit_log", "method", "TEXT NOT NULL DEFAULT 'tools/call'");
}

/**
 * Adds a column if it is not already present.
 *
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, so we inspect `PRAGMA table_info`
 * first. Column names are hard-coded by callers (never user input), and PRAGMA
 * does not accept bound parameters for the table name, so interpolation here is
 * safe — but keep it that way: never pass a caller-supplied string in.
 */
async function ensureColumn(
  db: Database,
  table: string,
  column: string,
  definition: string
): Promise<void> {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) {
    throw new Error(`Refusing to migrate unsafe identifier: ${table}.${column}`);
  }
  const columns = await db.all(`PRAGMA table_info(${table})`);
  if (!columns.some((col: any) => col.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  }
}

// Policies CRUD
export async function getPolicy(db: Database, serverId: string): Promise<Policy> {
  const policy = await db.get<Policy>("SELECT * FROM policies WHERE server_id = ?", serverId);
  if (policy) {
    return policy;
  }

  // No row yet: return a secure-by-default policy rather than an empty object.
  // Defaults matter here — this is what applies the first time an unknown server
  // is shielded, so it must be the restrictive end of the range, not the
  // permissive one.
  return {
    server_id: serverId,
    mode: "Gated",
    readonly: 0,
    allowed_paths: "[]",
    allowed_domains: "[]",
    disabled_tools: "[]",
    status: "Shielded",
    max_payload_kb: 0,
    block_secrets: 1,
    deny_unlisted_domains: 0,
    scan_results: 1,
  };
}

export async function savePolicy(db: Database, policy: Policy): Promise<void> {
  // Validate the enum-like fields before persisting. The policy row is the
  // security source of truth and it is written from the webview, so an
  // unrecognised mode string must not silently become "not Gated and not
  // Strict" (which would have fallen through to allow).
  const mode: PolicyMode = ["Strict", "Gated", "Monitor", "Permissive"].includes(policy.mode)
    ? policy.mode
    : "Gated";
  const status = policy.status === "Unshielded" ? "Unshielded" : "Shielded";
  const bit = (v: unknown, fallback: 0 | 1): number => (v === 1 || v === 0 ? v : fallback);

  await db.run(
    `INSERT OR REPLACE INTO policies (
       server_id, mode, readonly, allowed_paths, allowed_domains, disabled_tools,
       status, max_payload_kb, block_secrets, deny_unlisted_domains, scan_results
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      policy.server_id,
      mode,
      bit(policy.readonly, 0),
      policy.allowed_paths,
      policy.allowed_domains,
      policy.disabled_tools,
      status,
      Math.max(0, Number(policy.max_payload_kb) || 0),
      bit(policy.block_secrets, 1),
      bit(policy.deny_unlisted_domains, 0),
      bit(policy.scan_results, 1),
    ]
  );
}

export async function getAllPolicies(db: Database): Promise<Policy[]> {
  return db.all<Policy[]>("SELECT * FROM policies");
}

// Audit Logs
export async function logAudit(db: Database, entry: AuditEntry): Promise<number> {
  const result = await db.run(
    `INSERT INTO audit_log (
       timestamp, server_id, tool_name, arguments, decision, reason,
       response, duration_ms, risk_score, findings, method
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      entry.timestamp,
      entry.server_id,
      entry.tool_name,
      entry.arguments,
      entry.decision,
      entry.reason,
      entry.response || null,
      entry.duration_ms || 0,
      entry.risk_score || 0,
      entry.findings || null,
      entry.method || "tools/call",
    ]
  );
  return result.lastID!;
}

export async function updateAuditResponse(
  db: Database,
  id: number,
  response: string,
  durationMs: number
): Promise<void> {
  await db.run(
    "UPDATE audit_log SET response = ?, duration_ms = ? WHERE id = ?",
    [response, durationMs, id]
  );
}

export async function getAuditLogs(db: Database, limit: number = 200): Promise<AuditEntry[]> {
  return db.all<AuditEntry[]>("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", limit);
}

// Security Warnings
export async function logWarning(db: Database, warning: Omit<SecurityWarning, "id">): Promise<void> {
  await db.run(
    `INSERT INTO security_warnings (timestamp, server_id, tool_name, smell_type, description, details, sanitized)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      warning.timestamp,
      warning.server_id,
      warning.tool_name,
      warning.smell_type,
      warning.description,
      warning.details,
      warning.sanitized,
    ]
  );
}

export async function getWarnings(db: Database): Promise<SecurityWarning[]> {
  return db.all<SecurityWarning[]>("SELECT * FROM security_warnings ORDER BY id DESC");
}

// Pending Approvals Gating
export async function createPendingApproval(db: Database, approval: PendingApproval): Promise<void> {
  await db.run(
    `INSERT INTO pending_approvals (id, timestamp, server_id, tool_name, arguments, status)
     VALUES (?, ?, ?, ?, ?, 'PENDING')`,
    [
      approval.id,
      approval.timestamp,
      approval.server_id,
      approval.tool_name,
      approval.arguments,
    ]
  );
}

export async function getPendingApproval(db: Database, id: string): Promise<PendingApproval | undefined> {
  return db.get<PendingApproval>("SELECT * FROM pending_approvals WHERE id = ?", id);
}

export async function getActivePendingApprovals(db: Database): Promise<PendingApproval[]> {
  return db.all<PendingApproval[]>("SELECT * FROM pending_approvals WHERE status = 'PENDING' ORDER BY timestamp ASC");
}

export async function updateApprovalStatus(db: Database, id: string, status: "APPROVED" | "DENIED"): Promise<void> {
  await db.run("UPDATE pending_approvals SET status = ? WHERE id = ?", [status, id]);
}

export async function deleteApproval(db: Database, id: string): Promise<void> {
  await db.run("DELETE FROM pending_approvals WHERE id = ?", id);
}

export async function clearAllPendingApprovals(db: Database): Promise<void> {
  await db.run("DELETE FROM pending_approvals");
}

export async function saveToolCapabilities(
  db: Database,
  serverId: string,
  toolName: string,
  capabilities: string[]
): Promise<void> {
  await db.run(
    `INSERT OR REPLACE INTO tool_capabilities (server_id, tool_name, capabilities)
     VALUES (?, ?, ?)`,
    [serverId, toolName, JSON.stringify(capabilities)]
  );
}

export async function getToolCapabilities(
  db: Database,
  serverId: string,
  toolName: string
): Promise<string[]> {
  const row = await db.get<{ capabilities: string }>(
    "SELECT capabilities FROM tool_capabilities WHERE server_id = ? AND tool_name = ?",
    serverId,
    toolName
  );
  if (row) {
    try {
      return JSON.parse(row.capabilities);
    } catch {}
  }
  return [];
}
// ─────────────────────────────────────────────────────────────────────────────
// Approval rules ("don't ask me again")
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Records a standing approval so a tool can skip the confirmation prompt.
 *
 * Scope semantics:
 *   ALWAYS  — persists until the user revokes it from the dashboard.
 *   SESSION — expires at `expiresAt`, so a long refactor can be waved through
 *             without permanently widening the policy.
 */
export async function saveApprovalRule(
  db: Database,
  serverId: string,
  toolName: string,
  scope: "ALWAYS" | "SESSION",
  ttlMs: number = 0
): Promise<void> {
  const now = Date.now();
  await db.run(
    `INSERT OR REPLACE INTO approval_rules (server_id, tool_name, scope, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [serverId, toolName, scope, now, scope === "SESSION" ? now + ttlMs : 0]
  );
}

/**
 * Is there a live standing approval for this tool?
 *
 * Deliberately narrow: matches one exact server + tool pair. There is no
 * wildcard form, because "always allow everything on this server" is what
 * `Strict` mode is for, and conflating the two would let a single click
 * silently widen scope well beyond what the user was looking at.
 */
export async function hasActiveApprovalRule(
  db: Database,
  serverId: string,
  toolName: string
): Promise<boolean> {
  const row = await db.get<ApprovalRule>(
    "SELECT * FROM approval_rules WHERE server_id = ? AND tool_name = ?",
    serverId,
    toolName
  );
  if (!row) return false;
  if (row.scope === "ALWAYS") return true;
  if (row.expires_at > Date.now()) return true;

  // Expired session rule: clean it up so the table does not accumulate cruft.
  await db.run(
    "DELETE FROM approval_rules WHERE server_id = ? AND tool_name = ?",
    [serverId, toolName]
  );
  return false;
}

export async function getApprovalRules(db: Database): Promise<ApprovalRule[]> {
  return db.all<ApprovalRule[]>("SELECT * FROM approval_rules ORDER BY created_at DESC");
}

export async function deleteApprovalRule(
  db: Database,
  serverId: string,
  toolName: string
): Promise<void> {
  await db.run(
    "DELETE FROM approval_rules WHERE server_id = ? AND tool_name = ?",
    [serverId, toolName]
  );
}

/** Drops all SESSION-scoped rules. Called when the extension activates. */
export async function clearSessionApprovalRules(db: Database): Promise<void> {
  await db.run("DELETE FROM approval_rules WHERE scope = 'SESSION'");
}
