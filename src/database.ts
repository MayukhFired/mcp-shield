import { open, Database } from "sqlite";
import sqlite3 from "sqlite3";

export interface Policy {
  server_id: string;
  mode: "Permissive" | "Gated" | "Strict";
  readonly: number; // 1 = true, 0 = false
  allowed_paths: string; // JSON string array
  allowed_domains: string; // JSON string array
  disabled_tools: string; // JSON string array
  status: "Shielded" | "Unshielded";
  max_payload_kb: number; // 0 = disabled, >0 = max response size in KB
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
}

export interface SecurityWarning {
  id?: number;
  timestamp: number;
  server_id: string;
  tool_name: string;
  smell_type: "PROMPT_INJECTION" | "PATH_TRAVERSAL" | "SUSPICIOUS_SCHEMA";
  description: string;
  details: string;
  sanitized: number; // 1 = true, 0 = false
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
  `);

  // Safe migration for existing databases: add max_payload_kb if missing
  const columns = await db.all("PRAGMA table_info(policies)");
  const hasPayloadCol = columns.some((col: any) => col.name === "max_payload_kb");
  if (!hasPayloadCol) {
    await db.exec("ALTER TABLE policies ADD COLUMN max_payload_kb INTEGER NOT NULL DEFAULT 0;");
  }
}

// Policies CRUD
export async function getPolicy(db: Database, serverId: string): Promise<Policy> {
  const policy = await db.get<Policy>("SELECT * FROM policies WHERE server_id = ?", serverId);
  if (policy) {
    return policy;
  }

  // Return default policy if none exists
  return {
    server_id: serverId,
    mode: "Gated",
    readonly: 0,
    allowed_paths: "[]",
    allowed_domains: "[]",
    disabled_tools: "[]",
    status: "Shielded",
    max_payload_kb: 0,
  };
}

export async function savePolicy(db: Database, policy: Policy): Promise<void> {
  await db.run(
    `INSERT OR REPLACE INTO policies (server_id, mode, readonly, allowed_paths, allowed_domains, disabled_tools, status, max_payload_kb)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      policy.server_id,
      policy.mode,
      policy.readonly,
      policy.allowed_paths,
      policy.allowed_domains,
      policy.disabled_tools,
      policy.status,
      policy.max_payload_kb || 0,
    ]
  );
}

export async function getAllPolicies(db: Database): Promise<Policy[]> {
  return db.all<Policy[]>("SELECT * FROM policies");
}

// Audit Logs
export async function logAudit(db: Database, entry: AuditEntry): Promise<number> {
  const result = await db.run(
    `INSERT INTO audit_log (timestamp, server_id, tool_name, arguments, decision, reason, response, duration_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      entry.timestamp,
      entry.server_id,
      entry.tool_name,
      entry.arguments,
      entry.decision,
      entry.reason,
      entry.response || null,
      entry.duration_ms || 0,
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
