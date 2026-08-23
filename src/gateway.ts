/**
 * MCP Shield — stdio Gateway Proxy
 * ================================
 *
 * A transparent man-in-the-middle for the MCP stdio transport.
 *
 * How it gets invoked
 * -------------------
 * The extension rewrites the MCP client's config so that instead of launching
 *
 *     command: "uvx", args: ["some-mcp-server"]
 *
 * the client launches
 *
 *     command: "node", args: [gateway.js, --server <id>, --db <path>, "--", "uvx", "some-mcp-server"]
 *
 * So the *client* spawns this proxy, and this proxy spawns the real server. That
 * matters for two reasons: we inherit the client's process lifecycle management
 * for free (no daemon to supervise), and we sit on the only channel the client
 * and server have, so there is no path around us short of editing the config back.
 *
 * Data flow
 * ---------
 *     client stdin  → handleClientMessage → policy → child stdin
 *     child stdout  → handleServerMessage → sanitize → client stdout
 *
 * Both directions are newline-delimited JSON-RPC. stderr is inherited straight
 * through so the target server's diagnostics still reach the client, and so that
 * our own logging (which must never touch stdout) stays visible.
 *
 * Invariant: nothing is ever written to stdout except well-formed JSON-RPC. A
 * stray `console.log` here corrupts the protocol stream, which is why every
 * diagnostic in this file uses `console.error`.
 */

import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import {
  openDB,
  getPolicy,
  logAudit,
  updateAuditResponse,
  logWarning,
  saveToolCapabilities,
} from "./database";
import {
  evaluatePolicy,
  evaluateResourceAccess,
  analyzeToolList,
  scanTextForInjection,
  classifyToolCapabilities,
} from "./policy";
import type { PolicyDecision } from "./policy";
import { requestApproval, denialReason, APPROVAL_TIMEOUT_MS } from "./approval";

// ─────────────────────────────────────────────────────────────────────────────
// Command line
// ─────────────────────────────────────────────────────────────────────────────
// Example: node gateway.js --server git --db ./mcp-shield.db -- git-mcp-server --repo .

const args = process.argv.slice(2);
let serverId = "unknown-server";
let dbPath = "mcp-shield.db";
const separatorIndex = args.indexOf("--");

// Only parse our own flags, i.e. everything before the "--" separator. Anything
// after it belongs to the target server and must be passed through untouched.
const ownArgsEnd = separatorIndex === -1 ? args.length : separatorIndex;
for (let i = 0; i < ownArgsEnd; i++) {
  if (args[i] === "--server" && i + 1 < ownArgsEnd) {
    serverId = args[i + 1];
    i++;
  } else if (args[i] === "--db" && i + 1 < ownArgsEnd) {
    dbPath = args[i + 1];
    i++;
  }
}

const targetCmd = separatorIndex !== -1 ? args[separatorIndex + 1] : null;
const targetArgs = separatorIndex !== -1 ? args.slice(separatorIndex + 2) : [];

/** Jest imports this module for its pure functions; suppress the side effects. */
const isTesting = process.env.JEST_WORKER_ID !== undefined;

if (!targetCmd && !isTesting) {
  console.error("Error: Target command not specified. Use '-- <command> [args...]'");
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Process state
// ─────────────────────────────────────────────────────────────────────────────

let db: any = null;
let child: ChildProcess | null = null;
let absoluteDbPath = dbPath;

/**
 * In-flight client requests, keyed by JSON-RPC id.
 *
 * We need the method to interpret the *response* (only a tools/list response
 * should be run through the tool scanner), and we keep the audit row id plus a
 * start timestamp so the response and its latency can be written back to the
 * same audit entry. Without this the audit log's `response` and `duration_ms`
 * columns stayed permanently empty.
 */
interface OutstandingRequest {
  method: string;
  auditId?: number;
  startedAt: number;
}
const outstandingRequests = new Map<string | number, OutstandingRequest>();

/** Guards against unbounded growth if a server never answers some requests. */
const MAX_OUTSTANDING = 1000;

async function start() {
  try {
    absoluteDbPath = path.isAbsolute(dbPath) ? dbPath : path.resolve(process.cwd(), dbPath);
    db = await openDB(absoluteDbPath);

    // shell: false is essential. With shell: true, a server id or argument
    // containing shell metacharacters would be interpreted by the shell — the
    // proxy itself would become the command-injection vector it exists to stop.
    child = spawn(targetCmd!, targetArgs, {
      stdio: ["pipe", "pipe", "inherit"],
      shell: false,
    });

    child.on("error", (err) => {
      console.error(`[MCP Shield] Failed to start target server: ${err.message}`);
      process.exit(1);
    });

    child.on("exit", (code) => {
      process.exit(code || 0);
    });

    setupLineReader(process.stdin, handleClientMessage);
    setupLineReader(child.stdout!, handleServerMessage);
  } catch (err: any) {
    // Fail closed: if we cannot open the policy database we cannot enforce
    // anything, so we refuse to proxy rather than silently passing traffic.
    console.error(`[MCP Shield] Initialization error: ${err.message}`);
    process.exit(1);
  }
}

/**
 * Split a stream into newline-delimited frames.
 *
 * Note the deliberate concurrency choice: handlers are dispatched without
 * awaiting the previous one. A gated tool call can block for up to 90 seconds
 * waiting for a human, and serializing would stall every other message behind
 * it — including the client's own cancellation notifications. JSON-RPC carries
 * request ids precisely so responses may arrive out of order, so interleaving is
 * protocol-safe. Errors are caught per frame so one bad message cannot kill the
 * proxy with an unhandled rejection.
 */
function setupLineReader(
  stream: NodeJS.ReadableStream,
  onLine: (line: string) => Promise<void>
) {
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    let idx;
    while ((idx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.substring(0, idx).trim();
      buffer = buffer.substring(idx + 1);
      if (!line) continue;
      void onLine(line).catch((err) => {
        console.error(`[MCP Shield] Handler error: ${err?.message ?? err}`);
      });
    }
  });
}

function writeToClient(payload: unknown) {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function forwardToChild(line: string) {
  if (child && child.stdin && child.stdin.writable) {
    child.stdin.write(line + "\n");
  }
}

/** Build a JSON-RPC error object for a blocked request. */
function blockedError(id: string | number | null, code: number, message: string) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message: `Blocked by MCP Shield: ${message}` },
  };
}

function sendErrorToClient(id: string | number | null, code: number, message: string) {
  writeToClient(blockedError(id, code, message));
}

function rememberRequest(id: string | number, entry: OutstandingRequest) {
  if (outstandingRequests.size >= MAX_OUTSTANDING) {
    // Drop the oldest tracked request rather than leaking memory. Losing the
    // correlation only costs us response enrichment, never enforcement.
    const oldest = outstandingRequests.keys().next().value;
    if (oldest !== undefined) outstandingRequests.delete(oldest);
  }
  outstandingRequests.set(id, entry);
}

// ─────────────────────────────────────────────────────────────────────────────
// Client → server
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Entry point for every frame arriving from the MCP client.
 *
 * Handles three shapes:
 *   - a single JSON-RPC object
 *   - a JSON-RPC *batch* (array), which the original implementation forwarded
 *     unexamined because an array has no `.method` property — a complete bypass
 *     of every policy rule
 *   - non-JSON, forwarded untouched so raw channels are not broken
 */
async function handleClientMessage(line: string): Promise<void> {
  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    forwardToChild(line);
    return;
  }

  if (Array.isArray(msg)) {
    await handleClientBatch(msg, line);
    return;
  }

  const verdict = await screenClientRequest(msg);
  if (verdict.action === "BLOCK") {
    sendErrorToClient(msg.id ?? null, verdict.code, verdict.reason);
    return;
  }

  if (msg.id !== undefined && msg.method) {
    rememberRequest(msg.id, {
      method: msg.method,
      auditId: verdict.auditId,
      startedAt: Date.now(),
    });
  }

  forwardToChild(line);
}

/**
 * Screen a JSON-RPC batch.
 *
 * Policy: if any member of the batch would be blocked, the whole batch is
 * rejected. Partial execution of a batch is ambiguous — the client cannot tell
 * which members ran — and permitting the clean members while blocking one is an
 * invitation to smuggle a call in alongside benign traffic. Note that the current
 * MCP specification does not use JSON-RPC batching, so this path exists to be
 * safe rather than to be used.
 */
async function handleClientBatch(batch: any[], line: string): Promise<void> {
  const verdicts = await Promise.all(batch.map((member) => screenClientRequest(member)));
  const blockedIndex = verdicts.findIndex((v) => v.action === "BLOCK");

  if (blockedIndex === -1) {
    for (let i = 0; i < batch.length; i++) {
      const member = batch[i];
      const verdict = verdicts[i];
      if (member && member.id !== undefined && member.method) {
        rememberRequest(member.id, {
          method: member.method,
          auditId: verdict.action === "FORWARD" ? verdict.auditId : undefined,
          startedAt: Date.now(),
        });
      }
    }
    forwardToChild(line);
    return;
  }

  const blocked = verdicts[blockedIndex] as { reason: string; code: number };
  const responses = batch
    .filter((member) => member && member.id !== undefined)
    .map((member) =>
      blockedError(
        member.id,
        blocked.code,
        `Batch rejected because one or more members violated policy: ${blocked.reason}`
      )
    );

  if (responses.length > 0) {
    writeToClient(responses);
  }
}

type Verdict =
  | { action: "FORWARD"; auditId?: number }
  | { action: "BLOCK"; reason: string; code: number };

/**
 * Apply policy to one JSON-RPC request.
 *
 * Which methods are intercepted, and why:
 *
 *   tools/call     — the obvious one: arbitrary side effects.
 *   resources/read — previously unguarded. A server that exposes the filesystem
 *                    as MCP *resources* rather than tools bypassed path gating
 *                    entirely. Enforced but not prompted, because resource reads
 *                    are high-frequency and a prompt per read is unusable; the
 *                    containment rules carry the weight here.
 *   everything else — forwarded. Notifications, initialize, ping and completion
 *                    carry no direct capability to touch the host.
 */
async function screenClientRequest(msg: any): Promise<Verdict> {
  if (!msg || typeof msg !== "object" || !msg.method) {
    return { action: "FORWARD" };
  }

  if (msg.method === "tools/call") {
    return screenToolCall(msg);
  }

  if (msg.method === "resources/read") {
    return screenResourceRead(msg);
  }

  return { action: "FORWARD" };
}

async function screenToolCall(msg: any): Promise<Verdict> {
  const toolName: string = msg.params?.name ?? "<unnamed>";
  const toolArgs = msg.params?.arguments ?? {};
  const argumentsJson = safeStringify(toolArgs);

  const policy = await getPolicy(db, serverId);
  const evaluation = await evaluatePolicy(db, policy, toolName, toolArgs);

  if (evaluation.decision === "BLOCKED") {
    await auditDecision({
      toolName,
      argumentsJson,
      decision: "BLOCKED",
      evaluation,
      method: "tools/call",
    });
    return { action: "BLOCK", reason: evaluation.reason, code: -32000 };
  }

  // Monitor mode may allow a call that produced findings. Record them so the
  // dashboard can show "this would have been blocked under Strict".
  if (evaluation.findings.length > 0) {
    await recordFindingWarnings(toolName, evaluation);
  }

  if (policy.mode === "Gated") {
    const outcome = await requestApproval({
      db,
      dbPath: absoluteDbPath,
      serverId,
      toolName,
      argumentsJson,
    });

    if (outcome.status !== "APPROVED") {
      const reason = denialReason(outcome.status, APPROVAL_TIMEOUT_MS);
      await auditDecision({
        toolName,
        argumentsJson,
        decision: "BLOCKED",
        evaluation: { ...evaluation, reason },
        method: "tools/call",
      });
      return { action: "BLOCK", reason, code: -32002 };
    }

    const auditId = await auditDecision({
      toolName,
      argumentsJson,
      decision: "ALLOWED",
      evaluation: {
        ...evaluation,
        reason:
          outcome.channel === "RULE"
            ? `Auto-approved by a standing approval rule for '${toolName}'.`
            : "Approved manually by developer.",
      },
      method: "tools/call",
    });
    return { action: "FORWARD", auditId };
  }

  const auditId = await auditDecision({
    toolName,
    argumentsJson,
    decision: "ALLOWED",
    evaluation,
    method: "tools/call",
  });
  return { action: "FORWARD", auditId };
}

async function screenResourceRead(msg: any): Promise<Verdict> {
  const uri: string = msg.params?.uri ?? "";
  const policy = await getPolicy(db, serverId);
  const evaluation = evaluateResourceAccess(policy, uri);

  if (evaluation.decision === "BLOCKED") {
    await auditDecision({
      toolName: `resources/read:${uri}`,
      argumentsJson: safeStringify({ uri }),
      decision: "BLOCKED",
      evaluation,
      method: "resources/read",
    });
    return { action: "BLOCK", reason: evaluation.reason, code: -32000 };
  }

  const auditId = await auditDecision({
    toolName: `resources/read:${uri}`,
    argumentsJson: safeStringify({ uri }),
    decision: "ALLOWED",
    evaluation,
    method: "resources/read",
  });
  return { action: "FORWARD", auditId };
}

// ─────────────────────────────────────────────────────────────────────────────
// Server → client
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inspect frames coming back from the target server.
 *
 * Three transformations happen here:
 *   1. tools/list responses are scanned and prompt-injection text redacted (T-01).
 *   2. tools/call and resources/read *results* are scanned for injected
 *      instructions. This is the half of T-01 the original missed: indirect
 *      prompt injection arrives in the content the agent reads, not in the tool's
 *      advertised description.
 *   3. Oversized payloads are truncated to protect the agent's context window.
 */
async function handleServerMessage(line: string): Promise<void> {
  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stdout.write(line + "\n");
    return;
  }

  if (Array.isArray(msg)) {
    process.stdout.write(line + "\n");
    return;
  }

  if (msg.id === undefined) {
    process.stdout.write(line + "\n");
    return;
  }

  const pending = outstandingRequests.get(msg.id);
  outstandingRequests.delete(msg.id);

  if (!pending) {
    process.stdout.write(line + "\n");
    return;
  }

  try {
    if (pending.method === "tools/list" && msg.result && Array.isArray(msg.result.tools)) {
      msg.result.tools = await applyToolListScan(msg.result.tools);
      writeToClient(msg);
      return;
    }

    if (
      (pending.method === "tools/call" || pending.method === "resources/read") &&
      msg.result
    ) {
      const policy = await getPolicy(db, serverId);
      let mutated = false;

      if (policy.scan_results !== 0) {
        mutated = (await scanResultForInjection(msg, pending.method)) || mutated;
      }
      mutated = (await enforcePayloadLimit(msg, line, policy.max_payload_kb)) || mutated;

      const serialized = mutated ? JSON.stringify(msg) : line;
      await recordResponse(pending, serialized);
      process.stdout.write(serialized + "\n");
      return;
    }

    await recordResponse(pending, line);
    process.stdout.write(line + "\n");
  } catch (err: any) {
    // Never drop a response because our own inspection failed — that would hang
    // the client waiting for an id that will never be answered.
    console.error(`[MCP Shield] Response inspection failed: ${err?.message ?? err}`);
    process.stdout.write(line + "\n");
  }
}

/** Persist tool capabilities and smells discovered in a tools/list response. */
async function applyToolListScan(tools: any[]): Promise<any[]> {
  const result = analyzeToolList(tools);

  // Awaited rather than fire-and-forget, so a write failure is visible and the
  // capability cache is actually populated before the next call is evaluated.
  await Promise.all(
    result.capabilities.map((entry) =>
      saveToolCapabilities(db, serverId, entry.toolName, entry.capabilities).catch((err) =>
        console.error(`[MCP Shield] Failed to cache capabilities: ${err.message}`)
      )
    )
  );

  await Promise.all(
    result.smells.map((smell) =>
      logWarning(db, {
        timestamp: Date.now(),
        server_id: serverId,
        tool_name: smell.toolName,
        smell_type: smell.smellType,
        description: smell.originalDescription,
        details: smell.details,
        sanitized: smell.smellType === "PROMPT_INJECTION" ? 1 : 0,
      }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`))
    )
  );

  return result.tools;
}

/**
 * Scan text blocks in a result for instruction-override payloads.
 * Returns true when the message was modified.
 */
async function scanResultForInjection(msg: any, method: string): Promise<boolean> {
  const blocks: { text: string; set: (v: string) => void }[] = [];

  if (Array.isArray(msg.result?.content)) {
    for (const block of msg.result.content) {
      if (block && block.type === "text" && typeof block.text === "string") {
        blocks.push({ text: block.text, set: (v) => (block.text = v) });
      }
    }
  }
  if (Array.isArray(msg.result?.contents)) {
    for (const block of msg.result.contents) {
      if (block && typeof block.text === "string") {
        blocks.push({ text: block.text, set: (v) => (block.text = v) });
      }
    }
  }

  let mutated = false;
  for (const block of blocks) {
    const { matches, sanitized } = scanTextForInjection(block.text);
    if (matches.length === 0) continue;
    block.set(sanitized);
    mutated = true;
    await logWarning(db, {
      timestamp: Date.now(),
      server_id: serverId,
      tool_name: `${method} response`,
      smell_type: "RESULT_INJECTION",
      description: matches.join(" | ").slice(0, 500),
      details: `Instruction-override payload found in tool output and redacted before it reached the model. Patterns: ${matches
        .map((m) => JSON.stringify(m.slice(0, 120)))
        .join(", ")}`,
      sanitized: 1,
    }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));
  }

  return mutated;
}

/**
 * Truncate oversized responses.
 *
 * Two fixes over the original: the byte budget is applied by measuring bytes
 * rather than slicing characters with a byte count, and the limit applies to the
 * *total* of all text blocks instead of each block individually (previously N
 * blocks each just under the limit passed through unchecked).
 */
async function enforcePayloadLimit(
  msg: any,
  originalLine: string,
  maxPayloadKb: number
): Promise<boolean> {
  if (!maxPayloadKb || maxPayloadKb <= 0) return false;

  const limitBytes = maxPayloadKb * 1024;
  const totalBytes = Buffer.byteLength(originalLine, "utf8");
  if (totalBytes <= limitBytes) return false;

  const blocks: any[] = Array.isArray(msg.result?.content) ? msg.result.content : [];
  const textBlocks = blocks.filter(
    (b) => b && b.type === "text" && typeof b.text === "string"
  );

  if (textBlocks.length > 0) {
    // Share the budget across blocks so the shape of the response is preserved.
    const perBlock = Math.max(512, Math.floor(limitBytes / textBlocks.length));
    for (const block of textBlocks) {
      if (Buffer.byteLength(block.text, "utf8") <= perBlock) continue;
      block.text =
        truncateToBytes(block.text, perBlock) +
        `\n\n... [TRUNCATED BY MCP SHIELD: response exceeded the ${maxPayloadKb} KB limit ` +
        `(${Math.round(totalBytes / 1024)} KB received). Request a narrower range or a more specific query.]`;
    }
  }

  await logWarning(db, {
    timestamp: Date.now(),
    server_id: serverId,
    tool_name: `tools/call response (id: ${msg.id})`,
    smell_type: "PAYLOAD_LIMIT",
    description: `Response payload exceeded the configured limit of ${maxPayloadKb} KB.`,
    details: `Original size ${Math.round(totalBytes / 1024)} KB against a ${maxPayloadKb} KB limit. Truncated to protect the agent's context window from being flooded.`,
    sanitized: 1,
  }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));

  return true;
}

/** Cut a string to a UTF-8 byte budget without splitting a multi-byte char. */
function truncateToBytes(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return text;
  // Decoding a slice can leave a partial code point at the tail; stripping the
  // replacement character removes it cleanly.
  return buf.subarray(0, maxBytes).toString("utf8").replace(/\uFFFD+$/, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit helpers
// ─────────────────────────────────────────────────────────────────────────────

async function auditDecision(entry: {
  toolName: string;
  argumentsJson: string;
  decision: "ALLOWED" | "BLOCKED";
  evaluation: PolicyDecision;
  method: string;
}): Promise<number | undefined> {
  try {
    return await logAudit(db, {
      timestamp: Date.now(),
      server_id: serverId,
      tool_name: entry.toolName,
      arguments: entry.argumentsJson,
      decision: entry.decision,
      reason: entry.evaluation.reason,
      risk_score: entry.evaluation.riskScore,
      findings: entry.evaluation.findings.length
        ? JSON.stringify(entry.evaluation.findings)
        : undefined,
      method: entry.method,
    });
  } catch (err: any) {
    console.error(`[MCP Shield] Failed to write audit entry: ${err.message}`);
    return undefined;
  }
}

/** Record findings that were observed but not enforced (Monitor mode). */
async function recordFindingWarnings(toolName: string, evaluation: PolicyDecision) {
  await Promise.all(
    evaluation.findings.map((finding) =>
      logWarning(db, {
        timestamp: Date.now(),
        server_id: serverId,
        tool_name: toolName,
        smell_type: finding.rule === "R-SECRET-EXFIL" ? "SECRET_EXFIL" : "SUSPICIOUS_SCHEMA",
        description: `${finding.rule} (${finding.severity})`,
        details: finding.message,
        sanitized: 0,
      }).catch(() => undefined)
    )
  );
}

/** Attach the response body and latency to the audit row for this request. */
async function recordResponse(pending: OutstandingRequest, serialized: string) {
  if (pending.auditId === undefined) return;
  try {
    await updateAuditResponse(
      db,
      pending.auditId,
      serialized.length > 8192 ? serialized.slice(0, 8192) + "…[truncated]" : serialized,
      Date.now() - pending.startedAt
    );
  } catch (err: any) {
    console.error(`[MCP Shield] Failed to record response: ${err.message}`);
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return '"[unserializable arguments]"';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backwards-compatible re-exports
// ─────────────────────────────────────────────────────────────────────────────
// The policy engine moved to policy.ts. These re-exports keep older imports
// (including existing tests) working against the new implementation.

export { evaluatePolicy, classifyToolCapabilities } from "./policy";

/**
 * @deprecated Use `analyzeToolList` from policy.ts, which is pure and returns
 * its findings instead of writing them. Retained because it is the shape the
 * original test suite and any external callers expect.
 */
export function scanAndSanitizeTools(tools: any[], scanServerId: string, testDb?: any): any[] {
  const activeDb = testDb || db;
  const result = analyzeToolList(tools);

  if (activeDb) {
    for (const entry of result.capabilities) {
      saveToolCapabilities(activeDb, scanServerId, entry.toolName, entry.capabilities).catch(
        (err) => console.error(`[MCP Shield] Failed to save tool capabilities: ${err.message}`)
      );
    }
    for (const smell of result.smells) {
      logWarning(activeDb, {
        timestamp: Date.now(),
        server_id: scanServerId,
        tool_name: smell.toolName,
        smell_type: smell.smellType,
        description: smell.originalDescription,
        details: smell.details,
        sanitized: 1,
      }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));
    }
  }

  return result.tools;
}

if (!isTesting) {
  start();
}
