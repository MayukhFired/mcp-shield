/**
 * MCP Shield — Transport-Agnostic Interception Layer
 * ==================================================
 *
 * `policy.ts` decides *whether* a call is allowed. This module decides *what to
 * do about it*: write the audit row, raise the approval prompt, sanitize the
 * response, log the warning.
 *
 * It knows nothing about stdio or HTTP. Both proxies are thin transport adapters
 * over the functions here:
 *
 *     gateway.ts       (stdio)  ─┐
 *                                ├─→ interceptor.ts ─→ policy.ts
 *     gateway-http.ts  (HTTP)  ─┘
 *
 * This split exists because the two transports previously carried ~120 lines of
 * copy-pasted logic that had already diverged — the HTTP proxy silently lacked
 * payload-size limiting and capability caching. Any rule added here now applies
 * to both transports by construction rather than by discipline.
 */

import {
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
} from "./policy";
import type { PolicyDecision } from "./policy";
import { requestApproval, denialReason, APPROVAL_TIMEOUT_MS } from "./approval";

/** Everything the interceptor needs about the connection it is policing. */
export interface InterceptContext {
  db: any;
  /** Absolute path to the SQLite file; also keys the IPC channel. */
  dbPath: string;
  serverId: string;
}

export type Verdict =
  | { action: "FORWARD"; auditId?: number }
  | { action: "BLOCK"; reason: string; code: number };

/** Tracks an in-flight request so its response can be enriched and audited. */
export interface OutstandingRequest {
  method: string;
  auditId?: number;
  startedAt: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Request screening
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Apply policy to one JSON-RPC request.
 *
 * Which methods are intercepted, and why:
 *
 *   tools/call     — arbitrary side effects on the host. Full evaluation, plus
 *                    an interactive prompt in Gated mode.
 *   resources/read — previously unguarded. A server exposing the filesystem as
 *                    MCP *resources* instead of tools bypassed path gating
 *                    completely. Enforced, but not prompted: resource reads are
 *                    high-frequency and one modal per read is unusable, so
 *                    containment does the work here.
 *   anything else  — forwarded. initialize, ping, notifications and completion
 *                    carry no direct capability to touch the host.
 *
 * Anything not recognised is forwarded rather than blocked, because the MCP
 * method set grows over time and refusing unknown methods would break clients on
 * every protocol revision. The tradeoff is explicit: a future method with host
 * access would need to be added here. That is a maintenance obligation, and it
 * is why the threat model lists protocol drift as a known limitation.
 */
export async function screenRequest(ctx: InterceptContext, msg: any): Promise<Verdict> {
  if (!msg || typeof msg !== "object" || !msg.method) {
    return { action: "FORWARD" };
  }
  if (msg.method === "tools/call") return screenToolCall(ctx, msg);
  if (msg.method === "resources/read") return screenResourceRead(ctx, msg);
  return { action: "FORWARD" };
}

async function screenToolCall(ctx: InterceptContext, msg: any): Promise<Verdict> {
  const toolName: string = msg.params?.name ?? "<unnamed>";
  const toolArgs = msg.params?.arguments ?? {};
  const argumentsJson = safeStringify(toolArgs);

  const policy = await getPolicy(ctx.db, ctx.serverId);
  const evaluation = await evaluatePolicy(ctx.db, policy, toolName, toolArgs);

  if (evaluation.decision === "BLOCKED") {
    await auditDecision(ctx, {
      toolName,
      argumentsJson,
      decision: "BLOCKED",
      evaluation,
      method: "tools/call",
    });
    return { action: "BLOCK", reason: evaluation.reason, code: -32000 };
  }

  // Monitor mode can allow a call that produced findings. Record them so the
  // dashboard can answer "what would Strict mode have blocked?".
  if (evaluation.findings.length > 0) {
    await recordFindingWarnings(ctx, toolName, evaluation);
  }

  if (policy.mode === "Gated") {
    const outcome = await requestApproval({
      db: ctx.db,
      dbPath: ctx.dbPath,
      serverId: ctx.serverId,
      toolName,
      argumentsJson,
    });

    if (outcome.status !== "APPROVED") {
      const reason = denialReason(outcome.status, APPROVAL_TIMEOUT_MS);
      await auditDecision(ctx, {
        toolName,
        argumentsJson,
        decision: "BLOCKED",
        evaluation: { ...evaluation, reason },
        method: "tools/call",
      });
      return { action: "BLOCK", reason, code: -32002 };
    }

    const auditId = await auditDecision(ctx, {
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

  const auditId = await auditDecision(ctx, {
    toolName,
    argumentsJson,
    decision: "ALLOWED",
    evaluation,
    method: "tools/call",
  });
  return { action: "FORWARD", auditId };
}

async function screenResourceRead(ctx: InterceptContext, msg: any): Promise<Verdict> {
  const uri: string = msg.params?.uri ?? "";
  const policy = await getPolicy(ctx.db, ctx.serverId);
  const evaluation = evaluateResourceAccess(policy, uri);
  const label = `resources/read:${uri}`;

  if (evaluation.decision === "BLOCKED") {
    await auditDecision(ctx, {
      toolName: label,
      argumentsJson: safeStringify({ uri }),
      decision: "BLOCKED",
      evaluation,
      method: "resources/read",
    });
    return { action: "BLOCK", reason: evaluation.reason, code: -32000 };
  }

  const auditId = await auditDecision(ctx, {
    toolName: label,
    argumentsJson: safeStringify({ uri }),
    decision: "ALLOWED",
    evaluation,
    method: "resources/read",
  });
  return { action: "FORWARD", auditId };
}

/**
 * Screen a JSON-RPC batch.
 *
 * Policy: if any member would be blocked, the entire batch is rejected.
 *
 * Partial execution is ambiguous — the client cannot tell which members ran —
 * and allowing the clean members while dropping one invites smuggling a hostile
 * call in alongside benign traffic. The current MCP specification does not use
 * JSON-RPC batching, so this path exists to be safe rather than to be exercised.
 *
 * The original implementation had no batch handling at all: an array has no
 * `.method` property, so `msg.method === "tools/call"` was false and the batch
 * fell through to the unconditional forward. Every rule in the engine could be
 * bypassed by wrapping the call in `[...]`.
 */
export async function screenBatch(
  ctx: InterceptContext,
  batch: any[]
): Promise<{ verdicts: Verdict[]; blocked: { reason: string; code: number } | null }> {
  const verdicts = await Promise.all(batch.map((member) => screenRequest(ctx, member)));
  const firstBlock = verdicts.find((v) => v.action === "BLOCK");
  return {
    verdicts,
    blocked: firstBlock && firstBlock.action === "BLOCK"
      ? { reason: firstBlock.reason, code: firstBlock.code }
      : null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Response inspection
// ─────────────────────────────────────────────────────────────────────────────

/** Persist capabilities and smells found in a tools/list response. */
export async function applyToolListScan(
  ctx: InterceptContext,
  tools: any[]
): Promise<any[]> {
  const result = analyzeToolList(tools);

  // Awaited, not fire-and-forget: the capability cache must be populated before
  // the next call is evaluated, or read-only mode falls back to name heuristics
  // for the first call against every tool.
  await Promise.all(
    result.capabilities.map((entry) =>
      saveToolCapabilities(ctx.db, ctx.serverId, entry.toolName, entry.capabilities).catch(
        (err) => console.error(`[MCP Shield] Failed to cache capabilities: ${err.message}`)
      )
    )
  );

  await Promise.all(
    result.smells.map((smell) =>
      logWarning(ctx.db, {
        timestamp: Date.now(),
        server_id: ctx.serverId,
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
 * Inspect a response to a request we intercepted.
 *
 * Mutates `msg` in place and reports whether anything changed, so the caller can
 * avoid re-serializing an untouched message (which would otherwise reorder keys
 * and change bytes for no reason).
 */
export async function inspectResponse(
  ctx: InterceptContext,
  msg: any,
  method: string,
  originalSerialized: string
): Promise<boolean> {
  const policy = await getPolicy(ctx.db, ctx.serverId);
  let mutated = false;

  if (policy.scan_results !== 0) {
    mutated = (await scanResultForInjection(ctx, msg, method)) || mutated;
  }
  mutated = (await enforcePayloadLimit(ctx, msg, originalSerialized, policy.max_payload_kb)) || mutated;

  return mutated;
}

/**
 * Scan text blocks in a result for instruction-override payloads (T-01).
 *
 * This is the half of T-01 the original implementation missed. It sanitized tool
 * *descriptions*, but indirect prompt injection overwhelmingly arrives in the
 * content the agent reads — a poisoned README, an issue comment, a fetched web
 * page — never in the tool's own self-description.
 */
async function scanResultForInjection(
  ctx: InterceptContext,
  msg: any,
  method: string
): Promise<boolean> {
  const blocks: { text: string; set: (v: string) => void }[] = [];

  // tools/call uses `content`; resources/read uses `contents`.
  for (const key of ["content", "contents"] as const) {
    const arr = msg.result?.[key];
    if (!Array.isArray(arr)) continue;
    for (const block of arr) {
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
    await logWarning(ctx.db, {
      timestamp: Date.now(),
      server_id: ctx.serverId,
      tool_name: `${method} response`,
      smell_type: "RESULT_INJECTION",
      description: matches.join(" | ").slice(0, 500),
      details:
        `Instruction-override payload found in tool output and redacted before it reached the model. ` +
        `Patterns: ${matches.map((m) => JSON.stringify(m.slice(0, 120))).join(", ")}`,
      sanitized: 1,
    }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));
  }

  return mutated;
}

/**
 * Truncate oversized responses to protect the agent's context window.
 *
 * Two corrections over the original: the budget is applied by measuring UTF-8
 * bytes rather than slicing characters against a byte count, and the limit
 * applies to the response *total* instead of each block independently — before,
 * N blocks each just under the limit passed through unchecked.
 */
async function enforcePayloadLimit(
  ctx: InterceptContext,
  msg: any,
  originalSerialized: string,
  maxPayloadKb: number
): Promise<boolean> {
  if (!maxPayloadKb || maxPayloadKb <= 0) return false;

  const limitBytes = maxPayloadKb * 1024;
  const totalBytes = Buffer.byteLength(originalSerialized, "utf8");
  if (totalBytes <= limitBytes) return false;

  const blocks: any[] = Array.isArray(msg.result?.content) ? msg.result.content : [];
  const textBlocks = blocks.filter((b) => b && b.type === "text" && typeof b.text === "string");

  if (textBlocks.length > 0) {
    // Share the budget so the response keeps its shape rather than losing blocks.
    const perBlock = Math.max(512, Math.floor(limitBytes / textBlocks.length));
    for (const block of textBlocks) {
      if (Buffer.byteLength(block.text, "utf8") <= perBlock) continue;
      block.text =
        truncateToBytes(block.text, perBlock) +
        `\n\n... [TRUNCATED BY MCP SHIELD: response exceeded the ${maxPayloadKb} KB limit ` +
        `(${Math.round(totalBytes / 1024)} KB received). Request a narrower range or a more specific query.]`;
    }
  }

  await logWarning(ctx.db, {
    timestamp: Date.now(),
    server_id: ctx.serverId,
    tool_name: `response (id: ${msg.id})`,
    smell_type: "PAYLOAD_LIMIT",
    description: `Response payload exceeded the configured limit of ${maxPayloadKb} KB.`,
    details:
      `Original size ${Math.round(totalBytes / 1024)} KB against a ${maxPayloadKb} KB limit. ` +
      `Truncated to stop a hostile or careless server flooding the agent's context window.`,
    sanitized: 1,
  }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));

  return true;
}

/** Cut a string to a UTF-8 byte budget without splitting a multi-byte char. */
export function truncateToBytes(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return text;
  // Decoding a slice can leave a partial code point at the tail; stripping the
  // resulting replacement characters removes it cleanly.
  return buf.subarray(0, maxBytes).toString("utf8").replace(/\uFFFD+$/, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit helpers
// ─────────────────────────────────────────────────────────────────────────────

export async function auditDecision(
  ctx: InterceptContext,
  entry: {
    toolName: string;
    argumentsJson: string;
    decision: "ALLOWED" | "BLOCKED";
    evaluation: PolicyDecision;
    method: string;
  }
): Promise<number | undefined> {
  try {
    return await logAudit(ctx.db, {
      timestamp: Date.now(),
      server_id: ctx.serverId,
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
    // A failed audit write must not block the call: the security decision has
    // already been made. We surface it on stderr and continue.
    console.error(`[MCP Shield] Failed to write audit entry: ${err.message}`);
    return undefined;
  }
}

/** Record findings observed but not enforced (Monitor mode). */
export async function recordFindingWarnings(
  ctx: InterceptContext,
  toolName: string,
  evaluation: PolicyDecision
): Promise<void> {
  await Promise.all(
    evaluation.findings.map((finding) =>
      logWarning(ctx.db, {
        timestamp: Date.now(),
        server_id: ctx.serverId,
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
export async function recordResponse(
  ctx: InterceptContext,
  pending: OutstandingRequest,
  serialized: string
): Promise<void> {
  if (pending.auditId === undefined) return;
  try {
    await updateAuditResponse(
      ctx.db,
      pending.auditId,
      serialized.length > 8192 ? serialized.slice(0, 8192) + "…[truncated]" : serialized,
      Date.now() - pending.startedAt
    );
  } catch (err: any) {
    console.error(`[MCP Shield] Failed to record response: ${err.message}`);
  }
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return '"[unserializable arguments]"';
  }
}

/** Build a JSON-RPC error object for a blocked request. */
export function blockedError(id: string | number | null, code: number, message: string) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message: `Blocked by MCP Shield: ${message}` },
  };
}
