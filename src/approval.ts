/**
 * MCP Shield — Interactive Approval Channel (gateway side)
 * ========================================================
 *
 * Implements threat T-06: halt a tool call and wait for a human decision.
 *
 * This lives in its own module because both proxies need it and the logic was
 * previously copy-pasted verbatim into each of them.
 *
 * Transport design
 * ----------------
 * The proxy runs as a *separate process* from the VS Code extension — the MCP
 * client spawns it, not VS Code — so they need an IPC channel. Two exist:
 *
 *   1. Primary: a named pipe (Windows) / Unix domain socket, keyed by a hash of
 *      the database path. Push-based, so approval latency is a few milliseconds.
 *   2. Fallback: polling the `pending_approvals` table in SQLite. Used when the
 *      socket is unavailable, e.g. the extension has not activated yet or the
 *      user has VS Code closed entirely.
 *
 * Both paths converge on the same table, so the audit trail is identical either
 * way. If neither answers within the timeout the call is DENIED, not allowed —
 * an unattended machine must not become an open door.
 */

import * as net from "net";
import { getSocketPath, ApprovalRequest, ApprovalResponse } from "./ipc";
import {
  createPendingApproval,
  getPendingApproval,
  deleteApproval,
  hasActiveApprovalRule,
} from "./database";

/** How long a proxy waits for a human before giving up and denying. */
export const APPROVAL_TIMEOUT_MS = 90_000;

/** Interval for the SQLite fallback poll. */
const POLL_INTERVAL_MS = 150;

/** How the decision was reached — recorded in the audit log for explainability. */
export type ApprovalChannel = "RULE" | "IPC" | "POLL" | "TIMEOUT";

export interface ApprovalOutcome {
  status: "APPROVED" | "DENIED" | "TIMEOUT";
  channel: ApprovalChannel;
}

/**
 * Ask the VS Code extension for a decision over the socket.
 *
 * Resolves `null` on any transport problem — connection refused, socket closed
 * early, or timeout — which signals the caller to try the SQLite fallback. It
 * deliberately does not distinguish those cases: from the proxy's point of view
 * "nobody answered on this channel" is one condition.
 */
export function askApprovalViaIpc(
  dbPath: string,
  req: ApprovalRequest,
  timeoutMs: number = APPROVAL_TIMEOUT_MS
): Promise<"APPROVED" | "DENIED" | null> {
  return new Promise((resolve) => {
    const socketPath = getSocketPath(dbPath);
    let settled = false;
    let timer: NodeJS.Timeout | null = null;

    const finish = (value: "APPROVED" | "DENIED" | null) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        client.destroy();
      } catch {
        /* already gone */
      }
      resolve(value);
    };

    const client = net.connect(socketPath);

    client.on("connect", () => {
      client.write(JSON.stringify(req) + "\n");
    });

    // Newline-delimited JSON, same framing as the MCP stream itself.
    let buffer = "";
    client.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (!line) continue;
        try {
          const res = JSON.parse(line) as ApprovalResponse;
          // Ignore responses for other requests sharing this channel.
          if (res.id === req.id) {
            finish(res.status);
            return;
          }
        } catch {
          /* ignore malformed frame and keep reading */
        }
      }
    });

    client.on("error", () => finish(null));
    client.on("close", () => finish(null));

    timer = setTimeout(() => finish(null), timeoutMs);
  });
}

/**
 * Obtain a human decision for one tool call.
 *
 * Order of resolution:
 *   1. A standing approval rule ("always allow this tool") → approve silently.
 *      This is what makes Gated mode survivable; without it users abandon gating
 *      entirely, which is a far worse outcome than a scoped standing approval.
 *   2. Insert the pending row, so the decision is durable and visible to the
 *      dashboard even if this process dies mid-wait.
 *   3. Ask over IPC.
 *   4. Fall back to polling the row.
 *   5. Timeout → DENIED (fail closed).
 *
 * The pending row is always deleted before returning, including on the error
 * path, so a crashed prompt cannot leave a stale entry that makes the dashboard
 * show a phantom approval request.
 */
export async function requestApproval(opts: {
  db: any;
  dbPath: string;
  serverId: string;
  toolName: string;
  argumentsJson: string;
  timeoutMs?: number;
}): Promise<ApprovalOutcome> {
  const { db, dbPath, serverId, toolName, argumentsJson } = opts;
  const timeoutMs = opts.timeoutMs ?? APPROVAL_TIMEOUT_MS;

  // 1. Standing approval?
  try {
    if (await hasActiveApprovalRule(db, serverId, toolName)) {
      return { status: "APPROVED", channel: "RULE" };
    }
  } catch {
    // A failure to read the rule table must not auto-approve. Fall through to
    // asking the human.
  }

  const approvalId = newApprovalId();

  // 2. Durable record of the request.
  await createPendingApproval(db, {
    id: approvalId,
    timestamp: Date.now(),
    server_id: serverId,
    tool_name: toolName,
    arguments: argumentsJson,
    status: "PENDING",
  });

  try {
    // 3. Push channel.
    const viaIpc = await askApprovalViaIpc(
      dbPath,
      { id: approvalId, serverId, toolName, arguments: argumentsJson },
      timeoutMs
    );
    if (viaIpc !== null) {
      return { status: viaIpc, channel: "IPC" };
    }

    // 4. Pull fallback.
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const row = await getPendingApproval(db, approvalId);
      if (!row) {
        // Row vanished — treat as denied. Something removed it without deciding,
        // and guessing "allow" here would be the wrong default.
        return { status: "DENIED", channel: "POLL" };
      }
      if (row.status === "APPROVED") return { status: "APPROVED", channel: "POLL" };
      if (row.status === "DENIED") return { status: "DENIED", channel: "POLL" };
      await sleep(POLL_INTERVAL_MS);
    }

    // 5. Nobody answered.
    return { status: "TIMEOUT", channel: "TIMEOUT" };
  } finally {
    try {
      await deleteApproval(db, approvalId);
    } catch {
      /* best effort cleanup */
    }
  }
}

/**
 * Collision-resistant approval id.
 *
 * The original used `Date.now() + Math.random() * 1000`, which has a real
 * collision chance when several tool calls are gated in the same millisecond —
 * and an id collision means one call could consume another's decision.
 */
function newApprovalId(): string {
  const rand = Math.random().toString(36).slice(2, 10);
  const rand2 = Math.random().toString(36).slice(2, 10);
  return `approval_${Date.now().toString(36)}_${rand}${rand2}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Human-readable reason for a non-approval, used in audit entries and errors. */
export function denialReason(status: "DENIED" | "TIMEOUT", timeoutMs: number): string {
  return status === "TIMEOUT"
    ? `Request timed out waiting for developer approval (${Math.round(timeoutMs / 1000)}s limit).`
    : "Rejected manually by developer.";
}
