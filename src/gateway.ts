/**
 * MCP Shield — stdio Gateway Proxy
 * ================================
 *
 * A transparent man-in-the-middle for the MCP stdio transport. This file is only
 * the transport adapter: framing, process management, and moving bytes. Every
 * security decision lives in `policy.ts`, and every action taken on that
 * decision lives in `interceptor.ts`.
 *
 * How it gets invoked
 * -------------------
 * The extension rewrites the MCP client's config so that instead of launching
 *
 *     command: "uvx", args: ["some-mcp-server"]
 *
 * the client launches
 *
 *     command: "node",
 *     args: [gateway.js, --server <id>, --db <path>, "--", "uvx", "some-mcp-server"]
 *
 * So the *client* spawns this proxy, and this proxy spawns the real server. Two
 * consequences worth being able to explain:
 *
 *   1. We inherit the client's process lifecycle management — no daemon to
 *      supervise, no orphaned processes, and the proxy dies with the client.
 *   2. We sit on the only channel the client and server share. There is no path
 *      around us short of editing the config back, which is itself visible in
 *      the dashboard.
 *
 * Data flow
 * ---------
 *     client stdin  → handleClientMessage → interceptor → child stdin
 *     child stdout  → handleServerMessage → interceptor → client stdout
 *
 * Both directions are newline-delimited JSON-RPC. stderr is inherited so the
 * target server's diagnostics still reach the client.
 *
 * INVARIANT: nothing is written to stdout except well-formed JSON-RPC. A stray
 * `console.log` corrupts the protocol stream, which is why every diagnostic in
 * this file uses `console.error`.
 */

import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import { openDB } from "./database";
import {
  screenRequest,
  screenBatch,
  applyToolListScan,
  inspectResponse,
  recordResponse,
  blockedError,
  type InterceptContext,
  type OutstandingRequest,
} from "./interceptor";

// ─────────────────────────────────────────────────────────────────────────────
// Command line
// ─────────────────────────────────────────────────────────────────────────────
// node gateway.js --server git --db ./mcp-shield.db -- git-mcp-server --repo .

const args = process.argv.slice(2);
let serverId = "unknown-server";
let dbPath = "mcp-shield.db";
const separatorIndex = args.indexOf("--");

// Parse only our own flags: everything before "--". Anything after belongs to the
// target server and must pass through untouched, including flags we also use.
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

/**
 * Only run as a proxy when executed directly, not when imported.
 *
 * This must NOT be inferred from the environment. The previous version used
 * `process.env.JEST_WORKER_ID !== undefined`, but spawned children inherit their
 * parent's environment — so a gateway launched from inside a Jest process saw
 * JEST_WORKER_ID, concluded it was "under test", skipped `start()` entirely and
 * exited 0. That made genuine end-to-end testing impossible, and it would equally
 * break any user whose environment happened to carry that variable.
 *
 * `require.main === module` asks the only question that actually matters: am I the
 * entry point, or is someone importing me?
 */
const isEntryPoint = typeof require !== "undefined" && require.main === module;

if (!targetCmd && isEntryPoint) {
  console.error("Error: Target command not specified. Use '-- <command> [args...]'");
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Process state
// ─────────────────────────────────────────────────────────────────────────────

let child: ChildProcess | null = null;
let ctx: InterceptContext | null = null;

/**
 * In-flight client requests, keyed by JSON-RPC id.
 *
 * We need the method to interpret the response — only a tools/list response
 * should go through the tool scanner — and we keep the audit row id plus a start
 * timestamp so the response body and its latency can be written back to the same
 * row. Without this correlation the audit log's `response` and `duration_ms`
 * columns stayed permanently empty.
 */
const outstandingRequests = new Map<string | number, OutstandingRequest>();

/** Bounds memory if a server never answers some requests. */
const MAX_OUTSTANDING = 1000;

async function start() {
  try {
    const absoluteDbPath = path.isAbsolute(dbPath)
      ? dbPath
      : path.resolve(process.cwd(), dbPath);

    const db = await openDB(absoluteDbPath);
    ctx = { db, dbPath: absoluteDbPath, serverId };

    // shell: false is essential. Under shell: true a target command or argument
    // containing shell metacharacters would be interpreted by the shell, making
    // the proxy itself the command-injection vector it exists to prevent.
    child = spawn(targetCmd!, targetArgs, {
      stdio: ["pipe", "pipe", "inherit"],
      shell: false,
    });

    child.on("error", (err) => {
      console.error(`[MCP Shield] Failed to start target server: ${err.message}`);
      process.exit(1);
    });

    child.on("exit", (code) => process.exit(code || 0));

    setupLineReader(process.stdin, handleClientMessage);
    setupLineReader(child.stdout!, handleServerMessage);
  } catch (err: any) {
    // Fail closed: without the policy database we cannot enforce anything, so we
    // refuse to proxy rather than quietly passing traffic through unchecked.
    console.error(`[MCP Shield] Initialization error: ${err.message}`);
    process.exit(1);
  }
}

/**
 * Split a stream into newline-delimited frames.
 *
 * Deliberate concurrency choice: handlers are dispatched without awaiting the
 * previous one. A gated tool call can block for up to 90 seconds waiting for a
 * human, and serializing would stall every other message behind it — including
 * the client's own cancellation notifications. JSON-RPC carries request ids
 * precisely so responses may arrive out of order, so interleaving is
 * protocol-safe. Errors are caught per frame so one bad message cannot take down
 * the proxy with an unhandled rejection.
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

function rememberRequest(id: string | number, entry: OutstandingRequest) {
  if (outstandingRequests.size >= MAX_OUTSTANDING) {
    // Drop the oldest tracked request rather than leaking memory. Losing the
    // correlation only costs response enrichment, never enforcement.
    const oldest = outstandingRequests.keys().next().value;
    if (oldest !== undefined) outstandingRequests.delete(oldest);
  }
  outstandingRequests.set(id, entry);
}

// ─────────────────────────────────────────────────────────────────────────────
// Client → server
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Handles three frame shapes:
 *   - a single JSON-RPC object
 *   - a JSON-RPC batch (array), which the original forwarded unexamined because
 *     an array has no `.method` property — a total bypass of every policy rule
 *   - non-JSON, forwarded untouched so raw channels are not broken
 */
async function handleClientMessage(line: string): Promise<void> {
  if (!ctx) return;

  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    forwardToChild(line);
    return;
  }

  if (Array.isArray(msg)) {
    const { verdicts, blocked } = await screenBatch(ctx, msg);

    if (blocked) {
      // Whole-batch rejection. See screenBatch for why partial execution is not
      // an option.
      const responses = msg
        .filter((member: any) => member && member.id !== undefined)
        .map((member: any) =>
          blockedError(
            member.id,
            blocked.code,
            `Batch rejected because one or more members violated policy: ${blocked.reason}`
          )
        );
      if (responses.length > 0) writeToClient(responses);
      return;
    }

    for (let i = 0; i < msg.length; i++) {
      const member = msg[i];
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

  const verdict = await screenRequest(ctx, msg);
  if (verdict.action === "BLOCK") {
    writeToClient(blockedError(msg.id ?? null, verdict.code, verdict.reason));
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

// ─────────────────────────────────────────────────────────────────────────────
// Server → client
// ─────────────────────────────────────────────────────────────────────────────

async function handleServerMessage(line: string): Promise<void> {
  if (!ctx) {
    process.stdout.write(line + "\n");
    return;
  }

  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stdout.write(line + "\n");
    return;
  }

  // Batches and notifications carry no id to correlate, so pass them straight on.
  if (Array.isArray(msg) || msg.id === undefined) {
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
      msg.result.tools = await applyToolListScan(ctx, msg.result.tools);
      const serialized = JSON.stringify(msg);
      await recordResponse(ctx, pending, serialized);
      process.stdout.write(serialized + "\n");
      return;
    }

    if ((pending.method === "tools/call" || pending.method === "resources/read") && msg.result) {
      const mutated = await inspectResponse(ctx, msg, pending.method, line);
      const serialized = mutated ? JSON.stringify(msg) : line;
      await recordResponse(ctx, pending, serialized);
      process.stdout.write(serialized + "\n");
      return;
    }

    await recordResponse(ctx, pending, line);
    process.stdout.write(line + "\n");
  } catch (err: any) {
    // Never drop a response because our own inspection failed: the client would
    // hang forever waiting on an id that will never be answered.
    console.error(`[MCP Shield] Response inspection failed: ${err?.message ?? err}`);
    process.stdout.write(line + "\n");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backwards-compatible re-exports
// ─────────────────────────────────────────────────────────────────────────────
// The policy engine now lives in policy.ts. These keep older import paths — and
// the original test suite — working against the new implementation.

export { evaluatePolicy, classifyToolCapabilities } from "./policy";
export { scanAndSanitizeTools } from "./compat";

if (isEntryPoint) {
  start();
}
