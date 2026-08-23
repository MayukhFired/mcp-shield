/**
 * MCP Shield — VS Code Extension Host
 * ===================================
 *
 * Responsibilities, in order of importance:
 *
 *   1. Own the SQLite database that the out-of-process proxies read policy from
 *      and write audit records to.
 *   2. Run the IPC server that answers approval requests from those proxies.
 *   3. Discover MCP client configuration files and rewrite them to insert or
 *      remove the shield.
 *   4. Supervise HTTP proxy child processes (stdio proxies are spawned by the
 *      MCP client itself, so they need no supervision here).
 *   5. Render the dashboard.
 *
 * The extension is *not* in the data path for stdio servers. That is deliberate:
 * if VS Code is closed, a shielded stdio server still gets policy enforcement,
 * because the proxy reads the same database directly. What is lost without
 * VS Code running is the interactive prompt — and in that case a gated call
 * fails closed after the approval timeout rather than being waved through.
 */

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import * as crypto from "crypto";
import { spawn, ChildProcess } from "child_process";
import {
  openDB,
  getAuditLogs,
  getWarnings,
  getAllPolicies,
  savePolicy,
  updateApprovalStatus,
  getActivePendingApprovals,
  saveApprovalRule,
  getApprovalRules,
  deleteApprovalRule,
  clearSessionApprovalRules,
  clearAllPendingApprovals,
} from "./database";
import { getSocketPath, ApprovalRequest, ApprovalResponse } from "./ipc";
import { getWebviewContent } from "./webview";

// ─────────────────────────────────────────────────────────────────────────────
// Module state
// ─────────────────────────────────────────────────────────────────────────────

let dbInstance: any = null;
let dbPathGlobal = "";
let approvalInterval: NodeJS.Timeout | null = null;
let ipcServer: net.Server | null = null;
let activeSocketPath: string | null = null;
let statusBarItem: vscode.StatusBarItem | null = null;
let treeProvider: ShieldTreeProvider | null = null;
let outputChannel: vscode.OutputChannel | null = null;

/**
 * Approval ids currently showing a modal, so the same request is not prompted
 * twice by the IPC handler and the polling fallback simultaneously.
 */
const activePrompts = new Set<string>();

/** Running HTTP proxy children, keyed by `${configPath}::${serverId}`. */
const httpProxies = new Map<string, ChildProcess>();

/**
 * How long a pending row must sit unclaimed before the polling fallback offers
 * it to the user.
 *
 * This fixes a race in the original design. Both the IPC handler and a 1-second
 * poller raised the same modal; whichever won inserted the id into
 * `activePrompts`, and if the poller won, the IPC handler returned early
 * *without writing a socket response*. The proxy then waited out its full
 * 90-second timeout even though the user had already clicked Allow. Giving IPC a
 * head start means the push path handles everything it can, and polling only
 * picks up genuinely orphaned rows.
 */
const POLL_GRACE_MS = 2500;

// ─────────────────────────────────────────────────────────────────────────────
// Activation
// ─────────────────────────────────────────────────────────────────────────────

export async function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("MCP Shield");
  context.subscriptions.push(outputChannel);

  const dbPath = getDatabasePath(context);
  dbPathGlobal = dbPath;

  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  try {
    dbInstance = await openDB(dbPath);
    // Session-scoped approvals must not survive a window reload, or "allow for
    // this session" would quietly become "allow forever".
    await clearSessionApprovalRules(dbInstance);
    // Any pending row here is a leftover from a proxy that died mid-prompt.
    await clearAllPendingApprovals(dbInstance);
    startIpcServer(dbPath, dbInstance);
  } catch (err: any) {
    vscode.window.showErrorMessage(
      `MCP Shield: failed to initialize the policy database: ${err.message}`
    );
    return;
  }

  log(`Database: ${dbPath}`);
  log(`IPC channel: ${getSocketPath(dbPath)}`);

  // ── Commands ─────────────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("mcp-shield.openDashboard", () => {
      DashboardPanel.createOrShow(context, dbPath);
    }),
    vscode.commands.registerCommand("mcp-shield.scanConfigs", async () => {
      const configs = scanMcpConfigs(context);
      const serverCount = configs.reduce((n, c) => n + c.servers.length, 0);
      const shieldedCount = configs.reduce(
        (n, c) => n + c.servers.filter((s) => s.isShielded).length,
        0
      );
      vscode.window.showInformationMessage(
        `MCP Shield: found ${configs.length} config file(s), ${serverCount} server(s), ${shieldedCount} shielded.`
      );
      treeProvider?.refresh();
      DashboardPanel.createOrShow(context, dbPath);
    }),
    vscode.commands.registerCommand("mcp-shield.runAttackDemo", () =>
      runAttackDemo(context, dbPath)
    ),
    vscode.commands.registerCommand("mcp-shield.revokeAllRules", async () => {
      const rules = await getApprovalRules(dbInstance);
      for (const rule of rules) {
        await deleteApprovalRule(dbInstance, rule.server_id, rule.tool_name);
      }
      vscode.window.showInformationMessage(
        `MCP Shield: revoked ${rules.length} standing approval rule(s).`
      );
    })
  );

  // ── Tree view ────────────────────────────────────────────────────────────
  treeProvider = new ShieldTreeProvider(context);
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("mcp-shield-sidebar", treeProvider)
  );

  // ── Status bar ───────────────────────────────────────────────────────────
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = "mcp-shield.openDashboard";
  context.subscriptions.push(statusBarItem);
  updateStatusBar(context);
  statusBarItem.show();

  // ── Approval fallback poll ───────────────────────────────────────────────
  approvalInterval = setInterval(() => {
    if (dbInstance) void pollPendingApprovals(dbInstance);
  }, 1000);

  // ── Restore HTTP proxies for already-shielded servers ────────────────────
  // Unlike stdio, nothing else starts these: the MCP client only knows a URL.
  setTimeout(() => {
    const configs = scanMcpConfigs(context);
    for (const config of configs) {
      for (const server of config.servers) {
        if (server.transport === "http" && server.isShielded && server.proxyPort && server.url) {
          startHttpProxy(context, config.path, server.id, server.url, server.proxyPort);
        }
      }
    }
    updateStatusBar(context);
    treeProvider?.refresh();
  }, 1500);
}

export function deactivate() {
  if (approvalInterval) clearInterval(approvalInterval);
  if (ipcServer) ipcServer.close();

  for (const [key, child] of httpProxies) {
    try {
      child.kill();
    } catch {
      /* already gone */
    }
    httpProxies.delete(key);
  }

  // Unix sockets leave a filesystem entry behind; Windows named pipes do not.
  if (activeSocketPath && process.platform !== "win32" && fs.existsSync(activeSocketPath)) {
    try {
      fs.unlinkSync(activeSocketPath);
    } catch {
      /* best effort */
    }
  }
}

function log(message: string) {
  outputChannel?.appendLine(`[${new Date().toISOString()}] ${message}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// IPC server (answers approval requests from proxy processes)
// ─────────────────────────────────────────────────────────────────────────────

function startIpcServer(dbPath: string, db: any) {
  const socketPath = getSocketPath(dbPath);
  activeSocketPath = socketPath;

  // A stale socket file from a crashed window would make listen() fail with
  // EADDRINUSE, so clear it first. Windows named pipes are cleaned up by the OS.
  if (process.platform !== "win32" && fs.existsSync(socketPath)) {
    try {
      fs.unlinkSync(socketPath);
    } catch {
      /* fall through to the listen error handler */
    }
  }

  ipcServer = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (!line) continue;
        try {
          const req = JSON.parse(line) as ApprovalRequest;
          void handleIpcApprovalRequest(req, socket, db);
        } catch (err) {
          log(`IPC: malformed request frame ignored: ${err}`);
        }
      }
    });

    socket.on("error", (err) => log(`IPC socket error: ${err.message}`));
  });

  ipcServer.listen(socketPath, () => log("IPC server listening"));
  ipcServer.on("error", (err) => {
    log(`IPC server error: ${err.message}`);
    vscode.window.showWarningMessage(
      "MCP Shield: could not open the approval channel. Gated tool calls will fall back to slower database polling."
    );
  });
}

/**
 * Prompt the developer and answer the proxy over the socket.
 *
 * Critically, this *always* writes a response — including when the request is a
 * duplicate. The original returned early on a duplicate id without replying,
 * leaving the proxy to wait out its 90-second timeout.
 */
async function handleIpcApprovalRequest(req: ApprovalRequest, socket: net.Socket, db: any) {
  const respond = (status: "APPROVED" | "DENIED") => {
    const res: ApprovalResponse = { id: req.id, status };
    try {
      if (!socket.destroyed) socket.write(JSON.stringify(res) + "\n");
    } catch (err) {
      log(`IPC: failed to write response: ${err}`);
    }
  };

  if (activePrompts.has(req.id)) {
    // Already being handled elsewhere; do not raise a second modal, but do not
    // leave the caller hanging either.
    return;
  }
  activePrompts.add(req.id);

  try {
    const decision = await promptForApproval({
      serverId: req.serverId,
      toolName: req.toolName,
      argumentsJson: req.arguments,
    });

    if (decision.status === "APPROVED" && decision.remember) {
      await saveApprovalRule(
        db,
        req.serverId,
        req.toolName,
        decision.remember,
        decision.remember === "SESSION" ? SESSION_RULE_TTL_MS : 0
      );
    }

    await updateApprovalStatus(db, req.id, decision.status).catch(() => undefined);
    respond(decision.status);
  } catch (err: any) {
    log(`Approval handling failed, denying: ${err?.message ?? err}`);
    // Fail closed on an internal error.
    respond("DENIED");
  } finally {
    activePrompts.delete(req.id);
  }
}

/** Session rules last two hours, long enough for a work session. */
const SESSION_RULE_TTL_MS = 2 * 60 * 60 * 1000;

interface ApprovalDecision {
  status: "APPROVED" | "DENIED";
  /** Set when the user asked not to be prompted for this tool again. */
  remember?: "ALWAYS" | "SESSION";
}

/**
 * Show the authorization modal.
 *
 * The "Allow" / "Allow for Session" / "Always Allow" spread exists to solve a
 * real security problem, not just an annoyance. When the only options are
 * approve-every-time or disable protection, users disable protection. Offering a
 * *scoped* standing approval — one tool, one server, optionally time-limited —
 * removes the incentive to loosen the whole policy.
 *
 * Dismissing the dialog counts as DENIED. An unattended machine must not become
 * an open door.
 */
async function promptForApproval(req: {
  serverId: string;
  toolName: string;
  argumentsJson: string;
}): Promise<ApprovalDecision> {
  let formattedArgs: string;
  try {
    formattedArgs = JSON.stringify(JSON.parse(req.argumentsJson), null, 2);
  } catch {
    formattedArgs = req.argumentsJson;
  }

  // Keep the dialog readable; the dashboard has the full payload.
  if (formattedArgs.length > 1500) {
    formattedArgs = formattedArgs.slice(0, 1500) + "\n… (truncated, see dashboard)";
  }

  const detail =
    `Server: ${req.serverId}\n` +
    `Tool: ${req.toolName}\n\n` +
    `Arguments:\n${formattedArgs}\n\n` +
    `This tool passed automated policy checks and needs your authorization.`;

  const selection = await vscode.window.showWarningMessage(
    "MCP Shield — Authorization Required",
    { modal: true, detail },
    "Allow Once",
    "Allow for Session",
    "Always Allow"
  );

  switch (selection) {
    case "Allow Once":
      vscode.window.setStatusBarMessage("$(check) MCP Shield: tool call allowed", 3000);
      return { status: "APPROVED" };
    case "Allow for Session":
      vscode.window.setStatusBarMessage(
        `$(check) MCP Shield: '${req.toolName}' allowed for this session`,
        4000
      );
      return { status: "APPROVED", remember: "SESSION" };
    case "Always Allow":
      vscode.window.setStatusBarMessage(
        `$(check) MCP Shield: '${req.toolName}' always allowed — revoke from the dashboard`,
        5000
      );
      return { status: "APPROVED", remember: "ALWAYS" };
    default:
      // Includes Cancel and dialog dismissal.
      vscode.window.setStatusBarMessage("$(x) MCP Shield: tool call blocked", 3000);
      return { status: "DENIED" };
  }
}

/**
 * Fallback path: offer approvals that the IPC channel did not claim.
 *
 * Only rows older than POLL_GRACE_MS are considered, so this never competes with
 * the push channel for a live request.
 */
async function pollPendingApprovals(db: any) {
  try {
    const pending = await getActivePendingApprovals(db);
    const now = Date.now();

    for (const approval of pending) {
      if (activePrompts.has(approval.id)) continue;
      if (now - approval.timestamp < POLL_GRACE_MS) continue;

      activePrompts.add(approval.id);
      void (async () => {
        try {
          const decision = await promptForApproval({
            serverId: approval.server_id,
            toolName: approval.tool_name,
            argumentsJson: approval.arguments,
          });
          if (decision.status === "APPROVED" && decision.remember) {
            await saveApprovalRule(
              db,
              approval.server_id,
              approval.tool_name,
              decision.remember,
              decision.remember === "SESSION" ? SESSION_RULE_TTL_MS : 0
            );
          }
          await updateApprovalStatus(db, approval.id, decision.status);
        } catch (err: any) {
          log(`Fallback approval failed: ${err?.message ?? err}`);
        } finally {
          activePrompts.delete(approval.id);
        }
      })();
    }
  } catch {
    // The proxy may be mid-write; a failed poll is retried in one second.
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database location
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve where the policy database lives.
 *
 * Defaults to the extension's global storage, NOT the workspace root.
 *
 * The original defaulted to `<workspaceRoot>/mcp-shield.db`, which caused two
 * problems. It scattered audit databases into unrelated projects, and — worse —
 * the absolute path gets baked into the MCP client's config at shield time. Open
 * a different folder in VS Code and the extension would open a *different*
 * database with a *different* IPC pipe hash, so approval prompts silently stopped
 * appearing until every gated call timed out.
 *
 * Global storage gives one database, one IPC channel, and policies that follow
 * the user rather than the folder. A workspace-local file is still available by
 * setting `mcpShield.databasePath` explicitly.
 */
function getDatabasePath(context: vscode.ExtensionContext): string {
  const configured = vscode.workspace.getConfiguration("mcpShield").get<string>("databasePath");

  if (configured && configured.trim() !== "") {
    if (path.isAbsolute(configured)) return configured;
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceRoot) return path.resolve(workspaceRoot, configured);
  }

  return path.join(context.globalStorageUri.fsPath, "mcp-shield.db");
}
