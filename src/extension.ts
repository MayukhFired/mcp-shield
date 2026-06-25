import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as net from "net";
import { getSocketPath, ApprovalRequest, ApprovalResponse } from "./ipc";
import {
  openDB,
  getPolicy,
  savePolicy,
  getAllPolicies,
  getAuditLogs,
  getWarnings,
  getActivePendingApprovals,
  updateApprovalStatus,
  Policy,
} from "./database";
import { getWebviewContent } from "./webview";

let dbInstance: any = null;
let approvalInterval: NodeJS.Timeout | null = null;
const activePrompts = new Set<string>();
let ipcServer: net.Server | null = null;
let activeSocketPath: string | null = null;

export async function activate(context: vscode.ExtensionContext) {
  console.log('MCP Shield extension is now active!');

  // Determine database path
  const dbPath = getDatabasePath(context);
  
  // Ensure the directory for the database exists
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  try {
    dbInstance = await openDB(dbPath);
    startIpcServer(dbPath, dbInstance);
  } catch (err: any) {
    vscode.window.showErrorMessage(`MCP Shield: Failed to initialize SQLite database: ${err.message}`);
    return;
  }

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("mcp-shield.openDashboard", () => {
      DashboardPanel.createOrShow(context.extensionUri, dbPath);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("mcp-shield.scanConfigs", async () => {
      const configs = scanMcpConfigs(context, dbPath);
      vscode.window.showInformationMessage(
        `MCP Shield scan complete. Found ${configs.length} MCP configurations.`
      );
      DashboardPanel.createOrShow(context.extensionUri, dbPath);
    })
  );

  // Status Bar Item
  const statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBarItem.command = "mcp-shield.openDashboard";
  statusBarItem.text = "$(shield) MCP Shield: Active";
  statusBarItem.tooltip = "Click to open MCP Shield Security Dashboard";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Start polling loop for pending approvals (gated tools)
  approvalInterval = setInterval(() => {
    if (dbInstance) {
      pollPendingApprovals(dbInstance);
    }
  }, 1000);

  // Auto-scan configurations on startup
  setTimeout(() => {
    scanMcpConfigs(context, dbPath);
  }, 3000);
}

export function deactivate() {
  if (approvalInterval) {
    clearInterval(approvalInterval);
  }
  if (ipcServer) {
    ipcServer.close();
  }
  if (activeSocketPath && process.platform !== "win32" && fs.existsSync(activeSocketPath)) {
    try {
      fs.unlinkSync(activeSocketPath);
    } catch (e) {}
  }
}

function startIpcServer(dbPath: string, db: any) {
  const socketPath = getSocketPath(dbPath);
  activeSocketPath = socketPath;

  // If Unix socket, remove existing file if it exists
  if (process.platform !== "win32" && fs.existsSync(socketPath)) {
    try {
      fs.unlinkSync(socketPath);
    } catch (e) {}
  }

  ipcServer = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", async (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (line) {
          try {
            const req = JSON.parse(line) as ApprovalRequest;
            await handleIpcApprovalRequest(req, socket, db);
          } catch (err) {
            console.error("[MCP Shield Extension IPC] Error parsing request:", err);
          }
        }
      }
    });

    socket.on("error", (err) => {
      console.error("[MCP Shield Extension IPC] Socket error:", err);
    });
  });

  ipcServer.listen(socketPath, () => {
    console.log(`[MCP Shield Extension IPC] Server listening on ${socketPath}`);
  });

  ipcServer.on("error", (err) => {
    console.error("[MCP Shield Extension IPC] Server error:", err);
  });
}

async function handleIpcApprovalRequest(req: ApprovalRequest, socket: net.Socket, db: any) {
  if (activePrompts.has(req.id)) {
    return;
  }

  activePrompts.add(req.id);

  let formattedArgs = "";
  try {
    formattedArgs = JSON.stringify(JSON.parse(req.arguments), null, 2);
  } catch {
    formattedArgs = req.arguments;
  }

  const detailMessage = `Server: ${req.serverId}\nTool: ${req.toolName}\n\nArguments:\n${formattedArgs}\n\nChoose 'Allow' to run this tool call, or 'Block' to prevent execution.`;

  vscode.window
    .showWarningMessage(
      `[MCP Shield Gating] Authorization Required`,
      {
        modal: true,
        detail: detailMessage,
      },
      "Allow",
      "Block"
    )
    .then(async (selection) => {
      let status: "APPROVED" | "DENIED" = "DENIED";
      try {
        if (selection === "Allow") {
          status = "APPROVED";
          await updateApprovalStatus(db, req.id, "APPROVED");
          vscode.window.setStatusBarMessage(`$(check) MCP Shield: Tool call allowed`, 3000);
        } else {
          status = "DENIED";
          await updateApprovalStatus(db, req.id, "DENIED");
          vscode.window.setStatusBarMessage(`$(x) MCP Shield: Tool call blocked`, 3000);
        }
      } catch (err: any) {
        console.error(`Failed to update approval status: ${err.message}`);
      } finally {
        activePrompts.delete(req.id);
        const res: ApprovalResponse = { id: req.id, status };
        try {
          socket.write(JSON.stringify(res) + "\n");
        } catch (err) {
          console.error("Failed to write IPC response back to gateway socket:", err);
        }
      }
    });
}

// Determines the SQLite database path
function getDatabasePath(context: vscode.ExtensionContext): string {
  const config = vscode.workspace.getConfiguration("mcpShield");
  const customPath = config.get<string>("databasePath");

  if (customPath) {
    if (path.isAbsolute(customPath)) {
      return customPath;
    }
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceRoot) {
      return path.resolve(workspaceRoot, customPath);
    }
  }

  // Default to workspace root if open
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (workspaceRoot) {
    return path.join(workspaceRoot, "mcp-shield.db");
  }

  // Default to global storage
  return path.join(context.globalStorageUri.fsPath, "mcp-shield.db");
}

// Poll pending approvals in SQLite database and show detailed modal confirmation
async function pollPendingApprovals(db: any) {
  try {
    const pending = await getActivePendingApprovals(db);
    for (const app of pending) {
      if (activePrompts.has(app.id)) {
        continue;
      }

      activePrompts.add(app.id);

      let formattedArgs = "";
      try {
        formattedArgs = JSON.stringify(JSON.parse(app.arguments), null, 2);
      } catch {
        formattedArgs = app.arguments;
      }

      // Display Modal for Explainability & explicit Least Privilege authorization
      const detailMessage = `Server: ${app.server_id}\nTool: ${app.tool_name}\n\nArguments:\n${formattedArgs}\n\nChoose 'Allow' to run this tool call, or 'Block' to prevent execution.`;

      vscode.window
        .showWarningMessage(
          `[MCP Shield Gating] Authorization Required`,
          {
            modal: true,
            detail: detailMessage,
          },
          "Allow",
          "Block"
        )
        .then(async (selection) => {
          try {
            if (selection === "Allow") {
              await updateApprovalStatus(db, app.id, "APPROVED");
              vscode.window.setStatusBarMessage(`$(check) MCP Shield: Tool call allowed`, 3000);
            } else {
              await updateApprovalStatus(db, app.id, "DENIED");
              vscode.window.setStatusBarMessage(`$(x) MCP Shield: Tool call blocked`, 3000);
            }
          } catch (err: any) {
            console.error(`Failed to update approval status: ${err.message}`);
          } finally {
            activePrompts.delete(app.id);
          }
        });
    }
  } catch (err) {
    // Suppress polling errors
  }
}

// Scans typical path locations for MCP configurations
export interface DetectedConfig {
  name: string;
  path: string;
  servers: {
    id: string;
    transport: "stdio" | "http";
    command: string;
    args: string[];
    url?: string;
    proxyPort?: number;
    isShielded: boolean;
  }[];
}

export function scanMcpConfigs(
  context: vscode.ExtensionContext,
  dbPath: string
): DetectedConfig[] {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const appData = process.env.APPDATA || "";
  
  const scanPaths = [
    {
      name: "Claude Desktop",
      path:
        process.platform === "win32"
          ? path.join(appData, "Claude", "claude_desktop_config.json")
          : process.platform === "darwin"
          ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
          : path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    },
    {
      name: "Cline Settings",
      path:
        process.platform === "win32"
          ? path.join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
          : process.platform === "darwin"
          ? path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
          : path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
    },
    {
      name: "Roo Code Settings",
      path:
        process.platform === "win32"
          ? path.join(appData, "Code", "User", "globalStorage", "roodesignertoken.roo-cline", "settings", "cline_mcp_settings.json")
          : process.platform === "darwin"
          ? path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "roodesignertoken.roo-cline", "settings", "cline_mcp_settings.json")
          : path.join(home, ".config", "Code", "User", "globalStorage", "roodesignertoken.roo-cline", "settings", "cline_mcp_settings.json"),
    }
  ];

  const results: DetectedConfig[] = [];
  const gatewayPath = path.join(context.extensionPath, "dist", "gateway.js");
  const gatewayHttpPath = path.join(context.extensionPath, "dist", "gateway-http.js");

  for (const config of scanPaths) {
    if (fs.existsSync(config.path)) {
      try {
        const rawContent = fs.readFileSync(config.path, "utf8");
        const parsed = JSON.parse(rawContent);
        const servers = parsed.mcpServers || {};
        const detectedServers = [];

        for (const serverId in servers) {
          const s = servers[serverId];

          // ── HTTP / SSE Transport ──────────────────────────────────────────
          if (s.url) {
            // Detect if HTTP server is already shielded (url points to localhost proxy)
            let isShielded = false;
            let originalUrl: string = s.url;
            let proxyPort: number | undefined;

            try {
              const parsedUrl = new URL(s.url);
              if (
                (parsedUrl.hostname === "localhost" || parsedUrl.hostname === "127.0.0.1") &&
                s._mcpShieldUpstream
              ) {
                isShielded = true;
                originalUrl = s._mcpShieldUpstream;
                proxyPort = parseInt(parsedUrl.port, 10);
              }
            } catch (_) {}

            detectedServers.push({
              id: serverId,
              transport: "http" as const,
              command: "",
              args: [],
              url: originalUrl,
              proxyPort,
              isShielded,
            });
            continue;
          }

          // ── STDIO Transport ───────────────────────────────────────────────
          const argsList: string[] = s.args || [];
          let isShielded = false;
          let originalCommand = s.command;
          let originalArgs = [...argsList];

          if (
            s.command === "node" &&
            argsList.length > 0 &&
            argsList[0].includes("gateway.js")
          ) {
            isShielded = true;
            const separatorIdx = argsList.indexOf("--");
            if (separatorIdx !== -1 && separatorIdx + 1 < argsList.length) {
              originalCommand = argsList[separatorIdx + 1];
              originalArgs = argsList.slice(separatorIdx + 2);
            }
          }

          detectedServers.push({
            id: serverId,
            transport: "stdio" as const,
            command: originalCommand,
            args: originalArgs,
            isShielded,
          });
        }

        results.push({
          name: config.name,
          path: config.path,
          servers: detectedServers,
        });
      } catch (err) {
        console.error(`Failed to parse config at ${config.path}:`, err);
      }
    }
  }

  return results;
}

// Allocates an unused local TCP port for the HTTP proxy
function allocateProxyPort(basePort: number = 3100): number {
  // Simple incrementing allocator — scan existing shields to avoid collision
  return basePort + Math.floor(Math.random() * 900);
}

// Performs the Shielding process by rewriting the target MCP configuration
function toggleShieldServer(
  context: vscode.ExtensionContext,
  configPath: string,
  serverId: string,
  shield: boolean,
  dbPath: string,
  serverTransport: "stdio" | "http" = "stdio"
): boolean {
  if (!fs.existsSync(configPath)) return false;

  try {
    const rawContent = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(rawContent);
    const servers = parsed.mcpServers || {};

    if (!servers[serverId]) return false;

    const s = servers[serverId];

    // Create a backup file before editing configuration
    fs.writeFileSync(`${configPath}.bak`, rawContent, "utf8");

    // ── HTTP Transport ────────────────────────────────────────────────────
    if (serverTransport === "http" || s.url) {
      const gatewayHttpPath = path.join(context.extensionPath, "dist", "gateway-http.js");

      if (shield) {
        if (s._mcpShieldUpstream) {
          return true; // Already shielded
        }
        const proxyPort = allocateProxyPort();
        const originalUrl: string = s.url;
        // Rewrite the url to point to the local HTTP proxy
        s._mcpShieldUpstream = originalUrl;
        s._mcpShieldProxyPort = proxyPort;
        s.url = `http://localhost:${proxyPort}`;
        // Inject a launcher entry so the proxy process starts with the client
        s._mcpShieldHttpLauncher = [
          "node",
          gatewayHttpPath,
          "--server", serverId,
          "--db", dbPath,
          "--upstream", originalUrl,
          "--port", String(proxyPort),
        ];
      } else {
        // Unshield: restore original URL
        if (s._mcpShieldUpstream) {
          s.url = s._mcpShieldUpstream;
          delete s._mcpShieldUpstream;
          delete s._mcpShieldProxyPort;
          delete s._mcpShieldHttpLauncher;
        }
      }

      fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), "utf8");
      return true;
    }

    // ── STDIO Transport ───────────────────────────────────────────────────
    const gatewayPath = path.join(context.extensionPath, "dist", "gateway.js");

    if (shield) {
      // Shield: Wrap with gateway.js
      if (s.command === "node" && s.args && s.args[0].includes("gateway.js")) {
        return true; // Already shielded
      }

      const originalCommand = s.command;
      const originalArgs = s.args || [];

      s.command = "node";
      s.args = [
        gatewayPath,
        "--server",
        serverId,
        "--db",
        dbPath,
        "--",
        originalCommand,
        ...originalArgs,
      ];
    } else {
      // Unshield: Restore original command
      if (s.command === "node" && s.args && s.args[0].includes("gateway.js")) {
        const argsList: string[] = s.args;
        const separatorIdx = argsList.indexOf("--");

        if (separatorIdx !== -1 && separatorIdx + 1 < argsList.length) {
          s.command = argsList[separatorIdx + 1];
          s.args = argsList.slice(separatorIdx + 2);
        }
      }
    }

    fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), "utf8");
    return true;
  } catch (err) {
    console.error(`Failed to toggle shield on ${serverId} in ${configPath}:`, err);
    return false;
  }
}

// Dashboard Webview Class
class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  public static readonly viewType = "mcpShieldDashboard";

  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private readonly _dbPath: string;
  private _disposables: vscode.Disposable[] = [];
  private _updateTimer: NodeJS.Timeout | null = null;

  public static createOrShow(extensionUri: vscode.Uri, dbPath: string) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

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
        localResourceRoots: [extensionUri],
      }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel, extensionUri, dbPath);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    extensionUri: vscode.Uri,
    dbPath: string
  ) {
    this._panel = panel;
    this._extensionUri = extensionUri;
    this._dbPath = dbPath;

    // Set HTML content
    this._updateHtml();

    // Handle panel disposal
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    // Handle messages from Webview
    this._panel.webview.onDidReceiveMessage(
      async (message) => {
        switch (message.command) {
          case "refresh":
            await this._sendDataToWebview();
            break;

          case "savePolicy":
            if (dbInstance) {
              await savePolicy(dbInstance, message.policy);
              vscode.window.showInformationMessage(
                `MCP Shield: Security policy updated for server '${message.policy.server_id}'.`
              );
              await this._sendDataToWebview();
            }
            break;

          case "toggleShield":
            const success = toggleShieldServer(
              { extensionPath: this._extensionUri.fsPath } as any,
              message.configPath,
              message.serverId,
              message.shield,
              this._dbPath
            );
            if (success) {
              vscode.window.showInformationMessage(
                `MCP Shield: Server '${message.serverId}' is now ${
                  message.shield ? "Shielded" : "Unshielded"
                }. Please restart your MCP client.`
              );
              await this._sendDataToWebview();
            } else {
              vscode.window.showErrorMessage(
                `MCP Shield: Failed to configure shield for server '${message.serverId}'.`
              );
            }
            break;
        }
      },
      null,
      this._disposables
    );

    // Initial data load
    this._sendDataToWebview();

    // Set up real-time polling updates for the dashboard
    this._updateTimer = setInterval(() => {
      this._sendDataToWebview();
    }, 2000);
  }

  private _updateHtml() {
    this._panel.webview.html = getWebviewContent();
  }

  private async _sendDataToWebview() {
    if (!dbInstance) return;

    try {
      const logs = await getAuditLogs(dbInstance, 100);
      const warnings = await getWarnings(dbInstance);
      const policies = await getAllPolicies(dbInstance);
      const detectedConfigs = scanMcpConfigs(
        { extensionPath: this._extensionUri.fsPath } as any,
        this._dbPath
      );

      this._panel.webview.postMessage({
        type: "updateData",
        logs,
        warnings,
        policies,
        configs: detectedConfigs,
      });
    } catch (err: any) {
      console.error("Failed to fetch dashboard data:", err);
    }
  }

  public dispose() {
    DashboardPanel.currentPanel = undefined;

    this._panel.dispose();

    if (this._updateTimer) {
      clearInterval(this._updateTimer);
    }

    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }
}
