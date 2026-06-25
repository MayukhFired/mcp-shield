import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import * as url from "url";
import * as net from "net";
import { getSocketPath, ApprovalRequest, ApprovalResponse } from "./ipc";
import {
  openDB,
  getPolicy,
  logAudit,
  logWarning,
  getPendingApproval,
  createPendingApproval,
  deleteApproval,
  saveToolCapabilities,
  getToolCapabilities,
  Policy,
} from "./database";

// Parse CLI Arguments
// Example command: node gateway.js --server git --db ./mcp-shield.db -- git-mcp-server args...
const args = process.argv.slice(2);
let serverId = "unknown-server";
let dbPath = "mcp-shield.db";
let separatorIndex = args.indexOf("--");

for (let i = 0; i < args.length && i < separatorIndex; i++) {
  if (args[i] === "--server" && i + 1 < separatorIndex) {
    serverId = args[i + 1];
    i++;
  } else if (args[i] === "--db" && i + 1 < separatorIndex) {
    dbPath = args[i + 1];
    i++;
  }
}

const targetCmd = separatorIndex !== -1 ? args[separatorIndex + 1] : null;
const targetArgs = separatorIndex !== -1 ? args.slice(separatorIndex + 2) : [];
const isTesting = process.env.JEST_WORKER_ID !== undefined;

if (!targetCmd && !isTesting) {
  console.error("Error: Target command not specified. Use '-- <command> [args...]'");
  process.exit(1);
}

// Global Variables
let db: any = null;
let child: ChildProcess | null = null;
const outstandingRequests = new Map<string | number, string>(); // id -> method

async function start() {
  try {
    // Resolve absolute path for SQLite DB
    const absoluteDbPath = path.isAbsolute(dbPath)
      ? dbPath
      : path.resolve(process.cwd(), dbPath);

    // Initialize database
    db = await openDB(absoluteDbPath);
    
    // Spawn Target MCP Server safely (without shell to prevent command injection)
    child = spawn(targetCmd!, targetArgs, {
      stdio: ["pipe", "pipe", "inherit"],
      shell: false,
    });

    child.on("error", (err) => {
      console.error(`[MCP Shield Proxy] Failed to start target server: ${err.message}`);
      process.exit(1);
    });

    child.on("exit", (code, signal) => {
      process.exit(code || 0);
    });

    // Intercept Stdin (Client -> Proxy -> Target Server)
    setupLineReader(process.stdin, async (line) => {
      await handleClientMessage(line);
    });

    // Intercept Stdout (Target Server -> Proxy -> Client)
    setupLineReader(child.stdout!, async (line) => {
      await handleServerMessage(line);
    });

  } catch (err: any) {
    console.error(`[MCP Shield Proxy] Initialization error: ${err.message}`);
    process.exit(1);
  }
}

// Stream splitter for newline-delimited JSON-RPC packets
function setupLineReader(
  stream: NodeJS.ReadableStream,
  onLine: (line: string) => Promise<void>
) {
  let buffer = "";
  stream.on("data", async (chunk) => {
    buffer += chunk.toString("utf8");
    let idx;
    while ((idx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.substring(0, idx);
      buffer = buffer.substring(idx + 1);
      await onLine(line.trim());
    }
  });
}

// Forward JSON-RPC error back to client
function sendErrorToClient(id: string | number | null, code: number, message: string) {
  const errorResponse = {
    jsonrpc: "2.0",
    id: id,
    error: {
      code: code,
      message: `Blocked by MCP Shield: ${message}`,
    },
  };
  process.stdout.write(JSON.stringify(errorResponse) + "\n");
}

// Policy Evaluation Engine
export async function evaluatePolicy(
  db: any,
  policy: Policy,
  toolName: string,
  toolArgs: any
): Promise<{ decision: "ALLOWED" | "BLOCKED"; reason: string }> {
  // 1. Check if the server is unshielded
  if (policy.status === "Unshielded") {
    return { decision: "ALLOWED", reason: "Server status is set to Unshielded." };
  }

  // 2. Check Permissive mode
  if (policy.mode === "Permissive") {
    return { decision: "ALLOWED", reason: "Policy mode is Permissive." };
  }

  // 3. Check Disabled Tools
  let disabledTools: string[] = [];
  try {
    disabledTools = JSON.parse(policy.disabled_tools);
  } catch {}
  if (disabledTools.includes(toolName)) {
    return { decision: "BLOCKED", reason: `Tool '${toolName}' is disabled in the security policy.` };
  }

  // 4. Check Read-Only Mode
  if (policy.readonly === 1) {
    const capabilities = await getToolCapabilities(db, policy.server_id, toolName);
    const hasWriteCapability = capabilities.includes("WRITE");

    const writeRegex =
      /write|delete|remove|update|create|execute|run|install|uninstall|post|put|patch|destroy|mkdir|rmdir|unlink/i;

    const isBlocked = capabilities.length > 0 ? hasWriteCapability : writeRegex.test(toolName);

    if (isBlocked) {
      return {
        decision: "BLOCKED",
        reason: `Write operations are blocked on this server. Tool '${toolName}' is classified as write-capable or matches read-only restriction pattern.`,
      };
    }
  }

  // Scan arguments recursively for path traversal, command injection, and network requests
  const argValues: string[] = [];
  function extractStringValues(obj: any) {
    if (typeof obj === "string") {
      argValues.push(obj);
    } else if (typeof obj === "object" && obj !== null) {
      for (const key in obj) {
        extractStringValues(obj[key]);
      }
    }
  }
  extractStringValues(toolArgs);

  // 5. Directory Traversal / Path Gating (Strict and Gated modes)
  let allowedPaths: string[] = [];
  try {
    allowedPaths = JSON.parse(policy.allowed_paths);
  } catch {}
  
  // Default to process.cwd() if allowedPaths is empty
  if (allowedPaths.length === 0) {
    allowedPaths = [process.cwd()];
  }

  const resolvedAllowedPaths = allowedPaths.map((p) => path.resolve(p));

  for (const val of argValues) {
    // Check for explicit traversal sequences
    if (val.includes("..") && (val.includes("/") || val.includes("\\"))) {
      return {
        decision: "BLOCKED",
        reason: `Potential path traversal attempt detected in arguments: "${val}"`,
      };
    }

    // Check absolute path containment if it looks like a path
    if (path.isAbsolute(val) || val.startsWith("/") || val.startsWith("\\") || /^[a-zA-Z]:\\/.test(val)) {
      const resolvedVal = path.resolve(val);
      const isContained = resolvedAllowedPaths.some((allowed) =>
        resolvedVal.startsWith(allowed)
      );
      if (!isContained) {
        return {
          decision: "BLOCKED",
          reason: `Access to path outside authorized directories is blocked: "${val}". Authorized directories: ${allowedPaths.join(", ")}`,
        };
      }
    }
  }

  // 6. Command Injection / Safety Gating
  const dangerousCommandChars = /[;&|`$<>]/;
  // If the tool name implies execution, check string arguments for metacharacters
  if (/run|execute|shell|cmd|terminal/i.test(toolName)) {
    for (const val of argValues) {
      if (dangerousCommandChars.test(val)) {
        return {
          decision: "BLOCKED",
          reason: `Dangerous shell metacharacter detected in command tool arguments: "${val}"`,
        };
      }
    }
  }

  // 7. Network Gating (URL scanning)
  let allowedDomains: string[] = [];
  try {
    allowedDomains = JSON.parse(policy.allowed_domains);
  } catch {}

  const urlRegex = /https?:\/\/[^\s"'()]+/g;
  for (const val of argValues) {
    const urls = val.match(urlRegex);
    if (urls) {
      for (const u of urls) {
        try {
          const parsed = new url.URL(u);
          const hostname = parsed.hostname;

          if (allowedDomains.length > 0) {
            const isDomainAllowed = allowedDomains.some((domain) => {
              if (domain.startsWith("*.")) {
                const suffix = domain.substring(2);
                return hostname === suffix || hostname.endsWith("." + suffix);
              }
              return hostname === domain;
            });

            if (!isDomainAllowed) {
              return {
                decision: "BLOCKED",
                reason: `External URL access blocked: "${u}". Domain '${hostname}' is not in the allowed list: ${allowedDomains.join(", ")}`,
              };
            }
          }
        } catch {
          // Invalid URL format, parse failure
          return {
            decision: "BLOCKED",
            reason: `Malformed URL pattern detected in arguments: "${u}"`,
          };
        }
      }
    }
  }

  return { decision: "ALLOWED", reason: "Passed all automated security rules." };
}

function askApprovalViaIpc(dbPath: string, req: ApprovalRequest): Promise<"APPROVED" | "DENIED" | null> {
  return new Promise((resolve) => {
    const socketPath = getSocketPath(dbPath);
    const client = net.connect(socketPath);

    client.on("connect", () => {
      client.write(JSON.stringify(req) + "\n");
    });

    let buffer = "";
    client.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.substring(0, idx).trim();
        buffer = buffer.substring(idx + 1);
        if (line) {
          try {
            const res = JSON.parse(line) as ApprovalResponse;
            if (res.id === req.id) {
              client.destroy();
              resolve(res.status);
              return;
            }
          } catch (e) {}
        }
      }
    });

    client.on("error", () => {
      resolve(null);
    });

    client.on("close", () => {
      resolve(null);
    });

    // Enforce gateway's own timeout (90s limit)
    setTimeout(() => {
      client.destroy();
      resolve(null);
    }, 90000);
  });
}

// Client Input Handler (Client -> Proxy -> Target Server)
async function handleClientMessage(line: string) {
  if (!line) return;

  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    // If not JSON-RPC, forward raw line to avoid breaking raw channels
    if (child && child.stdin) {
      child.stdin.write(line + "\n");
    }
    return;
  }

  // Track client requests to match response methods later
  if (msg.id !== undefined && msg.method) {
    outstandingRequests.set(msg.id, msg.method);
  }

  // Intercept tool calls
  if (msg.method === "tools/call") {
    const toolName = msg.params?.name;
    const toolArgs = msg.params?.arguments || {};
    const reqId = msg.id;

    // Fetch active policy
    const policy = await getPolicy(db, serverId);

    // Evaluate automated checks
    const evaluation = await evaluatePolicy(db, policy, toolName, toolArgs);

    if (evaluation.decision === "BLOCKED") {
      // 1. Audit Log Block Event
      await logAudit(db, {
        timestamp: Date.now(),
        server_id: serverId,
        tool_name: toolName,
        arguments: JSON.stringify(toolArgs),
        decision: "BLOCKED",
        reason: evaluation.reason,
      });

      // 2. Reject client request
      sendErrorToClient(reqId, -32000, evaluation.reason);
      return;
    }

    // Gated Interactive Confirmation mode
    if (policy.mode === "Gated") {
      const approvalId = `approval_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

      // Log the pending request to the SQLite database
      await createPendingApproval(db, {
        id: approvalId,
        timestamp: Date.now(),
        server_id: serverId,
        tool_name: toolName,
        arguments: JSON.stringify(toolArgs),
        status: "PENDING",
      });

      // Poll database for user's decision (timeout after 90 seconds)
      let userDecision: "APPROVED" | "DENIED" | "TIMEOUT" = "TIMEOUT";

      // Try IPC first
      const ipcResult = await askApprovalViaIpc(dbPath, {
        id: approvalId,
        serverId,
        toolName,
        arguments: JSON.stringify(toolArgs),
      });

      if (ipcResult !== null) {
        userDecision = ipcResult;
      } else {
        // Fallback to polling database for user's decision (timeout after 90 seconds)
        const pollStartTime = Date.now();
        const timeoutMs = 90000;

        while (Date.now() - pollStartTime < timeoutMs) {
          const approval = await getPendingApproval(db, approvalId);
          if (approval) {
            if (approval.status === "APPROVED") {
              userDecision = "APPROVED";
              break;
            } else if (approval.status === "DENIED") {
              userDecision = "DENIED";
              break;
            }
          } else {
            // If deleted, count as denied
            userDecision = "DENIED";
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 150));
        }
      }

      // Cleanup pending entry
      await deleteApproval(db, approvalId);

      if (userDecision === "APPROVED") {
        // Log event allowed by developer
        const auditId = await logAudit(db, {
          timestamp: Date.now(),
          server_id: serverId,
          tool_name: toolName,
          arguments: JSON.stringify(toolArgs),
          decision: "ALLOWED",
          reason: "Approved manually by developer.",
        });

        // Forward to real server
        if (child && child.stdin) {
          child.stdin.write(line + "\n");
        }
        return;
      } else {
        const blockReason =
          userDecision === "TIMEOUT"
            ? "Request timed out waiting for developer approval (90s limit)."
            : "Rejected manually by developer.";

        await logAudit(db, {
          timestamp: Date.now(),
          server_id: serverId,
          tool_name: toolName,
          arguments: JSON.stringify(toolArgs),
          decision: "BLOCKED",
          reason: blockReason,
        });

        sendErrorToClient(reqId, -32002, blockReason);
        return;
      }
    }

    // If allowed in strict/permissive mode, log and forward
    await logAudit(db, {
      timestamp: Date.now(),
      server_id: serverId,
      tool_name: toolName,
      arguments: JSON.stringify(toolArgs),
      decision: "ALLOWED",
      reason: evaluation.reason,
    });

    if (child && child.stdin) {
      child.stdin.write(line + "\n");
    }
    return;
  }

  // Forward all other requests
  if (child && child.stdin) {
    child.stdin.write(line + "\n");
  }
}

// Server Response Handler (Target Server -> Proxy -> Client)
async function handleServerMessage(line: string) {
  if (!line) return;

  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    // If not JSON, write directly to client
    process.stdout.write(line + "\n");
    return;
  }

  // Intercept responses to client requests
  if (msg.id !== undefined) {
    const requestMethod = outstandingRequests.get(msg.id);
    outstandingRequests.delete(msg.id);

    // Intercept response to tools/list to scan for security smells
    if (requestMethod === "tools/list" && msg.result && Array.isArray(msg.result.tools)) {
      const originalTools = msg.result.tools;
      const sanitizedTools = scanAndSanitizeTools(originalTools, serverId);
      
      // Replace the tools list with the sanitized version
      msg.result.tools = sanitizedTools;
      process.stdout.write(JSON.stringify(msg) + "\n");
      return;
    }

    // Payload Size Limit: Intercept tools/call responses that exceed the configured limit
    if (requestMethod === "tools/call" && msg.result) {
      const policy = await getPolicy(db, serverId);

      if (policy.max_payload_kb > 0) {
        const limitBytes = policy.max_payload_kb * 1024;
        const lineBytes = Buffer.byteLength(line, "utf8");

        if (lineBytes > limitBytes) {
          // Truncate text content blocks to fit within the limit
          if (msg.result.content && Array.isArray(msg.result.content)) {
            for (const block of msg.result.content) {
              if (block.type === "text" && typeof block.text === "string") {
                const textBytes = Buffer.byteLength(block.text, "utf8");
                if (textBytes > limitBytes) {
                  // Slice to approximate byte budget (UTF-8 safe via substring)
                  let truncated = block.text.substring(0, limitBytes);
                  truncated += `\n\n... [TRUNCATED BY MCP SHIELD: Payload exceeded ${policy.max_payload_kb} KB limit (${Math.round(textBytes / 1024)} KB received). Please use tools to read smaller chunks, or refine your search.]`;
                  block.text = truncated;
                }
              }
            }
          }

          // Log the truncation event as a security warning
          if (db) {
            logWarning(db, {
              timestamp: Date.now(),
              server_id: serverId,
              tool_name: `tools/call response (id: ${msg.id})`,
              smell_type: "SUSPICIOUS_SCHEMA",
              description: `Response payload exceeded configured limit of ${policy.max_payload_kb} KB.`,
              details: `Original size: ${Math.round(lineBytes / 1024)} KB. Limit: ${policy.max_payload_kb} KB. Response was automatically truncated to protect context window.`,
              sanitized: 1,
            }).catch((err) => {
              console.error(`[MCP Shield] Failed to log payload truncation warning: ${err.message}`);
            });
          }

          // Forward the truncated message
          process.stdout.write(JSON.stringify(msg) + "\n");
          return;
        }
      }
    }
  }

  // Forward all other messages unmodified
  process.stdout.write(line + "\n");
}

export function classifyToolCapabilities(tool: any): string[] {
  const capabilities: string[] = [];
  const name = (tool.name || "").toLowerCase();

  // Keywords indicating mutate / write capability
  const writeKeywords = [
    "write", "delete", "remove", "update", "create", "execute", "run",
    "install", "uninstall", "post", "put", "patch", "destroy", "mkdir",
    "rmdir", "unlink", "apply", "commit", "push", "save", "edit", "modify",
    "append", "set", "touch", "exec"
  ];

  // Keywords indicating read-only / query capability
  const readKeywords = [
    "read", "get", "list", "describe", "view", "show", "info", "query",
    "explain", "check", "scan", "search", "find", "status", "audit"
  ];

  // If name has write keywords
  let isWrite = writeKeywords.some(kw => name.includes(kw));

  // If it matches a write keyword, check if it's overridden by a read keyword in name
  if (isWrite) {
    const hasReadPrefix = readKeywords.some(kw => name.startsWith(kw));
    // If name starts with a read prefix, it's likely a read operation returning info
    if (hasReadPrefix && !name.includes("run") && !name.includes("exec")) {
      isWrite = false;
    }
  }

  // Also check inputSchema for clues
  if (tool.inputSchema && tool.inputSchema.properties) {
    const props = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());
    // If a tool takes "content", "text", "code", or "value" along with a path/file,
    // and is not named read_..., it is likely write-capable
    if ((props.includes("content") || props.includes("text") || props.includes("code") || props.includes("value")) &&
        !readKeywords.some(kw => name.includes(kw))) {
      isWrite = true;
    }
  }

  if (isWrite) {
    capabilities.push("WRITE");
  } else {
    capabilities.push("READ");
  }

  return capabilities;
}

// Scan tool definitions and sanitize prompt injections
export function scanAndSanitizeTools(tools: any[], serverId: string, testDb?: any): any[] {
  const activeDb = testDb || db;
  // Regex to detect hidden prompt injections or instruction overrides
  const injectionRegex =
    /(?:note\s+to\s+ai|ignore\s+previous|system\s+instruction|instead\s+of|always\s+read|secretly|covertly|you\s+must\s+first|before\s+doing|do\s+not\s+tell)[^.]*/gi;
  
  // Sensitive file path keywords in descriptions
  const sensitiveFileRegex =
    /(?:\.ssh|id_rsa|passwd|shadow|\.env|credentials|private_key|\.key|\.pem)/gi;

  return tools.map((tool) => {
    // Classify and save capabilities asynchronously
    const capabilities = classifyToolCapabilities(tool);
    if (activeDb) {
      saveToolCapabilities(activeDb, serverId, tool.name, capabilities).catch((err) => {
        console.error(`[MCP Shield] Failed to save tool capabilities to DB: ${err.message}`);
      });
    }

    let description = tool.description || "";
    let hasSmell = false;
    let details = "";
    let smellType: "PROMPT_INJECTION" | "PATH_TRAVERSAL" | "SUSPICIOUS_SCHEMA" = "PROMPT_INJECTION";

    // Scan for prompt injection instruction overrides
    const injectionMatches = description.match(injectionRegex);
    if (injectionMatches) {
      hasSmell = true;
      details += `Prompt injection patterns detected: "${injectionMatches.join(", ")}". `;
      description = description.replace(
         injectionRegex,
        "[Description redacted by MCP Shield for prompt injection safety]"
      );
    }

    // Scan for sensitive file paths in tool definitions
    const fileMatches = description.match(sensitiveFileRegex);
    if (fileMatches) {
      hasSmell = true;
      smellType = "PATH_TRAVERSAL";
      details += `Sensitive file references detected: "${fileMatches.join(", ")}". `;
    }

    if (hasSmell) {
      // Log warning to SQLite async if DB is active
      if (activeDb) {
        logWarning(activeDb, {
          timestamp: Date.now(),
          server_id: serverId,
          tool_name: tool.name,
          smell_type: smellType,
          description: tool.description || "",
          details: details.trim(),
          sanitized: 1,
        }).catch((err) => {
          // Console error goes to stderr so it does not pollute stdout JSON-RPC stream
          console.error(`[MCP Shield] Failed to log warning to DB: ${err.message}`);
        });
      }

      return {
        ...tool,
        description: description,
      };
    }

    return tool;
  });
}

// Start Proxy
if (!isTesting) {
  start();
}
