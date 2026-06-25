import * as http from "http";
import * as url from "url";
import * as net from "net";
import { getSocketPath, ApprovalRequest, ApprovalResponse } from "./ipc";
import {
  openDB,
  getPolicy,
  logAudit,
  getPendingApproval,
  createPendingApproval,
  deleteApproval,
} from "./database";
import { evaluatePolicy, scanAndSanitizeTools } from "./gateway";

const args = process.argv.slice(2);
let serverId = "unknown-server";
let dbPath = "mcp-shield.db";
let upstreamUrlStr = "";
let localPort = 3010;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--server" && i + 1 < args.length) {
    serverId = args[i + 1];
    i++;
  } else if (args[i] === "--db" && i + 1 < args.length) {
    dbPath = args[i + 1];
    i++;
  } else if (args[i] === "--upstream" && i + 1 < args.length) {
    upstreamUrlStr = args[i + 1];
    i++;
  } else if (args[i] === "--port" && i + 1 < args.length) {
    localPort = parseInt(args[i + 1], 10);
    i++;
  }
}

const isTesting = process.env.JEST_WORKER_ID !== undefined;

if (!upstreamUrlStr && !isTesting) {
  console.error("Error: Upstream target URL not specified. Use '--upstream <url>'");
  process.exit(1);
}

let db: any = null;

async function start() {
  try {
    db = await openDB(dbPath);

    const upstreamUrl = new URL(upstreamUrlStr);

    const server = http.createServer(async (req, res) => {
      const targetUrl = new URL(req.url || "", upstreamUrlStr);
      const headers = { ...req.headers };
      headers.host = upstreamUrl.host;

      if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString("utf8");
        });

        req.on("end", async () => {
          try {
            const payload = JSON.parse(body);

            // Intercept tools/call
            if (payload.method === "tools/call") {
              const toolName = payload.params?.name;
              const toolArgs = payload.params?.arguments || {};

              const policy = await getPolicy(db, serverId);
              const evaluation = await evaluatePolicy(db, policy, toolName, toolArgs);

              if (evaluation.decision === "BLOCKED") {
                await logAudit(db, {
                  timestamp: Date.now(),
                  server_id: serverId,
                  tool_name: toolName,
                  arguments: JSON.stringify(toolArgs),
                  decision: "BLOCKED",
                  reason: evaluation.reason,
                });

                sendJsonRpcError(res, payload.id, -32000, evaluation.reason);
                return;
              }

              if (policy.mode === "Gated") {
                const approvalId = `approval_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

                await createPendingApproval(db, {
                  id: approvalId,
                  timestamp: Date.now(),
                  server_id: serverId,
                  tool_name: toolName,
                  arguments: JSON.stringify(toolArgs),
                  status: "PENDING",
                });

                let userDecision: "APPROVED" | "DENIED" | "TIMEOUT" = "TIMEOUT";
                const ipcResult = await askApprovalViaIpc(dbPath, {
                  id: approvalId,
                  serverId,
                  toolName,
                  arguments: JSON.stringify(toolArgs),
                });

                if (ipcResult !== null) {
                  userDecision = ipcResult;
                } else {
                  // Fallback to SQLite polling
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
                      userDecision = "DENIED";
                      break;
                    }
                    await new Promise((resolve) => setTimeout(resolve, 150));
                  }
                }

                await deleteApproval(db, approvalId);

                if (userDecision !== "APPROVED") {
                  const blockReason = userDecision === "TIMEOUT"
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

                  sendJsonRpcError(res, payload.id, -32002, blockReason);
                  return;
                }

                // Log allowed gated call
                await logAudit(db, {
                  timestamp: Date.now(),
                  server_id: serverId,
                  tool_name: toolName,
                  arguments: JSON.stringify(toolArgs),
                  decision: "ALLOWED",
                  reason: "Approved manually by developer.",
                });
              } else {
                // Log allowed strict/permissive call
                await logAudit(db, {
                  timestamp: Date.now(),
                  server_id: serverId,
                  tool_name: toolName,
                  arguments: JSON.stringify(toolArgs),
                  decision: "ALLOWED",
                  reason: evaluation.reason,
                });
              }
            }

            // Forward POST request to upstream
            const proxyReq = http.request({
              hostname: upstreamUrl.hostname,
              port: upstreamUrl.port,
              path: targetUrl.pathname + targetUrl.search,
              method: "POST",
              headers: headers,
            }, (proxyRes) => {
              const isToolsList = payload.method === "tools/list";
              if (isToolsList) {
                let resBody = "";
                proxyRes.on("data", (chunk) => {
                  resBody += chunk.toString("utf8");
                });
                proxyRes.on("end", () => {
                  try {
                    const json = JSON.parse(resBody);
                    if (json.result && Array.isArray(json.result.tools)) {
                      json.result.tools = scanAndSanitizeTools(json.result.tools, serverId, db);
                    }
                    const finalBody = JSON.stringify(json);
                    const responseHeaders = { ...proxyRes.headers };
                    responseHeaders["content-length"] = Buffer.byteLength(finalBody).toString();
                    res.writeHead(proxyRes.statusCode || 200, responseHeaders);
                    res.end(finalBody);
                  } catch (err) {
                    res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
                    res.end(resBody);
                  }
                });
              } else {
                res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
                proxyRes.pipe(res);
              }
            });

            proxyReq.on("error", (err) => {
              res.writeHead(502);
              res.end(`[MCP Shield Proxy] Upstream proxy error: ${err.message}`);
            });

            proxyReq.write(body);
            proxyReq.end();

          } catch (err) {
            // Forward raw post if parsing failed
            const proxyReq = http.request({
              hostname: upstreamUrl.hostname,
              port: upstreamUrl.port,
              path: targetUrl.pathname + targetUrl.search,
              method: "POST",
              headers: headers,
            }, (proxyRes) => {
              res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
              proxyRes.pipe(res);
            });
            proxyReq.write(body);
            proxyReq.end();
          }
        });
      } else {
        // Handle GET / SSE request
        const proxyReq = http.request({
          hostname: upstreamUrl.hostname,
          port: upstreamUrl.port,
          path: targetUrl.pathname + targetUrl.search,
          method: req.method,
          headers: headers,
        }, (proxyRes) => {
          const isSSE = proxyRes.headers["content-type"]?.includes("event-stream");

          if (isSSE) {
            res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
            let buffer = "";

            proxyRes.on("data", (chunk) => {
              buffer += chunk.toString("utf8");
              let lines = buffer.split("\n");
              buffer = lines.pop() || "";

              for (let i = 0; i < lines.length; i++) {
                let line = lines[i];
                // Rewrite SSE endpoint events
                if (line.startsWith("data:") && (line.includes("http://") || line.includes("https://"))) {
                  try {
                    const urlStr = line.substring(5).trim();
                    const endpointUrl = new URL(urlStr);
                    // Rewrite endpoint to point to proxy
                    endpointUrl.hostname = "localhost";
                    endpointUrl.port = localPort.toString();
                    line = `data: ${endpointUrl.toString()}`;
                  } catch (e) {}
                }
                res.write(line + "\n");
              }
            });

            proxyRes.on("end", () => {
              if (buffer) {
                res.write(buffer);
              }
              res.end();
            });
          } else {
            res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
            proxyRes.pipe(res);
          }
        });

        proxyReq.on("error", (err) => {
          res.writeHead(502);
          res.end(`[MCP Shield Proxy] Upstream proxy error: ${err.message}`);
        });

        proxyReq.end();
      }
    });

    server.listen(localPort, () => {
      console.log(`[MCP Shield HTTP Gateway] Listening on http://localhost:${localPort} proxying to ${upstreamUrlStr}`);
    });

  } catch (err: any) {
    console.error(`[MCP Shield HTTP Proxy] Initialization error: ${err.message}`);
    process.exit(1);
  }
}

function sendJsonRpcError(res: http.ServerResponse, id: any, code: number, message: string) {
  const errorResponse = {
    jsonrpc: "2.0",
    id: id,
    error: {
      code: code,
      message: `Blocked by MCP Shield: ${message}`,
    },
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(errorResponse));
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

    setTimeout(() => {
      client.destroy();
      resolve(null);
    }, 90000);
  });
}

// Start Proxy
if (!isTesting) {
  start();
}
