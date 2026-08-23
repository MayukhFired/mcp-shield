/**
 * MCP Shield — HTTP / SSE Gateway Proxy
 * =====================================
 *
 * The HTTP counterpart to `gateway.ts`. Same interception, different transport:
 * remote MCP servers speak JSON-RPC over HTTP POST, optionally with an SSE
 * channel for server-initiated messages.
 *
 * Like the stdio gateway this file is only a transport adapter — all policy lives
 * in `policy.ts` and all enforcement action in `interceptor.ts`.
 *
 * Two security properties of this file are worth being able to explain:
 *
 *   1. IT BINDS TO LOOPBACK ONLY. `server.listen(port)` with no host binds
 *      0.0.0.0, which would expose an unauthenticated proxy — one that forwards
 *      the client's credentials upstream — to every machine on the network. The
 *      original implementation did exactly that. Binding 127.0.0.1 is the fix,
 *      and it is why the `host` is a constant rather than a setting.
 *
 *   2. IT PRESERVES THE UPSTREAM SCHEME. The original imported only `http` and
 *      always used `http.request`, so shielding an `https://` MCP server both
 *      broke it and silently downgraded the transport to cleartext. We now select
 *      the module from the upstream URL and default the port accordingly.
 */

import * as http from "http";
import * as https from "https";
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

/**
 * Run as a proxy only when executed directly. See the equivalent comment in
 * `gateway.ts`: an environment-variable check is wrong here because spawned
 * children inherit the parent's environment.
 */
const isEntryPoint = typeof require !== "undefined" && require.main === module;

if (!upstreamUrlStr && isEntryPoint) {
  console.error("Error: Upstream target URL not specified. Use '--upstream <url>'");
  process.exit(1);
}

/**
 * The proxy is only ever addressed by the MCP client on the same machine, so
 * there is no reason to accept connections from anywhere else. Hard-coded rather
 * than configurable: a "bind address" setting is a foot-gun on a security tool.
 */
const BIND_HOST = "127.0.0.1";

let ctx: InterceptContext | null = null;
const outstandingRequests = new Map<string | number, OutstandingRequest>();

async function start() {
  try {
    const db = await openDB(dbPath);
    ctx = { db, dbPath, serverId };

    const upstream = new URL(upstreamUrlStr);
    const isSecureUpstream = upstream.protocol === "https:";
    const transport = isSecureUpstream ? https : http;
    const upstreamPort = upstream.port
      ? Number(upstream.port)
      : isSecureUpstream
      ? 443
      : 80;

    const server = http.createServer((req, res) => {
      handleRequest(req, res, {
        upstream,
        transport,
        upstreamPort,
      }).catch((err) => {
        console.error(`[MCP Shield] Request handling failed: ${err?.message ?? err}`);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "text/plain" });
        }
        res.end("[MCP Shield] Internal proxy error");
      });
    });

    server.listen(localPort, BIND_HOST, () => {
      console.error(
        `[MCP Shield HTTP Gateway] Listening on http://${BIND_HOST}:${localPort} → ${upstreamUrlStr}`
      );
    });

    server.on("error", (err: any) => {
      // A port collision must be loud. Silently failing here would leave the
      // client pointed at a dead address with no explanation.
      console.error(`[MCP Shield HTTP Gateway] Server error: ${err.message}`);
      process.exit(1);
    });
  } catch (err: any) {
    // Fail closed, same reasoning as the stdio gateway.
    console.error(`[MCP Shield HTTP Proxy] Initialization error: ${err.message}`);
    process.exit(1);
  }
}

interface UpstreamTarget {
  upstream: URL;
  transport: typeof http | typeof https;
  upstreamPort: number;
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  target: UpstreamTarget
): Promise<void> {
  const targetUrl = new URL(req.url || "/", upstreamUrlStr);

  const headers: http.OutgoingHttpHeaders = { ...req.headers };
  // Rewrite Host so upstream virtual-host routing and TLS SNI resolve correctly.
  headers.host = target.upstream.host;

  if (req.method === "POST") {
    const body = await readBody(req);
    await handlePost(req, res, target, targetUrl, headers, body);
    return;
  }

  await handleGetOrSse(req, res, target, targetUrl, headers);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;
    // Cap the buffered request so a hostile local client cannot exhaust memory.
    const MAX_BODY_BYTES = 32 * 1024 * 1024;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("Request body exceeded 32 MB limit"));
        req.destroy();
        return;
      }
      body += chunk.toString("utf8");
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

async function handlePost(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  target: UpstreamTarget,
  targetUrl: URL,
  headers: http.OutgoingHttpHeaders,
  body: string
): Promise<void> {
  let payload: any = null;
  try {
    payload = JSON.parse(body);
  } catch {
    // Not JSON-RPC. Forward verbatim rather than guessing at the content.
    forwardRaw(res, target, targetUrl, headers, body);
    return;
  }

  if (!ctx) {
    forwardRaw(res, target, targetUrl, headers, body);
    return;
  }

  // ── Batch ────────────────────────────────────────────────────────────────
  if (Array.isArray(payload)) {
    const { verdicts, blocked } = await screenBatch(ctx, payload);
    if (blocked) {
      const responses = payload
        .filter((m: any) => m && m.id !== undefined)
        .map((m: any) =>
          blockedError(
            m.id,
            blocked.code,
            `Batch rejected because one or more members violated policy: ${blocked.reason}`
          )
        );
      sendJson(res, responses);
      return;
    }
    for (let i = 0; i < payload.length; i++) {
      const member = payload[i];
      const verdict = verdicts[i];
      if (member && member.id !== undefined && member.method) {
        outstandingRequests.set(member.id, {
          method: member.method,
          auditId: verdict.action === "FORWARD" ? verdict.auditId : undefined,
          startedAt: Date.now(),
        });
      }
    }
    proxyPost(res, target, targetUrl, headers, body, payload);
    return;
  }

  // ── Single request ───────────────────────────────────────────────────────
  const verdict = await screenRequest(ctx, payload);
  if (verdict.action === "BLOCK") {
    // Returned as HTTP 200 with a JSON-RPC error body: the transport succeeded,
    // the *call* was refused. An HTTP error status would make clients retry or
    // report a connectivity fault instead of surfacing the policy decision.
    sendJson(res, blockedError(payload.id ?? null, verdict.code, verdict.reason));
    return;
  }

  if (payload.id !== undefined && payload.method) {
    outstandingRequests.set(payload.id, {
      method: payload.method,
      auditId: verdict.auditId,
      startedAt: Date.now(),
    });
  }

  proxyPost(res, target, targetUrl, headers, body, payload);
}

/**
 * Forward a screened POST upstream, inspecting the response on the way back.
 *
 * Responses are buffered when we need to inspect them (tools/list, tools/call,
 * resources/read) and streamed otherwise. Buffering is unavoidable for
 * inspection: we cannot decide whether a payload contains an injected
 * instruction until we have seen all of it.
 */
function proxyPost(
  res: http.ServerResponse,
  target: UpstreamTarget,
  targetUrl: URL,
  headers: http.OutgoingHttpHeaders,
  body: string,
  payload: any
): void {
  const method: string | undefined = Array.isArray(payload) ? undefined : payload?.method;
  const needsInspection =
    method === "tools/list" || method === "tools/call" || method === "resources/read";

  const proxyReq = target.transport.request(
    {
      protocol: target.upstream.protocol,
      hostname: target.upstream.hostname,
      port: target.upstreamPort,
      path: targetUrl.pathname + targetUrl.search,
      method: "POST",
      headers,
    },
    (proxyRes) => {
      if (!needsInspection) {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res);
        return;
      }

      let raw = "";
      proxyRes.on("data", (chunk) => (raw += chunk.toString("utf8")));
      proxyRes.on("end", () => {
        void finishInspectedResponse(res, proxyRes, raw, payload).catch((err) => {
          console.error(`[MCP Shield] Response inspection failed: ${err?.message ?? err}`);
          // Pass the untouched body through rather than dropping the response.
          if (!res.headersSent) res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          res.end(raw);
        });
      });
    }
  );

  proxyReq.on("error", (err) => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`[MCP Shield Proxy] Upstream error: ${err.message}`);
  });

  proxyReq.write(body);
  proxyReq.end();
}

async function finishInspectedResponse(
  res: http.ServerResponse,
  proxyRes: http.IncomingMessage,
  raw: string,
  payload: any
): Promise<void> {
  if (!ctx) {
    res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
    res.end(raw);
    return;
  }

  let json: any;
  try {
    json = JSON.parse(raw);
  } catch {
    // Server-sent events or a non-JSON body; nothing to inspect.
    res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
    res.end(raw);
    return;
  }

  const pending =
    json && json.id !== undefined ? outstandingRequests.get(json.id) : undefined;
  if (json && json.id !== undefined) outstandingRequests.delete(json.id);

  const method: string = pending?.method ?? payload?.method ?? "";
  let finalBody = raw;

  if (method === "tools/list" && json.result && Array.isArray(json.result.tools)) {
    json.result.tools = await applyToolListScan(ctx, json.result.tools);
    finalBody = JSON.stringify(json);
  } else if ((method === "tools/call" || method === "resources/read") && json.result) {
    const mutated = await inspectResponse(ctx, json, method, raw);
    if (mutated) finalBody = JSON.stringify(json);
  }

  if (pending) {
    await recordResponse(ctx, pending, finalBody);
  }

  // Content-Length must be recomputed: sanitization changes the body length, and
  // a stale header would truncate the response or hang the client.
  const responseHeaders = { ...proxyRes.headers };
  delete responseHeaders["content-length"];
  delete responseHeaders["transfer-encoding"];
  responseHeaders["content-length"] = Buffer.byteLength(finalBody, "utf8").toString();

  res.writeHead(proxyRes.statusCode || 200, responseHeaders);
  res.end(finalBody);
}

/**
 * Proxy a GET, including the SSE channel.
 *
 * SSE needs special handling: the MCP HTTP+SSE transport sends the client an
 * `endpoint` event containing the URL to POST subsequent messages to. That URL
 * points at the real server, so if we passed it through unchanged the client
 * would talk directly to upstream and route around the shield entirely. We
 * rewrite the host and port to point back at this proxy.
 */
async function handleGetOrSse(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  target: UpstreamTarget,
  targetUrl: URL,
  headers: http.OutgoingHttpHeaders
): Promise<void> {
  const proxyReq = target.transport.request(
    {
      protocol: target.upstream.protocol,
      hostname: target.upstream.hostname,
      port: target.upstreamPort,
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers,
    },
    (proxyRes) => {
      const isSSE = proxyRes.headers["content-type"]?.includes("event-stream");

      if (!isSSE) {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res);
        return;
      }

      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      let buffer = "";

      proxyRes.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const lines = buffer.split("\n");
        // Keep the trailing partial line for the next chunk.
        buffer = lines.pop() || "";

        for (let line of lines) {
          if (line.startsWith("data:") && /https?:\/\//.test(line)) {
            try {
              const endpointUrl = new URL(line.substring(5).trim());
              endpointUrl.protocol = "http:";
              endpointUrl.hostname = BIND_HOST;
              endpointUrl.port = String(localPort);
              line = `data: ${endpointUrl.toString()}`;
            } catch {
              // Not a bare URL payload; leave the event untouched.
            }
          }
          res.write(line + "\n");
        }
      });

      proxyRes.on("end", () => {
        if (buffer) res.write(buffer);
        res.end();
      });
    }
  );

  proxyReq.on("error", (err) => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`[MCP Shield Proxy] Upstream error: ${err.message}`);
  });

  proxyReq.end();
}

function forwardRaw(
  res: http.ServerResponse,
  target: UpstreamTarget,
  targetUrl: URL,
  headers: http.OutgoingHttpHeaders,
  body: string
): void {
  const proxyReq = target.transport.request(
    {
      protocol: target.upstream.protocol,
      hostname: target.upstream.hostname,
      port: target.upstreamPort,
      path: targetUrl.pathname + targetUrl.search,
      method: "POST",
      headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on("error", (err) => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`[MCP Shield Proxy] Upstream error: ${err.message}`);
  });
  proxyReq.write(body);
  proxyReq.end();
}

function sendJson(res: http.ServerResponse, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body, "utf8").toString(),
  });
  res.end(body);
}

if (isEntryPoint) {
  start();
}
