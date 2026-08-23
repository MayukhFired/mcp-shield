// Temporary diagnostic: replicate the E2E test conditions exactly —
// parent opens the DB first, then spawns the gateway against the same file,
// and writes the handshake immediately with no delay.
const { spawn } = require("child_process");
const path = require("path");
const os = require("os");

const GATEWAY = path.resolve(__dirname, "dist/gateway.js");
const EVIL = path.resolve(__dirname, "resources/demo-evil-server.js");
const DB = path.join(os.tmpdir(), `mcp-shield-debug2-${Date.now()}.db`);

(async () => {
  const { open } = require("sqlite");
  const sqlite3 = require("sqlite3");

  console.log("Parent opening DB first (as the test does)...");
  const db = await open({ filename: DB, driver: sqlite3.Database });
  await db.exec("PRAGMA busy_timeout = 10000;");
  await db.exec("PRAGMA journal_mode = WAL;");
  await db.exec(`CREATE TABLE IF NOT EXISTS policies (
    server_id TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'Gated',
    readonly INTEGER NOT NULL DEFAULT 0, allowed_paths TEXT NOT NULL DEFAULT '[]',
    allowed_domains TEXT NOT NULL DEFAULT '[]', disabled_tools TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'Shielded', max_payload_kb INTEGER NOT NULL DEFAULT 0);`);
  console.log("Parent DB open. Spawning gateway with NO startup delay...");

  const t0 = Date.now();
  const child = spawn(
    process.execPath,
    [GATEWAY, "--server", "debug", "--db", DB, "--", process.execPath, EVIL],
    { stdio: ["pipe", "pipe", "pipe"], shell: false, cwd: os.tmpdir() }
  );

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (d) =>
    console.log(`[+${Date.now() - t0}ms] STDOUT:`, d.slice(0, 200))
  );
  child.stderr.on("data", (d) => console.log(`[+${Date.now() - t0}ms] STDERR:`, d.trim()));
  child.on("error", (e) => console.log("SPAWN ERROR:", e.message));
  child.on("exit", (code, sig) => console.log(`[+${Date.now() - t0}ms] EXIT:`, code, sig));

  // Immediately, exactly like the test harness does.
  const req = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {} },
  };
  console.log("--> writing initialize immediately");
  child.stdin.write(JSON.stringify(req) + "\n");

  setTimeout(() => {
    console.log("--- 15s elapsed, killing");
    child.kill();
    process.exit(0);
  }, 15000);
})();
