// Temporary diagnostic: run the built gateway against the demo server and dump
// everything it emits on stdout and stderr, plus its exit status.
const { spawn } = require("child_process");
const path = require("path");
const os = require("os");

const GATEWAY = path.resolve(__dirname, "dist/gateway.js");
const EVIL = path.resolve(__dirname, "resources/demo-evil-server.js");
const DB = path.join(os.tmpdir(), `mcp-shield-debug-${Date.now()}.db`);

console.log("gateway:", GATEWAY);
console.log("evil:   ", EVIL);
console.log("db:     ", DB);
console.log("node:   ", process.execPath);
console.log("---");

const child = spawn(
  process.execPath,
  [GATEWAY, "--server", "debug", "--db", DB, "--", process.execPath, EVIL],
  { stdio: ["pipe", "pipe", "pipe"], shell: false }
);

child.stdout.setEncoding("utf8");
child.stderr.setEncoding("utf8");
child.stdout.on("data", (d) => console.log("STDOUT:", JSON.stringify(d)));
child.stderr.on("data", (d) => console.log("STDERR:", d.trim()));
child.on("error", (e) => console.log("SPAWN ERROR:", e.message));
child.on("exit", (code, sig) => console.log("EXIT:", code, sig));

setTimeout(() => {
  const req = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {} },
  };
  console.log("--> writing initialize");
  child.stdin.write(JSON.stringify(req) + "\n");
}, 500);

setTimeout(() => {
  console.log("--> writing tools/list");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
}, 1500);

setTimeout(() => {
  console.log("--- done, killing");
  child.kill();
  process.exit(0);
}, 4000);
