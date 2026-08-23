/**
 * MCP Shield — build script
 * =========================
 *
 * Produces three separate bundles, because the project runs as three distinct
 * processes:
 *
 *   dist/extension.js    — the VS Code extension host
 *   dist/gateway.js      — the stdio proxy, spawned by the MCP *client*
 *   dist/gateway-http.js — the HTTP proxy, spawned by the extension
 *
 * The gateways cannot be part of the extension bundle: they are launched as
 * standalone Node processes by a different parent, so they need their own
 * entry points and must not import `vscode`.
 *
 * `sqlite3` is a native module and `sqlite` is its promise wrapper, so both stay
 * external and are resolved from node_modules at runtime. That is also why
 * `.vscodeignore` must keep node_modules/sqlite3 in the package.
 */

const esbuild = require("esbuild");

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

/** Shared options; only the entry point and output path differ per bundle. */
const base = {
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node16",
  minify: production,
  sourcemap: !production,
  sourcesContent: false,
  logLevel: "info",
};

const targets = [
  {
    label: "VS Code extension",
    ...base,
    entryPoints: ["src/extension.ts"],
    outfile: "dist/extension.js",
    external: ["vscode", "sqlite3", "sqlite"],
  },
  {
    label: "stdio gateway",
    ...base,
    entryPoints: ["src/gateway.ts"],
    outfile: "dist/gateway.js",
    external: ["sqlite3", "sqlite"],
  },
  {
    label: "HTTP gateway",
    ...base,
    entryPoints: ["src/gateway-http.ts"],
    outfile: "dist/gateway-http.js",
    external: ["sqlite3", "sqlite"],
  },
];

async function main() {
  if (watch) {
    // The previous version accepted --watch, logged that it was "not fully
    // implemented", and did a one-shot build instead — so `npm run watch`
    // silently did nothing useful.
    const contexts = await Promise.all(
      targets.map(({ label, ...config }) => esbuild.context(config))
    );
    await Promise.all(contexts.map((ctx) => ctx.watch()));
    console.log("Watching for changes. Press Ctrl+C to stop.");
    return;
  }

  for (const { label, ...config } of targets) {
    console.log(`Building ${label}...`);
    await esbuild.build(config);
  }
  console.log("Build complete.");
}

main().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
