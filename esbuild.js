const esbuild = require("esbuild");

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

async function main() {
  const extensionConfig = {
    entryPoints: ["src/extension.ts"],
    bundle: true,
    format: "cjs",
    minify: production,
    sourcemap: !production,
    sourcesContent: false,
    platform: "node",
    target: "node16",
    outfile: "dist/extension.js",
    external: ["vscode", "sqlite3", "sqlite"],
    logLevel: "info",
  };

  const gatewayConfig = {
    entryPoints: ["src/gateway.ts"],
    bundle: true,
    format: "cjs",
    minify: production,
    sourcemap: !production,
    sourcesContent: false,
    platform: "node",
    target: "node16",
    outfile: "dist/gateway.js",
    external: ["sqlite3", "sqlite"],
    logLevel: "info",
  };

  const gatewayHttpConfig = {
    entryPoints: ["src/gateway-http.ts"],
    bundle: true,
    format: "cjs",
    minify: production,
    sourcemap: !production,
    sourcesContent: false,
    platform: "node",
    target: "node16",
    outfile: "dist/gateway-http.js",
    external: ["sqlite3", "sqlite"],
    logLevel: "info",
  };

  if (watch) {
    console.log("Watch mode enabled (not fully implemented in script, standard run instead)...");
  }

  try {
    // Build all configurations
    console.log("Building VS Code Extension...");
    await esbuild.build(extensionConfig);

    console.log("Building Shield Gateway Proxy...");
    await esbuild.build(gatewayConfig);

    console.log("Building Shield HTTP Gateway Proxy...");
    await esbuild.build(gatewayHttpConfig);

    console.log("Build completed successfully!");
  } catch (err) {
    console.error("Build failed:", err);
    process.exit(1);
  }
}

main();
