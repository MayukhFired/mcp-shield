# MCP Shield 🛡️

A Security-First Middleware Gateway and Policy Enforcer for Model Context Protocol (MCP) servers.

MCP Shield acts as a secure reverse proxy and firewall between your AI Coding Assistants (such as Claude Desktop, Cline, Roo Code, etc.) and any local/remote MCP server. It intercepts JSON-RPC Stdout/Stdin channels to inspect tool definitions and enforce security boundaries.

## Architecture Overview

```
                      +-------------------+
                      | AI Agent / Client |
                      |  (e.g. Cline)     |
                      +---------+---------+
                                |
                   JSON-RPC     |     JSON-RPC
                   (Stdin)      |     (Stdout)
                                v
                      +---------+---------+
                      | MCP Shield Proxy  |<---- IPC (Fast Signal) ----+
                      |   (gateway.js)    |                            |
                      +---------+---------+                            |
                                |                                      |
                     Filtered   |     Filtered                         |
                     JSON-RPC   |     JSON-RPC                         |
                                v                                      v
                      +---------+---------+                  +---------+---------+
                      | Target MCP Server |                  | VS Code Extension |
                      | (e.g. filesystem) |                  |   (Dashboard)     |
                      +-------------------+                  +---------+---------+
                                                                       |
                                                                       v
                                                             +---------+---------+
                                                             | SQLite Database   |
                                                             | (Audit logs/rules)|
                                                             +-------------------+
```

## Features

1. **Prompt Injection Defense**: Scans tool description declarations on startup and automatically sanitizes hidden instructions (e.g. "Ignore previous commands...").
2. **Directory Gating & Path Traversal Prevention**: Prevents tools from accessing paths outside allowed project directories.
3. **Capability-Based Read-Only Mode**: Dynamically inspects input schemas (`inputSchema`) to detect write/mutation capabilities (e.g. tools taking `content`, `text`, `code`, or `value`) to enforce strict read-only compliance without false positives.
4. **Command Injection Block**: Scans arguments of process execution tools for shell metacharacters (e.g. `;`, `&`, `|`, `` ` ``).
5. **Network Firewall**: Restricts tool HTTP fetch calls to a whitelisted set of domains (supporting wildcard domains).
6. **Context Window Protection (Payload Size Limits)**: Prevents "Denial of Wallet" and AI context crashes by measuring JSON-RPC responses and automatically truncating oversized tool payloads to a user-configured limit (e.g., 500 KB). 
7. **Event-Driven Gated Authorization**: Prompts the developer inside VS Code with a modal choice to Allow/Block tool execution when in `Gated` mode. Features instant responsiveness via named pipe/socket IPC.
8. **Comprehensive Audit Logging & Security Smells**: Stores every single event, decision, reasoning, and truncation warning in a local SQLite database for compliance and dashboard analytics.

## Quick Start

### Installation

1. Open this folder in VS Code.
2. Run `npm install` to install dependencies.
3. Run `npm run build` to compile the TypeScript sources.
4. Press `F5` to open a new VS Code window with the extension activated.

### Securing an MCP Server

1. Open the **MCP Shield Dashboard** using the VS Code activity bar icon or search for `MCP Shield: Open Security Dashboard` in the command palette (`Ctrl+Shift+P`).
2. Navigate to the **Shield Assistant** tab.
3. Press **Rescan Configs** to discover your MCP settings (Claude Desktop, Cline, Roo Code configs).
4. Click **Shield** next to any server. This wraps the server command in the configuration file using `gateway.js`.
5. Restart your MCP client/AI agent to load the new config.

## Security Policies

Configure these per-server in the **Policies** tab:

- **Permissive**: Log all tool calls, but block nothing.
- **Gated**: Intercept tool calls, query the developer via VS Code Modal, and run/block based on your direct decision.
- **Strict**: Enable automated policies (Read-only, Directory containment, URL whitelist, command injection blocking) and block immediately if a violation is detected.
- **Payload Limits (Context Protection)**: Configure a Max Payload Size (in KB) for any server to automatically truncate massive file reads or API responses, protecting your LLM context window. Default is disabled (0).

## Local Development & Testing

Run unit and integration tests:
```bash
npm test
```
