# MCP Shield Threat Model 🛡️

This document describes the security posture, threat boundaries, assumptions, and mitigations implemented by MCP Shield.

---

## 1. Threat Profile & Target Assets

The target environment is a developer workstation running local AI Coding Assistants (e.g. VS Code with Cline/Roo Code, or Claude Desktop) connected to Model Context Protocol (MCP) servers.

### Assets at Risk
- **Local Filesystem**: Access to source code, private keys (`.ssh`), configuration settings, credentials (`.env`).
- **Internal Network**: Access to local development servers, databases, and microservices.
- **Terminal Session**: Execute commands, shell scripts, or binaries.
- **Data Confidentiality**: Exfiltration of source code or secrets to arbitrary external servers.

---

## 2. Attack Vectors & Mitigations

| Threat ID | Threat Vector | Mitigation Strategy | Implementation Details |
|---|---|---|---|
| **T-01** | **Indirect Prompt Injection**<br>AI is fed malicious instructions embedded in a read file, overriding its behavior. | **Tool Description Sanitization** | Intercepts `tools/list` responses on startup. Uses regex to scan for instructional injection strings and redacts them. |
| **T-02** | **Directory Traversal**<br>AI attempts to read or write files outside the workspace (e.g. `/etc/passwd`). | **Path Gating & Containment** | Resolves absolute paths. Verifies that paths lie strictly within the project workspace directories. Blocks traversal sequences (`..`). |
| **T-03** | **Unwanted Writes in Read Mode**<br>Client issues write commands to files despite expecting a read-only session. | **Schema-Aware Read-Only Mode** | Analyzes `inputSchema` structure of all tools to classify them as `WRITE` or `READ`. Blocks `WRITE` tools in read-only mode. |
| **T-04** | **Command Injection**<br>Malicious instructions append shell characters to execute additional processes. | **Shell Metacharacter Gating** | Scans argument values for terminal tools (e.g. `/execute`, `/run`) for dangerous metacharacters like `;`, `&`, `|`, `` ` ``. |
| **T-05** | **Data Exfiltration**<br>AI accesses external URLs to upload secrets harvested from the codebase. | **Network Domain Whitelisting** | Inspects all arguments for URL patterns. Enforces DNS whitelisting (with wildcard support) on HTTP fetch tools. |
| **T-06** | **Rogue Tool Calls**<br>AI calls dangerous tools (e.g. `destroy_database`) without permission. | **Interactive Gatekeeper Mode** | Halts tool execution, sends IPC signal to VS Code, displays confirmation dialog to the developer, and blocks if denied/timed out. |

---

## 3. Threat Boundary & Out-of-Scope Risks

MCP Shield acts as a protocol-level firewall. Certain risks fall outside its boundary:

### Out-of-Scope
- **Compromised Target Server**: If the MCP target server code itself is compromised and contains malicious backdoors executing during start-up, MCP Shield cannot inspect inner-process execution (use sandboxing tools like Docker or gVisor for this).
- **Direct OS Compromise**: If the developer's computer is already infected with malware, MCP Shield can be bypassed.
- **Local SQLite DB Protection**: MCP Shield stores state in `mcp-shield.db`. If another user or process on the system alters this file, they can approve or deny actions. Secure filesystem permissions are assumed.
- **Heuristic Limitations**: While capabilities classing uses schema properties (`content`, `text`, `code`, `value`), custom servers with completely obscure property names might bypass classification (it will still fall back to name heuristics).

---

## 4. Security Assumptions
1. **VS Code Trust**: The VS Code editor hosting MCP Shield is secure and uncompromised.
2. **Local Loopback Security**: Named pipes (`\\.\pipe\*`) and Unix sockets are secure from remote interception under standard operating system access control lists.
