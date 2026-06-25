import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";

export interface ApprovalRequest {
  id: string;
  serverId: string;
  toolName: string;
  arguments: string;
}

export interface ApprovalResponse {
  id: string;
  status: "APPROVED" | "DENIED";
}

/**
 * Returns a platform-specific socket/pipe path based on a hash of the database path.
 * This guarantees a unique IPC channel per SQLite database instance.
 */
export function getSocketPath(dbPath: string): string {
  const normalizedPath = path.resolve(dbPath).toLowerCase();
  const hash = crypto.createHash("md5").update(normalizedPath).digest("hex");
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\mcp-shield-${hash}`;
  } else {
    return path.join(os.tmpdir(), `mcp-shield-${hash}.sock`);
  }
}
