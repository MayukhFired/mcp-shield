/**
 * MCP Shield — Compatibility Shims
 * ================================
 *
 * Holds the older side-effecting API surface so the transport adapters stay pure
 * transport. Nothing new should be added here.
 */

import { saveToolCapabilities, logWarning } from "./database";
import { analyzeToolList } from "./policy";

/**
 * @deprecated Use `analyzeToolList` from `policy.ts` instead.
 *
 * The original scanner mixed three responsibilities: analysing tool definitions,
 * caching capabilities, and logging warnings — with the database writes issued as
 * unawaited floating promises from inside a `.map()`. That made it impossible to
 * unit-test without a database and turned write failures into unhandled
 * rejections.
 *
 * `analyzeToolList` is the pure replacement; this wrapper preserves the old
 * signature and fire-and-forget behaviour for existing callers and tests.
 */
export function scanAndSanitizeTools(
  tools: any[],
  serverId: string,
  db?: any
): any[] {
  const result = analyzeToolList(tools);

  if (db) {
    for (const entry of result.capabilities) {
      saveToolCapabilities(db, serverId, entry.toolName, entry.capabilities).catch((err) =>
        console.error(`[MCP Shield] Failed to save tool capabilities: ${err.message}`)
      );
    }
    for (const smell of result.smells) {
      logWarning(db, {
        timestamp: Date.now(),
        server_id: serverId,
        tool_name: smell.toolName,
        smell_type: smell.smellType,
        description: smell.originalDescription,
        details: smell.details,
        sanitized: 1,
      }).catch((err) => console.error(`[MCP Shield] Failed to log warning: ${err.message}`));
    }
  }

  return result.tools;
}
