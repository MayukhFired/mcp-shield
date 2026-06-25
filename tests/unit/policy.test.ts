import { evaluatePolicy } from "../../src/gateway";
import { getToolCapabilities } from "../../src/database";

jest.mock("../../src/database", () => ({
  getToolCapabilities: jest.fn(),
  saveToolCapabilities: jest.fn(),
  logAudit: jest.fn(),
  logWarning: jest.fn(),
}));

describe("evaluatePolicy", () => {
  let mockDb: any;
  let defaultPolicy: any;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDb = {};
    defaultPolicy = {
      server_id: "test-server",
      mode: "Strict",
      readonly: 0,
      allowed_paths: "[]",
      allowed_domains: "[]",
      disabled_tools: "[]",
      status: "Shielded",
    };
  });

  test("should allow any tool when policy is Unshielded", async () => {
    defaultPolicy.status = "Unshielded";
    const result = await evaluatePolicy(mockDb, defaultPolicy, "delete_everything", {});
    expect(result.decision).toBe("ALLOWED");
    expect(result.reason).toContain("Unshielded");
  });

  test("should allow any tool when mode is Permissive", async () => {
    defaultPolicy.mode = "Permissive";
    const result = await evaluatePolicy(mockDb, defaultPolicy, "delete_everything", {});
    expect(result.decision).toBe("ALLOWED");
    expect(result.reason).toContain("Permissive");
  });

  test("should block disabled tools", async () => {
    defaultPolicy.disabled_tools = JSON.stringify(["delete_file", "write_file"]);
    const result = await evaluatePolicy(mockDb, defaultPolicy, "delete_file", {});
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("disabled in the security policy");
  });

  test("should enforce Read-Only mode using cached WRITE capability", async () => {
    defaultPolicy.readonly = 1;
    (getToolCapabilities as jest.Mock).mockResolvedValue(["WRITE"]);

    const result = await evaluatePolicy(mockDb, defaultPolicy, "some_custom_tool", {});
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("classified as write-capable");
  });

  test("should enforce Read-Only mode using heuristic regex fallback", async () => {
    defaultPolicy.readonly = 1;
    (getToolCapabilities as jest.Mock).mockResolvedValue([]); // No cached capabilities

    const result = await evaluatePolicy(mockDb, defaultPolicy, "delete_file", {});
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("matches read-only restriction pattern");
  });

  test("should allow write-regex-matching tool in Read-Only mode if capability is cached as READ", async () => {
    defaultPolicy.readonly = 1;
    (getToolCapabilities as jest.Mock).mockResolvedValue(["READ"]); // Cached as READ override

    const result = await evaluatePolicy(mockDb, defaultPolicy, "get_write_permissions", {});
    expect(result.decision).toBe("ALLOWED");
  });

  test("should block path traversal sequences", async () => {
    const result = await evaluatePolicy(mockDb, defaultPolicy, "read_file", {
      path: "../../sensitive/config.json",
    });
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("path traversal");
  });

  test("should block absolute paths outside authorized directories", async () => {
    defaultPolicy.allowed_paths = JSON.stringify(["/safe/dir"]);
    const result = await evaluatePolicy(mockDb, defaultPolicy, "read_file", {
      path: "/etc/passwd",
    });
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("Access to path outside authorized directories");
  });

  test("should allow absolute paths inside authorized directories", async () => {
    defaultPolicy.allowed_paths = JSON.stringify(["/safe/dir"]);
    const result = await evaluatePolicy(mockDb, defaultPolicy, "read_file", {
      path: "/safe/dir/project/index.js",
    });
    expect(result.decision).toBe("ALLOWED");
  });

  test("should block command injection metacharacters on terminal execution tools", async () => {
    const result = await evaluatePolicy(mockDb, defaultPolicy, "run_command", {
      cmd: "npm install && cat /etc/passwd",
    });
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("shell metacharacter");
  });

  test("should block external URLs not in the allowed domains", async () => {
    defaultPolicy.allowed_domains = JSON.stringify(["api.github.com", "*.npm.org"]);
    const result = await evaluatePolicy(mockDb, defaultPolicy, "fetch_url", {
      url: "https://evil.com/malicious-payload",
    });
    expect(result.decision).toBe("BLOCKED");
    expect(result.reason).toContain("External URL access blocked");
  });

  test("should allow external URLs matching allowed domains (including wildcards)", async () => {
    defaultPolicy.allowed_domains = JSON.stringify(["api.github.com", "*.npm.org"]);
    const result1 = await evaluatePolicy(mockDb, defaultPolicy, "fetch_url", {
      url: "https://api.github.com/users/octocat",
    });
    const result2 = await evaluatePolicy(mockDb, defaultPolicy, "fetch_url", {
      url: "https://registry.npm.org/mcp-shield",
    });
    expect(result1.decision).toBe("ALLOWED");
    expect(result2.decision).toBe("ALLOWED");
  });
});
