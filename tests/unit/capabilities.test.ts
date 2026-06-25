import { classifyToolCapabilities } from "../../src/gateway";

describe("classifyToolCapabilities", () => {
  test("should classify read-only tools as READ", () => {
    const tools = [
      { name: "read_file", description: "Read a file from disk" },
      { name: "get_user", description: "Get user details" },
      { name: "list_directory", description: "List directories" },
      { name: "view_logs", description: "View system logs" }
    ];

    for (const tool of tools) {
      expect(classifyToolCapabilities(tool)).toEqual(["READ"]);
    }
  });

  test("should classify mutating/write tools as WRITE", () => {
    const tools = [
      { name: "write_file", description: "Write content to a file" },
      { name: "delete_record", description: "Delete a database record" },
      { name: "apply_patch", description: "Apply a git patch" },
      { name: "commit_changes", description: "Commit files to repo" },
      { name: "push_code", description: "Push commits to remote" }
    ];

    for (const tool of tools) {
      expect(classifyToolCapabilities(tool)).toEqual(["WRITE"]);
    }
  });

  test("should correctly handle read prefixes override for write keywords", () => {
    const tools = [
      { name: "get_write_permission", description: "Check if write is allowed" },
      { name: "list_delete_policies", description: "List policies that allow deletion" },
      { name: "view_update_logs", description: "Check logs about updates" }
    ];

    for (const tool of tools) {
      expect(classifyToolCapabilities(tool)).toEqual(["READ"]);
    }
  });

  test("should detect WRITE capability via inputSchema parameter hints", () => {
    // Tool name is neutral/unrelated to write keywords, but has schema indicators
    const tool = {
      name: "run_my_handler",
      description: "Custom handler",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string" },
          content: { type: "string" }
        }
      }
    };

    expect(classifyToolCapabilities(tool)).toEqual(["WRITE"]);
  });
});
