import { describe, expect, it } from "vitest";
import { renderJson, renderSarif, renderText, shouldFail } from "../src/output.js";
import type { ScanResult } from "../src/types.js";

const result: ScanResult = {
  files: ["/repo/mcp.json"],
  parseErrors: [],
  findings: [
    {
      ruleId: "MCP004",
      title: "Unpinned package execution",
      severity: "high",
      message: "Server runs package without a version.",
      filePath: "/repo/mcp.json",
      serverName: "filesystem",
      pointer: "/mcpServers/filesystem",
      recommendation: "Pin package versions."
    }
  ]
};

describe("output", () => {
  it("renders text output", () => {
    expect(renderText(result, "/repo")).toContain("MCP004");
    expect(renderText(result, "/repo")).toContain("Pin package versions");
  });

  it("renders machine-readable output", () => {
    expect(JSON.parse(renderJson(result)).tool.name).toBe("mcp-lint");
    expect(JSON.parse(renderJson(result)).summary.high).toBe(1);
    expect(JSON.parse(renderSarif(result, "/repo")).runs[0].tool.driver.name).toBe("mcp-lint");
    expect(JSON.parse(renderSarif(result, "/repo")).runs[0].results[0].ruleId).toBe("MCP004");
  });

  it("honors fail thresholds", () => {
    expect(shouldFail(result, "critical")).toBe(false);
    expect(shouldFail(result, "high")).toBe(true);
    expect(shouldFail(result, "none")).toBe(false);
  });
});
