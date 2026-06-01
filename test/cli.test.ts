import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { main, parseArgs } from "../src/cli.js";

describe("cli", () => {
  it("parses options", () => {
    expect(parseArgs(["config.json", "--format", "json", "--fail-on=critical", "--quiet"])).toMatchObject({
      paths: ["config.json"],
      format: "json",
      failOn: "critical",
      quiet: true
    });
  });

  it("returns nonzero when threshold is met", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-lint-cli-"));
    const configPath = join(dir, "mcp.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          insecure: {
            url: "http://example.com/mcp"
          }
        }
      })
    );

    const originalLog = console.log;
    console.log = () => undefined;
    try {
      await expect(main([configPath, "--format", "json", "--fail-on", "high"])).resolves.toBe(1);
      await expect(main([configPath, "--format", "json", "--fail-on", "critical"])).resolves.toBe(0);
    } finally {
      console.log = originalLog;
    }
  });
});
