import { discoverConfigFiles } from "./discovery.js";
import { parseConfigFile } from "./jsonc.js";
import { extractServers } from "./server-extractor.js";
import { rules } from "./rules.js";
import type { Finding, ScanResult } from "./types.js";

export async function scan(paths: string[], cwd = process.cwd()): Promise<ScanResult> {
  const files = await discoverConfigFiles(paths, cwd);
  const findings: Finding[] = [];
  const parseErrors: Finding[] = [];

  for (const file of files) {
    const parsed = await parseConfigFile(file);
    if (parsed.errors.length > 0) {
      parseErrors.push({
        ruleId: "MCP000",
        title: "Invalid JSON/JSONC",
        severity: "critical",
        message: parsed.errors.join("; "),
        filePath: file,
        pointer: "",
        recommendation: "Fix the config syntax before reviewing MCP server behavior."
      });
      continue;
    }

    const servers = extractServers(parsed.value);
    for (const server of servers) {
      for (const rule of rules) {
        findings.push(...rule(server, file));
      }
    }
  }

  return { files, findings, parseErrors };
}
