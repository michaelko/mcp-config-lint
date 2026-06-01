import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { buildJsonPointerLineMap, lineForPointer } from "./pointer-location.js";
import type { Finding, ScanResult, Severity } from "./types.js";

const severityRank: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function shouldFail(result: ScanResult, failOn: Severity | "none"): boolean {
  if (failOn === "none") {
    return false;
  }
  const minimum = severityRank[failOn];
  return [...result.parseErrors, ...result.findings].some((finding) => severityRank[finding.severity] >= minimum);
}

export function renderText(result: ScanResult, cwd = process.cwd(), quiet = false): string {
  const findings = [...result.parseErrors, ...result.findings];
  if (findings.length === 0) {
    return quiet ? "" : `mcp-lint: no findings across ${result.files.length} file${result.files.length === 1 ? "" : "s"}.`;
  }

  const lines: string[] = [];
  if (!quiet) {
    lines.push(`mcp-lint: ${findings.length} finding${findings.length === 1 ? "" : "s"} across ${result.files.length} file${result.files.length === 1 ? "" : "s"}.`, "");
  }

  for (const finding of findings.sort(compareFindings)) {
    const location = [relative(cwd, finding.filePath) || finding.filePath, finding.serverName ? `server=${finding.serverName}` : undefined, finding.pointer || undefined].filter(Boolean).join(" ");
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.title}`);
    lines.push(`  ${location}`);
    lines.push(`  ${finding.message}`);
    if (finding.context) {
      lines.push(`  Context: ${finding.context}`);
    }
    lines.push(`  Fix: ${finding.recommendation}`);
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}

export function renderJson(result: ScanResult): string {
  const severityCounts = summarize(result);
  return JSON.stringify(
    {
      tool: {
        name: "mcp-lint"
      },
      files: result.files,
      summary: {
        filesScanned: result.files.length,
        findings: result.findings.length,
        parseErrors: result.parseErrors.length,
        ...severityCounts
      },
      findings: [...result.parseErrors, ...result.findings]
    },
    null,
    2
  );
}

export function renderSarif(result: ScanResult, cwd = process.cwd()): string {
  const findings = [...result.parseErrors, ...result.findings];
  const rules = new Map<string, Finding>();
  const locationCache = new Map<string, Map<string, number>>();
  for (const finding of findings) {
    rules.set(finding.ruleId, finding);
  }

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "mcp-lint",
              informationUri: "https://github.com/michaelko/mcp-config-lint",
              rules: [...rules.values()].map((finding) => ({
                id: finding.ruleId,
                name: finding.title,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.recommendation },
                defaultConfiguration: { level: sarifLevel(finding.severity) }
              }))
            }
          },
          results: findings.map((finding) => ({
            ruleId: finding.ruleId,
            level: sarifLevel(finding.severity),
            message: { text: `${finding.message} ${finding.recommendation}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: (relative(cwd, finding.filePath) || finding.filePath).replaceAll("\\", "/")
                  },
                  region: {
                    startLine: startLineForFinding(finding, locationCache)
                  }
                },
                logicalLocations: finding.serverName
                  ? [
                      {
                        name: finding.serverName,
                        fullyQualifiedName: finding.pointer
                      }
                    ]
                  : []
              }
            ]
            ,
            properties: {
              severity: finding.severity,
              serverName: finding.serverName,
              pointer: finding.pointer,
              context: finding.context
            }
          }))
        }
      ]
    },
    null,
    2
  );
}

function startLineForFinding(finding: Finding, locationCache: Map<string, Map<string, number>>): number {
  let locations = locationCache.get(finding.filePath);
  if (!locations) {
    try {
      locations = buildJsonPointerLineMap(readFileSync(finding.filePath, "utf8"));
    } catch {
      locations = new Map<string, number>([["", 1]]);
    }
    locationCache.set(finding.filePath, locations);
  }

  return lineForPointer(finding.pointer, locations) ?? 1;
}

function summarize(result: ScanResult) {
  const summary: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };
  for (const finding of [...result.parseErrors, ...result.findings]) {
    summary[finding.severity] += 1;
  }
  return summary;
}

function sarifLevel(severity: Severity): "note" | "warning" | "error" {
  if (severity === "low") {
    return "note";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "error";
}

function compareFindings(left: Finding, right: Finding): number {
  const severityDiff = severityRank[right.severity] - severityRank[left.severity];
  if (severityDiff !== 0) {
    return severityDiff;
  }
  return `${left.filePath}:${left.pointer}:${left.ruleId}`.localeCompare(`${right.filePath}:${right.pointer}:${right.ruleId}`);
}
