export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  filePath: string;
  serverName?: string;
  pointer: string;
  context?: string;
  recommendation: string;
}

export interface ServerDefinition {
  name: string;
  pointer: string;
  value: Record<string, unknown>;
}

export interface ParsedConfig {
  filePath: string;
  value: unknown;
  errors: string[];
}

export interface ScanResult {
  files: string[];
  findings: Finding[];
  parseErrors: Finding[];
}

export interface CliOptions {
  paths: string[];
  format: "text" | "json" | "sarif";
  failOn: Severity | "none";
  quiet: boolean;
}
