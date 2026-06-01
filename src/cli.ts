#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { renderJson, renderSarif, renderText, shouldFail } from "./output.js";
import { scan } from "./scanner.js";
import type { CliOptions, Severity } from "./types.js";

const VALID_FORMATS = new Set(["text", "json", "sarif"]);
const VALID_FAIL_ON = new Set(["low", "medium", "high", "critical", "none"]);

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const options = parseArgs(argv);
  if (options === "help") {
    console.log(helpText());
    return 0;
  }
  if (options === "version") {
    console.log(version());
    return 0;
  }

  const result = await scan(options.paths);
  const output =
    options.format === "json"
      ? renderJson(result)
      : options.format === "sarif"
        ? renderSarif(result, process.cwd())
        : renderText(result, process.cwd(), options.quiet);

  if (output) {
    console.log(output);
  }
  if (result.parseErrors.length > 0) {
    return 2;
  }
  return shouldFail(result, options.failOn) ? 1 : 0;
}

export function parseArgs(argv: string[]): CliOptions | "help" | "version" {
  const options: CliOptions = {
    paths: [],
    format: "text",
    failOn: "high",
    quiet: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] ?? "";
    if (arg === "--help" || arg === "-h") {
      return "help";
    }
    if (arg === "--version" || arg === "-v") {
      return "version";
    }
    if (arg === "--quiet" || arg === "-q") {
      options.quiet = true;
      continue;
    }
    if (arg === "--format") {
      const value = argv[++index];
      if (!value || !VALID_FORMATS.has(value)) {
        throw new Error("--format must be one of text, json, sarif");
      }
      options.format = value as CliOptions["format"];
      continue;
    }
    if (arg.startsWith("--format=")) {
      const value = arg.slice("--format=".length);
      if (!VALID_FORMATS.has(value)) {
        throw new Error("--format must be one of text, json, sarif");
      }
      options.format = value as CliOptions["format"];
      continue;
    }
    if (arg === "--fail-on") {
      const value = argv[++index];
      if (!value || !VALID_FAIL_ON.has(value)) {
        throw new Error("--fail-on must be one of low, medium, high, critical, none");
      }
      options.failOn = value as Severity | "none";
      continue;
    }
    if (arg.startsWith("--fail-on=")) {
      const value = arg.slice("--fail-on=".length);
      if (!VALID_FAIL_ON.has(value)) {
        throw new Error("--fail-on must be one of low, medium, high, critical, none");
      }
      options.failOn = value as Severity | "none";
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    }
    options.paths.push(arg);
  }

  return options;
}

function helpText(): string {
  return `mcp-lint

Security lint MCP JSON/JSONC configuration files.

Usage:
  mcp-lint [paths...] [--format text|json|sarif] [--fail-on low|medium|high|critical|none]

Options:
  --format <type>   Output format. Defaults to text.
  --fail-on <sev>   Exit 1 when findings at or above severity exist. Defaults to high.
  --quiet, -q       Suppress success summary for text output.
  --version, -v     Print version.
  --help, -h        Print help.

When no paths are provided, mcp-lint discovers common MCP config files below the current directory.`;
}

function version(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const packageJson = JSON.parse(readFileSync(join(here, "../package.json"), "utf8")) as { version?: string };
  return packageJson.version ?? "0.0.0";
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    }
  );
}
