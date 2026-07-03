import type { Finding, ServerDefinition, Severity } from "./types.js";
import { asStringArray, isRecord } from "./server-extractor.js";

type Rule = (server: ServerDefinition, filePath: string) => Finding[];

const SHELLS = new Set(["sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"]);
const SENSITIVE_KEY = /(token|secret|password|passwd|api[_-]?key|auth|credential|private[_-]?key)/i;
const URL_PATTERN = /https?:\/\/[^\s"'`]+/gi;
const ENV_EXPANSION = /\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%/g;
const COMMAND_SUBSTITUTION = /\$\([^)]*\)|`[^`]+`/;

export const rules: Rule[] = [
  requireRunnableTarget,
  detectShellExecution,
  detectRemoteFetchExecution,
  detectUnpinnedPackageExecution,
  detectHardcodedSecrets,
  detectBroadFilesystemAccess,
  detectInsecureRemoteUrl,
  detectRiskyEnvExpansion
];

function requireRunnableTarget(server: ServerDefinition, filePath: string): Finding[] {
  if (typeof server.value.command === "string" || typeof server.value.url === "string") {
    return [];
  }
  return [
    finding(filePath, server, "MCP001", "Missing runnable target", "high", "Server does not define a command or url, which makes review and runtime behavior ambiguous.", "Define an explicit command for local servers or an explicit HTTPS url for remote servers.")
  ];
}

function detectShellExecution(server: ServerDefinition, filePath: string): Finding[] {
  const command = basename(String(server.value.command ?? ""));
  const args = asStringArray(server.value.args);
  if (!SHELLS.has(command)) {
    return [];
  }

  const hasInlineScript = args.some((arg) => arg === "-c" || arg === "/c" || arg.includes(";") || arg.includes("&&") || arg.includes("|"));
  return [
    finding(filePath, server, "MCP002", "Shell execution", hasInlineScript ? "critical" : "high", `Server launches through ${command}${hasInlineScript ? " with inline shell syntax" : ""}.`, "Replace shell wrappers with direct executable arguments, or pin and document the command path.", joinedCommand(server), `${server.pointer}/command`)
  ];
}

function detectRemoteFetchExecution(server: ServerDefinition, filePath: string): Finding[] {
  const joined = joinedCommand(server);
  const risky = /(curl|wget)\b[\s\S]*(\||bash|sh|zsh|powershell|pwsh)|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[\s\S]*(iex|Invoke-Expression)/i.test(joined);
  if (!risky) {
    return [];
  }
  return [
    finding(filePath, server, "MCP003", "Remote fetch execution", "critical", "Server appears to download remote content and execute it.", "Vendor the server, pin a package version, or install through a reviewed package manager step outside the MCP config.", redact(joined), `${server.pointer}/args`)
  ];
}

function detectUnpinnedPackageExecution(server: ServerDefinition, filePath: string): Finding[] {
  const command = basename(String(server.value.command ?? ""));
  const args = asStringArray(server.value.args);
  const findings: Finding[] = [];

  if (["npx", "pnpm", "yarn", "bunx", "uvx"].includes(command)) {
    const candidate = firstPackageArg(command, args);
    if (candidate && !isPinnedPackage(candidate)) {
      findings.push(finding(filePath, server, "MCP004", "Unpinned package execution", "high", `Server runs ${candidate} through ${command} without an explicit version or immutable ref.`, "Pin packages with an immutable version, commit SHA, digest, or reviewed local path.", candidate, `${server.pointer}/args`));
    }
  }

  if (command === "docker" || command === "podman") {
    const image = firstContainerImage(args);
    if (image && !isPinnedImage(image)) {
      findings.push(finding(filePath, server, "MCP005", "Unpinned container image", "high", `Server runs container image ${image} without a stable tag or digest.`, "Use a specific version tag or immutable digest for container images.", image, `${server.pointer}/args`));
    }
  }

  return findings;
}

function detectHardcodedSecrets(server: ServerDefinition, filePath: string): Finding[] {
  const findings: Finding[] = [];

  for (const containerName of ["env", "environment", "headers"] as const) {
    const container = server.value[containerName];
    if (!isRecord(container)) {
      continue;
    }
    const entries = collectStringEntries(container, `${server.pointer}/${containerName}`);
    for (const entry of entries) {
      if (!SENSITIVE_KEY.test(entry.key)) {
        continue;
      }
      if (entry.value && !isVariableReference(entry.value) && entry.value.length > 6) {
        findings.push(finding(filePath, server, "MCP006", "Hardcoded secret", "critical", `Sensitive key ${entry.key} appears to contain a literal value.`, "Read secrets from environment variables or a dedicated secret manager; do not commit literal credentials.", `${entry.key}=${redactSecret(entry.value)}`, entry.pointer));
      }
    }
  }

  const args = asStringArray(server.value.args);
  for (const [index, arg] of args.entries()) {
    if (SENSITIVE_KEY.test(arg) && /[:=][^$%{\s][^\s]+/.test(arg)) {
      findings.push(finding(filePath, server, "MCP007", "Secret-like CLI argument", "high", `Argument ${redact(arg)} looks like a hardcoded credential.`, "Pass credential references through environment variables instead of command arguments.", redact(arg), `${server.pointer}/args/${index}`));
    }
  }

  return findings;
}

function detectBroadFilesystemAccess(server: ServerDefinition, filePath: string): Finding[] {
  const args = asStringArray(server.value.args);
  const env = isRecord(server.value.env) ? Object.values(server.value.env).filter((value): value is string => typeof value === "string") : [];
  const values = [...args, ...env, typeof server.value.cwd === "string" ? server.value.cwd : ""].filter(Boolean);
  const broad = values.find((value) => isBroadFilesystemGrant(value));
  if (!broad) {
    return [];
  }
  return [
    finding(filePath, server, "MCP008", "Broad filesystem access", "high", `Server is configured with broad filesystem access: ${broad}.`, "Limit filesystem access to the smallest project directory required by the server.", broad)
  ];
}

function detectInsecureRemoteUrl(server: ServerDefinition, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const entries = collectServerStringValues(server);
  for (const entry of entries) {
    const urls = entry.value.match(URL_PATTERN) ?? [];
    for (const url of urls) {
      if (url.startsWith("http://") && !/^http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::|\/|$)/.test(url)) {
        findings.push(finding(filePath, server, "MCP009", "Insecure remote URL", "high", `Server references non-TLS URL ${url}.`, "Use HTTPS for remote MCP endpoints and package sources.", url, entry.pointer));
      }
    }
  }
  return findings;
}

function detectRiskyEnvExpansion(server: ServerDefinition, filePath: string): Finding[] {
  const findings: Finding[] = [];

  for (const entry of collectServerStringValues(server)) {
    if (COMMAND_SUBSTITUTION.test(entry.value)) {
      findings.push(finding(filePath, server, "MCP010", "Risky environment expansion", "critical", "Server configuration contains shell command substitution syntax.", "Remove command substitution from MCP config values and compute required values in a reviewed setup step.", entry.value, entry.pointer));
      continue;
    }

    const expansions = extractEnvExpansions(entry.value);
    if (expansions.length === 0) {
      continue;
    }

    const sensitive = SENSITIVE_KEY.test(entry.key) || expansions.some((name) => SENSITIVE_KEY.test(name));
    findings.push(finding(
      filePath,
      server,
      "MCP010",
      "Risky environment expansion",
      sensitive ? "medium" : "low",
      sensitive
        ? `Sensitive value ${entry.key} expands host environment variable ${expansions[0]}.`
        : `Value ${entry.key} expands host environment variable ${expansions[0]}.`,
      "Keep environment expansion explicit, documented, and limited to values the server truly needs.",
      entry.value,
      entry.pointer
    ));
  }

  return findings;
}

function finding(filePath: string, server: ServerDefinition, ruleId: string, title: string, severity: Severity, message: string, recommendation: string, context?: string, pointer = server.pointer): Finding {
  const result: Finding = {
    ruleId,
    title,
    severity,
    message,
    filePath,
    serverName: server.name,
    pointer,
    recommendation
  };
  if (context) {
    result.context = context;
  }
  return result;
}

function joinedCommand(server: ServerDefinition): string {
  return [server.value.command, ...asStringArray(server.value.args)].filter((value): value is string => typeof value === "string").join(" ");
}

function basename(command: string): string {
  const normalized = command.replaceAll("\\", "/");
  return normalized.slice(normalized.lastIndexOf("/") + 1).toLowerCase();
}

function firstPackageArg(command: string, args: string[]): string | undefined {
  const skip = new Set(["-y", "--yes", "dlx", "exec", "--package", "-p"]);
  for (const arg of args) {
    if (arg.startsWith("-") || skip.has(arg)) {
      continue;
    }
    if (command === "pnpm" && ["dlx", "exec"].includes(arg)) {
      continue;
    }
    if (command === "yarn" && ["dlx"].includes(arg)) {
      continue;
    }
    return arg;
  }
  return undefined;
}

function firstContainerImage(args: string[]): string | undefined {
  const runIndex = args.findIndex((arg) => arg === "run");
  if (runIndex === -1) {
    return undefined;
  }
  for (let index = runIndex + 1; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg.startsWith("-")) {
      if (["-v", "--volume", "-e", "--env", "-p", "--publish", "--name"].includes(arg)) {
        index += 1;
      }
      continue;
    }
    return arg;
  }
  return undefined;
}

function isPinnedImage(value: string): boolean {
  if (value.includes("@sha256:")) {
    return true;
  }
  const imageName = value.split("/").pop() ?? value;
  const tagIndex = imageName.lastIndexOf(":");
  if (tagIndex === -1) {
    return false;
  }
  const tag = imageName.slice(tagIndex + 1);
  return tag.length > 0 && !/^(latest|main|master|edge|dev)$/i.test(tag);
}

function isPinnedPackage(value: string): boolean {
  if (value.startsWith(".") || value.startsWith("/")) {
    return true;
  }
  if (isGitOrUrlPackageSpec(value)) {
    return hasImmutableGitOrUrlRef(value);
  }
  const withoutScope = value.startsWith("@") ? value.slice(1) : value;
  return /@(?:\d+\.\d+\.\d+|[a-f0-9]{7,}|sha256:|v?\d)/i.test(withoutScope);
}

function isGitOrUrlPackageSpec(value: string): boolean {
  return /^(?:git\+)?https?:\/\//i.test(value) || /^github:[^/]+\/[^#]+/i.test(value) || /^git(?:\+ssh)?:/i.test(value) || /^git@/i.test(value);
}

function hasImmutableGitOrUrlRef(value: string): boolean {
  if (/sha256:[a-f0-9]{32,}/i.test(value)) {
    return true;
  }

  const fragment = value.includes("#") ? value.slice(value.lastIndexOf("#") + 1) : "";
  if (isStableRef(fragment)) {
    return true;
  }

  return /(?:\/|%2F)(?:refs\/tags\/)?v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?(?:[/?#.]|$)/i.test(value)
    || /(?:\/|%2F)[a-f0-9]{7,40}(?:[/?#.]|$)/i.test(value);
}

function isStableRef(value: string): boolean {
  return /^[a-f0-9]{7,40}$/i.test(value) || /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/i.test(value);
}

function isVariableReference(value: string): boolean {
  return /^\$[A-Z_][A-Z0-9_]*$/i.test(value) || /^\$\{(?:env:)?[A-Z_][A-Z0-9_]*\}$/i.test(value) || /^%[A-Z_][A-Z0-9_]*%$/i.test(value);
}

function redact(value: string): string {
  return value.replace(/([:=]).+$/, "$1<redacted>");
}

function redactSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 6) {
    return "<redacted>";
  }
  return `${trimmed.slice(0, 2)}...${trimmed.slice(-2)}`;
}

function collectServerStringValues(server: ServerDefinition): Array<{ key: string; value: string; pointer: string }> {
  return collectStringEntries(server.value, server.pointer);
}

function collectStringEntries(value: unknown, pointer: string, key = "server", depth = 0): Array<{ key: string; value: string; pointer: string }> {
  if (depth > 8) {
    return [];
  }
  if (typeof value === "string") {
    return [{ key, value, pointer }];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectStringEntries(item, `${pointer}/${index}`, String(index), depth + 1));
  }
  if (!isRecord(value)) {
    return [];
  }
  return Object.entries(value).flatMap(([childKey, child]) => collectStringEntries(child, `${pointer}/${escapePointer(childKey)}`, childKey, depth + 1));
}

function extractEnvExpansions(value: string): string[] {
  const names: string[] = [];
  for (const match of value.matchAll(ENV_EXPANSION)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (name) {
      names.push(name);
    }
  }
  return names;
}

function isBroadFilesystemGrant(value: string): boolean {
  const trimmed = value.trim().replace(/^["']|["']$/g, "");
  return /^\/$|^~\/?$|^\$HOME$|^\$\{HOME\}$|^%USERPROFILE%$/i.test(trimmed)
    || /^(\/|~|\$HOME|\$\{HOME\}|[A-Za-z]:[\\/]):/.test(trimmed)
    || /(?:--root|--dir|--directory|--path|--workspace|--allow(?:ed)?-?(?:dir|directory|path)|--volume|--mount)=(\/|~|\$HOME|\$\{HOME\}|[A-Za-z]:[\\/])/i.test(trimmed)
    || /(?:^|,)(?:source|src)=\/(?:,|$)/i.test(trimmed)
    || /^\/(?:Users|home|var|etc|private)\/?$/i.test(trimmed)
    || /^[A-Za-z]:[\\/]?$/.test(trimmed);
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}
