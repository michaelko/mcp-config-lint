import { lstat, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const CONFIG_FILE_NAMES = new Set([
  "mcp.json",
  ".mcp.json",
  ".mcp.jsonc",
  "mcp.jsonc",
  "mcp.config.json",
  "mcp.config.jsonc",
  "mcp-config.json",
  "mcp-config.jsonc",
  "claude_desktop_config.json",
  "claude_desktop_config.jsonc"
]);

const CONFIG_PATH_SUFFIXES = [
  ".cursor/mcp.json",
  ".cursor/mcp.jsonc",
  ".vscode/mcp.json",
  ".vscode/mcp.jsonc",
  ".vscode/settings.json",
  ".vscode/settings.jsonc",
  ".windsurf/mcp_config.json",
  ".continue/mcpServers.json",
  ".continue/config.json",
  ".continue/config.jsonc"
];

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".cache"
]);

export async function discoverConfigFiles(paths: string[], cwd = process.cwd()): Promise<string[]> {
  const seeds = paths.length > 0 ? paths : [cwd];
  const found = new Set<string>();
  const includeAllJson = paths.length > 0;

  for (const seed of seeds) {
    const absolute = resolve(cwd, seed);
    const stat = await safeLstat(absolute);
    if (!stat) {
      continue;
    }
    if (stat.isFile()) {
      found.add(absolute);
      continue;
    }
    if (stat.isDirectory()) {
      await walkDirectory(absolute, found, absolute, includeAllJson);
    }
  }

  return [...found].sort();
}

async function walkDirectory(dir: string, found: Set<string>, root: string, includeAllJson: boolean): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        await walkDirectory(fullPath, found, root, includeAllJson);
      }
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const relative = fullPath.slice(root.length + 1).replaceAll("\\", "/");
    if (
      (includeAllJson && /\.(?:json|jsonc)$/i.test(entry.name))
      || CONFIG_FILE_NAMES.has(entry.name)
      || CONFIG_PATH_SUFFIXES.includes(relative)
    ) {
      found.add(fullPath);
    }
  }
}

async function safeLstat(path: string) {
  try {
    return await lstat(path);
  } catch {
    return undefined;
  }
}
