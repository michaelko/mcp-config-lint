import type { ServerDefinition } from "./types.js";

export function extractServers(value: unknown, sourcePath = ""): ServerDefinition[] {
  const servers: ServerDefinition[] = [];
  visit(value, "", servers, sourcePath.replaceAll("\\", "/"));
  return dedupeServers(servers);
}

function visit(value: unknown, pointer: string, servers: ServerDefinition[], sourcePath: string): void {
  if (!isRecord(value)) {
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    const childPointer = `${pointer}/${escapePointer(key)}`;
    if ((key === "mcpServers" || isVsCodeServersObject(key, childPointer, sourcePath)) && isRecord(child)) {
      collectServerMap(child, childPointer, servers);
      continue;
    }
    visit(child, childPointer, servers, sourcePath);
  }
}

function collectServerMap(value: Record<string, unknown>, pointer: string, servers: ServerDefinition[]): void {
  for (const [serverName, serverValue] of Object.entries(value)) {
    if (isRecord(serverValue)) {
      servers.push({
        name: serverName,
        pointer: `${pointer}/${escapePointer(serverName)}`,
        value: serverValue
      });
    }
  }
}

function isVsCodeServersObject(key: string, pointer: string, sourcePath: string): boolean {
  if (key !== "servers") {
    return false;
  }
  if (pointer === "/servers" && /(?:^|\/)(?:\.vscode\/)?mcp\.jsonc?$/.test(sourcePath)) {
    return true;
  }
  return pointer.endsWith("/customizations/vscode/mcp/servers");
}

function dedupeServers(servers: ServerDefinition[]): ServerDefinition[] {
  const seen = new Set<string>();
  return servers.filter((server) => {
    const key = `${server.pointer}:${server.name}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  if (typeof value === "string") {
    return [value];
  }
  return [];
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}
