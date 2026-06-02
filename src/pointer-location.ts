import { stripJsonComments } from "./jsonc.js";

type TokenType = "{" | "}" | "[" | "]" | ":" | "," | "string" | "primitive";

interface Token {
  type: TokenType;
  line: number;
  value?: string;
}

export function buildJsonPointerLineMap(input: string): Map<string, number> {
  const tokens = tokenize(stripJsonComments(input));
  let cursor = 0;
  const locations = new Map<string, number>([["", 1]]);

  parseValue("");
  return locations;

  function parseValue(pointer: string): void {
    const token = tokens[cursor];
    if (!token) {
      return;
    }
    if (token.type === "{") {
      parseObject(pointer);
      return;
    }
    if (token.type === "[") {
      parseArray(pointer);
      return;
    }
    cursor += 1;
  }

  function parseObject(pointer: string): void {
    cursor += 1;
    while (cursor < tokens.length && tokens[cursor]?.type !== "}") {
      const keyToken = tokens[cursor];
      if (!keyToken || keyToken.type !== "string" || keyToken.value === undefined) {
        cursor += 1;
        continue;
      }

      const childPointer = appendPointer(pointer, keyToken.value);
      locations.set(childPointer, keyToken.line);
      cursor += 1;

      if (tokens[cursor]?.type === ":") {
        cursor += 1;
      }
      parseValue(childPointer);

      if (tokens[cursor]?.type === ",") {
        cursor += 1;
      }
    }

    if (tokens[cursor]?.type === "}") {
      cursor += 1;
    }
  }

  function parseArray(pointer: string): void {
    cursor += 1;
    let index = 0;
    while (cursor < tokens.length && tokens[cursor]?.type !== "]") {
      const token = tokens[cursor];
      if (!token) {
        return;
      }
      const childPointer = appendPointer(pointer, String(index));
      locations.set(childPointer, token.line);
      parseValue(childPointer);
      index += 1;

      if (tokens[cursor]?.type === ",") {
        cursor += 1;
      }
    }

    if (tokens[cursor]?.type === "]") {
      cursor += 1;
    }
  }
}

export function lineForPointer(pointer: string, locations: Map<string, number>): number | undefined {
  if (locations.has(pointer)) {
    return locations.get(pointer);
  }

  let candidate = pointer;
  while (candidate.includes("/")) {
    candidate = candidate.slice(0, candidate.lastIndexOf("/"));
    if (locations.has(candidate)) {
      return locations.get(candidate);
    }
  }

  return locations.get("");
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let line = 1;
  let cursor = 0;

  while (cursor < input.length) {
    const char = input[cursor] ?? "";
    if (char === "\n") {
      line += 1;
      cursor += 1;
      continue;
    }
    if (/\s/.test(char)) {
      cursor += 1;
      continue;
    }
    if (isPunctuation(char)) {
      tokens.push({ type: char, line });
      cursor += 1;
      continue;
    }
    if (char === "\"" || char === "'") {
      const result = readString(input, cursor, line);
      tokens.push({ type: "string", line, value: result.value });
      line = result.line;
      cursor = result.cursor;
      continue;
    }

    const startLine = line;
    while (cursor < input.length && !/\s/.test(input[cursor] ?? "") && !isPunctuation(input[cursor] ?? "")) {
      cursor += 1;
    }
    tokens.push({ type: "primitive", line: startLine });
  }

  return tokens;
}

function readString(input: string, start: number, line: number): { value: string; cursor: number; line: number } {
  const quote = input[start] ?? "\"";
  let cursor = start + 1;
  let escaped = false;
  let raw = "";

  while (cursor < input.length) {
    const char = input[cursor] ?? "";
    if (char === "\n") {
      line += 1;
    }
    if (escaped) {
      raw += `\\${char}`;
      escaped = false;
      cursor += 1;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      cursor += 1;
      continue;
    }
    if (char === quote) {
      cursor += 1;
      break;
    }
    raw += char;
    cursor += 1;
  }

  return { value: decodeString(raw, quote), cursor, line };
}

function decodeString(raw: string, quote: string): string {
  if (quote === "\"") {
    try {
      return JSON.parse(`"${raw}"`) as string;
    } catch {
      return raw;
    }
  }
  return raw.replaceAll("\\'", "'");
}

function isPunctuation(value: string): value is "{" | "}" | "[" | "]" | ":" | "," {
  return value === "{" || value === "}" || value === "[" || value === "]" || value === ":" || value === ",";
}

function appendPointer(parent: string, segment: string): string {
  return `${parent}/${segment.replaceAll("~", "~0").replaceAll("/", "~1")}`;
}
