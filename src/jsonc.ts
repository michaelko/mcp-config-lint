import { readFile } from "node:fs/promises";
import type { ParsedConfig } from "./types.js";

export async function parseConfigFile(filePath: string): Promise<ParsedConfig> {
  const raw = await readFile(filePath, "utf8");
  try {
    return { filePath, value: JSON.parse(stripJsonComments(raw)), errors: [] };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { filePath, value: undefined, errors: [message] };
  }
}

export function stripJsonComments(input: string): string {
  let output = "";
  let inString = false;
  let quote = "";
  let escaped = false;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index] ?? "";
    const next = input[index + 1] ?? "";

    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        inString = false;
        quote = "";
      }
      continue;
    }

    if (char === "\"" || char === "'") {
      inString = true;
      quote = char;
      output += char;
      continue;
    }

    if (char === "/" && next === "/") {
      while (index < input.length && input[index] !== "\n") {
        index += 1;
      }
      output += "\n";
      continue;
    }

    if (char === "/" && next === "*") {
      index += 2;
      while (index < input.length && !(input[index] === "*" && input[index + 1] === "/")) {
        output += input[index] === "\n" ? "\n" : " ";
        index += 1;
      }
      index += 1;
      continue;
    }

    output += char;
  }

  return removeTrailingCommas(output);
}

function removeTrailingCommas(input: string): string {
  let output = "";
  let inString = false;
  let quote = "";
  let escaped = false;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index] ?? "";

    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        inString = false;
        quote = "";
      }
      continue;
    }

    if (char === "\"" || char === "'") {
      inString = true;
      quote = char;
      output += char;
      continue;
    }

    if (char === ",") {
      let cursor = index + 1;
      while (/\s/.test(input[cursor] ?? "")) {
        cursor += 1;
      }
      if (input[cursor] === "}" || input[cursor] === "]") {
        continue;
      }
    }

    output += char;
  }

  return output;
}
