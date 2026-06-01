import { describe, expect, it } from "vitest";
import { stripJsonComments } from "../src/jsonc.js";

describe("stripJsonComments", () => {
  it("removes comments and trailing commas without changing strings", () => {
    const input = `{
      // comment
      "url": "https://example.com//literal",
      "items": ["a", "b",],
    }`;

    expect(JSON.parse(stripJsonComments(input))).toEqual({
      url: "https://example.com//literal",
      items: ["a", "b"]
    });
  });
});
