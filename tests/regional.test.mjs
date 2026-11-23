import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";
import { scanInput } from "../src/scanner.ts";

const fixtures = JSON.parse(readFileSync(new URL("../datasets/regional-fixtures.json", import.meta.url), "utf8"));
for (const [index, fixture] of fixtures.entries()) {
  test(`${fixture.category} ${fixture.label} fixture ${index + 1}`, () => {
    const result = scanInput(fixture.input, "text");
    assert.equal(result.status, "ok");
    assert.equal(result.verdict, fixture.verdict);
  });
}
