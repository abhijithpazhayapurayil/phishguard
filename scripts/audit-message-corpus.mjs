import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { RULE_VERSION, scanInput } from "../src/scanner.ts";

const input = process.argv[2];
if (!input) throw new Error("Pass the SMSSpamCollection text file from the UCI archive.");
const seen = new Set();
const counts = { ham: {}, spam: {} };
for await (const line of createInterface({ input: createReadStream(input, { encoding: "utf8" }), crlfDelay: Infinity })) {
  const separator = line.indexOf("\t");
  const label = line.slice(0, separator);
  const text = line.slice(separator + 1);
  if (separator < 0 || !Object.hasOwn(counts, label)) throw new Error("Unknown SMS source format.");
  if (seen.has(text.trim())) continue;
  seen.add(text.trim());
  const result = scanInput(text, "text");
  const verdict = result.status === "ok" ? result.verdict : "invalid";
  counts[label][verdict] = (counts[label][verdict] ?? 0) + 1;
}
const fixtures = JSON.parse(await readFile(new URL("../datasets/regional-fixtures.json", import.meta.url), "utf8"));
const regional = {};
for (const {category, label, input: message, verdict} of fixtures) {
  const result = scanInput(message, "text");
  const group = regional[category] ??= { checked: 0, matched: 0 };
  group.checked++;
  if (result.status === "ok" && result.verdict === verdict) group.matched++;
}
const report = { ruleVersion: RULE_VERSION, deduplicatedSmsRows: seen.size, spamHamVerdicts: counts, regionalSyntheticFixtures: regional };
await writeFile(new URL("../models/message-classification-audit.json", import.meta.url), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report));

