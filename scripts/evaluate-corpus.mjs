import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { writeFile } from "node:fs/promises";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import { parse } from "tldts";
import { RULE_VERSION, scanInput } from "../src/scanner.ts";

const dir = new URL("../datasets/", import.meta.url);
const gzip = createGzip();
const written = pipeline(gzip, createWriteStream(new URL("benchmark.jsonl.gz", dir)));
const lines = createInterface({input: process.stdin, crlfDelay: Infinity});
const stats = {};
const seen = new Set();
const seenUrls = new Set();
let external;
const timed = [];
const digest = (value) => createHash("sha256").update(value).digest("hex");

for await (const line of lines) {
  const { source, input, label, sha256 } = JSON.parse(line);
  if (sha256) {
    if (source === "edgephish") {
      const stream = createGzip();
      external = { stream, written: pipeline(stream, createWriteStream(new URL("edgephish.local.jsonl.gz", dir))) };
    }
    stats[source] = { sha256, sourceRows: 0, duplicates: 0, rows: 0, counts: {} };
    continue;
  }
  const summary = stats[source];
  const mode = source === "sms-spam" ? "text" : "url";
  summary.sourceRows++;
  const id = digest(source + "\0" + input.trim());
  const urlId = mode === "url" ? digest(input.trim()) : null;
  if (seen.has(id) || (source === "edgephish" && seenUrls.has(urlId))) {
    summary.duplicates++;
    continue;
  }
  seen.add(id);
  if (urlId) seenUrls.add(urlId);
  const groupKey = mode === "url" ? (parse(input, {allowPrivateDomains: true}).domain ?? input)
    : input.toLowerCase().replace(/https?:\/\/\S+/g, " url ").replace(/\d+/g, "#").replace(/\s+/g, " ").trim();
  const group = digest(source + "\0" + groupKey).slice(0, 24);
  const split = parseInt(group.slice(0, 8), 16) % 5 === 0 ? "holdout" : "development";
  const start = performance.now();
  const scan = scanInput(input, mode);
  if (summary.rows % 31 === 0) timed.push(performance.now() - start);
  const verdict = scan.status === "ok" ? scan.verdict : "invalid";
  const findings = scan.status === "ok"
    ? [...new Set([...scan.messageFindings, ...scan.links.flatMap(link => link.findings)].map(finding => finding.id))]
    : [];
  const row = { id: id.slice(0, 24), group, source, split, label, verdict, findings,
    score: scan.status === "ok" ? scan.score : null };
  const output = source === "edgephish" ? external.stream : gzip;
  if (!output.write(JSON.stringify(row) + "\n")) await once(output, "drain");
  summary.rows++;
  const counts = summary.counts[split] ??= {};
  const labels = counts[label] ??= {};
  labels[verdict] = (labels[verdict] ?? 0) + 1;
}

gzip.end();
if (external) external.stream.end();
await Promise.all([written, external?.written]);
timed.sort((a, b) => a - b);
const p95 = timed.length ? +timed[Math.ceil(timed.length * 0.95) - 1].toFixed(3) : null;
await writeFile(new URL("benchmark-summary.json", dir),
  JSON.stringify({ ruleVersion: RULE_VERSION, timing: { runtime: process.version, samples: timed.length, p95Ms: p95 }, sources: stats }, null, 2) + "\n");
console.log(JSON.stringify({ sources: Object.fromEntries(Object.entries(stats).map(([key, val]) => [key, val.rows])), p95Ms: p95 }));

