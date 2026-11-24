import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { parse } from "tldts";
import { URL_RULE_VERSION, scanInput } from "../src/scanner.ts";
import { URL_FEATURES, urlFeatures } from "../src/url-features.ts";

const output = createWriteStream(process.argv[2]);
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
const phiDomains = new Set();
const developmentDomains = new Set();
const allSourceDomains = new Set();
const seen = new Set();
const statistics = {};
const digest = input => createHash("sha256").update(input).digest("hex");
let timed = 0;
const milliseconds = [];

async function write(value) {
  if (!output.write(JSON.stringify(value) + "\n")) await once(output, "drain");
}
await write({ version: 1, ruleVersion: URL_RULE_VERSION, features: URL_FEATURES });

for await (const line of lines) {
  const { source, input, label, sha256 } = JSON.parse(line);
  if (sha256) {
    statistics[source] = { sha256, rows: 0, invalid: 0, duplicate: 0, overlappingDomain: 0 };
    continue;
  }
  const counts = statistics[source];
  counts.rows++;
  const raw = input.trim();
  const scan = scanInput(raw, "url");
  if (scan.status !== "ok") {
    counts.invalid++;
    continue;
  }
  const address = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : "https://" + raw;
  if (!URL.canParse(address)) {
    counts.invalid++;
    continue;
  }
  const url = new URL(address);
  const hostname = url.hostname.replace(/\.$/, "").toLowerCase();
  const domain = parse(hostname, { allowPrivateDomains: true }).domain ?? hostname;
  if (source === "hannousse" && allSourceDomains.has(domain)) {
    counts.overlappingDomain++;
    continue;
  }
  if (source !== "hannousse") allSourceDomains.add(domain);
  if (source === "edgephish" && phiDomains.has(domain)) {
    counts.overlappingDomain++;
    continue;
  }
  if (source === "phreshphish" && developmentDomains.has(domain)) {
    counts.overlappingDomain++;
    continue;
  }
  if (source === "phiusiil") phiDomains.add(domain);
  if (source !== "phreshphish") developmentDomains.add(domain);
  url.hash = "";
  url.hostname = hostname;
  const key = url.href;
  if (seen.has(key)) {
    counts.duplicate++;
    continue;
  }
  seen.add(key);
  const slot = parseInt(digest(domain).slice(0, 8), 16) % 100;
  const split = source === "hannousse" ? "hannousse" : source === "phreshphish" ? "phreshphish" : source === "edgephish" ? "external"
    : slot < 70 ? "train" : slot < 85 ? "calibration" : "test";
  const start = performance.now();
  const features = urlFeatures(url, scan.links[0].findings.map(({id}) => id));
  if (++timed % 31 === 0) milliseconds.push(performance.now() - start);
  await write({ split, domainSlot: slot, label: Number(label === "phishing"), baseline: scan.verdict, features });
}
milliseconds.sort((a, b) => a - b);
await write({ statistics, featureTiming: {
  runtime: process.version,
  samples: milliseconds.length,
  p95Ms: milliseconds[Math.ceil(milliseconds.length * 0.95) - 1],
} });
output.end();
await once(output, "finish");
console.log("Feature extraction completed for " + seen.size + " distinct URLs.");



