import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";


const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PHISHGUARD_PLAYWRIGHT ?? "playwright");
const modelFile = process.argv[2] ?? new URL("../models/url-mobile-v2.local.json", import.meta.url);
const reportFile = process.argv[3] ?? "models/mobile-inference-audit.json";
const modelText = await readFile(modelFile, "utf8");
const viteRequire = createRequire(require.resolve("vite/package.json"));
const { build } = viteRequire("esbuild");
const bundle = await build({
  stdin: {
    contents: [
      'export { scanInput } from "./src/scanner.ts";',
      'export { urlFeatures, URL_FEATURES } from "./src/url-features.ts";',
      'export { modelScore } from "./src/url-classifier.ts";',
    ].join("\n"),
    resolveDir: process.cwd(),
  },
  bundle: true,
  minify: true,
  write: false,
  format: "iife",
  globalName: "PhishGuardAudit",
});
const browser = await chromium.launch(process.env.PHISHGUARD_BROWSER_EXECUTABLE
  ? { executablePath: process.env.PHISHGUARD_BROWSER_EXECUTABLE } : {});
try {
  const results = [];
  for (const cpu of [1, 4, 6]) {
    const context = await browser.newContext({ viewport: { width: 375, height: 800 }, isMobile: true, hasTouch: true });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpu });
    await page.setContent("<main>PhishGuard model benchmark</main>");
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    results.push(await page.evaluate(({ model, cpu }) => {
      const audit = globalThis.PhishGuardAudit;
      if (JSON.stringify(audit.URL_FEATURES) !== JSON.stringify(model.features)) throw new Error("Feature mismatch");
      const url = "https://parivahan-gov.in/vehicle-challan";
      const input = "Final warning. " + Array.from({length: 10}, (_, i) =>
        "https://tenant" + i + ".example.com/verify/" + i).join(" ");
      const longMessage = "Routine notification requiring no action. ".repeat(370) + input;
      const urls = Array.from({length: 10}, (_, i) => new URL("https://tenant" + i + ".example.com/verify/" + i));
      const features = audit.urlFeatures(new URL(url), ["brand"]);
      function classify(scan, items) {
        return items.map((item, index) => audit.modelScore(
          audit.urlFeatures(item, scan.links[index].findings.map(finding => finding.id)), model));
      }
      const tasks = {
        oneUrlRules: () => audit.scanInput(url, "url"),
        oneUrlRulesAndModel: () => classify(audit.scanInput(url, "url"), [new URL(url)]),
        tenLinksRulesAndModel: () => classify(audit.scanInput(input, "text"), urls),
        nearLimitMessageRulesAndModel: () => classify(audit.scanInput(longMessage, "text"), urls),
        modelDotOrTreesOnly: () => audit.modelScore(features, model),
      };
      const latency = {};
      for (const [name, fn] of Object.entries(tasks)) {
        for (let i = 0; i < 100; i++) fn();
        const durations = [];
        const batch = name === "modelDotOrTreesOnly" ? 500 : 25;
        for (let i = 0; i < 40; i++) {
          const start = performance.now();
          for (let j = 0; j < batch; j++) fn();
          durations.push((performance.now() - start) / batch);
        }
        durations.sort((a, b) => a - b);
        latency[name] = { medianMs: +durations[19].toFixed(4), p95Ms: +durations[37].toFixed(4) };
      }
      const exampleScore = audit.modelScore(features, model);
      if (!Number.isFinite(exampleScore)) throw new Error("Non-finite inference score");
      return { cpuSlowdown: cpu, latency };
    }, { model: JSON.parse(modelText), cpu }));
    await context.close();
  }
  const report = { browser: browser.version(), modelBytes: Buffer.byteLength(modelText),
    gzipBytes: gzipSync(modelText).length, profiles: results, type: "Desktop Edge mobile viewport and CPU throttling" };
  assert.equal(results.length, 3);
  await writeFile(reportFile, JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report));
} finally {
  await browser.close();
}



