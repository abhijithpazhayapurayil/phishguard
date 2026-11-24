import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PHISHGUARD_PLAYWRIGHT ?? "playwright");

const base = "http://127.0.0.1:4187/";
const modelAdvisorySample = "https://id.sample-portal.example.com/verify/record/25?ref=12345";
const reportFile = process.argv[2] ?? "models/phone-flow-audit.json";
const server = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "preview", "--outDir", "dist/client",
  "--host", "127.0.0.1", "--port", "4187", "--strictPort"], { stdio: "ignore", windowsHide: true });

function percentiles(times) {
  const sorted = [...times].sort((a, b) => a - b);
  const percentile = p => +sorted[Math.ceil(sorted.length * p) - 1].toFixed(1);
  return { samples: times.length, medianMs: percentile(.5), p95Ms: percentile(.95), maxMs: percentile(1) };
}

function elapsed(start) {
  return +(performance.now() - start).toFixed(1);
}

let browser;
try {
  for (let attempt = 0; ; attempt++) {
    if (server.exitCode !== null || attempt >= 40) throw new Error("Preview server unavailable.");
    if (await fetch(base).then(response => response.ok, () => false)) break;
    await delay(250);
  }
  const executablePath = process.env.PHISHGUARD_BROWSER_EXECUTABLE;
  browser = await chromium.launch(executablePath ? { executablePath } : {});
  const report = { browser: browser.version(), profiles: [] };
  for (const cpu of [1, 4]) {
    const context = await browser.newContext({
      viewport: { width: 375, height: 800 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, reducedMotion: "reduce",
    });
    // The Windows test host injects this antivirus script into local HTTP pages.
    const antivirusHost = "me.kis.v2.scr.kaspersky-labs.com";
    await context.route(url => url.hostname === antivirusHost, route => route.abort());
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpu });
    await cdp.send("Network.enable");
    await cdp.send("Network.emulateNetworkConditions", {
      offline: false, latency: 80, downloadThroughput: 1_000_000, uploadThroughput: 250_000,
    });
    const exceptions = [];
    page.on("pageerror", error => exceptions.push(error.message));
    const requests = [];
    context.on("request", request => {
      if (new URL(request.url()).hostname !== antivirusHost) requests.push({ url: request.url(), method: request.method() });
    });
    const start = performance.now();
    await page.goto(base);
    await page.getByRole("heading", { name: "PhishGuard" }).waitFor();
    const coldLoadToHeadingMs = elapsed(start);
    const manifest = await page.evaluate(async () => (await fetch("manifest.webmanifest")).json());
    assert.equal(manifest.display, "standalone");
    assert.ok(manifest.icons.some(icon => icon.sizes === "192x192"));
    assert.ok(manifest.icons.some(icon => icon.sizes === "512x512"));
    await page.evaluate(() => Promise.race([
      navigator.serviceWorker.ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Service worker did not become ready")), 15000)),
    ]));
    await page.reload();
    await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 375);
    assert.ok(!requests.some(({url}) => url.includes("/ocr/v1/")));
    assert.ok(!requests.some(({url}) => url.includes("/api/explain")));

    const scans = {};
    for (const sample of [
      { name: "oneUrl", mode: "URL", label: "URL to check", input: "hxxps://parivahan-gov[.]in/vehicle-challan", verdict: "Suspicious" },
      { name: "offlineModelAdvisory", mode: "URL", label: "URL to check", input: modelAdvisorySample, verdict: "Inconclusive" },
      { name: "messageWithLinks", mode: "Message", label: "Message to check",
        input: "India Post: Final warning. Pay the redelivery fee and forward OTP. https://example.com/ and https://bit.ly/fixture-only.",
        verdict: "High risk" },
      { name: "boundedLargeMessage", mode: "Message", label: "Message to check",
        input: ("This is a routine reminder. ".repeat(420)) + Array.from({length: 11}, (_, i) => " https://example.com/" + i).join(""),
        verdict: "Inconclusive" },
    ]) {
      await page.getByText(sample.mode, { exact: true }).click();
      const before = requests.length;
      const times = [];
      for (let i = 0; i < 13; i++) {
        const field = page.getByLabel(sample.label);
        await field.fill("");
        await field.fill(sample.input);
        const time = await page.evaluate(() => new Promise((resolve, reject) => {
          const panel = document.querySelector(".inspection");
          const begin = performance.now();
          const observer = new MutationObserver(() => {
            if (!panel.querySelector(".verdict-banner")) return;
            observer.disconnect();
            clearTimeout(timeout);
            requestAnimationFrame(() => resolve(performance.now() - begin));
          });
          const timeout = setTimeout(() => { observer.disconnect(); reject(new Error("No scan update")); }, 5000);
          observer.observe(panel, { childList: true, subtree: true });
          document.querySelector("button[type='submit']").click();
        }));
        if (i > 0) times.push(time);
      }
      await page.getByRole("heading", { name: sample.verdict, exact: true }).waitFor();
      assert.equal(requests.length, before, "Local scans issued a request");
      assert.equal(await page.locator(".scan-result a").count(), 0);
      scans[sample.name] = percentiles(times);
    }

    await page.getByLabel("Message to check").fill("é".repeat(9000));
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await page.locator(".input-error").getByText("Input exceeds the 16 KiB scan limit.", { exact: true }).waitFor();

    await page.getByText("Message", { exact: true }).click();
    await page.getByLabel("Message to check").fill("Share your OTP 123456 to continue. https://example.com/private-token");
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await page.getByText("Online explanation with Gemini", { exact: true }).click();
    const outbound = page.waitForRequest(req => req.url().endsWith("/api/explain"));
    await page.getByRole("button", { name: "Send these findings" }).click();
    const geminiPayload = (await outbound).postDataJSON();
    assert.deepEqual(Object.keys(geminiPayload).sort(), ["findings", "verdict"]);
    assert.deepEqual(geminiPayload.findings, ["coercion"]);
    assert.doesNotMatch(JSON.stringify(geminiPayload), /123456|private-token|example\.com/);

    await page.getByText("Screenshot", { exact: true }).click();
    const uploader = page.getByLabel("Upload or paste a screenshot");
    await uploader.setInputFiles({ name: "bad.png", mimeType: "image/png", buffer: Buffer.from("invalid") });
    await page.getByText("Choose a readable PNG or JPEG screenshot.", { exact: true }).waitFor();
    const image = await page.evaluate(() => {
      const canvas = document.createElement("canvas");
      canvas.width = 1080; canvas.height = 320;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#fff"; ctx.fillRect(0,0,1080,320);
      ctx.fillStyle = "#000"; ctx.font = "42px Arial";
      ctx.fillText("India Post: Final warning.", 40, 75);
      ctx.fillText("Pay the redelivery fee and forward OTP.", 40, 145);
      return { png: canvas.toDataURL("image/png").split(",")[1], jpg: canvas.toDataURL("image/jpeg").split(",")[1] };
    });
    const pictures = {
      png: { name: "receipt.png", mimeType: "image/png", buffer: Buffer.from(image.png, "base64") },
      jpg: { name: "receipt.jpg", mimeType: "image/jpeg", buffer: Buffer.from(image.jpg, "base64") },
    };
    const ocr = {};
    const coldStart = performance.now();
    await uploader.setInputFiles(pictures.png);
    await page.waitForFunction(() => /forward OTP/i.test(document.querySelector("#scan-input").value), null, {timeout: 40000});
    ocr.englishPngColdMs = elapsed(coldStart);
    const crossOrigin = requests.filter(({url}) => /^https?:/i.test(url) && !url.startsWith(base));
    assert.deepEqual([...new Set(crossOrigin.map(({url}) => new URL(url).origin))], [], "Image path contacted an external origin");
    await page.getByLabel("Extracted text").fill("Never forward your OTP.");
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await page.getByRole("heading", { name: "No warning signs found in completed checks" }).waitFor();

    const warmStart = performance.now();
    await uploader.setInputFiles(pictures.jpg);
    await page.waitForFunction(() => /forward OTP/i.test(document.querySelector("#scan-input").value), null, {timeout: 40000});
    ocr.englishJpegWarmMs = elapsed(warmStart);

    await uploader.setInputFiles(pictures.png);
    await page.getByRole("button", { name: "Cancel OCR" }).click();
    await page.getByText("Screenshot reading canceled.", { exact: true }).waitFor();
    assert.equal(await page.getByLabel("Extracted text").inputValue(), "");

    await page.getByLabel("Screenshot language").selectOption("hin");
    const hindiStart = performance.now();
    await page.getByRole("group", { name: "Screenshot upload and paste area" }).evaluate(node => {
      const canvas = document.createElement("canvas");
      canvas.width = 1080; canvas.height = 300;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#fff"; ctx.fillRect(0,0,1080,300);
      ctx.fillStyle = "#000"; ctx.font = "58px Nirmala UI";
      ctx.fillText("बिजली बोर्ड",45,90); ctx.fillText("बिजली कट जाएगी",45,180);
      canvas.toBlob(blob => {
        const data = new DataTransfer();
        data.items.add(new File([blob], "hindi.png", {type: "image/png"}));
        node.dispatchEvent(new ClipboardEvent("paste", {bubbles: true, cancelable: true, clipboardData: data}));
      });
    });
    await page.waitForFunction(() => /बिजली/.test(document.querySelector("#scan-input").value), null, {timeout: 40000});
    ocr.hindiPasteMs = elapsed(hindiStart);

    await page.getByLabel("Screenshot language").selectOption("eng");
    await cdp.send("Network.emulateNetworkConditions", {
      offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0,
    });
    await context.setOffline(true);
    assert.equal(await page.evaluate(() => navigator.onLine), false);
    const offlineStart = performance.now();
    await uploader.setInputFiles(pictures.png);
    await page.waitForFunction(() => /forward OTP/i.test(document.querySelector("#scan-input").value), null, {timeout: 40000});
    ocr.englishOfflineMs = elapsed(offlineStart);
    await page.reload();
    await page.getByLabel("URL to check").fill(modelAdvisorySample);
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await page.getByText("The on-device model recommends verifying at least one link independently.", { exact: true }).waitFor();
    assert.doesNotMatch(await page.locator(".scan-result").innerText(), /12345/);
    await page.getByLabel("URL to check").fill("example.com");
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await page.getByRole("heading", { name: "No warning signs found in completed checks" }).waitFor();
    await page.getByText("Online explanation with Gemini", { exact: true }).click();
    await page.getByRole("button", { name: "Send these findings" }).click();
    await page.getByText("Online explanation is unavailable. The local verdict still applies.", { exact: true }).waitFor();
    assert.deepEqual(exceptions, []);
    report.profiles.push({ cpuSlowdown: cpu, viewport: "375×800", network: "80 ms, 8 Mbps down, 2 Mbps up",
      coldLoadToHeadingMs, scans, ocr, checked: [
        "manifest, icons and service-worker control", "zero requests during local scan", "defanged and inert URLs",
        "mixed multi-link verdict and bounded large input", "private-data-free Gemini request",
        "offline Gemini failure leaves verdict visible", "invalid image",
        "English PNG and JPEG", "corrected OCR text", "OCR cancel",
        "Hindi clipboard image", "offline OCR, classifier advisory and reload", "reduced motion and single-column fit",
      ] });
    console.log(JSON.stringify(report.profiles.at(-1)));
    await context.close();
  }
  await mkdir("models", {recursive: true});
  await writeFile(reportFile, JSON.stringify(report, null, 2) + "\n");
} finally {
  try { await browser?.close(); }
  finally { server.kill(); }
}
