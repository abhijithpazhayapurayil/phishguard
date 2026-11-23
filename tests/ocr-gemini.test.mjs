import assert from "node:assert/strict";
import test from "node:test";
import { imageDimensions } from "../src/image-bounds.ts";
import { scanInput } from "../src/scanner.ts";
import { geminiPlugin, parseExplanation, validateEvidence } from "../scripts/gemini.mjs";

function pngHeader(width, height) {
  const bytes = new Uint8Array(24);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  bytes.set([73, 72, 68, 82], 12);
  const view = new DataView(bytes.buffer);
  view.setUint32(16, width);
  view.setUint32(20, height);
  return bytes.buffer;
}

test("image metadata rejects invalid or oversized dimensions before image decoding", () => {
  assert.deepEqual(imageDimensions(pngHeader(1080, 1920)), { width: 1080, height: 1920 });
  assert.throws(() => imageDimensions(pngHeader(8000, 8000)), /too large/);
  assert.throws(() => imageDimensions(new ArrayBuffer(6)), /readable PNG or JPEG/);
});

test("path cues separate unrelated brand requests from recognized brand domains", () => {
  assert.equal(scanInput("https://example.com/pa%79pal/verify", "url").score, 35);
  assert.equal(scanInput("https://paypal.com/account/login", "url").score, 0);
  assert.equal(scanInput("https://example.com/login?name=paypal", "url").score, 0);
});

test("Gemini accepts only fixed rule IDs and a verdict", () => {
  assert.deepEqual(validateEvidence({ verdict: "low", findings: ["brand", "brand"] }),
    { verdict: "low", findings: ["brand"] });
  assert.equal(validateEvidence({ verdict: "low", findings: ["a private message"] }), null);
  assert.equal(validateEvidence({ verdict: "low", findings: [], url: "https://example.com" }), null);
});

test("Gemini response requires a short explanation and action", () => {
  const model = (text) => ({ candidates: [{ content: { parts: [{ text }] } }] });
  const explanation = { summary: "A rule matched.", nextStep: "Verify with the sender." };
  assert.deepEqual(parseExplanation(model(JSON.stringify(explanation))), explanation);
  assert.throws(() => parseExplanation(model('{"summary":"Bad"}')));
});

test("configured local proxy forwards only validated evidence and returns a structured explanation", async (t) => {
  let middleware;
  geminiPlugin().configureServer({ middlewares: { use(handler) { middleware = handler; } } });
  const oldKey = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "test-placeholder";
  t.after(() => {
    if (oldKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = oldKey;
  });
  const provider = t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(new URL(url).origin, "https://generativelanguage.googleapis.com");
    assert.match(options.body, /brand-path/);
    assert.doesNotMatch(options.body, /private input/);
    return Response.json({ candidates: [{ content: { parts: [
      { text: '{"summary":"A sign-in cue matched.","nextStep":"Use the official app."}' },
    ] } }] });
  });
  function send(payload) {
    const request = {
      url: "/api/explain", method: "POST", socket: { remoteAddress: "127.0.0.1" },
      headers: { "sec-fetch-site": "same-origin", "content-type": "application/json" },
      async *[Symbol.asyncIterator]() { yield Buffer.from(JSON.stringify(payload)); },
    };
    let status;
    return new Promise((resolve, reject) => {
      middleware(request, {
        writeHead(code) { status = code; },
        end(body) { resolve({ status, body: JSON.parse(body) }); },
      }, () => reject(new Error("Unexpected pass-through"))).catch(reject);
    });
  }
  assert.equal((await send({ verdict: "suspicious", findings: ["brand-path"], text: "private input" })).status, 400);
  assert.equal(provider.mock.callCount(), 0);
  assert.deepEqual(await send({ verdict: "suspicious", findings: ["brand-path"] }), {
    status: 200, body: { summary: "A sign-in cue matched.", nextStep: "Use the official app." },
  });
  assert.equal(provider.mock.callCount(), 1);
});
