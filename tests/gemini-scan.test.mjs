import assert from "node:assert/strict";
import { test } from "node:test";
import { createGeminiScan } from "../scripts/gemini-scan.mjs";
import worker from "../worker/index.js";

const origin = "https://phishguard.example";
const message = { mode: "text", input: "A courier asks for a redelivery fee at https://delivery.example/." };
const link = { mode: "url", input: "https://delivery.example/verify" };

function post(payload, headers = {}, host = origin) {
  return new Request(host + "/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: host, "Sec-Fetch-Site": "same-origin", ...headers },
    body: JSON.stringify(payload),
  });
}

test("online scan fails closed without a configured key or a valid submission", async t => {
  const fetch = t.mock.method(globalThis, "fetch");
  const scan = createGeminiScan();
  assert.equal((await scan(post(link), undefined)).status, 503);
  assert.equal((await scan(post(link, { Origin: "https://other.example" }), "test")).status, 403);
  assert.equal((await scan(post({ mode: "url", input: "file:///dev/null" }), "test")).status, 400);
  assert.equal((await scan(post({ ...message, input: "ह".repeat(6000) }), "test")).status, 400);
  const site = "https://phishguard-local-scanner.freekazoo256.chatgpt.site";
  assert.equal((await worker.fetch(post(message, {}, site), { GEMINI_API_KEY: "test" })).status, 401);
  assert.equal(fetch.mock.callCount(), 0);
});

test("Gemini receives the opted-in message or URL and returns a separate assessment", async t => {
  const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({
    candidates: [{ content: { parts: [{ text: JSON.stringify({ risk: "suspicious", summary: "Unexpected redelivery fee." }) }] } }],
  }));
  for (const payload of [message, link]) {
    const scan = createGeminiScan();
    const response = await scan(post(payload), "test");
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(await response.json(), { risk: "suspicious", summary: "Unexpected redelivery fee." });
    const [url, options] = fetch.mock.calls.at(-1).arguments;
    assert.equal(new URL(url).hostname, "generativelanguage.googleapis.com");
    assert.equal(options.redirect, "manual");
    const body = JSON.parse(options.body);
    assert.deepEqual(JSON.parse(body.contents[0].parts[0].text), payload);
    assert.equal(body.tools, undefined);
    assert.equal((await scan(post(payload), "test")).status, 429);
  }
  assert.equal(fetch.mock.callCount(), 2);
});

test("online scan rejects provider redirects without forwarding the key", async t => {
  const fetch = t.mock.method(globalThis, "fetch", async () => Response.redirect("https://redirect.example/", 307));
  assert.equal((await createGeminiScan()(post(link), "test")).status, 502);
  assert.equal(fetch.mock.callCount(), 1);
});

test("online scan rejects a model response claiming a link is safe", async t => {
  t.mock.method(globalThis, "fetch", async () => Response.json({
    candidates: [{ content: { parts: [{ text: '{"risk":"safe","summary":"Open the link."}' }] } }],
  }));
  assert.equal((await createGeminiScan()(post(link), "test")).status, 502);
});

test("online scan recovers from an upstream timeout with one retry", async t => {
  const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({
    candidates: [{ content: { parts: [{ text: '{"risk":"inconclusive","summary":"The destination is unverified."}' }] } }],
  }));
  fetch.mock.mockImplementationOnce(async () => { throw new DOMException("deadline", "TimeoutError"); });
  const response = await createGeminiScan()(post(link), "test");
  assert.equal(response.status, 200);
  assert.equal(fetch.mock.callCount(), 2);
});

test("online scan reports an exhausted retry and does not retry provider quota errors", async t => {
  const fetch = t.mock.method(globalThis, "fetch", async () => { throw new DOMException("deadline", "TimeoutError"); });
  const timedOut = await createGeminiScan()(post(message), "test");
  assert.equal(timedOut.status, 504);
  assert.match((await timedOut.json()).error, /too long/);
  assert.equal(fetch.mock.callCount(), 2);

  fetch.mock.mockImplementation(async () => new Response(null, { status: 429 }));
  const limited = await createGeminiScan()(post(message), "test");
  assert.equal(limited.status, 429);
  assert.match((await limited.json()).error, /request limit/);
  assert.equal(fetch.mock.callCount(), 3);
});
