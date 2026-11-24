import assert from "node:assert/strict";
import test from "node:test";
import { createWorker } from "../worker/index.js";

const origin = "https://phishguard-local-scanner.freekazoo256.chatgpt.site";
function request(body, overrides = {}) {
  const headers = {
    origin,
    "sec-fetch-site": "same-origin",
    "content-type": "application/json",
    "oai-authenticated-user-id": "test-owner",
    ...overrides,
  };
  return new Request(origin + "/api/explain", { method: "POST", headers, body: JSON.stringify(body) });
}

test("hosted fallback requires visitor identity, same origin, and a secret", async () => {
  const server = createWorker();
  assert.equal((await server.fetch(request({}, { "oai-authenticated-user-id": "" }), {})).status, 401);
  assert.equal((await server.fetch(request({}, { origin: "https://example.com" }), {})).status, 403);
  assert.equal((await server.fetch(request({}), {})).status, 503);
  const assets = { fetch: () => new Response("asset OK") };
  assert.equal(await (await server.fetch(new Request(origin), { ASSETS: assets })).text(), "asset OK");
});

test("hosted fallback rejects raw input and sends validated signals on accepted requests", async t => {
  const server = createWorker();
  const upstream = t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(new URL(url).origin, "https://generativelanguage.googleapis.com");
    assert.equal(options.headers["x-goog-api-key"], "test-secret");
    assert.match(options.body, /brand-path/);
    return Response.json({ candidates: [{ content: { parts: [
      { text: '{"summary":"A brand cue matched.","nextStep":"Check the official app."}' },
    ] } }] });
  });
  const env = { GEMINI_API_KEY: "test-secret" };
  const evidence = { verdict: "suspicious", findings: ["brand-path"] };
  assert.equal((await server.fetch(request({ ...evidence, message: "private message" }), env)).status, 400);
  assert.equal(upstream.mock.callCount(), 0);
  const result = await server.fetch(request(evidence), env);
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), { summary: "A brand cue matched.", nextStep: "Check the official app." });
  assert.equal((await server.fetch(request(evidence), env)).status, 429);
});
