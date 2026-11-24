import { explainEvidence, validateEvidence } from "../scripts/gemini.mjs";

const MAX_BODY = 1024;
const SITE_ORIGIN = "https://phishguard-local-scanner.freekazoo256.chatgpt.site";

function reply(status, value) {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

async function readEvidence(request) {
  const reader = request.body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let size = 0;
  let body = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) {
        await reader.cancel();
        return null;
      }
      body += decoder.decode(value, { stream: true });
    }
    return validateEvidence(JSON.parse(body + decoder.decode()));
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

export function createWorker() {
  let nextRequest = 0;
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname !== "/api/explain") {
        return env.ASSETS?.fetch(request) ?? new Response("Not found", { status: 404 });
      }
      if (!request.headers.get("oai-authenticated-user-id")) {
        return reply(401, { error: "Sign in to request an online explanation." });
      }
      if (request.method !== "POST") {
        return reply(405, { error: "Use POST to request an online explanation." });
      }
      const origin = request.headers.get("origin");
      if (request.headers.get("sec-fetch-site") !== "same-origin"
        || (origin !== url.origin && origin !== SITE_ORIGIN)
        || request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") {
        return reply(403, { error: "Same-origin JSON request required." });
      }
      if (!env.GEMINI_API_KEY) {
        return reply(503, { error: "Gemini is unavailable until the Site owner configures its API key." });
      }
      const evidence = await readEvidence(request);
      if (!evidence) return reply(400, { error: "Invalid or oversized scan evidence." });
      if (Date.now() < nextRequest) {
        return reply(429, { error: "Wait a moment before requesting another explanation." });
      }
      nextRequest = Date.now() + 2000;
      try {
        return reply(200, await explainEvidence(env.GEMINI_API_KEY, evidence));
      } catch {
        return reply(502, { error: "Gemini could not complete the explanation. The local verdict still applies." });
      }
    },
  };
}

export default createWorker();
