const PATH = "/api/explain";
const FINDINGS = new Set([
  "urgency", "lure", "coercion", "authority", "ip", "brand", "confusable", "entropy",
  "tld", "shortener", "brand-path", "credential-path",
]);
const VERDICTS = new Set(["high", "suspicious", "inconclusive", "low"]);

export function validateEvidence(value) {
  if (!value || Object.keys(value).sort().join(",") !== "findings,verdict"
    || !VERDICTS.has(value.verdict) || !Array.isArray(value.findings)
    || value.findings.length > FINDINGS.size || !value.findings.every(id => FINDINGS.has(id))) {
    return null;
  }
  return { verdict: value.verdict, findings: [...new Set(value.findings)] };
}

export function parseExplanation(value) {
  const parts = value?.candidates?.[0]?.content?.parts;
  const payload = JSON.parse(parts?.filter(part => !part.thought).map(part => part.text).join("") ?? "");
  if (typeof payload?.summary !== "string" || typeof payload?.nextStep !== "string"
    || !payload.summary.trim() || !payload.nextStep.trim()
    || payload.summary.length > 400 || payload.nextStep.length > 280) throw new Error("Invalid explanation");
  return { summary: payload.summary, nextStep: payload.nextStep };
}

export async function explainEvidence(key, evidence) {
  const result = await generateGemini(key, {
    contents: [{ parts: [{ text: "Explain the following fixed phishing heuristic categories in simple English. Keep the verdict unchanged. Do not infer any missing facts, URLs, brands, or messages. Give one low-risk verification step. A low score does not establish safety. Evidence: " + JSON.stringify(evidence) }] }],
    generationConfig: {
      maxOutputTokens: 512,
      responseMimeType: "application/json",
      responseJsonSchema: {
        type: "object", required: ["summary", "nextStep"],
        properties: { summary: { type: "string" }, nextStep: { type: "string" } },
      },
    },
  }, 3000);
  return parseExplanation(result);
}

export async function generateGemini(key, body, timeout) {
  const upstream = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent", {
    method: "POST",
    // Workers support manual redirects. Reject the 3xx response below without forwarding the key.
    redirect: "manual",
    signal: AbortSignal.timeout(timeout),
    headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify(body),
  });
  if (!upstream.ok) {
    const error = new Error("Gemini rejected the request");
    error.status = upstream.status;
    throw error;
  }
  return upstream.json();
}

export function geminiPlugin() {
  function setup(server) {
    let nextRequest = 0;
    server.middlewares.use(async (request, response, next) => {
      if (request.url !== PATH) return next();
      const reply = (status, value) => {
        response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
        response.end(JSON.stringify(value));
      };
      const loopback = ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(request.socket.remoteAddress);
      if (!loopback || request.method !== "POST" || request.headers["sec-fetch-site"] !== "same-origin"
        || !request.headers["content-type"]?.startsWith("application/json")) {
        return reply(403, { error: "Same-origin request required." });
      }
      const key = process.env.GEMINI_API_KEY;
      if (!key) return reply(503, { error: "Online explanation is disabled in this environment." });

      let body = "";
      try {
        for await (const chunk of request) {
          body += chunk.toString("utf8");
          if (body.length > 1024) return reply(413, { error: "Evidence payload is too large." });
        }
        const evidence = validateEvidence(JSON.parse(body));
        if (!evidence) return reply(400, { error: "Invalid scan evidence." });
        if (Date.now() < nextRequest) return reply(429, { error: "Wait a moment before requesting another explanation." });
        nextRequest = Date.now() + 2000;

        return reply(200, await explainEvidence(key, evidence));
      } catch {
        return reply(502, { error: "The online explanation could not complete. The local verdict still applies." });
      }
    });
  }
  return { name: "phishguard-gemini", configureServer: setup, configurePreviewServer: setup };
}

