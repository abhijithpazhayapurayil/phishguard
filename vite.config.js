import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { defineConfig } from "vite";
import { ocrAssetPlugin, ocrAssets } from "./scripts/ocr-assets.mjs";
import { geminiPlugin } from "./scripts/gemini.mjs";
import { createGeminiScan } from "./scripts/gemini-scan.mjs";

function geminiScanPlugin() {
  function setup(server) {
    const scan = createGeminiScan();
    server.middlewares.use(async (request, response, next) => {
      if (request.url !== "/api/scan") return next();
      if (!["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(request.socket.remoteAddress)) {
        response.writeHead(403).end();
        return;
      }
      const url = new URL(request.url, `http://${request.headers.host}`);
      const hasBody = request.method !== "GET" && request.method !== "HEAD";
      const result = await scan(new Request(url, {
        method: request.method,
        headers: request.headers,
        ...(hasBody ? { body: Readable.toWeb(request), duplex: "half" } : {}),
      }), process.env.GEMINI_API_KEY);
      response.writeHead(result.status, Object.fromEntries(result.headers));
      response.end(await result.text());
    });
  }
  return { name: "phishguard-online-scan", configureServer: setup, configurePreviewServer: setup };
}

export default defineConfig(({ mode }) => ({
  base: "./",
  define: {
    __PHISHGUARD_GEMINI__: JSON.stringify(mode === "sites" || (!process.env.VERCEL && Boolean(process.env.GEMINI_API_KEY))),
    __PHISHGUARD_ONLINE_SCAN__: JSON.stringify(mode === "sites" || Boolean(process.env.VERCEL || process.env.GEMINI_API_KEY)),
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/[\\/]node_modules[\\/](?:tldts(?:-core)?|tr46)[\\/]/.test(id)) return "domain-data";
        },
      },
    },
  },
  plugins: [ocrAssetPlugin(), geminiPlugin(), geminiScanPlugin(), {
    name: "phishguard-offline",
    apply: "build",
    enforce: "post",
    generateBundle(_options, bundle) {
      const publicAssets = ["manifest.webmanifest", "icon-192.png", "icon-512.png"];
      const hash = createHash("sha256");
      for (const name of publicAssets) hash.update(readFileSync(new URL("./public/" + name, import.meta.url)));
      for (const item of Object.values(bundle)) {
        hash.update(item.fileName);
        hash.update(item.type === "asset" ? item.source : item.code);
      }
      const assets = ["index.html", ...Object.keys(bundle).filter((name) => name !== "index.html" && !ocrAssets.has(name)), ...publicAssets];
      const source = [
        "const prefix = 'phishguard:' + self.registration.scope + ':';",
        "const current = prefix + " + JSON.stringify(hash.digest("hex").slice(0, 16)) + ";",
        "const urls = " + JSON.stringify(assets) + ".map(path => new URL(path, self.registration.scope).href);",
        "const optional = " + JSON.stringify([...ocrAssets.keys()]) + ".map(path => new URL(path, self.registration.scope).href);",
        "const scope = new URL(self.registration.scope);",
        "const assetsPath = new URL('assets/', scope).pathname;",
        "async function previousCaches() {",
        "  return (await caches.keys()).filter(key => key.startsWith(prefix) && key !== current);",
        "}",
        "self.addEventListener('install', event => {",
        "  event.waitUntil((async () => {",
        "    const cache = await caches.open(current);",
        "    await cache.addAll(urls);",
        "    await self.skipWaiting();",
        "  })());",
        "});",
        "self.addEventListener('activate', event => {",
        "  event.waitUntil((async () => {",
        "    // Open tabs may still need chunks from an older app shell.",
        "    const older = (await previousCaches()).slice(0, -2);",
        "    await Promise.all(older.map(key => caches.delete(key)));",
        "    await self.clients.claim();",
        "  })());",
        "});",
        "self.addEventListener('fetch', event => {",
        "  if (event.request.method !== 'GET') return;",
        "  const requestUrl = new URL(event.request.url);",
        "  if (requestUrl.origin !== scope.origin) return;",
        "  const navigation = event.request.mode === 'navigate'",
        "    && (requestUrl.pathname === scope.pathname || requestUrl.pathname === scope.pathname + 'index.html');",
        "  const buildAsset = requestUrl.pathname.startsWith(assetsPath);",
        "  const lazyAsset = optional.includes(event.request.url);",
        "  if (!navigation && !buildAsset && !lazyAsset && !urls.includes(event.request.url)) return;",
        "  event.respondWith(caches.open(current).then(async cache => {",
        "    if (navigation) {",
        "      try {",
        "        return await fetch(event.request, { cache: 'no-cache' });",
        "      } catch (error) {",
        "        const fallback = await cache.match(urls[0]);",
        "        if (fallback) return fallback;",
        "        throw error;",
        "      }",
        "    }",
        "    const cached = await cache.match(requestUrl.href, { ignoreVary: true });",
        "    if (cached) return cached;",
        "    if (buildAsset) {",
        "      for (const cacheName of (await previousCaches()).reverse()) {",
        "        const previous = await caches.match(requestUrl.href, { cacheName });",
        "        if (previous) return previous;",
        "      }",
        "    }",
        "    const result = await fetch(event.request);",
        "    if (lazyAsset && result.ok) await cache.put(requestUrl.href, result.clone());",
        "    return result;",
        "  }));",
        "});",
      ].join("\n");
      this.emitFile({ type: "asset", fileName: "sw.js", source });
    },
  }],
}));

