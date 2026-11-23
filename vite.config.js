import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/[\\/]node_modules[\\/](?:tldts(?:-core)?|tr46)[\\/]/.test(id)) return "domain-data";
        },
      },
    },
  },
  plugins: [{
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
      const assets = ["index.html", ...Object.keys(bundle).filter((name) => name !== "index.html"), ...publicAssets];
      const source = [
        "const prefix = 'phishguard:' + self.registration.scope + ':';",
        "const current = prefix + " + JSON.stringify(hash.digest("hex").slice(0, 16)) + ";",
        "const urls = " + JSON.stringify(assets) + ".map(path => new URL(path, self.registration.scope).href);",
        "self.addEventListener('install', event => {",
        "  event.waitUntil(caches.open(current).then(cache => cache.addAll(urls)));",
        "});",
        "self.addEventListener('activate', event => {",
        "  event.waitUntil(caches.keys().then(keys => Promise.all(keys",
        "    .filter(key => key.startsWith(prefix) && key !== current).map(key => caches.delete(key)))));",
        "});",
        "self.addEventListener('fetch', event => {",
        "  if (event.request.method !== 'GET') return;",
        "  const requestUrl = new URL(event.request.url);",
        "  const scope = new URL(self.registration.scope);",
        "  const navigation = event.request.mode === 'navigate' && requestUrl.origin === scope.origin",
        "    && (requestUrl.pathname === scope.pathname || requestUrl.pathname === scope.pathname + 'index.html');",
        "  if (!navigation && !urls.includes(event.request.url)) return;",
        "  event.respondWith(caches.open(current).then(async cache => {",
        "    if (navigation) {",
        "      return (await cache.match(urls[0])) ?? fetch(event.request);",

        "    }",
        "    return (await cache.match(requestUrl.href, { ignoreVary: true })) ?? fetch(event.request);",
        "  }));",
        "});",
      ].join("\n");
      this.emitFile({ type: "asset", fileName: "sw.js", source });
    },
  }],
});


