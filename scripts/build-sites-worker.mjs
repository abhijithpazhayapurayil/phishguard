import { cp, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";

const dist = new URL("../dist/", import.meta.url);
const client = new URL("client/", dist);
const files = await readdir(dist, { withFileTypes: true });
await mkdir(client);
await Promise.all(files.map(({ name }) => rename(new URL(name, dist), new URL(name, client))));
const server = new URL("server/", dist);
const configDir = new URL(".openai/", dist);
await Promise.all([mkdir(server, { recursive: true }), mkdir(configDir, { recursive: true })]);
const worker = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");
await Promise.all([
  writeFile(new URL("index.js", server), worker.replaceAll("../scripts/gemini", "./gemini")),
  cp(new URL("./gemini.mjs", import.meta.url), new URL("gemini.mjs", server)),
  cp(new URL("./gemini-scan.mjs", import.meta.url), new URL("gemini-scan.mjs", server)),
  cp(new URL("../.openai/hosting.json", import.meta.url), new URL("hosting.json", configDir)),
  writeFile(new URL("wrangler.json", server), JSON.stringify({
    name: "phishguard",
    main: "index.js",
    compatibility_date: "2026-11-24",
    assets: { directory: "../client", binding: "ASSETS", run_worker_first: ["/api/*"] },
  }, null, 2) + "\n"),
]);

