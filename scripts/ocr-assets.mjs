import { readFileSync, createReadStream } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const packageFile = (name, file) => join(dirname(require.resolve(name + "/package.json")), file);
export const ocrAssets = new Map([
  ["ocr/v1/worker.min.js", packageFile("tesseract.js", "dist/worker.min.js")],
  ["ocr/v1/tesseract-core-lstm.wasm.js", packageFile("tesseract.js-core", "tesseract-core-lstm.wasm.js")],
  ["ocr/v1/eng.traineddata.gz", packageFile("@tesseract.js-data/eng", "4.0.0_best_int/eng.traineddata.gz")],
  ["ocr/v1/hin.traineddata.gz", packageFile("@tesseract.js-data/hin", "4.0.0_best_int/hin.traineddata.gz")],
]);

export function ocrAssetPlugin() {
  return {
    name: "phishguard-ocr-assets",
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const file = request.method === "GET" && ocrAssets.get(request.url?.slice(1));
        if (!file) return next();
        response.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "application/octet-stream");
        createReadStream(file).pipe(response);
      });
    },
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "licenses/tesseract.txt", source: readFileSync(packageFile("tesseract.js", "LICENSE.md")) });
      this.emitFile({ type: "asset", fileName: "licenses/tesseract-core.txt", source: readFileSync(packageFile("tesseract.js-core", "LICENSE")) });
      for (const [fileName, path] of ocrAssets) {
        this.emitFile({ type: "asset", fileName, source: readFileSync(path) });
      }
    },
  };
}

