# PhishGuard

PhishGuard scans URLs, messages and screenshots on the device. Use Node.js 22.13 or newer.

```sh
pnpm install
pnpm test
pnpm dev
```

Use `pnpm build` and `pnpm preview` to try the production PWA. Open it online and reload after the service worker installs before checking offline behavior.

## Screenshot OCR

Choose **Screenshot**, select English or Hindi, and upload a PNG or JPEG or paste an image while focused in the upload area. Review and correct the extracted text, then choose **Scan**. The browser downloads the worker, OCR engine and selected language pack on first use. It processes the screenshot on-device and caches only those program assets for subsequent offline use. A new build or browser cache eviction can require another download.

## Optional Gemini explanation

Gemini is available in the local Node-backed Vite environment when `GEMINI_API_KEY` is supplied as a server process secret. Start `pnpm dev` on loopback with that environment variable set. For a local production preview, set it for both `pnpm build` and `pnpm preview`. Keep the key out of source control and avoid the client-exposed `VITE_` prefix.

After a scan, open **Online explanation with Gemini**, review the fixed verdict and rule IDs, and explicitly send them. The server validates that payload and applies a deadline. The explanation is independent of the local verdict. Screenshots, input text, and examined URLs stay on-device. The deployed static Site serves the local features. A hosted Gemini deployment requires an authenticated server-side route, secret configuration, and review against [Google's Gemini API terms](https://aistudio.google.com/docs/terms).

## Detection and benchmark

The result uses heuristic rules and reports only completed checks. Link and screenshot content can contain errors or missed signals. See [datasets/README.md](datasets/README.md) for the benchmark, source attribution, and current detection limits. Shortened destinations remain unresolved and no live reputation feed is configured.
