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

## Optional Gemini online scan

After a local scan, open **Online scan with Gemini** to review or edit the submitted link, message, or extracted screenshot text. Only clicking **Send** submits that text to Google. The image stays on-device. Gemini examines the text and provides a separate assessment. It does not retrieve the page, resolve redirects, verify a sender, or replace the local verdict.

For Vercel, set `GEMINI_API_KEY` as a sensitive Production environment variable and redeploy. The Vite build serves `dist` and Vercel runs `api/scan.js` on the server. Keep the key out of source control and avoid the client-exposed `VITE_` prefix. The route throttles bursts per instance. Apply Vercel's Firewall rate limiting to `/api/scan` for a shared limit on public deployments.

For local testing, set `GEMINI_API_KEY` in the server process and start `pnpm dev` on loopback. For local production preview, set it for both `pnpm build` and `pnpm preview`. The private hosted Site uses a runtime secret and authenticated Worker routes. Use `pnpm build:sites` for that host. It also offers the explanation-only option that sends just the local verdict and triggered rule IDs.

## Detection and benchmark

The result uses heuristic rules and reports only completed checks. Link and screenshot content can contain errors or missed signals. See [datasets/README.md](datasets/README.md) for the benchmark, source attribution, and current detection limits. Shortened destinations remain unresolved and no live reputation feed is configured.


See [offline detector architecture](models/offline-detector-architecture.md) for the qualified on-device review model, evaluation limits and reproduction steps.
