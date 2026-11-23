# PhishGuard

Phase 1 is a local URL and message scanner. Use Node.js 22.13 or newer.

```sh
pnpm install
pnpm test
pnpm dev
```

For the production build and offline shell, use `pnpm build` followed by `pnpm preview`. Open the preview URL online first and allow the service worker to install before testing an offline reload.

The detector uses version-one heuristic weights from the revised specification. Findings and coverage are available independently of the score. The result view displays only defanged hostnames and fixed finding labels. It does not echo message text, URL paths, query strings, or fragments. Scan input is held in browser memory and can be cleared.

Screenshot OCR, destination resolution, threat feeds, and cloud analysis are later phases. Thresholds and language coverage need validation against labeled data before public release.

See [datasets/README.md](datasets/README.md) for the benchmark, source attribution, and current detection limits.
