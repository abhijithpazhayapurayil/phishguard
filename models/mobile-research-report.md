# PhishGuard mobile detection evaluation

## Training and classification

Four local research candidates used 368,925 training URLs from PhiUSIIL and EdgePhish. The candidates were regularized logistic regression, shallow boosted trees restricted to hostname features, a 64-round full-feature boosted model, and a smaller 32-round full-feature model. The 64-round model had the strongest minimum recall across the two calibration partitions under a combined rules-or-model budget of at most one false alarm per 1,000 legitimate URLs. The threshold accounts for false alarms already made by the current rules.

The selected candidate uses 24 features. The largest drops in average precision when shuffling individual features on the EdgePhish calibration sample came from hostname length, hostname digit fraction, and subdomain depth. Path action words also contributed. This is evidence of reliance within that sample. It does not establish how a feature transfers to a different corpus.

The independent PhreshPhish test snapshot contains URL metadata collected from September to December 2025. Of 168,060 input rows, 100,245 remained after excluding unparseable inputs, canonical duplicates, and registrable domains shared with either development corpus. The remaining URLs were scored as strings. No destination was visited or webpage content downloaded.

| Held-out corpus | Phishing URLs | Legitimate URLs | Rules recall | Rules or model recall | Rules false alarms per 1,000 | Rules or model false alarms per 1,000 | Model ROC AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PhiUSIIL | 13,463 | 20,180 | 0.56% | 33.58% | 0.05 | 0.64 | 0.859 |
| EdgePhish | 24,497 | 20,127 | 11.28% | 36.22% | 0.50 | 1.19 | 0.913 |
| PhreshPhish | 56,366 | 43,879 | 0.56% | 20.16% | 0.07 | 12.60 | 0.834 |

**Release decision.** Keep the current rules in production. The new model exceeded the false-alarm target on EdgePhish and PhreshPhish. Its ranking results show a useful signal, but the current threshold does not transfer reliably. The model is a local research artifact. No benchmark or live deployment used it to replace the current scanner.

## Message classification

Current local rules matched expectations on all 28 synthetic regional fixtures. In 5,160 deduplicated UCI SMS messages, they flagged 45 of 642 spam records and 13 of 4,518 legitimate records as suspicious or high risk. Spam labels include promotional messages and do not measure scam-specific recall. URL-model training did not use these messages.

## Mobile compute latency

The 18.5 KB model compresses to 6.9 KB. The desktop Edge engine ran browser inference at mobile width, with three CPU profiles. The timings below are p95 per operation computed from timed batches. They exclude page load, rendering, screenshot OCR, and network requests.

| Workload | 4× CPU slowdown | 6× CPU slowdown |
| --- | ---: | ---: |
| One URL, rules and model | 1.29 ms | 1.41 ms |
| Ten links, rules and model | 8.24 ms | 16.32 ms |
| Near-limit message with ten links, rules and model | 15.84 ms | 23.46 ms |

Portable-model numerical parity was checked against the trainer on 300 held-out feature rows. The JavaScript scoring functions and feature contract also passed regression checks. Physical Android and iPhone timing and iOS Safari behavior remain unmeasured.

## Phone-sized browser flow

At 4× CPU throttling with an emulated 8 Mbps connection, the page heading appeared after 1.25 seconds from a cold navigation. With the app initialized, a local URL verdict reached the next animation frame in 32.3 ms p95 and the bounded large-message flow in 51.7 ms p95. Each scan scenario used 12 timed repetitions per profile. These end-to-end interface timings include more work than the compute-only timings above.

One controlled screenshot per timing scenario gave 1.54 seconds for first English PNG OCR, 1.26 seconds for cached English JPEG, 1.02 seconds for Hindi image paste after the OCR engine was cached, and 1.04 seconds for repeat English OCR offline. They are examples, not OCR percentiles. Desktop Edge performed the OCR and network emulation. The browser did not verify physical-device camera behavior or share-sheet integration.

The browser checks included input limits, multiple links, inert output, no requests during local scans, editable OCR, cancellation, offline reload, and the Gemini consent payload and offline error state. The existing hosted endpoint has separate unit coverage with a mocked Gemini provider. A new live provider request was outside this run. An unrelated antivirus-injected origin was blocked in the isolated test browser and excluded from application request counts.

## Artefacts and reproduction

- `url-mobile-v2.local.json` contains the selected compact research model.
- `url-mobile-v2.local-evaluation.json` contains calibration comparisons, feature results, confusion matrices and corpus checksums.
- `mobile-inference-audit.json` contains all three browser compute profiles.
- `phone-flow-audit.json` contains the installed-shell, scan, and OCR flow measurements.
- `message-classification-audit.json` contains SMS and regional fixture results.

Follow [dataset setup](../datasets/README.md) for PhiUSIIL and EdgePhish. Save the [PhreshPhish URL-only projection](https://github.com/aI-area/PhishDetecting/tree/main/dataset/PhreshPhish) as `phreshphish.csv.gz` in the archive cache. The extractor verifies the pinned checksum and records sources and exclusions. Download only the URL metadata. The underlying [PhreshPhish dataset and paper](https://arxiv.org/abs/2507.10854) describe its source, dates and benchmark design.

With the same Python dependencies as the [initial experiments](README.md), run the commands below from the project root. The first command writes a temporary numeric matrix. The training script never uses PhreshPhish for fitting, candidate selection or threshold setting.

```sh
python -c "import pathlib,runpy; runpy.run_path('scripts/train-url-model.py')['extract'](pathlib.Path('ARCHIVE_CACHE'),pathlib.Path('FEATURES_JSONL'),True)"
python scripts/research-url-model.py FEATURES_JSONL
pnpm build:sites
node scripts/audit-phone-flow.mjs
node scripts/audit-mobile-inference.mjs
```

The browser scripts require Playwright and a Chromium-compatible browser. Set `PHISHGUARD_PLAYWRIGHT` to an available Playwright package path if it is outside the repository. Set `PHISHGUARD_BROWSER_EXECUTABLE` to an existing Chromium or Edge executable if using a system browser.
