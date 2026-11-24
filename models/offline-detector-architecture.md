# Offline detector architecture

PhishGuard normalizes a pasted or extracted URL locally, runs the existing deterministic checks, and passes numeric URL features to a small classifier when the classifier has qualified for offline review. It caps input at 16 KiB and scans at most ten unique links. Screenshot OCR still runs in a separate worker and passes editable text through the same scanner.

The classifier supplies a separate **Inconclusive** result when its review threshold is met on a link that the rules would otherwise leave without a warning. It cannot clear a rule warning, assert that a link is safe, or create a high-risk verdict. Shortened destinations remain unresolved. The heuristic score belongs to the rules and is not a model probability.

The browser build includes an offline-model entry only when a reviewed artifact is promoted. The model consists of numeric feature names, thresholds and compact trees evaluated in JavaScript. It needs no browser ML runtime. The PWA caches its compiled assets, and URL features, message text and images stay on the device. Gemini remains a separate opt-in explanation and receives the existing verdict and rule IDs.

## Qualification

The release study fits balanced-source candidates on PhiUSIIL and PhreshPhish domain groups. EdgePhish can supply a separate calibration cohort, and the Hannousse corpus is used only for a fourth evaluation. Additional review prompts and automatic warnings are measured separately. Both use one-sided 95% Wilson upper bounds across each held-out corpus. The automatic warning budget is one false alarm per 1,000 legitimate URLs. The review budget is 25 additional verification prompts per 1,000 legitimate URLs. URL-level confidence bounds do not account for all campaign clustering.

Calibrate thresholds on development partitions. A candidate may qualify as an advisory even when it fails the stricter warning gate. The browser still uses verified deterministic warning rules and explicit uncertainty. A model cannot establish that an unseen destination is trustworthy from its URL alone.

## Reproduction

Generate a numeric matrix from the three archives described in the [research report](mobile-research-report.md). Add the labeled Hannousse CSV as `hannousse.csv` in the archive cache. The source is [Web page phishing detection](https://data.mendeley.com/datasets/c2gw7fy2j4/3), a CC BY 4.0 dataset. The downloaded URL and label columns came from [this CSV mirror](https://github.com/mashmail/phishing-detection-ml/tree/main/data/raw). The feature extractor excludes registrable domains shared with any of the other corpora and does not open any URL.

```sh
python -c "import pathlib,runpy; runpy.run_path('scripts/train-url-model.py')['extract'](pathlib.Path('ARCHIVE_CACHE'),pathlib.Path('FEATURES_JSONL'),True,True)"
python scripts/train-mobile-release.py FEATURES_JSONL --cross-calibrate
node scripts/audit-mobile-inference.mjs models/url-mobile-v4.json models/mobile-v4-inference-audit.json
```

Use the browser setup documented in the [research report](mobile-research-report.md) for the inference command.


## Selected model and measured results

The fourth-corpus release experiment selected a 32-round boosted-tree classifier from four candidates. It uses 24 features. EdgePhish was used for cross-source calibration on separately grouped domains. The remaining EdgePhish rows, test groups from the two training sources, and the disjoint Hannousse corpus were evaluated after selection. Hannousse was collected in 2020, so the fourth test measures transfer to a different source, not current threats.

| Domain-disjoint cohort | Existing warning recall | Rules or review recall | Additional verification prompts on legitimate URLs |
| --- | ---: | ---: | ---: |
| PhiUSIIL | 0.56% | 6.58% | 0 / 20,180 |
| PhreshPhish | 0.56% | 6.43% | 2 / 6,154 |
| EdgePhish | 12.50% | 16.11% | 1,378 / 113,410 |
| Hannousse | 3.50% | 8.82% | 7 / 2,876 |

The largest observed extra review rate was 12.15 per 1,000 legitimate URLs on EdgePhish. The browser exposes it only as an inconclusive result with verify-before-opening guidance. Detection coverage remains limited on novel URLs and these retrospective tests cannot establish that a real link is trustworthy.

See [the selected artifact](url-mobile-v4.json) and [held-out evaluation](url-mobile-v4-evaluation.json). The former V3 candidate exceeded both false-positive limits in EdgePhish transfer testing. Its results are retained separately. The model benchmark and phone-flow reports describe desktop Edge emulation, not physical Android or iPhone measurements.

## Phone-sized verification

The selected model file is 9,485 bytes, or 3,571 bytes with gzip. In desktop Edge with 6× CPU throttling, p95 compute was 2.59 ms for one URL, 11.19 ms for ten links, and 26.64 ms for a near-limit message. These timings include parsing and rule checks.

At 4× CPU throttling and an emulated 8 Mbps connection, the interface showed an advisory in 22.9 ms p95 over 12 runs. First English PNG OCR took 1.66 seconds for one test image. The browser also showed the advisory after taking the PWA offline, and the same run passed English and Hindi OCR and verified that the Gemini failure state leaves the local verdict visible. See the [compute benchmark](mobile-v4-inference-audit.json) and [browser flow checks](phone-v4-flow-audit.json).
