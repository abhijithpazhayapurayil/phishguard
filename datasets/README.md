# PhishGuard benchmark and regional fixtures

Rule version 1.2.0 was evaluated on 580,243 distinct source records, alongside 28 synthetic regression fixtures. Raw URLs and message text are excluded from derived exports and the browser build.

| Source | Input rows | Evaluated rows | Label |
| --- | ---: | ---: | --- |
| PhiUSIIL | 235,795 | 235,370 | Phishing or legitimate URL |
| SMS Spam Collection | 5,574 | 5,160 | Spam or ham |
| EdgePhish-5G | 340,000 | 339,713 | Phishing or legitimate URL |

## Reproduce

Run `python scripts/prepare-corpus.py <archive-cache-dir>` from the project root with Python 3.11+ and Node.js 22.13+. Keep the cache outside the project directory. The script fetches the two fixed UCI archives when needed. To include EdgePhish, download the publisher's `urls_dataset.csv` into the cache directory as `edgephish.csv`. No URLs found in the corpus are visited.

- `benchmark.jsonl.gz` contains one derived row per distinct UCI input with the source, label, hashed IDs, group, partition, verdict, rule IDs, and score.
- `edgephish.local.jsonl.gz` is a separate local export. It is ignored by Git and excluded from deployment because the publisher describes the dataset as intended for academic research and adds terms for commercial use.
- `benchmark-summary.json` records source checksums, duplicate counts, verdict counts, and desktop Node scan timing.
- `regional-fixtures.json` holds the 28 synthetic examples used in the regression suite.

The grouped split uses registrable domains for URLs and a rough normalized template for messages. EdgePhish also excludes exact input duplicates seen in PhiUSIIL. This reduces overlap but does not establish campaign independence or a chronological split. The results do not measure live threats.

## Results

At the Suspicious or High risk threshold, the scanner flagged 134 of 17,755 phishing URLs and 0 of 26,932 legitimate URLs in the PhiUSIIL holdout. In the EdgePhish holdout it flagged 4,198 of 33,152 phishing URLs and 15 of 33,828 legitimate URLs. These corpora have different sources and inputs, so their rates should not be compared as a before-and-after improvement. On the SMS holdout, it flagged 3 of 121 spam records and 1 of 922 ham records. Spam is broader than phishing.

Desktop Node scan p95 was 0.153 ms over 18,719 sampled calls. This excludes page load, rendering and OCR.

## Attribution

- [PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset). Prasad, A. and Chandra, S. UCI Machine Learning Repository, 2024.
- [SMS Spam Collection](https://doi.org/10.24432/C5CC84). Almeida, T. and Hidalgo, J. UCI Machine Learning Repository, 2011.
- The two UCI datasets are [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The released export adapts them through deduplication, grouping and scoring.
- [EdgePhish-5G](https://doi.org/10.5281/zenodo.19371661). Hassan Saeed AlBattra, 2026. See the [publisher's terms and dataset notes](https://github.com/Hassan-Albattra/EdgePhish-5G/blob/main/data/DATASET_README.md).

