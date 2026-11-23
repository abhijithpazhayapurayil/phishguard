# PhishGuard benchmark and regional fixtures

This is an evaluation corpus for the local detector. It is not part of the browser build. The public-source export contains 240,530 derived rows after dropping 839 exact input duplicates within sources. The separate synthetic fixture file contains 28 labeled regional cases and benign lookalikes.

| Source | Source records | Exported records | Label semantics |
| --- | ---: | ---: | --- |
| PhiUSIIL | 235,795 | 235,370 | Phishing or legitimate URL |
| SMS Spam Collection | 5,574 | 5,160 | Spam or ham. Spam is broader than scam or phishing. |
| Regional fixtures | 28 | 28 | Synthetic benign, scam, or unresolved |

## Files and reproduction

- `benchmark.jsonl.gz` contains one JSON object per distinct input, with source, source label, opaque input and group identifiers, partition, detector verdict, fired rule IDs, and heuristic score. Raw URLs and SMS content are omitted. The export supports analysis of current rule signals, and regenerating it from source is necessary when rules change.
- `benchmark-summary.json` records archive checksums, duplicates, verdict counts by source and partition, rule version, and desktop Node scan timing. The archive checksums identify the upstream snapshots used.
- `regional-fixtures.json` contains the checked-in examples exercised by the automated regression suite. These examples were authored alongside the rules and are development fixtures.

Run `python scripts/prepare-corpus.py <archive-cache-dir>` from the project root with Python 3.11+ and Node 22.13+ available. The script downloads only the two fixed UCI archive URLs when needed. It evaluates source inputs in memory and never visits URLs found in the corpus. Keep the source archive cache outside the project directory.

The reproducible split assigns groups to development or holdout. URL groups use registrable domains where available. SMS groups use a rough normalized message pattern. This reduces split overlap but does not establish campaign independence or a chronological split. The corpus is historical and does not measure current live threats or the prevalence of Indian scams.

## Initial measurement

On the grouped URL holdout, Suspicious or High risk was returned for 134 of 17,755 phishing records (0.75%). An additional 135 were inconclusive and 137 were invalid. None of the 26,932 legitimate holdout records returned Suspicious or High risk. On the SMS spam holdout, 3 of 121 spam records and 1 of 922 ham records returned Suspicious or High risk. These rates show narrow rule coverage. The local verdict only describes the completed checks.

Desktop scan p95 was 0.11 ms over 7,760 sampled calls in Node. This excludes page load, rendering and any OCR. No mobile performance claim is made.

## Source attribution

- Prasad, A. and Chandra, S. (2024). [PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset). UCI Machine Learning Repository. [Research paper DOI](https://doi.org/10.1016/j.cose.2023.103545).
- Almeida, T. and Hidalgo, J. (2011). [SMS Spam Collection](https://doi.org/10.24432/C5CC84). UCI Machine Learning Repository.
- Both source datasets are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The benchmark export adapts them through deduplication, grouping, and local rule scoring.

