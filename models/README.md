# PhishGuard URL classifier experiments

These models evaluate parseable HTTP(S) URLs with 24 numeric features extracted on-device. The weights fit a regularized logistic regression. Each prediction is the dot product of the feature vector and the stored weights plus the intercept. Compare that logit directly with a stored threshold. The logit is a ranking score and should not be shown as the probability that a link is phishing.

The inputs are parsed locally and never visited. Neither exported model contains URLs or example messages. The app continues to use its published rules. These models were evaluated as research candidates.

## Train and reproduce

Use Node.js 22.13+ and Python 3.11+ with scikit-learn. The original run used scikit-learn 1.9.1 and NumPy 2.5.5.

```sh
python -m pip install scikit-learn
python scripts/train-url-model.py /path/to/archive-cache
python scripts/train-url-model.py /path/to/archive-cache --mixed-research
```

Follow the [dataset instructions](../datasets/README.md) to obtain the source files. The mixed run requires the EdgePhish file `edgephish.csv` in the archive cache. EdgePhish data and the mixed model and evaluation are local research artifacts.

URL records are deduplicated after normalizing the host and dropping the fragment. Invalid inputs are reported among the excluded records. Registrable domains are assigned to training (70%), calibration (15%), or testing (15%) by a deterministic hash. EdgePhish groups that overlap any PhiUSIIL domain are excluded. The PhiUSIIL-only model uses the remaining EdgePhish corpus for an external transfer check. The mixed model reserves distinct EdgePhish calibration and test groups. The mixed experiment was designed after viewing aggregate results from the first experiment, so it still needs a newer independent test set.

The scripts choose operating thresholds on calibration groups only. One threshold uses the existing rules' calibration false-positive rate as its budget, and the other targets one false alarm per 1,000 legitimate calibration URLs. The mixed thresholds use the stricter threshold across the two calibration corpora. The held-out rates may differ.

## Initial finding

At the stricter threshold the PhiUSIIL-only model detected 5,726 of 13,463 held-out phishing URLs and flagged 1 of 20,180 legitimate URLs. The current rules detected 75 and produced the same single false alarm. On EdgePhish, however, that threshold flagged 130,707 of 133,468 legitimate URLs. The first model does not transfer reliably enough to replace the rules. See `url-logistic-v1-evaluation.json` for the complete counts.


## Mixed-source research result

The second model used 368,925 training URLs. Its exported weights and metadata occupy 1,600 bytes. At the one-per-thousand calibration operating point, keeping an alert when either the rules or the model flagged the URL gave these held-out results.

| Held-out corpus | Phishing caught by rules | Phishing caught by rules or model | Legitimate URLs flagged by rules | Legitimate URLs flagged by rules or model |
| --- | ---: | ---: | ---: | ---: |
| PhiUSIIL | 75 / 13,463 | 2,135 / 13,463 | 1 / 20,180 | 2 / 20,180 |
| EdgePhish | 2,764 / 24,497 | 4,481 / 24,497 | 10 / 20,127 | 38 / 20,127 |

The combined detector exceeded the one-per-thousand false-alarm target on the EdgePhish test split (about 1.89 per 1,000). The model artifacts passed a JavaScript inference smoke test. Real-phone latency, fresh campaign coverage and regional message detection were not measured in this experiment.
