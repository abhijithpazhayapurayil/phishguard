"""Fit and evaluate PhishGuard's numeric URL classifier without visiting any input URL."""
import argparse
import csv
import gzip
import hashlib
import json
import runpy
import subprocess
import tempfile
import time
from pathlib import Path

corpus_rows = runpy.run_path(str(Path(__file__).with_name("prepare-corpus.py")))["rows"]


def external_rows(path):
    with path.open("rb") as archive:
        checksum = hashlib.file_digest(archive, "sha256").hexdigest()
    if checksum != "ecc1efc3a8207f91b3953546011da5f35bc17907e7ae96ada6beb6635efa6dd7":
        raise ValueError("Unexpected PhreshPhish metadata snapshot checksum.")
    yield {"source": "phreshphish", "sha256": checksum}
    with gzip.open(path, "rt", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            yield {"source": "phreshphish", "input": row["url"],
                   "label": {"benign": "legitimate", "phish": "phishing"}[row["source_label"]]}


def hannousse_rows(path):
    with path.open("rb") as archive:
        checksum = hashlib.file_digest(archive, "sha256").hexdigest()
    yield {"source": "hannousse", "sha256": checksum}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            yield {"source": "hannousse", "input": row["url"],
                   "label": row["status"]}


def extract(cache, feature_file, include_external=False, include_hannousse=False):
    script = Path(__file__).with_name("extract-url-training.mjs")
    with subprocess.Popen(["node", "--experimental-strip-types", "--disable-warning=ExperimentalWarning",
                           str(script), str(feature_file)], stdin=subprocess.PIPE, encoding="utf-8") as process:
        for record in corpus_rows(cache):
            if record["source"] in ("phiusiil", "edgephish"):
                process.stdin.write(json.dumps(record, ensure_ascii=True) + "\n")
        if include_external:
            for record in external_rows(cache / "phreshphish.csv.gz"):
                process.stdin.write(json.dumps(record, ensure_ascii=True) + "\n")
        if include_hannousse:
            for record in hannousse_rows(cache / "hannousse.csv"):
                process.stdin.write(json.dumps(record, ensure_ascii=True) + "\n")
        process.stdin.close()
        if process.wait():
            raise RuntimeError("URL feature extraction failed.")


def read_features(path, mixed):
    records = {}
    with path.open(encoding="utf-8") as input_file:
        metadata = json.loads(next(input_file))
        for line in input_file:
            row = json.loads(line)
            if "statistics" in row:
                metadata.update(row)
                break
            split = row["split"]
            if split in ("phreshphish", "hannousse"):
                continue
            if mixed and split == "external":
                slot = row["domainSlot"]
                split = "train" if slot < 70 else "edge-calibration" if slot < 85 else "edge-test"
            group = records.setdefault(split, {"features": [], "label": [], "baseline": []})
            group["features"].append(row["features"])
            group["label"].append(row["label"])
            group["baseline"].append(row["baseline"])
    return metadata, records


def evaluate(labels, flags, inconclusive=None):
    import numpy as np
    positives = labels == 1
    negatives = ~positives
    true_positive = int(np.count_nonzero(flags & positives))
    false_positive = int(np.count_nonzero(flags & negatives))
    return {
        "phishing": int(np.count_nonzero(positives)),
        "legitimate": int(np.count_nonzero(negatives)),
        "flaggedPhishing": true_positive,
        "flaggedLegitimate": false_positive,
        "recall": true_positive / max(int(np.count_nonzero(positives)), 1),
        "falsePositiveRate": false_positive / max(int(np.count_nonzero(negatives)), 1),
        "precision": true_positive / max(true_positive + false_positive, 1),
        "inconclusive": int(np.count_nonzero(inconclusive)) if inconclusive is not None else 0,
    }


def threshold_for(logits, labels, budget):
    import numpy as np
    negative_scores = np.sort(logits[labels == 0])
    if not negative_scores.size:
        raise ValueError("Calibration requires legitimate URLs.")
    permitted = int(len(negative_scores) * budget)
    return float(np.nextafter(negative_scores[-(permitted + 1)], np.inf))


def train(features_path, output, mixed):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score
    from sklearn.preprocessing import StandardScaler

    metadata, records = read_features(features_path, mixed)
    train_rows = records.pop("train")
    matrix = np.asarray(train_rows["features"], dtype=np.float64)
    labels = np.asarray(train_rows["label"], dtype=np.uint8)
    scaler = StandardScaler()
    estimator = LogisticRegression(C=1, max_iter=300, solver="lbfgs")
    start = time.perf_counter()
    estimator.fit(scaler.fit_transform(matrix), labels)
    training_seconds = time.perf_counter() - start

    # Fold standardization into the exported weights so the browser needs one dot product.
    weights = estimator.coef_[0] / scaler.scale_
    intercept = float(estimator.intercept_[0] - weights @ scaler.mean_)
    calibration = records["calibration"]
    calibration_labels = np.asarray(calibration["label"], dtype=np.uint8)
    calibration_verdicts = np.asarray(calibration["baseline"])
    calibration_score = np.asarray(calibration["features"]) @ weights + intercept
    baseline_fpr = evaluate(calibration_labels, np.isin(calibration_verdicts, ["high", "suspicious"]))["falsePositiveRate"]
    thresholds = {
        "sameCalibrationFalseAlarmRate": threshold_for(calibration_score, calibration_labels, baseline_fpr),
        "oneFalseAlarmPerThousand": threshold_for(calibration_score, calibration_labels, 0.001),
    }

    if mixed:
        edge = records["edge-calibration"]
        edge_labels = np.asarray(edge["label"], dtype=np.uint8)
        edge_score = np.asarray(edge["features"]) @ weights + intercept
        edge_baseline = np.asarray(edge["baseline"])
        edge_baseline_fpr = evaluate(edge_labels, np.isin(edge_baseline, ["high", "suspicious"]))["falsePositiveRate"]
        thresholds["sameCalibrationFalseAlarmRate"] = max(thresholds["sameCalibrationFalseAlarmRate"],
            threshold_for(edge_score, edge_labels, edge_baseline_fpr))
        thresholds["oneFalseAlarmPerThousand"] = max(thresholds["oneFalseAlarmPerThousand"],
            threshold_for(edge_score, edge_labels, 0.001))

    metrics = {}
    for name, rows in records.items():
        observed = np.asarray(rows["label"], dtype=np.uint8)
        baseline = np.asarray(rows["baseline"])
        logits = np.asarray(rows["features"]) @ weights + intercept
        rules_flag = np.isin(baseline, ["high", "suspicious"])
        metrics[name] = {
            "currentRules": evaluate(observed, rules_flag, baseline == "inconclusive"),
            "modelAveragePrecision": float(average_precision_score(observed, logits)),
            "rulesOrModelAtBudget": evaluate(
                observed, rules_flag | (logits >= thresholds["oneFalseAlarmPerThousand"]),
                (baseline == "inconclusive") & (logits < thresholds["oneFalseAlarmPerThousand"])),
            **{key: evaluate(observed, logits >= threshold) for key, threshold in thresholds.items()},
        }

    output.mkdir(parents=True, exist_ok=True)
    model = {
        "schemaVersion": 1,
        "algorithm": "logistic-regression",
        "trainingCorpus": "PhiUSIIL and EdgePhish-5G (local research)" if mixed else "PhiUSIIL",
        "featureRuleVersion": metadata["ruleVersion"],
        "features": metadata["features"],
        "weights": weights.tolist(),
        "intercept": intercept,
        "thresholds": thresholds,
    }
    report = {
        "featureMetadata": metadata,
        "trainingRows": len(labels),
        "trainingPhishing": int(np.count_nonzero(labels)),
        "trainingSeconds": training_seconds,
        "operatingPointsChosenOn": ("Each corpus calibration partition independently, stricter threshold per operating point"
                                    if mixed else "PhiUSIIL calibration partition only"),
        "testDesign": "PhiUSIIL registrable-domain groups; EdgePhish excludes all domains shared with PhiUSIIL",
        "metrics": metrics,
    }
    stem = "url-logistic-mixed.local" if mixed else "url-logistic-v1"
    (output / (stem + ".json")).write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    (output / (stem + "-evaluation.json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"trainingRows": len(labels), "metrics": metrics}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive_cache", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models"))
    parser.add_argument("--feature-cache", type=Path, help="Keep the extracted numeric matrix at this path.")
    parser.add_argument("--reuse-feature-cache", action="store_true", help="Train from an existing complete numeric matrix.")
    parser.add_argument("--mixed-research", action="store_true", help="Use both corpora and export a local research-only model.")
    args = parser.parse_args()
    if args.reuse_feature_cache and not args.feature_cache:
        parser.error("--reuse-feature-cache requires --feature-cache")
    if args.mixed_research and not args.reuse_feature_cache and not (args.archive_cache / "edgephish.csv").is_file():
        parser.error("--mixed-research requires edgephish.csv in the archive cache")
    with tempfile.TemporaryDirectory(prefix="phishguard-model-") as temp:
        features = args.feature_cache or Path(temp) / "features.jsonl"
        if not args.reuse_feature_cache:
            extract(args.archive_cache, features)
        train(features, args.output, args.mixed_research)


if __name__ == "__main__":
    main()
