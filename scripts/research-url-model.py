"""Compare compact URL models at a fixed false-alarm budget across development corpora."""
import argparse
import json
import runpy
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

train_helpers = runpy.run_path(str(Path(__file__).with_name("train-url-model.py")))
evaluate = train_helpers["evaluate"]
FALSE_ALARM_BUDGET = 0.001


def load(path):
    groups = {}
    with path.open(encoding="utf-8") as stream:
        metadata = json.loads(next(stream))
        for line in stream:
            row = json.loads(line)
            if "statistics" in row:
                metadata.update(row)
                break
            split = row["split"]
            if split == "external":
                slot = row["domainSlot"]
                split = "train" if slot < 70 else "edge-calibration" if slot < 85 else "edge-test"
            group = groups.setdefault(split, ([], [], []))
            group[0].append(row["features"])
            group[1].append(row["label"])
            group[2].append(row["baseline"])
    if "statistics" not in metadata:
        raise ValueError("Feature matrix is incomplete.")
    return metadata, {
        key: (np.asarray(x, dtype=np.float64), np.asarray(y, dtype=np.uint8), np.asarray(baseline))
        for key, (x, y, baseline) in groups.items()
    }


def budget_threshold(scores, labels, rules):
    negative_scores = np.sort(scores[(labels == 0) & ~rules])
    remaining = int(np.count_nonzero(labels == 0) * FALSE_ALARM_BUDGET) - np.count_nonzero((labels == 0) & rules)
    if remaining < 0:
        raise ValueError("Existing rules already exceed the calibration budget.")
    if remaining >= len(negative_scores):
        raise ValueError("Insufficient eligible negative calibration examples.")
    return float(negative_scores[-(remaining + 1)] + 1e-10)


def rules_flag(baseline):
    return np.isin(baseline, ("high", "suspicious"))


def fit_candidates(x, y, feature_names):
    all_columns = np.arange(x.shape[1])
    host_columns = np.array([i for i, name in enumerate(feature_names)
                             if "path" not in name and "query" not in name and name not in
                             {"pct_encoded_count", "authority_with_action"}])
    scaler = StandardScaler().fit(x)
    linear = LogisticRegression(C=0.25, max_iter=300).fit(scaler.transform(x), y)
    weights = linear.coef_[0] / scaler.scale_
    bias = float(linear.intercept_[0] - weights @ scaler.mean_)
    yield "logistic", (lambda values: values @ weights + bias), {
        "kind": "logistic", "weights": weights.tolist(), "intercept": bias,
    }
    for name, columns, rounds in (
        ("boosted-host-only", host_columns, 48),
        ("boosted-full", all_columns, 64),
        ("boosted-full-small", all_columns, 32),
    ):
        model = HistGradientBoostingClassifier(
            max_iter=rounds, learning_rate=0.14, max_leaf_nodes=7,
            min_samples_leaf=70, l2_regularization=2, early_stopping=False,
        ).fit(x[:, columns], y)
        trees = []
        for iteration in model._predictors:
            trees.append([
                [float(node["value"])] if node["is_leaf"] else [
                    int(columns[node["feature_idx"]]), float(node["num_threshold"]),
                    int(node["left"]), int(node["right"]),
                ] for node in iteration[0].nodes
            ])
        yield name, (lambda values, m=model, c=columns: m.decision_function(values[:, c])), {
            "kind": "boosted-trees", "intercept": float(model._baseline_prediction[0, 0]), "trees": trees,
        }


def report_group(data, score, threshold):
    _, labels, baseline = data
    ruled = rules_flag(baseline)
    flagged = score >= threshold
    combined = ruled | flagged
    return {
        "rules": evaluate(labels, ruled, baseline == "inconclusive"),
        "model": evaluate(labels, flagged),
        "combined": evaluate(labels, combined, (baseline == "inconclusive") & ~flagged),
        "averagePrecision": float(average_precision_score(labels, score)),
        "rocAuc": float(roc_auc_score(labels, score)),
        "combinedConfusionMatrix": {
            "truePositive": int(np.count_nonzero((labels == 1) & combined)),
            "falsePositive": int(np.count_nonzero((labels == 0) & combined)),
            "trueNegative": int(np.count_nonzero((labels == 0) & ~combined)),
            "falseNegative": int(np.count_nonzero((labels == 1) & ~combined)),
        },
    }


def exported_scores(data, state):
    if state["kind"] == "logistic":
        return data @ state["weights"] + state["intercept"]
    scores = np.full(len(data), state["intercept"])
    for tree in state["trees"]:
        for row, values in enumerate(data):
            index = 0
            while len(tree[index]) != 1:
                col, threshold, left, right = tree[index]
                index = left if values[col] <= threshold else right
            scores[row] += tree[index][0]
    return scores


def importance(predict, calibration, feature_names):
    x, y, _ = calibration
    rng = np.random.default_rng(586)
    sample = rng.choice(len(x), size=min(5000, len(x)), replace=False)
    sample_x, sample_y = x[sample], y[sample]
    reference = average_precision_score(sample_y, predict(sample_x))
    results = {}
    for index, name in enumerate(feature_names):
        altered = sample_x.copy()
        altered[:, index] = rng.permutation(altered[:, index])
        results[name] = float(reference - average_precision_score(sample_y, predict(altered)))
    return dict(sorted(results.items(), key=lambda pair: -pair[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models"))
    args = parser.parse_args()
    metadata, groups = load(args.features)
    if "phreshphish" not in groups:
        raise ValueError("Independent PhreshPhish input is required.")
    x, y, _ = groups.pop("train")
    calibration_names = ("calibration", "edge-calibration")
    validation = [groups[name] for name in calibration_names]
    names = metadata["features"]
    candidates = {}
    selected = None
    with threadpool_limits(limits=3):
        for name, predict, export in fit_candidates(x, y, names):
            scores = [predict(data[0]) for data in validation]
            threshold = max(budget_threshold(value, data[1], rules_flag(data[2]))
                            for data, value in zip(validation, scores))
            diagnostics = [report_group(data, value, threshold) for data, value in zip(validation, scores)]
            rank = min(item["combined"]["recall"] for item in diagnostics)
            candidates[name] = dict(zip(calibration_names, diagnostics)) | {"minimumRecall": rank}
            print(f"Calibration: {name}, minimum recall {rank:.2%}", flush=True)
            if selected is None or rank > selected[0]:
                selected = (rank, name, predict, export, threshold)
        _, name, predict, export, threshold = selected
        scores = {split: report_group(groups[split], predict(groups[split][0]), threshold)
                  for split in ("test", "edge-test", "phreshphish")}
        sample = groups["test"][0][:300]
        np.testing.assert_allclose(exported_scores(sample, export), predict(sample), atol=1e-9, rtol=1e-9)
        feature_impact = importance(predict, groups["edge-calibration"], names)

    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    model = {"schemaVersion": 2, "name": name, "featureRuleVersion": metadata["ruleVersion"],
             "features": names, "threshold": threshold, **export}
    report = {"featureMetadata": metadata, "trainingRows": len(y), "trainingPhishing": int(y.sum()),
              "selected": name, "candidateCalibration": candidates, "heldOut": scores,
              "featurePermutationAveragePrecisionDelta": feature_impact,
              "releaseGate": "Combined false-positive rate must not exceed 0.001 on either held-out corpus or independent PhreshPhish."}
    (output / "url-mobile-v2.local.json").write_text(json.dumps(model, separators=(",", ":")) + "\n", encoding="utf-8")
    (output / "url-mobile-v2.local-evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"model": name, "metrics": {k: v["combined"] for k, v in scores.items()}}))


if __name__ == "__main__":
    main()

