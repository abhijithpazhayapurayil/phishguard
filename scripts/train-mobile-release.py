"""Train a small offline URL model and qualify warnings separately from review suggestions."""
import argparse
import json
import math
import runpy
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

helpers = runpy.run_path(str(Path(__file__).with_name("research-url-model.py")))
rules_flag = helpers["rules_flag"]
evaluate = helpers["evaluate"]
exported_scores = helpers["exported_scores"]
WARNING_TARGET = 0.001
REVIEW_TARGET = 0.025


def cohorts(path, cross_calibrate=False):
    groups = {}
    with path.open(encoding="utf-8-sig") as stream:
        metadata = json.loads(next(stream))
        for line in stream:
            row = json.loads(line)
            if "statistics" in row:
                metadata.update(row)
                break
            split = row["split"]
            if split == "external":
                subset = "edge-calibration" if cross_calibrate and row["domainSlot"] < 15 else "edge-transfer"
            elif split == "hannousse":
                subset = "hannousse"
            elif split == "phreshphish":
                slot = row["domainSlot"]
                subset = "phresh-train" if slot < 70 else "phresh-calibration" if slot < 85 else "phresh-test"
            else:
                subset = "phi-" + split
            group = groups.setdefault(subset, ([], [], []))
            group[0].append(row["features"])
            group[1].append(row["label"])
            group[2].append(row["baseline"])
    if "statistics" not in metadata:
        raise ValueError("Incomplete feature matrix.")
    return metadata, {name: (np.asarray(x), np.asarray(y), np.asarray(baseline))
                       for name, (x, y, baseline) in groups.items()}


def threshold(scores, labels, blocked, rate):
    negative = labels == 0
    available = np.sort(scores[negative & ~blocked])
    allowed = math.floor(negative.sum() * rate)
    if allowed < 0 or not len(available):
        raise ValueError("Calibration requires eligible legitimate URLs.")
    return float(available[-(min(allowed, len(available) - 1) + 1)] + 1e-9)


def upper_bound(events, total):
    if not total:
        return 1.0
    z = 1.645
    rate = events / total
    scale = z * z / total
    return (rate + scale / 2 + z * math.sqrt((rate * (1 - rate) + scale / 4) / total)) / (1 + scale)


def fit_models(x, y, weights):
    scaler = StandardScaler().fit(x)
    estimator = LogisticRegression(C=0.4, max_iter=350).fit(scaler.transform(x), y, sample_weight=weights)
    coef = estimator.coef_[0] / scaler.scale_
    bias = float(estimator.intercept_[0] - coef @ scaler.mean_)
    yield "linear", lambda values: values @ coef + bias, {
        "kind": "logistic", "intercept": bias, "weights": coef.tolist(),
    }
    for rounds, leaves in ((32, 7), (64, 7), (96, 9)):
        model = HistGradientBoostingClassifier(max_iter=rounds, max_leaf_nodes=leaves,
            learning_rate=0.13, min_samples_leaf=85, l2_regularization=3, early_stopping=False)
        model.fit(x, y, sample_weight=weights)
        trees = [
            [[float(node["value"])] if node["is_leaf"] else [
                int(node["feature_idx"]), float(node["num_threshold"]), int(node["left"]), int(node["right"]),
            ] for node in iteration[0].nodes]
            for iteration in model._predictors
        ]
        yield f"boosted-{rounds}x{leaves}", model.decision_function, {
            "kind": "boosted-trees", "intercept": float(model._baseline_prediction[0, 0]), "trees": trees,
        }


def calibration_cutoffs(predict, sets):
    warning_cutoffs = []
    review_cutoffs = []
    for values, labels, baseline in sets:
        logits = predict(values)
        warned = rules_flag(baseline)
        uncertain = baseline == "inconclusive"
        n = np.count_nonzero(labels == 0)
        false_warnings = np.count_nonzero((labels == 0) & warned)
        extra_warning_budget = max(0, (math.floor(n * 0.0006) - false_warnings) / n)
        warning_cutoffs.append(threshold(logits, labels, warned, extra_warning_budget))
        review_cutoffs.append(threshold(logits, labels, warned | uncertain, 0.012))
    return max(warning_cutoffs), max(review_cutoffs)


def measure(predict, data, cutoffs):
    values, labels, baseline = data
    logits = predict(values)
    warned = rules_flag(baseline)
    uncertain = baseline == "inconclusive"
    warning = warned | (logits >= cutoffs[0])
    review = ~warned & ~uncertain & (logits >= cutoffs[1])
    warning_metrics = evaluate(labels, warning)
    review_metrics = evaluate(labels, review)
    return {
        "rules": evaluate(labels, warned, uncertain),
        "rulesPlusModelWarning": warning_metrics,
        "warningFalsePositiveUpper95": upper_bound(warning_metrics["flaggedLegitimate"], warning_metrics["legitimate"]),
        "additionalReview": review_metrics,
        "reviewFalsePositiveUpper95": upper_bound(review_metrics["flaggedLegitimate"], review_metrics["legitimate"]),
        "rulesOrReviewOrUncertain": evaluate(labels, warned | review | uncertain),
        "modelAveragePrecision": float(average_precision_score(labels, logits)),
        "modelRocAuc": float(roc_auc_score(labels, logits)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models"))
    parser.add_argument("--cross-calibrate", action="store_true", help="Calibrate on a domain-disjoint 15% of EdgePhish.")
    args = parser.parse_args()
    metadata, groups = cohorts(args.matrix, args.cross_calibrate)
    phi, phresh = groups.pop("phi-train"), groups.pop("phresh-train")
    x, y = np.vstack((phi[0], phresh[0])), np.concatenate((phi[1], phresh[1]))
    weights = np.concatenate((np.full(len(phi[1]), len(y) / (2 * len(phi[1]))),
                              np.full(len(phresh[1]), len(y) / (2 * len(phresh[1])))))
    calibration = [groups["phi-calibration"], groups["phresh-calibration"]]
    if args.cross_calibrate:
        calibration.append(groups["edge-calibration"])
    selection = []
    winner = None
    with threadpool_limits(limits=3):
        for name, predict, portable in fit_models(x, y, weights):
            cutoffs = calibration_cutoffs(predict, calibration)
            metrics = [measure(predict, data, cutoffs) for data in calibration]
            rank = min(metric["rulesOrReviewOrUncertain"]["recall"] for metric in metrics)
            selection.append({"model": name, "minimumCalibrationReviewRecall": rank, "calibration": metrics})
            print(f"Calibration {name}: {rank:.2%} minimum review recall", flush=True)
            if winner is None or rank > winner[0]:
                winner = (rank, name, predict, portable, cutoffs)
        _, name, predict, portable, cutoffs = winner
        test_names = ("phi-test", "phresh-test", "edge-transfer", "hannousse")
        held_out = {key: measure(predict, groups[key], cutoffs) for key in test_names if key in groups}
        for key in held_out:
            sample = groups[key][0][:300]
            np.testing.assert_allclose(exported_scores(sample, portable), predict(sample), atol=1e-9, rtol=1e-9)
    warning_qualified = all(r["warningFalsePositiveUpper95"] <= WARNING_TARGET for r in held_out.values())
    review_qualified = all(r["reviewFalsePositiveUpper95"] <= REVIEW_TARGET for r in held_out.values())
    if args.cross_calibrate:
        warning_qualified &= "hannousse" in held_out
        review_qualified &= "hannousse" in held_out
    model = {"schemaVersion": 3, "name": name, "features": metadata["features"],
             "featureRuleVersion": metadata["ruleVersion"], "warningThreshold": cutoffs[0],
             "reviewThreshold": cutoffs[1], "warningQualified": warning_qualified,
             "reviewQualified": review_qualified, **portable}
    report = {"featureMetadata": metadata, "trainingRows": len(y), "trainingPhishing": int(y.sum()),
              "trainingSources": {"phiusiil": len(phi[1]), "phreshphish": len(phresh[1])},
              "selection": selection, "selected": name, "heldOut": held_out,
              "crossSourceCalibration": args.cross_calibrate,
              "limits": {"warningUpper95": WARNING_TARGET, "additionalReviewUpper95": REVIEW_TARGET},
              "warningQualified": warning_qualified, "reviewQualified": review_qualified,
              "confidenceMethod": "One-sided 95% Wilson upper bound at URL-row level; campaign clustering can widen the true interval."}
    args.output.mkdir(parents=True, exist_ok=True)
    stem = "url-mobile-v4" if args.cross_calibrate else "url-mobile-v3"
    (args.output / (stem + ".json")).write_text(json.dumps(model, separators=(",", ":")) + "\n", encoding="utf-8")
    (args.output / (stem + "-evaluation.json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"selected": name, "warningQualified": warning_qualified, "reviewQualified": review_qualified,
                      "heldOut": held_out}))


if __name__ == "__main__":
    main()

