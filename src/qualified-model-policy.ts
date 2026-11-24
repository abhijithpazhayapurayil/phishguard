import { URL_RULE_VERSION, type LinkReview } from "./scanner.ts";
import { URL_FEATURES, urlFeatures } from "./url-features.ts";
import { modelScore, type UrlClassifier } from "./url-classifier.ts";

function validClassifier(model: Record<string, unknown>): model is Record<string, unknown> & UrlClassifier {
  if (!Number.isFinite(model.intercept)) return false;
  if (model.kind === "logistic") {
    return Array.isArray(model.weights) && model.weights.length === URL_FEATURES.length
      && model.weights.every(Number.isFinite);
  }
  return model.kind === "boosted-trees" && Array.isArray(model.trees)
    && model.trees.length > 0 && model.trees.length <= 128
    && model.trees.every(tree => Array.isArray(tree) && tree.length > 0 && tree.length <= 31
      && tree.every((node, index) => {
        if (!Array.isArray(node) || !node.every(Number.isFinite)) return false;
        if (node.length === 1) return true;
        return node.length === 4 && Number.isInteger(node[0]) && node[0] >= 0 && node[0] < URL_FEATURES.length
          && [node[2], node[3]].every(child => Number.isInteger(child) && child > index && child < tree.length);
      }));
}

export function createOfflineReview(serialized: unknown): LinkReview {
  const model = serialized as Record<string, unknown> | null;
  if (!model || model.schemaVersion !== 3 || model.reviewQualified !== true
    || model.featureRuleVersion !== URL_RULE_VERSION
    || !Array.isArray(model.features) || model.features.length !== URL_FEATURES.length
    || !model.features.every((feature, index) => feature === URL_FEATURES[index])
    || typeof model.reviewThreshold !== "number" || !Number.isFinite(model.reviewThreshold)
    || !validClassifier(model)) {
    throw new Error("The on-device review model did not pass the release checks.");
  }
  const threshold = model.reviewThreshold;
  return (url, findingIds) => modelScore(urlFeatures(url, findingIds), model) >= threshold;
}
