import assert from "node:assert/strict";
import test from "node:test";
import { URL_FEATURES, urlFeatures } from "../src/url-features.ts";
import { modelScore } from "../src/url-classifier.ts";
import { createOfflineReview } from "../src/qualified-model-policy.ts";
import { scanInput, URL_RULE_VERSION } from "../src/scanner.ts";

test("URL feature contract maps URL structure and existing rule IDs to finite numeric inputs", () => {
  const url = new URL("https://parivahan-gov.in/vehicle-challan?reference=123");
  const result = scanInput(url.href, "url");
  assert.equal(result.status, "ok");
  const features = urlFeatures(url, result.links[0].findings.map(({ id }) => id));
  assert.equal(features.length, URL_FEATURES.length);
  assert.ok(features.every(Number.isFinite));
  const get = (name) => features[URL_FEATURES.indexOf(name)];
  assert.equal(get("recognized_brand_mismatch"), 1);
  assert.equal(get("authority_with_action"), 1);
  assert.equal(get("query_parameter_count"), 1);
  assert.equal(get("ip_host"), 0);
});

test("portable scoring supports the linear and compact tree exports", () => {
  assert.equal(modelScore([2, 3], { kind: "logistic", weights: [2, -1], intercept: 0.5 }), 1.5);
  const tree = { kind: "boosted-trees", intercept: 0.5,
    trees: [[[0, 2, 1, 2], [-0.25], [1]], [[1, 3, 1, 2], [0.5], [2]]] };
  assert.equal(modelScore([2, 3], tree), 0.75);
  assert.equal(modelScore([3, 4], tree), 3.5);
});


test("offline model promotion rejects a failed release gate or an incompatible feature contract", () => {
  const vetted = {
    kind: "logistic", intercept: 1, weights: URL_FEATURES.map(() => 0),
    schemaVersion: 3, features: URL_FEATURES, featureRuleVersion: URL_RULE_VERSION,
    reviewQualified: true, reviewThreshold: 0.5,
  };
  assert.throws(() => createOfflineReview({ ...vetted, reviewQualified: false }), /release checks/);
  assert.throws(() => createOfflineReview({ ...vetted, features: [...URL_FEATURES].reverse() }), /release checks/);
  assert.equal(createOfflineReview(vetted)(new URL("https://example.com"), []), true);
});
