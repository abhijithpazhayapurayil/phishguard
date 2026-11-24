type TreeNode = [value: number] | [feature: number, boundary: number, left: number, right: number];

export type UrlClassifier =
  | { kind: "logistic"; intercept: number; weights: number[] }
  | { kind: "boosted-trees"; intercept: number; trees: TreeNode[][] };

export function modelScore(values: number[], model: UrlClassifier): number {
  let score = model.intercept;
  if (model.kind === "logistic") {
    for (const [index, weight] of model.weights.entries()) score += values[index] * weight;
    return score;
  }
  for (const tree of model.trees) {
    let node = tree[0];
    while (node.length === 4) {
      const [feature, boundary, left, right] = node;
      node = tree[values[feature] <= boundary ? left : right];
    }
    score += node[0];
  }
  return score;
}
