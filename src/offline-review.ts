import type { LinkReview } from "./scanner.ts";

const models = import.meta.glob<LinkReview>("./qualified-review-model.ts", {
  import: "default",
  eager: true,
});

export const offlineReview = models["./qualified-review-model.ts"];
