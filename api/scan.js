import { createGeminiScan } from "../scripts/gemini-scan.mjs";

const scan = createGeminiScan();

export default {
  fetch(request) {
    return scan(request, process.env.GEMINI_API_KEY);
  },
};
