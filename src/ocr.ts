import { createWorker, type Worker } from "tesseract.js";
import { imageDimensions, MAX_IMAGE_BYTES } from "./image-bounds.ts";

export type OcrLanguage = "eng" | "hin";

export async function readScreenshot(
  file: File,
  language: OcrLanguage,
  signal: AbortSignal,
  onProgress: (percentage: number) => void,
) {
  if (file.size > MAX_IMAGE_BYTES) throw new Error("Choose a screenshot under 12 MiB.");
  const { width, height } = imageDimensions(await file.slice(0, 256 * 1024).arrayBuffer());
  signal.throwIfAborted();
  const scale = Math.min(1, 1800 / Math.max(width, height), Math.sqrt(2_500_000 / (width * height)));
  const bitmap = await createImageBitmap(file, {
    resizeWidth: Math.max(1, Math.round(width * scale)),
    resizeHeight: Math.max(1, Math.round(height * scale)),
    resizeQuality: "high",
    imageOrientation: "none",
  });
  const canvas = document.createElement("canvas");
  try {
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("This browser could not prepare the screenshot.");
    context.fillStyle = "#fff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(bitmap, 0, 0);
  } finally {
    bitmap.close();
  }

  let worker: Worker | undefined;
  const abort = () => { if (worker) void worker.terminate(); };
  signal.addEventListener("abort", abort, { once: true });
  try {
    signal.throwIfAborted();
    const assetBase = new URL("./ocr/v1/", window.location.href);
    worker = await createWorker(language, 1, {
      workerPath: new URL("worker.min.js", assetBase).href,
      corePath: new URL("tesseract-core-lstm.wasm.js", assetBase).href,
      langPath: assetBase.href.replace(/\/$/, ""),
      workerBlobURL: false,
      cacheMethod: "none",
      logger: ({ status, progress }) => {
        if (!signal.aborted && status === "recognizing text") onProgress(Math.floor(progress * 100));
      },
      errorHandler: () => {},
    });
    signal.throwIfAborted();
    const { data } = await worker.recognize(canvas);
    signal.throwIfAborted();
    return { text: data.text.trim(), confidence: data.confidence };
  } finally {
    signal.removeEventListener("abort", abort);
    canvas.width = canvas.height = 0;
    if (worker) await worker.terminate();
  }
}
