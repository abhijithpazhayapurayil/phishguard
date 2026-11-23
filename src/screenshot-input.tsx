import { useEffect, useRef, useState, type ClipboardEvent } from "react";
import type { OcrLanguage } from "./ocr.ts";

export function ScreenshotInput({ onText }: { onText: (text: string) => void }) {
  const current = useRef<AbortController | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [language, setLanguage] = useState<OcrLanguage>("eng");

  useEffect(() => () => current.current?.abort(), []);

  function cancel() {
    current.current?.abort();
    current.current = null;
    setBusy(false);
    setStatus("Screenshot reading canceled.");
  }

  async function recognize(file: File) {
    current.current?.abort();
    const request = new AbortController();
    const timeout = setTimeout(() => request.abort(), 45_000);
    current.current = request;
    setBusy(true);
    setStatus("Preparing on-device OCR…");
    onText("");
    try {
      const { readScreenshot } = await import("./ocr.ts");
      const stopped = new Promise<never>((_, reject) => {
        if (request.signal.aborted) reject(request.signal.reason);
        else request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true });
      });
      const output = await Promise.race([readScreenshot(file, language, request.signal, (progress) => {
        if (current.current === request) setStatus("Reading screenshot… " + progress + "%");
      }), stopped]);
      if (current.current !== request) return;
      onText(output.text);
      setStatus(output.text ? (output.confidence < 75
        ? "Some text may be inaccurate. Check the transcription below before scanning."
        : "Review the extracted text below, then scan it.") : "No text found. Try cropping around the message.");
    } catch (error) {
      if (current.current !== request) return;
      setStatus(request.signal.aborted ? "Screenshot reading timed out."
        : error instanceof Error ? error.message : "The screenshot could not be read.");
    } finally {
      clearTimeout(timeout);
      if (current.current === request) {
        current.current = null;
        setBusy(false);
      }
    }
  }

  function paste(event: ClipboardEvent<HTMLDivElement>) {
    const file = [...event.clipboardData.files].find((item) => item.type.startsWith("image/"));
    if (file) {
      event.preventDefault();
      void recognize(file);
    }
  }

  return <div className="screenshot-input" role="group" aria-label="Screenshot upload and paste area" tabIndex={0} onPaste={paste}>
    <label htmlFor="ocr-language">Screenshot language</label>
    <select id="ocr-language" value={language} disabled={busy}
      onChange={event => setLanguage(event.target.value === "hin" ? "hin" : "eng")}>
      <option value="eng">English</option><option value="hin">Hindi</option>
    </select>
    <label htmlFor="screenshot-file">Upload or paste a screenshot</label>
    <input id="screenshot-file" type="file" accept="image/png,image/jpeg" onChange={event => {
      const file = event.target.files?.[0];
      event.target.value = "";
      if (file) void recognize(file);
    }} />
    <p role="status">{status || "PNG or JPEG, up to 12 MiB. The first scan may need to download OCR files."}</p>
    {busy && <button className="quiet" type="button" onClick={cancel}>Cancel OCR</button>}
  </div>;
}

