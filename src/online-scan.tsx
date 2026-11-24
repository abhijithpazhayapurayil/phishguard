import { useState } from "react";
import { MAX_BYTES } from "./scanner.ts";

type Assessment = { risk: "suspicious" | "inconclusive"; summary: string };

export function OnlineScan({ mode, input }: { mode: "url" | "text" | "screenshot"; input: string }) {
  const [submission, setSubmission] = useState(input);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const oversized = new TextEncoder().encode(submission).length > MAX_BYTES;
  const label = mode === "url" ? "link" : mode === "screenshot" ? "extracted text" : "message";

  async function scanOnline() {
    setBusy(true);
    setAssessment(null);
    setStatus("Gemini is checking…");
    try {
      const response = await fetch(new URL("./api/scan", window.location.href), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mode === "url" ? "url" : "text", input: submission }),
        signal: AbortSignal.timeout(14000),
      });
      const result = await response.json();
      if (!response.ok) {
        setStatus(result.error ?? "Gemini is unavailable. Your local result is still available.");
        return;
      }
      setAssessment(result);
      setStatus("");
    } catch {
      setStatus("Gemini is unavailable. Your local result is still available.");
    } finally {
      setBusy(false);
    }
  }

  return <details className="online-explanation">
    <summary>Online scan with Gemini</summary>
    <p>Google receives the {label} in the box below when you send it. Remove any private details or passcodes first.</p>
    <p>Gemini checks the submitted text for scam clues. It cannot open links or verify the sender.</p>
    <label className="input-label" htmlFor="gemini-submission">Text to send to Gemini</label>
    <textarea id="gemini-submission" value={submission} rows={3} disabled={busy}
      autoComplete="off" spellCheck={false}
      onChange={event => { setSubmission(event.target.value); setAssessment(null); setStatus(""); }} />
    {oversized && <p>The online scan accepts up to 16 KB of text.</p>}
    <button type="button" disabled={busy || !submission.trim() || oversized} onClick={() => void scanOnline()}>
      Send {label} to Gemini
    </button>
    <div role="status">
      {status && <p>{status}</p>}
      {assessment && <div>
        <p><strong>Gemini assessment · {assessment.risk === "suspicious" ? "Suspicious" : "Inconclusive"}</strong></p>
        <p>{assessment.summary}</p>
        <p>Verify requests through the official app or a contact you already trust.</p>
      </div>}
    </div>
  </details>;
}
