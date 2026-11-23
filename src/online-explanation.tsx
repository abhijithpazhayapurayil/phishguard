import { useState } from "react";

export function OnlineExplanation({ verdict, findings }: { verdict: string; findings: string[] }) {
  const [state, setState] = useState<{ summary: string; nextStep: string } | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const payload = { verdict, findings: [...new Set(findings)] };

  async function explain() {
    setBusy(true);
    setStatus("Requesting an online explanation…");
    try {
      const response = await fetch(new URL("./api/explain", window.location.href), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(4500),
      });
      if (!response.headers.get("content-type")?.includes("application/json")) {
        setStatus("Online explanation is disabled in this deployment.");
        return;
      }
      const result = await response.json();
      if (!response.ok) {
        setStatus(result.error ?? "Online explanation is unavailable.");
        return;
      }
      setState(result);
      setStatus("");
    } catch {
      setStatus("Online explanation is unavailable. The local verdict still applies.");
    } finally {
      setBusy(false);
    }
  }

  return <details className="online-explanation">
    <summary>Online explanation with Gemini</summary>
    <p>Only the verdict and these rule IDs will be sent to Google.</p>
    <code>{JSON.stringify(payload)}</code>
    <button type="button" disabled={busy} onClick={() => void explain()}>Send these findings</button>
    <p role="status">{status}</p>
    {state && <div><p>{state.summary}</p><p>{state.nextStep}</p></div>}
  </details>;
}
