import { useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { scanInput, verdictFor } from "./scanner.ts";
import "./style.css";

const VERDICTS = {
  high: "High risk",
  suspicious: "Suspicious",
  inconclusive: "Inconclusive",
  low: "No warning signs found in completed checks",
};

function App() {
  const [mode, setMode] = useState<"url" | "text">("url");
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ReturnType<typeof scanInput> | null>(null);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const scan = scanInput(input, mode);
    if (scan.status === "ok") scan.links.sort((left, right) => right.score - left.score);
    setResult(scan);
  }

  return (
    <main>
      <h1>PhishGuard</h1>
      <p>Check a link or suspicious message on this device.</p>
      <form onSubmit={submit}>
        <label htmlFor="mode">Input type</label>
        <select id="mode" value={mode} onChange={(event) => {
          setMode(event.target.value === "text" ? "text" : "url");
          setResult(null);
        }}>
          <option value="url">URL</option>
          <option value="text">Message</option>
        </select>
        <label htmlFor="scan-input">{mode === "url" ? "URL to check" : "Message to check"}</label>
        <textarea id="scan-input" value={input} rows={mode === "url" ? 2 : 6}
          autoComplete="off" spellCheck={false} onChange={(event) => {
            setInput(event.target.value);
            setResult(null);
          }} />
        <div className="actions">
          <button type="submit">Scan</button>
          <button type="button" className="secondary" onClick={() => {
            setInput("");
            setResult(null);
          }}>Clear</button>
        </div>
      </form>
      <section aria-live="polite" aria-atomic="true">
        {result?.status === "invalid" && <p>{result.message}</p>}
        {result?.status === "ok" && (
          <>
            <h2>{VERDICTS[result.verdict]}</h2>
            <p>Heuristic score {result.score}/100</p>
            <ul>{result.coverage.map((item) => <li key={item}>{item}</li>)}</ul>
            {result.messageFindings.length > 0 && <>
              <h3>Message findings</h3>
              <ul>{result.messageFindings.map((finding) => <li key={finding.id}>{finding.label}</li>)}</ul>
            </>}
            {result.links.length > 0 && <>
              <h3>Links checked</h3>
              <ol>{result.links.map((link, index) => (
                <li key={index}>
                  <strong>{link.display}</strong>
                  <span className="link-verdict"> {VERDICTS[verdictFor(link.score, link.unresolved)]} · {link.score}/100</span>
                  {link.findings.length > 0 && (
                    <ul>{link.findings.map((finding) => <li key={finding.id}>{finding.label}</li>)}</ul>
                  )}
                </li>
              ))}</ol>
            </>}
            {result.messageFindings.some((finding) => finding.id === "coercion") ? (
              <p>Keep your PIN and OTP private. Verify the request through the official app or a contact you already trust.</p>
            ) : result.links.some((link) => link.unresolved) ? (
              <p>Ask the sender for the full destination or go directly to the official site.</p>
            ) : result.verdict === "high" || result.verdict === "suspicious" ? (
              <p>Verify any request for payment or account access through the official app before acting.</p>
            ) : null}
          </>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
if (import.meta.env.PROD && "serviceWorker" in navigator) {
  navigator.serviceWorker.register(new URL("./sw.js", location.href)).catch((error: unknown) => {
    console.warn("Offline installation failed", error);
  });
}
