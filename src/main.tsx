import { useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { scanInput, verdictFor } from "./scanner.ts";
import { ScreenshotInput } from "./screenshot-input.tsx";
import { OnlineExplanation } from "./online-explanation.tsx";
import { offlineReview } from "./offline-review.ts";
import "./style.css";

type Mode = "url" | "text" | "screenshot";
type Scan = ReturnType<typeof scanInput>;

const VERDICTS = {
  high: "High risk",
  suspicious: "Suspicious",
  inconclusive: "Inconclusive",
  low: "No warning signs found in completed checks",
};

const SHORT_VERDICTS = { ...VERDICTS, low: "No warning signs" };
const SAMPLES = {
  url: "https://sbi.com.account-review.example/",
  text: "India Post: Final warning. Pay a redelivery fee at https://delivery-review.example/ and forward your OTP.",
};

function Result({ scan, mode }: { scan: Extract<Scan, { status: "ok" }>; mode: Mode }) {
  const messageFindings = [...scan.messageFindings].sort((a, b) => b.weight - a.weight);
  const links = [...scan.links].sort((a, b) =>
    b.score - a.score || Number(Boolean(b.reviewRequested)) - Number(Boolean(a.reviewRequested)));
  const advice = messageFindings.some(({ id }) => id === "coercion")
    ? "Keep your PIN and OTP private. Verify the request through the official app or a contact you already trust."
    : links.some(({ unresolved }) => unresolved)
      ? "Ask the sender for the full destination or go directly to the official site."
      : scan.verdict === "high" || scan.verdict === "suspicious" || scan.verdict === "inconclusive"
        ? "Verify any request for payment or account access through the official app before acting."
        : null;

  return (
    <div className="scan-result">
      <div className="verdict-banner" data-verdict={scan.verdict}>
        <div>
          <span className="scan-complete"><span aria-hidden="true" />Scan complete</span>
          <h2>{VERDICTS[scan.verdict]}</h2>
        </div>
        <div className="score">
          <span><strong>{scan.score}</strong>/100</span>
          <small>Heuristic score</small>
        </div>
      </div>
      {scan.verdict === "low" && <p className="coverage">The local scan could not verify the destination or sender.</p>}
      <ul className="coverage">{scan.coverage.map(item => <li key={item}>{item}</li>)}</ul>
      {mode !== "url" && (
        <div className="result-group">
          <h3>Message signals</h3>
          {messageFindings.length > 0 ? (
            <ul className="signal-list">{messageFindings.map(finding => (
              <li key={finding.id}><span>{finding.label}</span><span className="points">+{finding.weight}</span></li>
            ))}</ul>
          ) : <p className="muted">No message rules fired.</p>}
        </div>
      )}
      {links.length > 0 && (
        <div className="result-group">
          <h3>Links checked <span className="count">{links.length}</span></h3>
          <ol className="link-list">{links.map((link, index) => {
            const verdict = verdictFor(link.score, link.unresolved || Boolean(link.reviewRequested));
            return (
              <li className="link-result" data-verdict={verdict} key={index}>
                <div className="link-heading">
                  <strong>{link.display}</strong>
                  <span className="link-verdict">{SHORT_VERDICTS[verdict]} <span>· {link.score}/100</span></span>
                </div>
                {link.reviewRequested && <p>Verify this destination through an official source before opening it.</p>}
                {link.findings.length > 0 && (
                  <ul className="signal-list">{link.findings.map(finding => (
                    <li key={finding.id}><span>{finding.label}</span><span className="points">+{finding.weight}</span></li>
                  ))}</ul>
                )}
              </li>
            );
          })}</ol>
        </div>
      )}
      {advice && <aside className="next-action"><h3>What to do</h3><p>{advice}</p></aside>}
      {__PHISHGUARD_GEMINI__ && <OnlineExplanation verdict={scan.verdict} findings={[
        ...messageFindings.map(item => item.id), ...links.flatMap(link => link.findings.map(item => item.id)),
      ]} />}
    </div>
  );
}

function App() {
  const [mode, setMode] = useState<Mode>("url");
  const [input, setInput] = useState("");
  const [result, setResult] = useState<Scan | null>(null);
  const [run, setRun] = useState(0);
  const field = useRef<HTMLTextAreaElement>(null);

  function updateInput(value: string) {
    setInput(value);
    setResult(null);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setResult(scanInput(input, mode === "url" ? "url" : "text", offlineReview));
    setRun(previous => previous + 1);
  }

  const announcement = result?.status === "invalid" ? result.message
    : result?.status === "ok"
      ? `${VERDICTS[result.verdict]}. Score ${result.score} out of 100. ${result.links.length} links checked.`
      : "";

  return (
    <main>
      <header className="masthead">
        <div className="brand"><span className="brand-mark" aria-hidden="true">P</span><h1>PhishGuard</h1></div>
        <span className="privacy"><span aria-hidden="true" />Scans stay on this device</span>
      </header>
      <div className="workspace">
        <div className="entry">
          <div className="intro">
            <p className="headline">Check a link<br />or message.</p>
          </div>
          <form className="editor" onSubmit={submit}>
            <fieldset className="mode-picker">
              <legend className="visually-hidden">Input type</legend>
              {(["url", "text", "screenshot"] as const).map(option => (
                <label key={option}>
                  <input type="radio" name="mode" value={option} checked={mode === option}
                    onChange={() => { setMode(option); updateInput(""); }} />
                  <span>{option === "url" ? "URL" : option === "text" ? "Message" : "Screenshot"}</span>
                </label>
              ))}
            </fieldset>
            {mode === "screenshot" && <ScreenshotInput onText={updateInput} />}
            <label className="input-label" htmlFor="scan-input">{mode === "url" ? "URL to check" : mode === "text" ? "Message to check" : "Extracted text"}</label>
            <textarea ref={field} id="scan-input" value={input} rows={mode === "url" ? 4 : 6}
              className={mode === "url" ? "url-input" : ""}
              placeholder={mode === "url" ? "https://" : "Paste the message here"}
              autoComplete="off" spellCheck={false} autoCapitalize="off"
              onChange={event => updateInput(event.target.value)} />
            <div className="actions">
              <button type="submit" className="scan-button">Scan</button>
              {input && <button type="button" className="quiet" onClick={() => {
                updateInput("");
                field.current?.focus();
              }}>Clear</button>}
              {mode !== "screenshot" && <button type="button" className="quiet sample" onClick={() => {
                updateInput(SAMPLES[mode]);
                field.current?.focus();
              }}>Try a sample</button>}
            </div>
          </form>
        </div>
        <section className="inspection" aria-label="Scan report">
          <div className="inspection-header">
            <span className="inspection-mark" aria-hidden="true" />
            <h2>Scan report</h2>
          </div>
          <div role="status" className="visually-hidden">{announcement}</div>
          {result === null && (
            <div className="empty-state">
              <span className="empty-mark" aria-hidden="true" />
              <p>Ready to scan</p>
              <p className="muted">The verdict and findings will appear here after you scan.</p>
            </div>
          )}
          {result?.status === "invalid" && <p className="input-error">{result.message}</p>}
          {result?.status === "ok" && <Result key={run} scan={result} mode={mode} />}
        </section>
      </div>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
if (import.meta.env.PROD && "serviceWorker" in navigator) {
  navigator.serviceWorker.register(new URL("./sw.js", location.href)).catch((error: unknown) => {
    console.warn("Offline installation failed", error);
  });
}
