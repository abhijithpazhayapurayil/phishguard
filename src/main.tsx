import { useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { HeroArt } from "./hero-art.tsx";
import { scanInput, verdictFor } from "./scanner.ts";
import { ScreenshotInput } from "./screenshot-input.tsx";
import { OnlineExplanation } from "./online-explanation.tsx";
import { OnlineScan } from "./online-scan.tsx";
import { offlineReview } from "./offline-review.ts";
import "./style.css";

type Mode = "url" | "text" | "screenshot";
type Scan = ReturnType<typeof scanInput>;

const MODES = [
  { value: "url", label: "Link", icon: "link" },
  { value: "text", label: "Message", icon: "message" },
  { value: "screenshot", label: "Screenshot", icon: "image" },
] as const;

function Icon({ name }: { name: string }) {
  return <span className={`icon icon-${name}`} aria-hidden="true" />;
}

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

function Result({ scan, mode, input }: { scan: Extract<Scan, { status: "ok" }>; mode: Mode; input: string }) {
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
          <h3>{VERDICTS[scan.verdict]}</h3>
        </div>
        <div className="score">
          <span><strong>{scan.score}</strong>/100</span>
          <small>Heuristic score</small>
        </div>
      </div>
      {advice && <aside className="next-action"><h3>What to do</h3><p>{advice}</p></aside>}
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
      {__PHISHGUARD_ONLINE_SCAN__ && <OnlineScan mode={mode} input={input} />}
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
  const report = useRef<HTMLElement>(null);

  useEffect(() => {
    if (result?.status !== "ok" || !matchMedia("(max-width: 760px)").matches) return;
    if (!report.current || report.current.getBoundingClientRect().top < innerHeight * 0.58) return;
    report.current.scrollIntoView({
      block: "start",
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth",
    });
  }, [run, result]);

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
    <>
      <header className="masthead">
        <div className="shell masthead-inner">
          <div className="brand"><span className="brand-mark"><Icon name="shield" /></span>PhishGuard</div>
          <span className="privacy"><span aria-hidden="true" />On-device scanning</span>
        </div>
      </header>
      <main className="shell">
        <section className="hero" aria-labelledby="page-title">
          <HeroArt />
          <div className="hero-content">
            <h1 id="page-title">Think before<br />you <em>click.</em></h1>
            <p>Check suspicious links, messages, and screenshots for signs of phishing.</p>
          </div>
        </section>
        <div className="workspace">
          <section className="entry panel" aria-labelledby="scan-title">
            <div className="panel-heading">
              <span className="panel-icon"><Icon name="scan" /></span>
              <h2 id="scan-title">New scan</h2>
            </div>
            <form className="editor" onSubmit={submit}>
              <fieldset className="mode-picker">
                <legend className="visually-hidden">Input type</legend>
                {MODES.map(option => (
                  <label key={option.value}>
                    <input type="radio" name="mode" value={option.value} checked={mode === option.value}
                      onChange={() => { setMode(option.value); updateInput(""); }} />
                    <span className="mode-option"><Icon name={option.icon} />{option.label}</span>
                  </label>
                ))}
              </fieldset>
              {mode === "screenshot" && <ScreenshotInput onText={updateInput} />}
              <div className="field-heading">
                <label className="input-label" htmlFor="scan-input">{mode === "url" ? "Link to check" : mode === "text" ? "Message to check" : "Extracted text"}</label>
                {mode !== "screenshot" && <button type="button" className="quiet sample" onClick={() => {
                  updateInput(SAMPLES[mode]);
                  field.current?.focus();
                }}>Try a sample</button>}
              </div>
              <textarea ref={field} id="scan-input" value={input} rows={mode === "url" ? 3 : 5}
                className={mode === "url" ? "url-input" : ""}
                aria-invalid={result?.status === "invalid"}
                aria-describedby={result?.status === "invalid" ? "scan-error" : undefined}
                placeholder={mode === "url" ? "https://example.com" : mode === "text" ? "Paste the message here" : "Text from your screenshot appears here"}
                autoComplete="off" spellCheck={false} autoCapitalize="off"
                onChange={event => updateInput(event.target.value)} />
              {result?.status === "invalid" && <p className="input-error" id="scan-error">{result.message}</p>}
              <div className="actions">
                <button type="submit" className="scan-button"><Icon name="scan" />Run scan<span className="button-arrow" aria-hidden="true" /></button>
                {input && <button type="button" className="quiet" onClick={() => {
                  updateInput("");
                  field.current?.focus();
                }}>Clear</button>}
              </div>
            </form>
          </section>
          <section className="inspection panel" ref={report} aria-labelledby="report-title">
            <div className="panel-heading">
              <span className="panel-icon report-icon"><Icon name="report" /></span>
              <h2 id="report-title">Scan report</h2>
            </div>
            <div role="status" className="visually-hidden">{announcement}</div>
            {result?.status !== "ok" && (
              <div className="empty-state">
                <span className="empty-mark"><Icon name="report" /></span>
                <p>Ready to scan</p>
                <p className="muted">Your verdict and findings will appear here.</p>
              </div>
            )}
            {result?.status === "ok" && <Result key={run} scan={result} mode={mode} input={input} />}
          </section>
        </div>
        <footer className="footer"><Icon name="lock" /><span>Your input stays on this device during local scans.</span></footer>
      </main>
    </>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
if (import.meta.env.PROD && "serviceWorker" in navigator) {
  navigator.serviceWorker.register(new URL("./sw.js", location.href)).catch((error: unknown) => {
    console.warn("Offline installation failed", error);
  });
}
