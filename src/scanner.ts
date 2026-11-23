import { parse } from "tldts";
import { toUnicode } from "tr46";

export const MAX_BYTES = 16 * 1024;
export const MAX_LINKS = 10;

type Finding = { id: string; label: string; weight: number; start: number; end: number };
type Link = {
  display: string;
  findings: Finding[];
  score: number;
  unresolved: boolean;
};
type Verdict = "high" | "suspicious" | "inconclusive" | "low";
type Scan = {
  status: "ok";
  links: Link[];
  messageFindings: Finding[];
  messageScore: number;
  score: number;
  verdict: Verdict;
  coverage: string[];
};

const BRANDS = new Map([
  ["paypal", ["paypal.com"]],
  ["sbi", ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"]],
  ["netflix", ["netflix.com"]],
  ["indiapost", ["indiapost.gov.in"]],
]);
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "is.gd", "t.co"]);
const TLDS = new Set(["top", "xyz", "buzz", "click", "cfd", "rest"]);
const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i",
  ѕ: "s", ӏ: "l", ԁ: "d", ο: "o", ρ: "p", α: "a", ν: "v", ι: "i",
};
const RULES = [
  ["urgency", "Urgency or a threat of immediate consequences", 20,
    /\b(?:act immediately|immediately|within (?:\d+|one|two) hours?|account suspended|electricity (?:will be )?(?:cut off|disconnected)|warrant issued|police action|final warning)\b/i],
  ["lure", "Unexpected reward, payment or refund language", 25,
    /\b(?:lottery reward|cashback bonus|income tax refund|crypto giveaway|kyc expired|fee refund|(?:telegram|prepaid) tasks?|redelivery charge|credited)\b/i],
  ["coercion", "Request involving credentials, a payment PIN or remote access", 30,
    /\b(?:(?:download|install) (?:an? )?apk|install (?:anydesk|teamviewer)|(?:enter|share) (?:your )?upi pin to receive|(?:forward|share|send|provide) (?:your |the )?otp)\b/i],
  ["authority", "Claims involving a frequently impersonated service", 25,
    /\b(?:india post|state electricity board|sbi yono|traffic e[- ]?challan)\b/i],
] as const;

const URL_CANDIDATE = /(?<![\p{L}\p{N}_@.\-])(?:[a-z][a-z\d+.-]*:\/\/[^\s<>"'\x60]+|(?:[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N}-]*\.)+(?:[\p{L}][\p{L}\p{M}\p{N}-]*|\d{1,3})(?![\p{L}\p{M}\p{N}@_-])(?::\d+)?(?:[/#?][^\s<>"'\x60]*)?)/giu;

function score(findings: Finding[]): number {
  return Math.min(100, findings.reduce((sum, finding) => sum + finding.weight, 0));
}

export function verdictFor(
  risk: number, incomplete: boolean, threatMatch = false,
): Verdict {
  if (threatMatch || risk >= 65) return "high";
  if (risk >= 30) return "suspicious";
  return incomplete ? "inconclusive" : "low";
}

function entropy(label: string): number {
  const chars = Array.from(label);
  const counts = new Map<string, number>();
  for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1);
  return -Array.from(counts.values()).reduce((sum, count) => {
    const probability = count / chars.length;
    return sum + probability * Math.log2(probability);
  }, 0);
}

function analyzeUrl(
  url: URL, identity: ReturnType<typeof parse>, start: number, end: number,
): Link {
  const host = url.hostname.replace(/\.$/, "");
  const registrable = identity.domain ?? host;
  const findings: Finding[] = [];
  const add = (id: string, label: string, weight: number) =>
    findings.push({ id, label, weight, start, end });

  if (identity.isIp) add("ip", "The link uses a numeric IP address", 35);

  const unicodeHost = toUnicode(host).domain.toLowerCase();
  const labels = unicodeHost.split(".");
  for (const [brand, domains] of BRANDS) {
    if (domains.includes(registrable)) continue;
    if (labels.some((label) => label.split("-").includes(brand))) {
      add("brand", "A brand appears on a domain outside its recognized domains", 50);
      break;
    }
  }
  if (labels.some((label) => {
    const skeleton = Array.from(label, (char) => CONFUSABLES[char] ?? char).join("");
    return skeleton !== label && BRANDS.has(skeleton);
  })) {
    add("confusable", "The domain uses lookalike characters in a brand name", 45);
  }

  if (identity.domainWithoutSuffix && entropy(identity.domainWithoutSuffix) > 4) {
    add("entropy", "The registered name contains an unusually varied character sequence", 10);
  }
  if (identity.publicSuffix && TLDS.has(identity.publicSuffix)) {
    add("tld", "The domain suffix is a weak risk signal", 5);
  }
  const unresolved = SHORTENERS.has(registrable);
  if (unresolved) add("shortener", "The shortened destination was not resolved", 15);

  return {
    display: host.replaceAll(".", "[.]"),
    findings,
    score: score(findings),
    unresolved,
  };
}

function normalize(text: string): { text: string; offsets: number[] } {
  const offsets: number[] = [];
  let position = 0;
  let normalized = "";
  for (const match of text.matchAll(/\[\.\]|\bhxxps?(?=:\/\/)/gi)) {
    const start = match.index;
    normalized += text.slice(position, start);
    for (let i = position; i < start; i++) offsets.push(i);
    const replacement = match[0] === "[.]" ? "." : match[0].toLowerCase().replace("xx", "tt");
    normalized += replacement;
    for (let i = 0; i < replacement.length; i++) offsets.push(start + i);
    position = start + match[0].length;
  }
  normalized += text.slice(position);
  for (let i = position; i <= text.length; i++) offsets.push(i);
  return { text: normalized, offsets };
}

export function scanInput(input: string, mode: "url" | "text"): Scan | {
  status: "invalid"; message: string;
} {
  if (!input.trim()) return { status: "invalid", message: "Enter a URL or paste a message." };
  if (input.length > MAX_BYTES || new TextEncoder().encode(input).length > MAX_BYTES) {
    return { status: "invalid", message: "Input exceeds the 16 KiB scan limit." };
  }

  const normalized = normalize(input);
  const candidates = mode === "url"
    ? [{ 0: normalized.text.trim(), index: normalized.text.length - normalized.text.trimStart().length }]
    : normalized.text.matchAll(URL_CANDIDATE);
  const links: Link[] = [];
  const ignoredSpans: [number, number][] = [];
  const seen = new Set<string>();
  const coverage = ["Local checks only"];
  let skipped = false;
  let invalidLink = false;

  for (const candidate of candidates) {
    const value = mode === "text" ? candidate[0].replace(/[.,!?;:)\]}]+$/u, "") : candidate[0];
    const start = normalized.offsets[candidate.index];
    const end = normalized.offsets[candidate.index + value.length];
    const explicit = /^[a-z][a-z\d+.-]*:\/\//i.test(value);
    let url: URL | null = null;
    if (!/[\s\\]/u.test(value) && (explicit || !value.startsWith("/"))) {
      url = URL.canParse(explicit ? value : "https://" + value)
        ? new URL(explicit ? value : "https://" + value)
        : null;
    }

    const identity = url && parse(url.hostname, { allowPrivateDomains: true });
    if (!url || !identity || !["http:", "https:"].includes(url.protocol)
      || url.username || url.password || (!identity.isIp && !identity.domain)
      || (!explicit && !identity.isIp && !identity.isIcann && !identity.isPrivate)) {
      if (mode === "url") {
        return { status: "invalid", message: "Enter one valid HTTP(S) URL or public domain without credentials." };
      }
      if (explicit) {
        invalidLink = true;
        ignoredSpans.push([start, end]);
      }
      continue;
    }

    ignoredSpans.push([start, end]);
    url.hostname = url.hostname.replace(/\.$/, "");
    url.hash = "";
    if (seen.has(url.href)) continue;
    if (links.length === MAX_LINKS) {
      skipped = true;
      continue;
    }
    seen.add(url.href);
    links.push(analyzeUrl(url, identity, start, end));
  }

  if (skipped) coverage.push("Some URLs were skipped because the scan reached its 10-link limit.");
  if (invalidLink) coverage.push("Some URL candidates were invalid or unsupported.");
  if (links.some((link) => link.unresolved)) coverage.push("One or more shortened destinations were not resolved.");

  const messageFindings: Finding[] = [];
  if (mode === "text") {
    let previousEnd = 0;
    let message = "";
    for (const [start, end] of ignoredSpans) {
      message += input.slice(previousEnd, start) + "\n".repeat(end - start);
      previousEnd = end;
    }
    message += input.slice(previousEnd);
    for (const [id, label, weight, pattern] of RULES) {
      const match = pattern.exec(message);
      if (match) messageFindings.push({ id, label, weight, start: match.index, end: match.index + match[0].length });
    }
  }

  const messageScore = score(messageFindings);
  const risk = Math.max(messageScore, ...links.map((link) => link.score));
  const usable = links.length > 0 || (mode === "text" && /\p{L}/u.test(input));
  if (!usable) coverage.push("There was no URL or readable message to score.");
  return {
    status: "ok",
    links,
    messageFindings,
    messageScore,
    score: risk,
    verdict: verdictFor(risk, skipped || invalidLink || !usable || links.some((link) => link.unresolved)),
    coverage,
  };
}
