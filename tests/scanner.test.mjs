import test from "node:test";
import assert from "node:assert/strict";
import { MAX_BYTES, MAX_LINKS, scanInput, verdictFor } from "../src/scanner.ts";

function scan(input, mode = "url") {
  const result = scanInput(input, mode);
  assert.equal(result.status, "ok");
  return result;
}

test("verdict boundaries and an authoritative threat match", () => {
  assert.equal(verdictFor(29, false), "low");
  assert.equal(verdictFor(29, true), "inconclusive");
  assert.equal(verdictFor(30, true), "suspicious");
  assert.equal(verdictFor(64, false), "suspicious");
  assert.equal(verdictFor(65, false), "high");
  assert.equal(verdictFor(0, false, true), "high");
});

test("shortened URL is inconclusive and does not reveal its path", () => {
  const result = scan("hxxps://bit[.]ly/private-token?otp=123456");
  assert.equal(result.verdict, "inconclusive");
  assert.equal(result.links[0].display, "bit[.]ly");
  assert.equal(result.score, 15);
  assert.ok(!JSON.stringify(result).includes("123456"));
});

test("brand spoof, confusable brand, bare IP, high entropy and abuse-prone TLD", () => {
  assert.equal(scan("sbi.com.unrelated.top").score, 55);
  assert.equal(scan("sbi.co.in").score, 0);
  assert.equal(scan("https://pаypal.com").links[0].findings[0].id, "confusable");
  assert.equal(scan("https://xn--pypal-4ve.com").links[0].findings[0].id, "confusable");
  for (const url of ["https://127.0.0.1", "https://0x7f000001", "http://[::1]"]) {
    assert.equal(scan(url).links[0].findings[0].id, "ip");
  }
  assert.deepEqual(scan("a2b3c4d5e6f7g8h9ij.xyz").links[0].findings.map(({id}) => id), ["entropy", "tld"]);
});

test("regional rules score distinct categories and retain original offsets", () => {
  const input = "India Post account suspended. Pay a redelivery charge and forward OTP. Forward OTP again.";
  const result = scan(input, "text");
  assert.equal(result.score, 100);
  assert.deepEqual(result.messageFindings.map(({id}) => id), ["urgency", "lure", "coercion", "authority"]);
  const coercion = result.messageFindings[2];
  assert.equal(input.slice(coercion.start, coercion.end), "forward OTP");
});

test("all links retain evidence and URL text does not score as message cues", () => {
  const result = scan("Visit https://example.com/?note=credited and (hxxps://sbi[.]com[.]other[.]top).", "text");
  assert.equal(result.links.length, 2);
  assert.equal(result.messageScore, 0);
  assert.equal(result.score, 55);
  const finding = result.links[1].findings[0];
  assert.equal("Visit https://example.com/?note=credited and (hxxps://sbi[.]com[.]other[.]top).".slice(finding.start, finding.end), "hxxps://sbi[.]com[.]other[.]top");
});

test("duplicate links do not consume the link budget", () => {
  const text = ["https://example.com", "https://EXAMPLE.com/#fragment",
    ...Array.from({length: MAX_LINKS}, (_, i) => "https://example.com/" + i)].join(" ");
  const result = scan(text, "text");
  assert.equal(result.links.length, MAX_LINKS);
  assert.equal(result.verdict, "inconclusive");
  assert.match(result.coverage.join(" "), /10-link limit/);
});

test("invalid, unsupported and oversized input reports incomplete or rejected coverage", () => {
  for (const url of ["", "ftp://example.com", "javascript:alert(1)", "https://user@example.com", "//example.com"]) {
    assert.equal(scanInput(url, "url").status, "invalid", url);
  }
  assert.equal(scanInput("é".repeat(MAX_BYTES / 2 + 1), "text").status, "invalid");
  assert.equal(scan("Contact qa@example.com at noon.", "text").links.length, 0);
  assert.equal(scan("See ftp://example.com", "text").verdict, "inconclusive");
  assert.equal(scan("https://example.com", "url").verdict, "low");
});
