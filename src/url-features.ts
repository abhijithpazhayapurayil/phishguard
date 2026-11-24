import { parse } from "tldts";

const ACTION_WORDS = new Set(["account", "login", "signin", "verify", "verification", "password", "payment", "pay", "otp", "challan", "wallet", "update", "support"]);
const AUTHORITY_WORDS = new Set(["gov", "government", "official", "bank", "tax", "police", "transport"]);

export const URL_FEATURES = [
  "log_host_length", "log_registered_label_length", "subdomain_depth", "host_digit_fraction",
  "host_hyphens", "ip_host", "idn_host", "log_path_length", "path_depth", "path_digit_fraction",
  "log_query_length", "query_parameter_count", "pct_encoded_count", "path_has_file_extension",
  "host_action_word_count", "path_action_word_count", "host_authority_word_count",
  "authority_with_action", "recognized_brand_mismatch", "confusable_brand", "unusual_label_entropy",
  "suffix_warning", "shortener", "brand_signin_path",
] as const;

const countMatching = (tokens: string[], dictionary: Set<string>) =>
  new Set(tokens.filter(token => dictionary.has(token))).size;

export function urlFeatures(url: URL, findingIds: readonly string[]): number[] {
  const host = url.hostname.replace(/\.$/, "").toLowerCase();
  const identity = parse(host, { allowPrivateDomains: true });
  const path = url.pathname === "/" ? "" : url.pathname.toLowerCase();
  const query = url.search.slice(1);
  const hostTokens = host.split(/[^a-z0-9]+/);
  const pathTokens = path.split(/[^a-z0-9]+/);
  const hostActions = countMatching(hostTokens, ACTION_WORDS);
  const pathActions = countMatching(pathTokens, ACTION_WORDS);
  const authority = countMatching(hostTokens, AUTHORITY_WORDS);
  const digits = (value: string) => (value.match(/\d/g)?.length ?? 0) / Math.max(value.length, 1);
  const hit = (id: string) => Number(findingIds.includes(id));
  return [
    Math.log1p(host.length),
    Math.log1p((identity.domainWithoutSuffix ?? host).length),
    Math.min(12, identity.subdomain?.split(".").filter(Boolean).length ?? 0),
    digits(host),
    Math.min(20, host.match(/-/g)?.length ?? 0),
    Number(identity.isIp),
    Number(/(?:^|\.)xn--/.test(host)),
    Math.log1p(path.length),
    Math.min(20, path.split("/").filter(Boolean).length),
    digits(path),
    Math.log1p(query.length),
    query ? Math.min(20, query.split("&").length) : 0,
    Math.min(20, (path + query).match(/%[\da-f]{2}/gi)?.length ?? 0),
    Number(/\.[a-z][a-z\d]{1,6}$/i.test(path)),
    hostActions,
    pathActions,
    authority,
    Number(authority > 0 && hostActions + pathActions > 0),
    hit("brand"), hit("confusable"), hit("entropy"), hit("tld"), hit("shortener"), hit("brand-path"),
  ];
}

