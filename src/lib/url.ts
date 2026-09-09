/**
 * Validates and normalizes a target root URL.
 *
 * Only absolute `http:`/`https:` URLs are accepted — anything else
 * (`javascript:`, `file:`, `data:`, a bare hostname, a relative path, ...) is
 * rejected outright rather than "handled". Credentials embedded in the URL
 * (`http://user:pass@host/`) are rejected too: there is no legitimate reason
 * for a target's root URL to carry them, and accepting one risks a secret
 * ending up stored and later logged.
 *
 * Normalization is whatever the WHATWG `URL` parser does when it serializes
 * back to `.href`: lower-cased scheme/host, default ports (80/443) dropped, a
 * bare root path filled in as `/`. That is enough for "the same target
 * registered twice looks the same" without inventing bespoke canonicalization
 * rules.
 *
 * This function never makes a network request, resolves DNS, or otherwise
 * touches the URL beyond parsing the string — Stage 2 is registration only.
 */
export function normalizeTargetUrl(value: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }

  if (parsed.username !== "" || parsed.password !== "") {
    return null;
  }

  return parsed.href;
}
