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

/**
 * Escapes a string for literal use inside a regular expression pattern.
 */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Builds the include-in-scope regex for a target's authorized origin.
 *
 * Stage 4's scope policy is a conservative same-origin check: scheme +
 * hostname + effective port, exactly as `URL.origin` computes it (default
 * ports already dropped by `normalizeTargetUrl`). The regex matches the
 * origin itself and anything under it (`https://example.com`,
 * `https://example.com/login`, `https://example.com/api/users`) but not a
 * different scheme, a different port, a different host, or a superficially
 * similar host (`evil-example.com`, `example.com.evil.com`, or an
 * unregistered subdomain like `sub.example.com` — subdomains are
 * deliberately not included; broadening scope to a whole domain is not done
 * silently).
 *
 * This regex is handed to ZAP's own context `includeInContext` action, so
 * scope is enforced by ZAP itself while spidering and active-scanning, not
 * re-implemented by intercepting ZAP's traffic — see the README's "Scope
 * Policy" section for what that does and does not cover (in particular,
 * around redirects).
 */
export function buildOriginScopeRegex(targetUrl: string): string {
  const origin = new URL(targetUrl).origin;
  return `^${escapeRegExp(origin)}(/.*)?$`;
}
