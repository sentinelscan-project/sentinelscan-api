/**
 * Sanitizes free-text scanner output (descriptions, evidence, attack
 * payloads, ...) before it is persisted.
 *
 * Every string a `Finding`/`FindingInstance` stores that ultimately came from
 * a scanner's own output (ZAP today; any future scanner tomorrow) passes
 * through this module first. It is treated as **untrusted data**, not markup:
 * nothing here (or anywhere findings are later rendered) interprets it as
 * HTML — the frontend is expected to render it as plain text.
 *
 * Two independent rules apply, in order:
 *
 * 1. **Redact credential-like content.** A scanner's evidence/attack fields
 *    are snippets of real HTTP traffic — an `evidence` string quoting a
 *    response header, for instance, could legitimately include a live
 *    `Set-Cookie` or `Authorization` value if the target actually returned
 *    one. Known-sensitive patterns (Authorization/Cookie/Set-Cookie headers,
 *    and generic `key=value` / `key: value` pairs for api-key/token/secret/
 *    password/bearer-shaped keys) are *replaced*, not merely flagged —
 *    "prefer redaction over truncation" for anything credential-shaped, since
 *    truncating a secret can still leave enough of it exposed to be useful to
 *    an attacker.
 * 2. **Cap length.** Applied after redaction, so a would-be-secret near the
 *    truncation boundary is still redacted rather than half-truncated into
 *    something that looks safe but isn't.
 */

const REDACTED = "[REDACTED]";

/**
 * Header-style secrets: `Header-Name: <value up to end of line>`. Covers the
 * request `Cookie` header, the response `Set-Cookie` header, and
 * `Authorization` (Bearer/Basic/anything else) in one pattern, replacing only
 * the value so the header name stays visible for context.
 */
const HEADER_SECRET_PATTERN = /\b(authorization|cookie|set-cookie|proxy-authorization)\s*:\s*[^\r\n]+/gi;

/**
 * `key=value` / `key: "value"` / `key: value` / `"key": "value"` shaped
 * secrets for common credential-flavored key names, wherever they appear in
 * a string (not just at a line start) — e.g. inside a URL query string or a
 * JSON-looking evidence blob. The optional `["']?` immediately after the key
 * name handles a JSON-quoted key (`"password": "..."`) — without it, the
 * closing quote of the key sits between the key name and the `:`, and the
 * pattern would not match at all. Only the value is redacted.
 */
const KEY_VALUE_SECRET_PATTERN =
  /\b((?:api[_-]?key|access[_-]?key|secret|token|bearer|password|passwd|pwd|session[_-]?id)s?)["']?\s*[:=]\s*["']?[^\s"'&,;]{3,}["']?/gi;

function redactSecrets(value: string): string {
  return value
    .replace(HEADER_SECRET_PATTERN, (_match, headerName: string) => `${headerName}: ${REDACTED}`)
    .replace(KEY_VALUE_SECRET_PATTERN, (_match, keyName: string) => `${keyName}=${REDACTED}`);
}

function cap(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}… [truncated]`;
}

/** Redacts credential-like content, then caps the result to `maxLength`. */
export function sanitizeFindingText(value: string, maxLength: number): string {
  return cap(redactSecrets(value.trim()), maxLength);
}

/** Same as {@link sanitizeFindingText}, but passes `null`/`undefined`/empty through unchanged. */
export function sanitizeOptionalFindingText(
  value: string | null | undefined,
  maxLength: number,
): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    return null;
  }
  return sanitizeFindingText(trimmed, maxLength);
}

/**
 * Sanitizes a list of reference URLs: redact (defensive — a reference is not
 * expected to carry secrets, but scanner-supplied data is never trusted),
 * cap each entry's length, drop blanks, and cap the list itself so a
 * malformed or hostile scanner response can't produce an unbounded array.
 */
export function sanitizeReferenceList(
  values: readonly string[],
  maxItems: number,
  maxItemLength: number,
): string[] {
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed === "") continue;
    result.push(sanitizeFindingText(trimmed, maxItemLength));
    if (result.length >= maxItems) break;
  }
  return result;
}
