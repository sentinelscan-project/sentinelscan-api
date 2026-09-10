import type { FindingCategory } from "../finding-category.js";

/**
 * ZAP `pluginId` → SentinelScan `FindingCategory`.
 *
 * Keyed by `pluginId` (ZAP's stable rule identifier) deliberately, not by
 * alert/rule *name* — names have changed across ZAP versions and are not a
 * reliable key for string-matching (the task's explicit instruction: prefer
 * stable IDs over name matching). This is a curated, deliberately incomplete
 * mapping of ZAP's most common default active/passive scan rules — not an
 * attempt to enumerate every rule ZAP ships. Anything not listed here maps to
 * `"other"`, and the finding's `sourceRuleId` (the same `pluginId`) is always
 * preserved on the persisted `Finding`, so no rule's origin is ever lost even
 * when its category isn't yet known. Extending this table for a newly
 * encountered `pluginId` is a one-line addition.
 *
 * Source: ZAP's publicly documented rule IDs
 * (https://www.zaproxy.org/docs/alerts/), cross-referenced against alerts
 * observed from a live ZAP 2.17.0 daemon during this stage's testing.
 */
const ZAP_PLUGIN_ID_TO_CATEGORY: Record<string, FindingCategory> = {
  // Injection
  "6": "injection", // Path Traversal
  "7": "injection", // Remote File Inclusion
  "40003": "injection", // CRLF Injection
  "40008": "injection", // Parameter Tampering
  "40009": "injection", // Server Side Include
  "40018": "injection", // SQL Injection
  "40019": "injection", // SQL Injection - MySQL
  "40020": "injection", // SQL Injection - Hypersonic SQL
  "40021": "injection", // SQL Injection - Oracle
  "40022": "injection", // SQL Injection - PostgreSQL
  "40024": "injection", // SQL Injection - SQLite
  "40027": "injection", // SQL Injection - MsSQL
  "90019": "injection", // Server Side Code Injection
  "90020": "injection", // Remote OS Command Injection
  "90023": "injection", // XML External Entity Attack
  "90025": "injection", // Expression Language Injection

  // Client-side
  "40012": "client-side", // Cross Site Scripting (Reflected)
  "40014": "client-side", // Cross Site Scripting (Persistent)
  "40016": "client-side", // Cross Site Scripting (Persistent) - Prime
  "40017": "client-side", // Cross Site Scripting (Persistent) - Spider
  "40026": "client-side", // Cross Site Scripting (DOM Based)
  "10017": "client-side", // Cross-Domain JavaScript Source File Inclusion
  "10043": "client-side", // User Controllable HTML Element Attribute
  "20019": "client-side", // External Redirect

  // Security headers
  "10015": "security-header", // Incomplete or No Cache-control and Pragma HTTP Header Set
  "10016": "security-header", // Web Browser XSS Protection Not Enabled
  "10019": "security-header", // Content-Type Header Missing
  "10020": "security-header", // X-Frame-Options Header Not Set
  "10021": "security-header", // X-Content-Type-Options Header Missing
  "10035": "security-header", // Strict-Transport-Security Header Not Set
  "10038": "security-header", // Content Security Policy (CSP) Header Not Set
  "10055": "security-header", // CSP
  "10063": "security-header", // Feature Policy Header Not Set

  // Security misconfiguration
  "10010": "security-misconfiguration", // Cookie No HttpOnly Flag
  "10011": "security-misconfiguration", // Cookie Without Secure Flag
  "10054": "security-misconfiguration", // Cookie without SameSite Attribute
  "10098": "security-misconfiguration", // Cross-Domain Misconfiguration
  "90027": "security-misconfiguration", // Cookie Slack Detector
  "90028": "security-misconfiguration", // Insecure HTTP Method
  "90033": "security-misconfiguration", // Loosely Scoped Cookie

  // Information disclosure
  "10023": "information-disclosure", // Information Disclosure - Debug Error Messages
  "10024": "information-disclosure", // Information Disclosure - Sensitive Information in URL
  "10025": "information-disclosure", // Information Disclosure - Sensitive Information in HTTP Referrer Header
  "10027": "information-disclosure", // Information Disclosure - Suspicious Comments
  "10036": "information-disclosure", // Server Leaks Version Information via "Server" HTTP Response Header
  "10037": "information-disclosure", // Server Leaks Information via "X-Powered-By" HTTP Response Header
  "10056": "information-disclosure", // X-Debug-Token Information Leak
  "10061": "information-disclosure", // X-AspNet-Version Response Header
  "10094": "information-disclosure", // Base64 Disclosure
  "10096": "information-disclosure", // Timestamp Disclosure
  "40025": "information-disclosure", // Proxy Disclosure
  "40028": "information-disclosure", // ELMAH Information Leak
  "40029": "information-disclosure", // Trace.axd Information Leak
  "40032": "information-disclosure", // .htaccess Information Leak
  "42": "information-disclosure", // Source Code Disclosure - Git
  "43": "information-disclosure", // Source Code Disclosure - SVN
  "90022": "information-disclosure", // Application Error Disclosure
  "10009": "information-disclosure", // In Page Banner Information Leak

  // Cryptography (transport security)
  "10106": "cryptography", // HTTP Only Site

  // Sensitive data exposure
  "10062": "sensitive-data-exposure", // PII Disclosure
  "40034": "sensitive-data-exposure", // .env Information Leak
  "90034": "sensitive-data-exposure", // Cloud Metadata Potentially Exposed

  // Authentication
  "10012": "authentication", // Password Autocomplete in Browser
  "10105": "authentication", // Weak Authentication Method
  "40023": "authentication", // Possible Username Enumeration

  // Authorization
  "10202": "authorization", // Absence of Anti-CSRF Tokens
  "20012": "authorization", // Anti-CSRF Tokens Scanner

  // Cryptography
  "10041": "cryptography", // HTTP to HTTPS Insecure Transition
  "20015": "cryptography", // Heartbleed OpenSSL Vulnerability
  "90024": "cryptography", // Generic Padding Oracle
};

/** Documented fallback: an unrecognized `pluginId` is `"other"`, never a guess. */
export const FALLBACK_CATEGORY: FindingCategory = "other";

export function mapZapPluginIdToCategory(pluginId: string | undefined): FindingCategory {
  if (pluginId === undefined) return FALLBACK_CATEGORY;
  return ZAP_PLUGIN_ID_TO_CATEGORY[pluginId.trim()] ?? FALLBACK_CATEGORY;
}
