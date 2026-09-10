import { promises as dns } from "node:dns";
import ipaddr from "ipaddr.js";

/**
 * Raised when a target fails the safety check below. Deliberately a plain
 * `Error`, not an `AppError`: this is never serialized directly as an HTTP
 * response (the check only ever runs inside `ZapScanExecutor`, at scan
 * execution time — never during target creation, which makes no network
 * request at all), so it does not need a status code. Callers that catch it
 * treat `.message` as safe to store in `Scan.errorMessage`.
 */
export class TargetSafetyViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetSafetyViolation";
  }
}

const BLOCKED_HOSTNAMES = new Set(["localhost"]);
const BLOCKED_HOSTNAME_SUFFIXES = [".localhost"];

/**
 * The only IP address classification this policy trusts. `ipaddr.js`
 * categorizes every address into a range name; rather than deny-listing the
 * ranges we know about (loopback, private, linkLocal, multicast, ...) this
 * allow-lists exactly one: ordinary global unicast. Anything ipaddr.js
 * doesn't recognize as plain "unicast" — including loopback, RFC1918
 * private ranges, link-local (which is what the 169.254.169.254 cloud
 * metadata endpoint falls under — no special case needed), multicast,
 * reserved/unspecified/broadcast, IPv6 unique-local, and IPv6 transition
 * mechanisms that embed an IPv4 address (`ipv4Mapped`, `6to4`, `teredo`,
 * which are exactly the kind of address that could otherwise be used to
 * smuggle a private IPv4 target past a naive check) — is rejected. This is a
 * fail-closed allow-list, not a deny-list: a range ipaddr.js adds in the
 * future that we haven't thought about is rejected by default, not silently
 * allowed.
 */
const SAFE_RANGE = "unicast";

function stripIpv6Brackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

function isSafeAddress(address: string): boolean {
  if (!ipaddr.isValid(address)) {
    return false;
  }
  return ipaddr.parse(address).range() === SAFE_RANGE;
}

/**
 * Validates that `rawUrl` is safe to hand to the ZAP daemon for spidering
 * and active scanning.
 *
 * This is the SSRF boundary for Stage 4. It runs exclusively at scan
 * execution time (see `ZapScanExecutor`) — never during target creation or
 * update, which stay pure database operations with no network I/O.
 *
 * What this function checks, in order:
 * 1. The URL parses and uses `http:`/`https:` (re-checked defensively; the
 *    same rule is already enforced when a target is created).
 * 2. The URL carries no embedded credentials (same reasoning).
 * 3. The hostname is not an explicitly blocked name (`localhost` and
 *    `*.localhost`).
 * 4. If the hostname is itself a literal IP address, that address must
 *    classify as ordinary global unicast (see `SAFE_RANGE` above).
 * 5. Otherwise, the hostname is resolved via this process's own DNS
 *    resolver, and *every* returned address (not just the first) must
 *    classify as safe — a hostname that resolves to even one unsafe address
 *    is rejected outright, rather than trusting whichever address happens to
 *    be tried first.
 *
 * ## What this function cannot guarantee: DNS rebinding
 *
 * The address(es) resolved and validated here are not necessarily the
 * address ZAP itself will connect to. ZAP is a separate process performing
 * its own independent DNS resolution when it actually issues requests,
 * moments later. A hostname with a very short DNS TTL could legitimately
 * resolve to a public address right now (passing this check) and to a
 * private address by the time ZAP connects — "DNS rebinding". Closing that
 * gap completely would require routing 100% of ZAP's outbound traffic
 * through an address-filtering forward proxy (or a custom DNS resolver
 * shared between this check and ZAP's own resolution), which is
 * infrastructure this stage deliberately does not introduce. This function
 * is therefore a strong, fail-closed filter against the common cases —
 * literal private/loopback/link-local addresses, static malicious DNS
 * records, IPv4-in-IPv6 smuggling — and an honest, *not* airtight, defense
 * against an attacker who controls DNS with a short TTL specifically to
 * rebind between this check and ZAP's connection. See the README's "Target
 * Safety Policy" section for the same explanation surfaced to operators.
 */
export async function assertTargetIsSafeToScan(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new TargetSafetyViolation("Target URL could not be parsed");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TargetSafetyViolation("Only http and https targets may be scanned");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new TargetSafetyViolation("Target URL must not contain credentials");
  }

  const hostname = stripIpv6Brackets(parsed.hostname.toLowerCase());

  if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new TargetSafetyViolation("Target hostname is not allowed");
  }

  if (ipaddr.isValid(hostname)) {
    if (!isSafeAddress(hostname)) {
      throw new TargetSafetyViolation("Target resolves to a disallowed IP address range");
    }
    return;
  }

  let resolved: Array<{ address: string }>;
  try {
    resolved = await dns.lookup(hostname, { all: true });
  } catch {
    throw new TargetSafetyViolation("Target hostname could not be resolved");
  }

  if (resolved.length === 0) {
    throw new TargetSafetyViolation("Target hostname did not resolve to any address");
  }

  for (const { address } of resolved) {
    if (!isSafeAddress(address)) {
      throw new TargetSafetyViolation("Target resolves to a disallowed IP address range");
    }
  }
}
