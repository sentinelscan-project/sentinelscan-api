import { describe, it, expect, vi, afterEach } from "vitest";

const { lookupMock } = vi.hoisted(() => ({ lookupMock: vi.fn() }));

vi.mock("node:dns", () => ({
  promises: {
    lookup: lookupMock,
  },
}));

import { assertTargetIsSafeToScan, TargetSafetyViolation } from "../src/lib/target-safety.js";

afterEach(() => {
  lookupMock.mockReset();
});

describe("assertTargetIsSafeToScan", () => {
  it("rejects unsupported protocols", async () => {
    await expect(assertTargetIsSafeToScan("javascript:alert(1)")).rejects.toBeInstanceOf(TargetSafetyViolation);
    await expect(assertTargetIsSafeToScan("file:///etc/passwd")).rejects.toBeInstanceOf(TargetSafetyViolation);
    await expect(assertTargetIsSafeToScan("ftp://example.com")).rejects.toBeInstanceOf(TargetSafetyViolation);
  });

  it("rejects a URL that fails to parse", async () => {
    await expect(assertTargetIsSafeToScan("not a url at all")).rejects.toBeInstanceOf(TargetSafetyViolation);
  });

  it("rejects embedded credentials", async () => {
    await expect(assertTargetIsSafeToScan("http://user:pass@example.com/")).rejects.toBeInstanceOf(
      TargetSafetyViolation,
    );
  });

  it("rejects 'localhost' and '*.localhost' without touching DNS", async () => {
    await expect(assertTargetIsSafeToScan("http://localhost/")).rejects.toBeInstanceOf(TargetSafetyViolation);
    await expect(assertTargetIsSafeToScan("http://LOCALHOST/")).rejects.toBeInstanceOf(TargetSafetyViolation);
    await expect(assertTargetIsSafeToScan("http://api.localhost/")).rejects.toBeInstanceOf(TargetSafetyViolation);
    expect(lookupMock).not.toHaveBeenCalled();
  });

  it.each([
    ["loopback IPv4", "http://127.0.0.1/"],
    ["0.0.0.0", "http://0.0.0.0/"],
    ["cloud metadata endpoint", "http://169.254.169.254/latest/meta-data/"],
    ["private RFC1918 10.x", "http://10.0.0.1/"],
    ["private RFC1918 172.16.x", "http://172.16.5.5/"],
    ["private RFC1918 192.168.x", "http://192.168.1.1/"],
    ["link-local IPv4", "http://169.254.1.1/"],
    ["multicast IPv4", "http://224.0.0.1/"],
    ["carrier-grade NAT", "http://100.64.0.1/"],
    ["IPv6 loopback", "http://[::1]/"],
    ["IPv6 unique-local", "http://[fc00::1]/"],
    ["IPv6 link-local", "http://[fe80::1]/"],
    ["IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]/"],
    ["6to4-encoded address", "http://[2002::1]/"],
  ])("rejects %s as an IP literal", async (_label, url) => {
    await expect(assertTargetIsSafeToScan(url)).rejects.toBeInstanceOf(TargetSafetyViolation);
    expect(lookupMock).not.toHaveBeenCalled();
  });

  it("allows an ordinary public IP literal", async () => {
    await expect(assertTargetIsSafeToScan("http://93.184.216.34/")).resolves.toBeUndefined();
    expect(lookupMock).not.toHaveBeenCalled();
  });

  it("resolves a hostname and allows it when every resolved address is public", async () => {
    lookupMock.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);

    await expect(assertTargetIsSafeToScan("http://example.com/app")).resolves.toBeUndefined();
    expect(lookupMock).toHaveBeenCalledWith("example.com", { all: true });
  });

  it("rejects a hostname when ANY resolved address is unsafe, not just the first", async () => {
    lookupMock.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]);

    await expect(assertTargetIsSafeToScan("http://sneaky.example.com/")).rejects.toBeInstanceOf(
      TargetSafetyViolation,
    );
  });

  it("rejects when DNS resolution fails", async () => {
    lookupMock.mockRejectedValue(new Error("ENOTFOUND"));

    await expect(assertTargetIsSafeToScan("http://does-not-resolve.invalid/")).rejects.toBeInstanceOf(
      TargetSafetyViolation,
    );
  });

  it("rejects when DNS resolution returns no addresses", async () => {
    lookupMock.mockResolvedValue([]);

    await expect(assertTargetIsSafeToScan("http://no-addresses.example.com/")).rejects.toBeInstanceOf(
      TargetSafetyViolation,
    );
  });
});
