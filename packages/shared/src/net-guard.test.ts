import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGuardedLookup,
  guardDomain,
  isPrivateIp,
  isPublicIp,
  isValidDomain,
  normalizeDomain,
  resolveAndGuard,
  type DnsResolver,
} from "./net-guard.js";

// Sahte resolver üretici — gerçek DNS'e çıkmadan senaryo kurar.
function fakeResolver(map: { v4?: string[]; v6?: string[] }): DnsResolver {
  return {
    resolve4: async () => map.v4 ?? [],
    resolve6: async () => map.v6 ?? [],
  };
}

// ----------------------------- normalizeDomain -----------------------------
test("normalizeDomain: şema/path/port/userinfo/parantez temizler", () => {
  assert.equal(normalizeDomain("HTTPS://Example.com/path?x=1"), "example.com");
  assert.equal(normalizeDomain("http://user:pass@evil.com/x"), "evil.com");
  assert.equal(normalizeDomain("example.com:8443"), "example.com");
  assert.equal(normalizeDomain("[2001:db8::1]"), "2001:db8::1");
  assert.equal(normalizeDomain("example.com."), "example.com");
});

// ----------------------------- isValidDomain -----------------------------
test("isValidDomain: geçerli alan adları", () => {
  for (const d of ["example.com", "sub.example.co.uk", "xn--d1acufc.xn--p1ai", "a-b.example.io"]) {
    assert.equal(isValidDomain(d), true, d);
  }
});

test("isValidDomain: IP ve alternatif IP gösterimleri reddedilir", () => {
  for (const d of [
    "127.0.0.1", // ham IPv4
    "::1", // ham IPv6
    "2130706433", // ondalık IP (127.0.0.1)
    "0x7f.0.0.1", // hex
    "0177.0.0.1", // oktal görünümlü (tümü rakam/nokta)
    "0x7f000001", // düz hex
    "localhost", // tek etiket
    "evil.com@127.0.0.1", // userinfo kaçışı
    "[::1]", // köşeli parantez
    "", // boş
  ]) {
    assert.equal(isValidDomain(d), false, d);
  }
});

// ----------------------------- isPrivateIp (IPv4) -----------------------------
test("isPrivateIp: IPv4 private/reserved aralıkları", () => {
  for (const ip of [
    "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.255",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1",
    "192.0.2.5", "255.255.255.255",
  ]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test("isPrivateIp: public IPv4", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "93.184.216.34"]) {
    assert.equal(isPrivateIp(ip), false, ip);
    assert.equal(isPublicIp(ip), true, ip);
  }
});

// ----------------------------- isPrivateIp (IPv6) -----------------------------
test("isPrivateIp: IPv6 private/reserved + gömülü IPv4", () => {
  for (const ip of [
    "::1", // loopback
    "::", // unspecified
    "fe80::1", // link-local
    "fe9f::abcd", // link-local (fe80::/10, fe80 dışı hextet)
    "fc00::1", // ULA
    "fd12:3456::1", // ULA
    "ff02::1", // multicast
    "2001:db8::1", // documentation
    "::ffff:127.0.0.1", // IPv4-mapped loopback
    "::ffff:169.254.169.254", // IPv4-mapped metadata
    "::ffff:a9fe:a9fe", // mapped metadata (hex biçim)
    "64:ff9b::7f00:1", // NAT64 → 127.0.0.1
  ]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test("isPrivateIp: public IPv6", () => {
  for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"]) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

// ----------------------------- resolveAndGuard -----------------------------
test("resolveAndGuard: tüm adresler public ise ok", async () => {
  const r = await resolveAndGuard("example.com", fakeResolver({ v4: ["93.184.216.34"] }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.addresses, ["93.184.216.34"]);
});

test("resolveAndGuard: HERHANGİ bir adres private ise reddeder (split-horizon)", async () => {
  const r = await resolveAndGuard(
    "rebind.evil",
    fakeResolver({ v4: ["93.184.216.34", "169.254.169.254"] }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "private_ip");
  assert.equal(r.offending, "169.254.169.254");
});

test("resolveAndGuard: çözülemezse resolve_failed", async () => {
  const r = await resolveAndGuard("nx.example", fakeResolver({}));
  assert.equal(r.ok, false);
  assert.equal(r.reason, "resolve_failed");
});

test("resolveAndGuard: geçersiz domain invalid_domain", async () => {
  const r = await resolveAndGuard("127.0.0.1", fakeResolver({ v4: ["127.0.0.1"] }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_domain");
});

test("guardDomain: public ilk adresi döndürür", async () => {
  const r = await guardDomain("example.com", fakeResolver({ v4: ["93.184.216.34"] }));
  assert.equal(r.ok, true);
  assert.equal(r.ip, "93.184.216.34");
});

// ----------------------------- createGuardedLookup (rebinding) -----------------------------
function runLookup(
  lookup: ReturnType<typeof createGuardedLookup>,
  host: string,
): Promise<{ err: Error | null; address?: string }> {
  return new Promise((resolve) => {
    lookup(host, {}, (err, address) => resolve({ err, address }));
  });
}

test("createGuardedLookup: public adres için IP döndürür", async () => {
  const lookup = createGuardedLookup(fakeResolver({ v4: ["93.184.216.34"] }));
  const { err, address } = await runLookup(lookup, "example.com");
  assert.equal(err, null);
  assert.equal(address, "93.184.216.34");
});

test("createGuardedLookup: private adresi engeller (ESSRFBLOCKED)", async () => {
  const lookup = createGuardedLookup(fakeResolver({ v4: ["169.254.169.254"] }));
  const { err } = await runLookup(lookup, "metadata.evil");
  assert.ok(err, "hata bekleniyor");
  assert.equal((err as NodeJS.ErrnoException).code, "ESSRFBLOCKED");
});

test("createGuardedLookup: DNS rebinding — bağlantı anındaki private çözüm engellenir", async () => {
  // İlk çözüm public (ön-kontrolü geçer), ikinci çözüm (bağlantı anı) private.
  let calls = 0;
  const rebinding: DnsResolver = {
    resolve4: async () => (++calls === 1 ? ["93.184.216.34"] : ["127.0.0.1"]),
    resolve6: async () => [],
  };
  // Ön-kontrol geçer:
  const pre = await resolveAndGuard("rebind.evil", rebinding);
  assert.equal(pre.ok, true);
  // Bağlantı anındaki guarded lookup yeniden çözer ve private'ı yakalar:
  const lookup = createGuardedLookup(rebinding);
  const { err } = await runLookup(lookup, "rebind.evil");
  assert.ok(err, "rebinding bağlantı anında engellenmeli");
  assert.equal((err as NodeJS.ErrnoException).code, "ESSRFBLOCKED");
});
