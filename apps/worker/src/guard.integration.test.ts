import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import { Agent, request } from "undici";
import { createGuardedLookup, type DnsResolver } from "@catdef/shared/net-guard";

// Gerçek bir yerel HTTP sunucusu kurar; guarded agent'ın, public gibi görünen
// ama loopback'e (iç servise) çözülen bir host'a BAĞLANMADIĞINI ispatlar.
// Not: undici yönlendirmeleri (redirect) aynı dispatcher/lookup üzerinden izler,
// dolayısıyla iç adrese 3xx yönlendirmesi de bu aynı kapıda engellenir.
test("guarded agent: loopback'e çözülen host'a istek ULAŞTIRMAZ", async () => {
  let receivedRequest = false;
  const server = http.createServer((_req, res) => {
    receivedRequest = true;
    res.end("INTERNAL-SECRET");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  // "attacker.test" public gibi görünsün ama 127.0.0.1'e çözülsün (SSRF denemesi).
  const loopbackResolver: DnsResolver = {
    resolve4: async () => ["127.0.0.1"],
    resolve6: async () => [],
  };
  // undici'nin lookup'ı GERÇEKTEN kullandığını kanıtlamak için sarmala
  // (aksi halde NXDOMAIN ile de "engellendi" görünür — yanlış pozitif).
  const inner = createGuardedLookup(loopbackResolver);
  let lookupCalled = false;
  const lookup = (hostname: string, options: unknown, cb: unknown) => {
    lookupCalled = true;
    return (inner as unknown as (...a: unknown[]) => void)(hostname, options, cb);
  };
  const agent = new Agent({ connect: { lookup: lookup as never } });

  let blocked = false;
  try {
    await request(`http://attacker.test:${port}/secret`, {
      dispatcher: agent,
      maxRedirections: 0,
    });
  } catch {
    blocked = true;
  } finally {
    await agent.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  assert.equal(lookupCalled, true, "undici guarded lookup'ı kullanmalıydı");
  assert.equal(blocked, true, "SSRF guard isteği engellemeliydi");
  assert.equal(receivedRequest, false, "iç servis HİÇ istek almamalıydı");
});

// Public host için guarded lookup, bağlantıya izin veren bir adres döndürür
// (undici'nin beklediği all=true dizi biçiminde). Bu, public taramanın guarded
// agent ile çalıştığını (yanlışlıkla her şeyi engellemediğimizi) doğrular.
test("guarded lookup: public adres için all=true dizi biçimi döndürür", async () => {
  const publicResolver: DnsResolver = {
    resolve4: async () => ["93.184.216.34"],
    resolve6: async () => [],
  };
  const lookup = createGuardedLookup(publicResolver);
  const result = await new Promise<{ err: unknown; addrs: unknown }>((resolve) => {
    (lookup as unknown as (h: string, o: unknown, cb: unknown) => void)(
      "example.com",
      { all: true },
      (err: unknown, addrs: unknown) => resolve({ err, addrs }),
    );
  });
  assert.equal(result.err, null);
  assert.deepEqual(result.addrs, [{ address: "93.184.216.34", family: 4 }]);
});
