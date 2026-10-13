// SSRF koruması: kullanıcının verdiği domaini sunucu tarafında çekmeden önce VE
// çekerken, çözülen IP'lerin PUBLIC olduğundan emin oluruz. Kendi güvenlik
// ürünümüz, iç ağa (localhost, 169.254.x, RFC1918, bulut metadata) istek
// yaptırma açığı barındırmamalı.
//
// Bu modül Node built-in'leri kullanır — tarayıcıya sızmamalı, bu yüzden
// shared/index.ts'ten dışa verilmez (ayrı export yolu: ./net-guard).
//
// Savunma katmanları:
//   1) Girdi doğrulama: ham IP / ondalık-oktal-hex / userinfo / köşeli parantez reddi.
//   2) resolveAndGuard: A + AAAA kayıtlarının TAMAMINI çözer; HERHANGİ biri private
//      ise reddeder (bölünmüş public/private DNS'e karşı).
//   3) createGuardedLookup: fiili TCP/TLS bağlantısı anında DNS'i yeniden çözüp
//      yeniden doğrular (DNS rebinding / TOCTOU) ve her yönlendirme (redirect)
//      hedefini de aynı kapıdan geçirir.

import { Resolver } from "node:dns/promises";
import net from "node:net";

// ----------------------------- Girdi normalleştirme -----------------------------

/** Domaini normalize eder: şema/userinfo/port/path atılır, küçük harfe indirilir. */
export function normalizeDomain(input: string): string {
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // şema
  s = s.replace(/^[^/@]*@/, ""); // userinfo (user:pass@)
  s = s.replace(/\/.*$/, ""); // path
  s = s.replace(/:\d+$/, ""); // port
  s = s.replace(/^\[|\]$/g, ""); // köşeli parantez (IPv6 literal)
  s = s.replace(/\.$/, ""); // sondaki nokta
  return s;
}

/**
 * Geçerli bir hostname mi? Ham IP (v4/v6), tek etiket, ondalık/oktal/hex IP
 * gösterimleri ve köşeli parantezli literal'ler reddedilir.
 */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (domain.includes("@") || domain.includes("[") || domain.includes("]")) return false;
  if (net.isIP(domain) !== 0) return false; // ham IP kabul etmiyoruz (v4/v6)
  // Tümü sayı/nokta ise (ör. 2130706433, 0x7f.0.0.1, 0177.0.0.1) → IP gösterimi, reddet.
  if (/^[0-9.]+$/.test(domain)) return false;
  if (/(^|\.)0x[0-9a-f]+/i.test(domain)) return false; // hex etiket
  // En az bir nokta + geçerli etiketler + harfle başlayan TLD (punycode xn-- dahil,
  // ama tümü-sayısal/IP TLD değil).
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(
    domain,
  );
}

// ----------------------------- IP sınıflandırma -----------------------------

/** Verilen IP private/reserved/loopback/link-local/metadata mı? */
export function isPrivateIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return true; // tanınmayan → güvenli tarafta kal
}

/** IP public (internet-erişilebilir) mi? isPrivateIp'in tersi, geçerli IP için. */
export function isPublicIp(ip: string): boolean {
  return net.isIP(ip) !== 0 && !isPrivateIp(ip);
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 169 && b === 254) return true; // link-local + metadata 169.254.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24 IETF
  if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
  if (a === 198 && b === 51 && parts[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224) return true; // 224.0.0.0/3 multicast + reserved + broadcast
  return false;
}

/** IPv6'yı 8 adet 16-bit gruba açar (:: sıkıştırması ve gömülü IPv4 dahil). */
function parseIpv6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  if (s.includes("%")) s = s.slice(0, s.indexOf("%")); // zone id at
  // Gömülü IPv4 (::ffff:1.2.3.4 gibi) → son 32 biti iki hextet'e çevir.
  const v4m = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4m) {
    const v4 = v4m[2]!.split(".").map(Number);
    if (v4.length !== 4 || v4.some((n) => n < 0 || n > 255)) return null;
    const h1 = ((v4[0]! << 8) | v4[1]!).toString(16);
    const h2 = ((v4[2]! << 8) | v4[3]!).toString(16);
    s = v4m[1]! + h1 + ":" + h2;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0]!.split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1]!.split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
  } else if (fill < 0) {
    return null;
  }
  const groups =
    halves.length === 2
      ? [...head, ...Array(fill).fill("0"), ...tail]
      : head;
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

function isPrivateIPv6(ip: string): boolean {
  const g = parseIpv6(ip);
  if (!g) return true; // ayrıştıramadık → güvenli tarafta kal
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [
    number, number, number, number, number, number, number, number,
  ];

  const allZeroExceptLast = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;

  if (g.every((x) => x === 0)) return true; // :: unspecified
  if (allZeroExceptLast && g5 === 0 && g6 === 0 && g7 === 1) return true; // ::1 loopback
  if (g0 >= 0xfe80 && g0 <= 0xfebf) return true; // fe80::/10 link-local
  if (g0 >= 0xfc00 && g0 <= 0xfdff) return true; // fc00::/7 unique local
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // 2001:db8::/32 documentation
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true; // 100::/64 discard

  // Gömülü IPv4'lü biçimler → IPv4 kurallarıyla denetle.
  const embeddedV4 = `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
  if (allZeroExceptLast && g5 === 0xffff) return isPrivateIPv4(embeddedV4); // ::ffff:0:0/96 mapped
  if (allZeroExceptLast && g5 === 0 && !(g6 === 0 && g7 <= 1)) {
    return isPrivateIPv4(embeddedV4); // ::/96 IPv4-compatible (deprecated)
  }
  if (g0 === 0x0064 && g1 === 0xff9b) return isPrivateIPv4(embeddedV4); // 64:ff9b::/96 NAT64

  return false;
}

// ----------------------------- Çözümleme + doğrulama -----------------------------

/** Enjekte edilebilir DNS çözümleyici (test için sahte verilebilir). */
export interface DnsResolver {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
}

function defaultResolver(): DnsResolver {
  const r = new Resolver();
  return {
    resolve4: (h) => r.resolve4(h),
    resolve6: (h) => r.resolve6(h),
  };
}

export interface GuardResult {
  ok: boolean;
  /** ok=true ise çözülen public IP (ilk adres). */
  ip?: string;
  /** ok=false ise engel nedeni. */
  reason?: "invalid_domain" | "resolve_failed" | "private_ip";
}

export interface ResolveGuardResult {
  ok: boolean;
  /** ok=true ise doğrulanmış tüm public adresler. */
  addresses?: string[];
  reason?: "invalid_domain" | "resolve_failed" | "private_ip";
  /** reason=private_ip ise sorunlu adres. */
  offending?: string;
}

/**
 * Domaini çözer (A + AAAA) ve çözülen adreslerin HEPSİNİN public olduğunu
 * doğrular. Adreslerden herhangi biri private ise reddeder — böylece bir alan
 * adının hem public hem private IP döndürmesi (split-horizon) istismar edilemez.
 */
export async function resolveAndGuard(
  host: string,
  resolver: DnsResolver = defaultResolver(),
): Promise<ResolveGuardResult> {
  if (!isValidDomain(host)) return { ok: false, reason: "invalid_domain" };
  const [v4, v6] = await Promise.all([
    resolver.resolve4(host).catch(() => [] as string[]),
    resolver.resolve6(host).catch(() => [] as string[]),
  ]);
  const all = [...v4, ...v6];
  if (all.length === 0) return { ok: false, reason: "resolve_failed" };
  const offending = all.find((ip) => isPrivateIp(ip));
  if (offending) return { ok: false, reason: "private_ip", offending };
  return { ok: true, addresses: all };
}

/**
 * Geriye dönük uyum + API ön-kontrolü için tek-adres özeti.
 * resolveAndGuard üzerine kuruludur.
 */
export async function guardDomain(
  domain: string,
  resolver?: DnsResolver,
): Promise<GuardResult> {
  const r = await resolveAndGuard(domain, resolver);
  if (!r.ok) return { ok: false, reason: r.reason };
  return { ok: true, ip: r.addresses![0] };
}

/** Node net/tls/undici `lookup` seçenekine uyumlu callback imzası.
 * options.all=true iken adres bir dizi olarak döner ([{address, family}]). */
type LookupAddress = { address: string; family: number };
type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address?: string | LookupAddress[],
  family?: number,
) => void;
interface LookupOptions {
  all?: boolean;
  family?: number;
  hints?: number;
}

/**
 * net/tls/undici için "guarded lookup": bağlantı KURULURKEN domaini yeniden
 * çözer ve public olduğunu yeniden doğrular. DNS rebinding/TOCTOU'yu engeller
 * (doğrulama ile bağlanma arasında DNS değişse bile burada yeniden denetlenir)
 * ve yönlendirme (redirect) hedefleri de dahil her bağlantıyı kapsar.
 *
 * Çözülen IP literal olarak döndürülüp bağlanıldığı için, dönen adres sabittir
 * (ikinci bir çözümlemeyle private'a kaydırılamaz).
 */
export function createGuardedLookup(resolver?: DnsResolver) {
  return function guardedLookup(
    hostname: string,
    options: LookupOptions | LookupCallback,
    callback?: LookupCallback,
  ): void {
    // Node ayrıca lookup(hostname, callback) imzasını da destekler.
    const cb: LookupCallback = (typeof options === "function" ? options : callback)!;
    const wantAll = typeof options === "object" && options?.all === true;

    resolveAndGuard(hostname, resolver)
      .then((r) => {
        if (!r.ok || !r.addresses || r.addresses.length === 0) {
          cb(
            Object.assign(new Error(`SSRF guard engelledi: ${r.reason ?? "unknown"}`), {
              code: "ESSRFBLOCKED",
            }),
          );
          return;
        }
        // undici/Node, options.all=true iken [{address, family}] dizisi bekler.
        if (wantAll) {
          cb(
            null,
            r.addresses.map((address) => ({
              address,
              family: net.isIP(address) === 6 ? 6 : 4,
            })),
          );
          return;
        }
        const address = r.addresses[0]!;
        cb(null, address, net.isIP(address) === 6 ? 6 : 4);
      })
      .catch((e) => cb(e as NodeJS.ErrnoException));
  };
}
