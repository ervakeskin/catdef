// SSRF koruması: kullanıcının verdiği domaini sunucu tarafında çekmeden önce
// çözülen IP'lerin PUBLIC olduğundan emin oluruz. Kendi güvenlik ürünümüz,
// iç ağa (localhost, 169.254.x, RFC1918, bulut metadata) istek yaptırma açığı
// barındırmamalı. Bu modül Node built-in'leri kullanır — tarayıcıya sızmamalı,
// bu yüzden shared/index.ts'ten dışa verilmez (ayrı export yolu: ./net-guard).

import { lookup } from "node:dns/promises";
import net from "node:net";

/** Domaini normalize eder: şema/port/path atılır, küçük harfe indirilir. */
export function normalizeDomain(input: string): string {
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, ""); // şema
  s = s.replace(/\/.*$/, ""); // path
  s = s.replace(/:\d+$/, ""); // port
  s = s.replace(/\.$/, ""); // sondaki nokta
  return s;
}

/** Geçerli bir hostname mi? (kaba doğrulama — IP değil, tek etiket değil). */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (net.isIP(domain) !== 0) return false; // ham IP kabul etmiyoruz
  // en az bir nokta, geçerli etiketler
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(domain);
}

/** Verilen IP private/reserved/loopback/link-local mı? */
export function isPrivateIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return true; // tanınmayan → güvenli tarafta kal
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local (bulut metadata 169.254.169.254)
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true; // loopback / unspecified
  if (lower.startsWith("fe80")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local fc00::/7
  // IPv4-mapped (::ffff:a.b.c.d)
  const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && mapped[1]) return isPrivateIPv4(mapped[1]);
  return false;
}

export interface GuardResult {
  ok: boolean;
  /** ok=true ise çözülen public IP. */
  ip?: string;
  /** ok=false ise engel nedeni. */
  reason?: "invalid_domain" | "resolve_failed" | "private_ip";
}

/**
 * Domaini çözer ve public bir IP'ye işaret ettiğini doğrular.
 * Tarama başlatılmadan önce API'de ve fiili istekten önce worker'da çağrılır.
 */
export async function guardDomain(domain: string): Promise<GuardResult> {
  if (!isValidDomain(domain)) {
    return { ok: false, reason: "invalid_domain" };
  }
  try {
    const { address } = await lookup(domain);
    if (isPrivateIp(address)) {
      return { ok: false, reason: "private_ip" };
    }
    return { ok: true, ip: address };
  } catch {
    return { ok: false, reason: "resolve_failed" };
  }
}
