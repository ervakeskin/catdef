import type { LookupFunction } from "node:net";
import tls from "node:tls";
import { Agent, request } from "undici";
import type { Finding, ModuleResult } from "@catdef/shared";
import { makeFinding } from "@catdef/shared";
import { createGuardedLookup } from "@catdef/shared/net-guard";
import { config } from "../config.js";

const REQUEST_TIMEOUT_MS = 10_000;

// SSRF savunması: tüm HTTP(S) ve TLS bağlantıları, bağlantı anında domaini
// yeniden çözüp public olduğunu doğrulayan guarded lookup'tan geçer. Bu, hem
// DNS rebinding'i hem de iç adreslere yapılan 3xx yönlendirmelerini engeller
// (yönlendirme hedefleri aynı dispatcher üzerinden tekrar denetlenir).
// createGuardedLookup, net/tls/undici'nin beklediği LookupFunction imzasıyla
// çalışır (runtime'da doğrulandı); tip olarak da öyle işaretliyoruz.
const guardedLookup = createGuardedLookup() as unknown as LookupFunction;
const guardedAgent = new Agent({ connect: { lookup: guardedLookup } });

/** Kontrol edilen güvenlik header'ları → eksikse üretilecek finding_code. */
const SECURITY_HEADERS: { header: string; code: string }[] = [
  { header: "strict-transport-security", code: "missing_hsts" },
  { header: "content-security-policy", code: "missing_csp" },
  { header: "x-frame-options", code: "missing_x_frame_options" },
  { header: "x-content-type-options", code: "missing_x_content_type_options" },
  { header: "referrer-policy", code: "missing_referrer_policy" },
  { header: "permissions-policy", code: "missing_permissions_policy" },
];

interface FetchOutcome {
  ok: boolean;
  scheme: "https" | "http";
  statusCode?: number;
  headers?: Record<string, string | string[] | undefined>;
}

async function tryFetch(url: string, scheme: "https" | "http"): Promise<FetchOutcome> {
  try {
    const res = await request(url, {
      method: "GET",
      headers: { "user-agent": config.userAgent },
      dispatcher: guardedAgent,
      maxRedirections: 3,
      headersTimeout: REQUEST_TIMEOUT_MS,
      bodyTimeout: REQUEST_TIMEOUT_MS,
    });
    // Gövdeyi tüketmeden bağlantı sızabilir.
    await res.body.dump();
    return { ok: true, scheme, statusCode: res.statusCode, headers: res.headers };
  } catch {
    return { ok: false, scheme };
  }
}

interface CertInfo {
  protocol: string | null;
  validTo: Date | null;
  authorized: boolean;
  authorizationError?: string;
}

/** 443'e TLS bağlantısı kurup sertifika + protokol bilgisini toplar. */
function inspectTls(domain: string): Promise<CertInfo | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        // Bağlantı anında domaini yeniden çözüp public doğrular (rebinding savunması).
        lookup: guardedLookup,
        timeout: REQUEST_TIMEOUT_MS,
        // Süresi dolmuş/uyumsuz sertifikayı da inceleyebilmek için elden doğrularız.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const info: CertInfo = {
          protocol: socket.getProtocol(),
          validTo: cert?.valid_to ? new Date(cert.valid_to) : null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError
            ? String(socket.authorizationError)
            : undefined,
        };
        socket.end();
        resolve(info);
      },
    );
    socket.on("error", () => resolve(null));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });
}

export async function runHeaderTls(domain: string): Promise<ModuleResult> {
  const findings: Finding[] = [];
  const rawData: Record<string, unknown> = {};

  // 1) HTTPS dene, olmazsa HTTP.
  let outcome = await tryFetch(`https://${domain}`, "https");
  if (!outcome.ok) {
    const httpOutcome = await tryFetch(`http://${domain}`, "http");
    if (httpOutcome.ok) {
      findings.push(makeFinding("no_https", { evidence: "HTTPS yanıt vermedi, yalnızca HTTP" }));
      outcome = httpOutcome;
    }
  }

  if (!outcome.ok) {
    return {
      moduleType: "header_tls",
      status: "failed",
      findings,
      rawData: { error: "Site HTTP/HTTPS üzerinden yanıt vermedi" },
    };
  }

  rawData.scheme = outcome.scheme;
  rawData.statusCode = outcome.statusCode;
  const headers = outcome.headers ?? {};
  rawData.headers = headers;

  // 2) Güvenlik header'ları
  for (const { header, code } of SECURITY_HEADERS) {
    if (headers[header] === undefined) {
      findings.push(makeFinding(code));
    }
  }

  // 3) TLS/sertifika (yalnızca HTTPS eriştiyse anlamlı)
  if (outcome.scheme === "https") {
    const cert = await inspectTls(domain);
    if (cert) {
      rawData.tls = {
        protocol: cert.protocol,
        validTo: cert.validTo?.toISOString() ?? null,
        authorized: cert.authorized,
        authorizationError: cert.authorizationError,
      };

      // Sertifika geçerlilik
      if (cert.validTo) {
        const now = Date.now();
        const msLeft = cert.validTo.getTime() - now;
        const daysLeft = msLeft / (1000 * 60 * 60 * 24);
        if (msLeft < 0) {
          findings.push(
            makeFinding("tls_cert_expired", {
              evidence: `Bitiş: ${cert.validTo.toISOString()}`,
            }),
          );
        } else if (daysLeft <= 21) {
          findings.push(
            makeFinding("tls_cert_expiring_soon", {
              evidence: `${Math.floor(daysLeft)} gün kaldı`,
            }),
          );
        }
      }

      // Hostname / güven zinciri uyuşmazlığı (süresi dolmuşu ayrı raporladık)
      if (
        !cert.authorized &&
        cert.authorizationError &&
        cert.authorizationError !== "CERT_HAS_EXPIRED"
      ) {
        findings.push(
          makeFinding("tls_cert_hostname_mismatch", { evidence: cert.authorizationError }),
        );
      }

      // Eski protokol
      if (cert.protocol === "TLSv1" || cert.protocol === "TLSv1.1") {
        findings.push(makeFinding("tls_outdated_protocol", { evidence: cert.protocol }));
      }
    }
  }

  return { moduleType: "header_tls", status: "completed", findings, rawData };
}
