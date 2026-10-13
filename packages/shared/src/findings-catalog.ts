import type { Finding, ModuleType, Severity } from "./types.js";

/** Sabit bulgu tanımı — kod, başlık, sade açıklama ve varsayılan severity. */
export interface FindingDefinition {
  moduleType: ModuleType;
  severity: Severity;
  title: string;
  /** Teknik açıklama (geliştiriciye). */
  description: string;
  /** (i) ikonunda gösterilen jargonsuz açıklama (yeni başlayana). */
  plainExplanation: string;
}

/**
 * finding_code → tanım. plainExplanation'lar ilk günden doldurulur —
 * ürünü rakiplerden ayıran "anlaşılır Türkçe rapor" farklılaştırıcısının temeli.
 */
export const FINDINGS_CATALOG: Record<string, FindingDefinition> = {
  // ---------------- Header & TLS ----------------
  no_https: {
    moduleType: "header_tls",
    severity: "high",
    title: "Site HTTPS kullanmıyor",
    description: "Site yalnızca HTTP üzerinden yanıt veriyor; trafik şifrelenmiyor.",
    plainExplanation:
      "Siten kilitsiz kapı gibi: ziyaretçilerinle site arasındaki bilgi (şifreler dahil) araya girenlerce okunabilir. HTTPS/SSL sertifikası şart.",
  },
  missing_hsts: {
    moduleType: "header_tls",
    severity: "high",
    title: "HSTS başlığı eksik",
    description:
      "Strict-Transport-Security header'ı yok; tarayıcı ilk isteği HTTP'ye düşürebilir.",
    plainExplanation:
      "Tarayıcıya 'bu siteye her zaman güvenli bağlan' talimatı verilmiyor. Saldırgan bağlantıyı güvensiz sürüme çekmeyi deneyebilir.",
  },
  missing_csp: {
    moduleType: "header_tls",
    severity: "high",
    title: "Content-Security-Policy eksik",
    description: "CSP header'ı yok; XSS ve içerik enjeksiyonuna karşı savunma zayıf.",
    plainExplanation:
      "Sitene hangi kodların yüklenebileceğini sınırlayan kural yok. Kötü niyetli script enjekte edilirse tarayıcı onu durdurmaz.",
  },
  missing_x_frame_options: {
    moduleType: "header_tls",
    severity: "medium",
    title: "X-Frame-Options eksik",
    description: "Clickjacking'e karşı X-Frame-Options / frame-ancestors tanımlı değil.",
    plainExplanation:
      "Siten başka bir sitenin içine gizlice gömülüp, kullanıcıya farkında olmadan tıklatma (clickjacking) yaptırılabilir.",
  },
  missing_x_content_type_options: {
    moduleType: "header_tls",
    severity: "low",
    title: "X-Content-Type-Options eksik",
    description: "nosniff yok; tarayıcı içerik türünü tahmin ederek (MIME sniffing) riske girebilir.",
    plainExplanation:
      "Tarayıcı bir dosyanın türünü yanlış tahmin edip zararlı içeriği çalıştırabilir. Basit bir başlıkla engellenir.",
  },
  missing_referrer_policy: {
    moduleType: "header_tls",
    severity: "low",
    title: "Referrer-Policy eksik",
    description: "Referrer-Policy tanımsız; ziyaretçi başka siteye giderken tam URL sızabilir.",
    plainExplanation:
      "Ziyaretçin başka bir siteye tıkladığında, geldiği tam adres karşı tarafa gönderilebilir — gizlilik sızıntısı.",
  },
  missing_permissions_policy: {
    moduleType: "header_tls",
    severity: "low",
    title: "Permissions-Policy eksik",
    description: "Kamera/mikrofon/konum gibi tarayıcı özellikleri için kısıtlama tanımlı değil.",
    plainExplanation:
      "Kamera, mikrofon, konum gibi hassas tarayıcı özelliklerinin kullanımı sınırlanmamış.",
  },
  tls_cert_expired: {
    moduleType: "header_tls",
    severity: "critical",
    title: "TLS sertifikası süresi dolmuş",
    description: "Sunucu sertifikasının geçerlilik süresi geçmiş; tarayıcılar uyarı gösterir.",
    plainExplanation:
      "Güvenlik sertifikanın süresi bitmiş. Ziyaretçiler büyük bir 'güvenli değil' uyarısıyla karşılaşır ve çoğu geri döner.",
  },
  tls_cert_expiring_soon: {
    moduleType: "header_tls",
    severity: "medium",
    title: "TLS sertifikası yakında sona eriyor",
    description: "Sertifika 21 gün içinde sona eriyor; otomatik yenileme kontrol edilmeli.",
    plainExplanation:
      "Güvenlik sertifikanın süresi yakında doluyor. Zamanında yenilenmezse siten 'güvenli değil' uyarısı vermeye başlar.",
  },
  tls_cert_hostname_mismatch: {
    moduleType: "header_tls",
    severity: "high",
    title: "Sertifika alan adıyla eşleşmiyor",
    description: "Sunulan sertifikanın CN/SAN değerleri istenen host ile eşleşmiyor.",
    plainExplanation:
      "Sitenin sertifikası başka bir alan adına ait. Tarayıcı bunu güvenlik uyarısı olarak gösterir.",
  },
  tls_outdated_protocol: {
    moduleType: "header_tls",
    severity: "medium",
    title: "Eski TLS sürümü destekleniyor",
    description: "Sunucu TLS 1.0/1.1 kabul ediyor; bu sürümler güvensiz sayılır.",
    plainExplanation:
      "Siten artık güvensiz kabul edilen eski şifreleme sürümlerini kabul ediyor. Yalnızca TLS 1.2+ kullanılmalı.",
  },

  // ---------------- DNS & Altyapı ----------------
  missing_spf: {
    moduleType: "dns",
    severity: "medium",
    title: "SPF kaydı yok",
    description: "Domain için SPF (TXT) kaydı bulunamadı; e-posta sahteciliğine açık.",
    plainExplanation:
      "Adına sahte e-posta gönderilmesini zorlaştıran kayıt yok. Biri senin domaininden geliyormuş gibi mail atabilir.",
  },
  missing_dmarc: {
    moduleType: "dns",
    severity: "medium",
    title: "DMARC kaydı yok",
    description: "_dmarc TXT kaydı yok; SPF/DKIM sonucuna göre politika uygulanmıyor.",
    plainExplanation:
      "E-posta sahteciliğine karşı 'sahte maili ne yap' politikan tanımlı değil. DMARC bunu belirler.",
  },
  dangling_cname: {
    moduleType: "dns",
    severity: "high",
    title: "Sahipsiz CNAME (subdomain takeover riski)",
    description:
      "Bir CNAME kaydı, artık size ait olmayan/çözülmeyen bir hedefe işaret ediyor olabilir.",
    plainExplanation:
      "Bir alt alan adın, artık kullanmadığın bir servise işaret ediyor. Saldırgan o servisi kaydedip alt alan adını ele geçirebilir.",
  },
};

/** Katalogdan tam bir Finding üretir (pointsDeducted skorlama aşamasında doldurulur). */
export function makeFinding(
  findingCode: string,
  opts: { evidence?: string; severity?: Severity } = {},
): Finding {
  const def = FINDINGS_CATALOG[findingCode];
  if (!def) {
    throw new Error(`Bilinmeyen finding_code: ${findingCode}`);
  }
  return {
    moduleType: def.moduleType,
    findingCode,
    severity: opts.severity ?? def.severity,
    title: def.title,
    description: def.description,
    plainExplanation: def.plainExplanation,
    evidence: opts.evidence,
    pointsDeducted: 0,
  };
}
