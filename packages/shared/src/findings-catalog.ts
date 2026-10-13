import type { Finding, ModuleType, Severity, StandardRefs } from "./types.js";

/** Sabit bulgu tanımı — kod, başlık, açıklamalar ve standart eşlemeleri. */
export interface FindingDefinition {
  moduleType: ModuleType;
  severity: Severity;
  title: string;
  /** Teknik açıklama (geliştiriciye). */
  description: string;
  /** (i) ikonunda gösterilen jargonsuz açıklama (yeni başlayana). */
  plainExplanation: string;
  /** Neden önemli — somut saldırı/risk senaryosu (TR). */
  whyItMatters: string;
  /** Yanlış-pozitif / bağlam notu: bulgu ne zaman önemsiz olabilir (TR). */
  falsePositiveNote: string;
  /** OWASP Top 10 (2025 + 2021) / CWE / ASVS 5.0 eşlemesi. */
  standards: StandardRefs;
}

/**
 * finding_code → tanım. plainExplanation'lar ilk günden doldurulur —
 * ürünü rakiplerden ayıran "anlaşılır Türkçe rapor" farklılaştırıcısının temeli.
 *
 * Standart eşlemeleri için kaynaklar ve bilinçli kararlar docs/SCORING.md'de
 * belgelenmiştir (ör. güvenlik başlıkları → Security Misconfiguration; TLS/transport
 * → Cryptographic Failures; SPF/DMARC e-posta katmanı olduğu için ASVS kapsamı dışıdır).
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
    whyItMatters:
      "Aynı Wi-Fi'daki veya ağ yolundaki bir saldırgan trafiği pasifçe dinleyip oturum çerezlerini, form verilerini ve şifreleri okuyabilir; hatta içeriği değiştirebilir.",
    falsePositiveNote:
      "Dışarıya içerik sunmayan, yalnızca HTTP'den HTTPS'e yönlendiren uç noktalarda beklenen olabilir. Ama son hedef her zaman HTTPS olmalı.",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-319: Cleartext Transmission of Sensitive Information",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },
  missing_hsts: {
    moduleType: "header_tls",
    severity: "high",
    title: "HSTS başlığı eksik",
    description:
      "Strict-Transport-Security header'ı yok; tarayıcı ilk isteği HTTP'ye düşürebilir.",
    plainExplanation:
      "Tarayıcıya 'bu siteye her zaman güvenli bağlan' talimatı verilmiyor. Saldırgan bağlantıyı güvensiz sürüme çekmeyi deneyebilir.",
    whyItMatters:
      "HSTS olmadan 'SSL stripping' mümkündür: saldırgan kullanıcının ilk (HTTP) isteğini yakalayıp HTTPS'e yükseltmesini engelleyerek araya girer. HSTS, tarayıcıyı sonraki tüm isteklerde HTTPS'e zorlar.",
    falsePositiveNote:
      "HTTPS'i yeni açmış sitelerde max-age düşük tutulup kademeli artırılabilir; bu durumda başlık 'var ama zayıf' olabilir. Biz yalnızca varlığını kontrol ediyoruz.",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-319: Cleartext Transmission of Sensitive Information",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },
  missing_csp: {
    moduleType: "header_tls",
    severity: "high",
    title: "Content-Security-Policy eksik",
    description: "CSP header'ı yok; XSS ve içerik enjeksiyonuna karşı savunma zayıf.",
    plainExplanation:
      "Sitene hangi kodların yüklenebileceğini sınırlayan kural yok. Kötü niyetli script enjekte edilirse tarayıcı onu durdurmaz.",
    whyItMatters:
      "CSP, XSS'e karşı en güçlü ikinci savunma hattıdır: bir XSS açığı sömürülse bile, iyi yapılandırılmış bir CSP yetkisiz script'in çalışmasını veya veriyi dışarı sızdırmasını engelleyebilir.",
    falsePositiveNote:
      "CSP'nin varlığı yeterli değildir; zayıf (ör. 'unsafe-inline' içeren) bir politika da raporda 'var' görünür. Biz Faz 0'da yalnızca varlığını denetliyoruz, kalitesini değil.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693: Protection Mechanism Failure",
      asvs: "ASVS 5.0 V3: Web Frontend Security",
    },
  },
  missing_x_frame_options: {
    moduleType: "header_tls",
    severity: "medium",
    title: "X-Frame-Options eksik",
    description: "Clickjacking'e karşı X-Frame-Options / frame-ancestors tanımlı değil.",
    plainExplanation:
      "Siten başka bir sitenin içine gizlice gömülüp, kullanıcıya farkında olmadan tıklatma (clickjacking) yaptırılabilir.",
    whyItMatters:
      "Saldırgan sitenizi görünmez bir iframe içine alıp üstüne sahte bir arayüz koyarak, kullanıcıya farkında olmadan kritik işlemler (ör. ayar değiştirme, onay) yaptırabilir.",
    falsePositiveNote:
      "Modern yaklaşım CSP'deki 'frame-ancestors' direktifidir; o varsa X-Frame-Options'ın yokluğu pratikte sorun olmayabilir. Sitenin iframe ile gömülmesi kasıtlıysa (ör. widget) bu bulgu beklenen olabilir.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
      asvs: "ASVS 5.0 V3: Web Frontend Security",
    },
  },
  missing_x_content_type_options: {
    moduleType: "header_tls",
    severity: "low",
    title: "X-Content-Type-Options eksik",
    description: "nosniff yok; tarayıcı içerik türünü tahmin ederek (MIME sniffing) riske girebilir.",
    plainExplanation:
      "Tarayıcı bir dosyanın türünü yanlış tahmin edip zararlı içeriği çalıştırabilir. Basit bir başlıkla engellenir.",
    whyItMatters:
      "'nosniff' olmadan tarayıcı, sunucunun bildirdiği içerik türünü yok sayıp tahmin edebilir; kullanıcı yüklemelerinin barındırıldığı sitelerde bu, zararsız görünen bir dosyanın script olarak çalıştırılmasına yol açabilir.",
    falsePositiveNote:
      "Etkisi yalnızca kullanıcı içeriği barındıran veya çok çeşitli dosya sunan sitelerde belirgindir; tek tip statik içerik sunan sitelerde pratik risk düşüktür.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693: Protection Mechanism Failure",
      asvs: "ASVS 5.0 V3: Web Frontend Security",
    },
  },
  missing_referrer_policy: {
    moduleType: "header_tls",
    severity: "low",
    title: "Referrer-Policy eksik",
    description: "Referrer-Policy tanımsız; ziyaretçi başka siteye giderken tam URL sızabilir.",
    plainExplanation:
      "Ziyaretçin başka bir siteye tıkladığında, geldiği tam adres karşı tarafa gönderilebilir — gizlilik sızıntısı.",
    whyItMatters:
      "URL'lerde oturum belirteci, sıfırlama anahtarı veya kişisel kimlik gibi hassas veriler taşınıyorsa, Referrer başlığı bunları üçüncü taraf sitelere sızdırabilir.",
    falsePositiveNote:
      "Tarayıcılar artık varsayılan olarak 'strict-origin-when-cross-origin' uygular; bu nedenle başlığın yokluğu modern tarayıcılarda çoğu zaman makul bir varsayılana düşer. Düşük önceliklidir.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
      asvs: "ASVS 5.0 V3: Web Frontend Security",
    },
  },
  missing_permissions_policy: {
    moduleType: "header_tls",
    severity: "low",
    title: "Permissions-Policy eksik",
    description: "Kamera/mikrofon/konum gibi tarayıcı özellikleri için kısıtlama tanımlı değil.",
    plainExplanation:
      "Kamera, mikrofon, konum gibi hassas tarayıcı özelliklerinin kullanımı sınırlanmamış.",
    whyItMatters:
      "Sitede bir XSS veya kötü niyetli üçüncü taraf script olması durumunda, Permissions-Policy bu script'in kamera/mikrofon/konum gibi hassas API'lere erişmesini sınırlayarak zararı azaltır.",
    falsePositiveNote:
      "Savunma derinliği amaçlı bir sertleştirmedir; tek başına bir açık değildir. Bu özellikleri hiç kullanmayan basit sitelerde etkisi semboliktir.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-693: Protection Mechanism Failure",
      asvs: "ASVS 5.0 V3: Web Frontend Security",
    },
  },
  tls_cert_expired: {
    moduleType: "header_tls",
    severity: "critical",
    title: "TLS sertifikası süresi dolmuş",
    description: "Sunucu sertifikasının geçerlilik süresi geçmiş; tarayıcılar uyarı gösterir.",
    plainExplanation:
      "Güvenlik sertifikanın süresi bitmiş. Ziyaretçiler büyük bir 'güvenli değil' uyarısıyla karşılaşır ve çoğu geri döner.",
    whyItMatters:
      "Süresi dolmuş sertifika, tarayıcının sunucunun kimliğini doğrulayamaması demektir; kullanıcılar uyarıyı tıklayıp geçmeye alışırsa gerçek bir ortadaki-adam saldırısını da fark etmez.",
    falsePositiveNote:
      "Sertifika ana alan adı için geçerli olup yalnızca taranan alt alan adını kapsamıyorsa benzer hata görülebilir; kanıttaki bitiş tarihini kontrol edin.",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-298: Improper Validation of Certificate Expiration",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },
  tls_cert_expiring_soon: {
    moduleType: "header_tls",
    severity: "medium",
    title: "TLS sertifikası yakında sona eriyor",
    description: "Sertifika 21 gün içinde sona eriyor; otomatik yenileme kontrol edilmeli.",
    plainExplanation:
      "Güvenlik sertifikanın süresi yakında doluyor. Zamanında yenilenmezse siten 'güvenli değil' uyarısı vermeye başlar.",
    whyItMatters:
      "Yenileme otomatikleştirilmemişse sertifika sessizce sona erer ve site bir anda tüm ziyaretçilere erişilemez/güvensiz görünür — tipik ve önlenebilir bir kesinti nedeni.",
    falsePositiveNote:
      "Let's Encrypt gibi 90 günlük sertifikalarda otomatik yenileme zaten son ~30 günde devreye girer; otomatik yenileme çalışıyorsa bu yalnızca bilgilendirmedir.",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-298: Improper Validation of Certificate Expiration",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },
  tls_cert_hostname_mismatch: {
    moduleType: "header_tls",
    severity: "high",
    title: "Sertifika alan adıyla eşleşmiyor",
    description: "Sunulan sertifikanın CN/SAN değerleri istenen host ile eşleşmiyor.",
    plainExplanation:
      "Sitenin sertifikası başka bir alan adına ait. Tarayıcı bunu güvenlik uyarısı olarak gösterir.",
    whyItMatters:
      "Sertifika istenen alan adını kapsamıyorsa, tarayıcı karşı tarafın gerçekten o site olduğunu doğrulayamaz; bu, yanlış yapılandırma veya ortadaki-adam belirtisi olabilir.",
    falsePositiveNote:
      "Paylaşımlı barındırma veya CDN'lerde sunucu, SNI olmadan varsayılan bir sertifika sunabilir; güven zinciri/ara sertifika eksikliği de benzer hataya yol açabilir. Kanıttaki hata koduna bakın.",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-297: Improper Validation of Certificate with Host Mismatch",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },
  tls_outdated_protocol: {
    moduleType: "header_tls",
    severity: "medium",
    title: "Eski TLS sürümü destekleniyor",
    description: "Sunucu TLS 1.0/1.1 kabul ediyor; bu sürümler güvensiz sayılır.",
    plainExplanation:
      "Siten artık güvensiz kabul edilen eski şifreleme sürümlerini kabul ediyor. Yalnızca TLS 1.2+ kullanılmalı.",
    whyItMatters:
      "TLS 1.0/1.1, bilinen zayıflıklar (ör. BEAST/POODLE sınıfı) ve zayıf şifre takımları içerir; PCI-DSS gibi standartlar bunları yasaklar. Yalnızca TLS 1.2 ve 1.3 etkinleştirilmelidir.",
    falsePositiveNote:
      "Faz 0'da bu kontrol yalnızca kurulan bağlantının protokolünü okur; eski sürümleri AKTİF olarak denemediği için çoğu modern sunucuda tetiklenmez. Kapsamlı tespit sonraki fazlara bırakılmıştır (bkz. docs/SCORING.md).",
    standards: {
      owaspTop10_2025: "A04:2025 Cryptographic Failures",
      owaspTop10_2021: "A02:2021 Cryptographic Failures",
      cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
      asvs: "ASVS 5.0 V12: Secure Communication",
    },
  },

  // ---------------- DNS & Altyapı ----------------
  missing_spf: {
    moduleType: "dns",
    severity: "medium",
    title: "SPF kaydı yok",
    description: "Domain için SPF (TXT) kaydı bulunamadı; e-posta sahteciliğine açık.",
    plainExplanation:
      "Adına sahte e-posta gönderilmesini zorlaştıran kayıt yok. Biri senin domaininden geliyormuş gibi mail atabilir.",
    whyItMatters:
      "SPF olmadan saldırgan, alan adınızdan geliyormuş gibi görünen oltalama (phishing) e-postaları gönderebilir; bu hem müşterilerinizi hedef alır hem de alan adınızın itibarını zedeler.",
    falsePositiveNote:
      "Alan adı e-posta göndermek için hiç kullanılmıyorsa, doğru yaklaşım 'v=spf1 -all' gibi reddedici bir kayıttır; kaydın tamamen yokluğu yine de eksikliktir. E-posta başka bir alt alan adından yönetiliyor olabilir.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-290: Authentication Bypass by Spoofing",
    },
  },
  missing_dmarc: {
    moduleType: "dns",
    severity: "medium",
    title: "DMARC kaydı yok",
    description: "_dmarc TXT kaydı yok; SPF/DKIM sonucuna göre politika uygulanmıyor.",
    plainExplanation:
      "E-posta sahteciliğine karşı 'sahte maili ne yap' politikan tanımlı değil. DMARC bunu belirler.",
    whyItMatters:
      "DMARC, SPF/DKIM doğrulamasını geçemeyen sahte e-postalara ne yapılacağını (reddet/karantina) alıcı sunuculara söyler ve size raporlar; olmadan SPF tek başına zayıf kalır.",
    falsePositiveNote:
      "Politika 'p=none' ile yalnızca gözlem modunda olabilir; bu durumda kayıt 'var' görünür ama koruma sağlamaz. Biz Faz 0'da yalnızca varlığını denetliyoruz.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-290: Authentication Bypass by Spoofing",
    },
  },
  dangling_cname: {
    moduleType: "dns",
    severity: "high",
    title: "Sahipsiz CNAME (subdomain takeover riski)",
    description:
      "Bir CNAME kaydı, artık size ait olmayan/çözülmeyen bir hedefe işaret ediyor olabilir.",
    plainExplanation:
      "Bir alt alan adın, artık kullanmadığın bir servise işaret ediyor. Saldırgan o servisi kaydedip alt alan adını ele geçirebilir.",
    whyItMatters:
      "Saldırgan terk edilmiş hedefi (ör. bir bulut/CDN kaynağını) kendi adına kaydederse, sizin alt alan adınızdan içerik sunabilir: oltalama, çerez çalma veya marka itibarının kötüye kullanımı mümkün olur.",
    falsePositiveNote:
      "Hedef geçici olarak çözülemiyor olabilir (DNS yayılımı, bakım); kaydın gerçekten sahipsiz olduğu, hedef servis kontrol edilerek doğrulanmalıdır. Faz 0 yalnızca 'www' için temel bir sinyal üretir.",
    standards: {
      owaspTop10_2025: "A02:2025 Security Misconfiguration",
      owaspTop10_2021: "A05:2021 Security Misconfiguration",
      cwe: "CWE-284: Improper Access Control",
      asvs: "ASVS 5.0 V13: Configuration",
    },
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
    whyItMatters: def.whyItMatters,
    falsePositiveNote: def.falsePositiveNote,
    standards: def.standards,
    evidence: opts.evidence,
    pointsDeducted: 0,
  };
}

/**
 * Bir finding_code için standart eşlemesi + açıklama metadata'sını döndürür.
 * API, DB'den okunan bulguları (standartları ayrı sütun olarak saklamadan)
 * yanıt anında zenginleştirmek için kullanır.
 */
export function findingMeta(findingCode: string): Pick<
  FindingDefinition,
  "whyItMatters" | "falsePositiveNote" | "standards"
> | null {
  const def = FINDINGS_CATALOG[findingCode];
  if (!def) return null;
  return {
    whyItMatters: def.whyItMatters,
    falsePositiveNote: def.falsePositiveNote,
    standards: def.standards,
  };
}
