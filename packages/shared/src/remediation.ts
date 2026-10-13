// Her bulgu için platform bazlı, kopyala-yapıştır düzeltme yapılandırmaları ve
// PASİF bir "düzeldi mi?" doğrulama adımı. Veri tarayıcı-güvenlidir (Node built-in
// kullanmaz), bu yüzden web doğrudan import edebilir; API'yi şişirmeye gerek yok.
//
// verify metinlerinde {{domain}} yer tutucusu arayüzde taranan alan adıyla değişir.

export type RemediationPlatform =
  | "nginx"
  | "apache"
  | "express"
  | "nextjs"
  | "vercel"
  | "cloudflare"
  | "dns";

export interface RemediationGuide {
  /** Platform → kopyala-yapıştır yapılandırma. */
  configs: Partial<Record<RemediationPlatform, string>>;
  /** Pasif doğrulama komutu/adımı ({{domain}} yer tutucusu değişir). */
  verify: string;
  /** Opsiyonel ek bağlam. */
  note?: string;
}

/** Tek bir güvenlik başlığı için 6 web platformunda ekleme yapılandırması üretir. */
function headerGuide(
  name: string,
  value: string,
  verifyHeader: string,
  note?: string,
): RemediationGuide {
  return {
    configs: {
      nginx: `# http veya server bloğunda\nadd_header ${name} "${value}" always;`,
      apache: `# VirtualHost veya .htaccess içinde (mod_headers gerekli)\nHeader always set ${name} "${value}"`,
      express: `// Tüm yanıtlara uygula (app tanımından sonra)\napp.use((req, res, next) => {\n  res.setHeader("${name}", "${value}");\n  next();\n});\n// Daha sağlamı için: helmet paketi`,
      nextjs: `// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/:path*",\n      headers: [{ key: "${name}", value: "${value}" }],\n    }];\n  },\n};`,
      vercel: `// vercel.json\n{\n  "headers": [{\n    "source": "/(.*)",\n    "headers": [{ "key": "${name}", "value": "${value}" }]\n  }]\n}`,
      cloudflare: `Dashboard → Rules → Transform Rules → Modify Response Header\n→ "Set static" ekle:  ${name} = ${value}\n(veya bir Worker ile response.headers.set("${name}", "${value}"))`,
    },
    verify: `curl -sSI https://{{domain}} | grep -i "${verifyHeader}"`,
    note,
  };
}

export const REMEDIATION: Record<string, RemediationGuide> = {
  // ---------------- Güvenlik başlıkları ----------------
  missing_hsts: headerGuide(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload",
    "strict-transport-security",
    "includeSubDomains ve preload yalnızca TÜM alt alan adların HTTPS ise eklenmeli. preload listesine girmeden önce siteyi iyi test et (geri almak zordur).",
  ),
  missing_csp: headerGuide(
    "Content-Security-Policy",
    "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'",
    "content-security-policy",
    "Bu başlangıç politikasıdır; sitenin kullandığı 3. taraf kaynaklara göre genişletilmeli. 'unsafe-inline'/'unsafe-eval' eklemekten kaçın. Önce Content-Security-Policy-Report-Only ile dene.",
  ),
  missing_x_frame_options: headerGuide(
    "X-Frame-Options",
    "SAMEORIGIN",
    "x-frame-options",
    "Modern tarayıcılar için asıl koruma CSP'deki frame-ancestors direktifidir; X-Frame-Options eski tarayıcılar için geriye dönük uyumluluk sağlar.",
  ),
  missing_x_content_type_options: headerGuide(
    "X-Content-Type-Options",
    "nosniff",
    "x-content-type-options",
  ),
  missing_referrer_policy: headerGuide(
    "Referrer-Policy",
    "strict-origin-when-cross-origin",
    "referrer-policy",
  ),
  missing_permissions_policy: headerGuide(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
    "permissions-policy",
    "Boş parantez () o özelliği tamamen kapatır. Sitenin gerçekten kullandığı özellikler için izin ver, ör. geolocation=(self).",
  ),

  // ---------------- HTTPS / TLS ----------------
  no_https: {
    configs: {
      nginx: `# 1) Ücretsiz sertifika (Let's Encrypt)\nsudo certbot --nginx -d {{domain}} -d www.{{domain}}\n\n# 2) HTTP'yi HTTPS'e kalıcı yönlendir\nserver {\n  listen 80;\n  server_name {{domain}} www.{{domain}};\n  return 301 https://$host$request_uri;\n}`,
      apache: `# mod_ssl + certbot\nsudo certbot --apache -d {{domain}} -d www.{{domain}}\n\n# HTTP vhost içinde kalıcı yönlendirme\n<VirtualHost *:80>\n  ServerName {{domain}}\n  Redirect permanent / https://{{domain}}/\n</VirtualHost>`,
      express: `// TLS'i uygulamada değil, önünde bir ters proxy (nginx) ya da\n// platformda (Vercel/Cloudflare) sonlandır. Proxy arkasında http→https:\napp.set("trust proxy", true);\napp.use((req, res, next) => {\n  if (req.secure) return next();\n  res.redirect(301, "https://" + req.headers.host + req.url);\n});`,
      vercel: `Otomatik: Vercel her dağıtıma ücretsiz TLS verir. Project → Settings →\nDomains'ten alan adını ekle; HTTPS ve HTTP→HTTPS yönlendirmesi otomatiktir.`,
      cloudflare: `SSL/TLS → Overview → şifreleme modunu "Full (strict)" yap.\nSSL/TLS → Edge Certificates → "Always Use HTTPS" = On.`,
    },
    verify: `curl -sSI http://{{domain}} | grep -i "^location"   # https'e 301 beklenir\ncurl -sSI https://{{domain}} | head -n1              # HTTP/.. 200 beklenir`,
    note: "Nihai hedef: tüm trafik geçerli bir sertifikayla HTTPS üzerinden sunulmalı ve HTTP kalıcı olarak HTTPS'e yönlenmeli.",
  },
  tls_cert_expired: {
    configs: {
      nginx: `# Let's Encrypt sertifikasını yenile ve otomatik yenilemeyi doğrula\nsudo certbot renew\nsudo systemctl list-timers | grep certbot   # otomatik yenileme zamanlayıcısı`,
      apache: `sudo certbot renew\nsudo systemctl reload apache2`,
      cloudflare: `Edge sertifikaları Cloudflare tarafından otomatik yenilenir. Origin\nsertifikası kullanıyorsan: SSL/TLS → Origin Server'dan yeniden oluştur.`,
      vercel: `Otomatik: Vercel sertifikaları süresi dolmadan yeniler; genelde eylem gerekmez.\nDomain "Invalid" görünüyorsa DNS kayıtlarını doğrula.`,
    },
    verify: `echo | openssl s_client -connect {{domain}}:443 -servername {{domain}} 2>/dev/null | openssl x509 -noout -enddate`,
    note: "Kök neden çoğu zaman otomatik yenilemenin kurulmamış olmasıdır; yenilemeyi bir zamanlayıcıya bağla.",
  },
  tls_cert_expiring_soon: {
    configs: {
      nginx: `sudo certbot renew --dry-run   # otomatik yenileme çalışıyor mu?\nsudo systemctl list-timers | grep certbot`,
      apache: `sudo certbot renew --dry-run`,
      cloudflare: `Otomatik yenilenir; ek işlem gerekmez.`,
      vercel: `Otomatik yenilenir; ek işlem gerekmez.`,
    },
    verify: `echo | openssl s_client -connect {{domain}}:443 -servername {{domain}} 2>/dev/null | openssl x509 -noout -enddate`,
    note: "Otomatik yenileme (ör. Let's Encrypt son ~30 günde yeniler) çalışıyorsa bu bilgilendirmedir.",
  },
  tls_cert_hostname_mismatch: {
    configs: {
      nginx: `# Sertifikayı istenen tüm host adlarını kapsayacak şekilde yeniden al\nsudo certbot --nginx -d {{domain}} -d www.{{domain}}\n# Doğru server_name ve ssl_certificate yolunu kullandığından emin ol`,
      apache: `sudo certbot --apache -d {{domain}} -d www.{{domain}}\n# ServerName/ServerAlias ile sertifikanın SAN'ları eşleşmeli`,
      cloudflare: `Proxy (turuncu bulut) açıkken Cloudflare edge sertifikası host'u kapsar.\nKendi origin sertifikan host adını içermeli (SSL/TLS → Origin Server).`,
      vercel: `Project → Settings → Domains'e doğru alan adını ekle; Vercel eşleşen\nbir sertifika sağlar. Yanlış/eksik alan adı bu hatayı verir.`,
    },
    verify: `echo | openssl s_client -connect {{domain}}:443 -servername {{domain}} 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName`,
    note: "subjectAltName (SAN) listesi taranan alan adını içermeli.",
  },
  tls_outdated_protocol: {
    configs: {
      nginx: `ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;`,
      apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`,
      express: `// Node TLS sunucusunda\nhttps.createServer({ key, cert, minVersion: "TLSv1.2" }, app);\n// Genelde TLS'i önündeki nginx/proxy sonlandırır; ayarı orada yap.`,
      cloudflare: `SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2`,
      vercel: `Otomatik: Vercel yalnızca modern TLS (1.2+) sunar; eylem gerekmez.`,
    },
    verify: `# TLS 1.1 el sıkışması BAŞARISIZ olmalı (kendi sunucunda):\nopenssl s_client -connect {{domain}}:443 -tls1_1 2>&1 | grep -iE "handshake|protocol|alert"`,
    note: "Yalnızca TLS 1.2 ve 1.3 etkin olmalı; 1.0/1.1 kapatılmalı.",
  },

  // ---------------- DNS / E-posta ----------------
  missing_spf: {
    configs: {
      dns: `# Apex alan adına TXT kaydı ekle (DNS sağlayıcı: Cloudflare/registrar paneli)\n# E-posta GÖNDEREN alan adı için (örnek: Google Workspace):\n{{domain}}.  IN  TXT  "v=spf1 include:_spf.google.com ~all"\n\n# Alan adı HİÇ e-posta göndermiyorsa (sertleştirme):\n{{domain}}.  IN  TXT  "v=spf1 -all"`,
    },
    verify: `nslookup -type=TXT {{domain}}      # Windows\n# veya:  dig +short TXT {{domain}}`,
    note: "Tek bir alan adında yalnızca BİR SPF (v=spf1) kaydı olmalı. ~all (softfail) yerine kademeli olarak -all (hardfail) hedeflenebilir.",
  },
  missing_dmarc: {
    configs: {
      dns: `# _dmarc alt alan adına TXT kaydı ekle\n_dmarc.{{domain}}.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@{{domain}}; adkim=s; aspf=s"\n\n# Önce gözlem için p=none ile başlayıp, raporları izleyip p=quarantine/p=reject'e geç.`,
    },
    verify: `nslookup -type=TXT _dmarc.{{domain}}\n# veya:  dig +short TXT _dmarc.{{domain}}`,
    note: "DMARC'ın etkili olması için SPF ve/veya DKIM'in kurulu ve hizalı (alignment) olması gerekir.",
  },
  dangling_cname: {
    configs: {
      dns: `# Sahipsiz/çözülmeyen CNAME kaydını DNS panelinden KALDIR:\nwww.{{domain}}.  IN  CNAME  <eski-hedef>   ← bu kaydı sil\n\n# Alt alan adı hâlâ gerekiyorsa, kontrol ettiğin GEÇERLİ bir hedefe yönlendir\n# ve ilgili servis hesabındaki kaynağı (CDN/bulut) geri al.`,
    },
    verify: `nslookup -type=CNAME www.{{domain}}\n# Hedef çözülüyor ve sana ait mi? Değilse kaydı kaldır.`,
    note: "Subdomain takeover'ı önlemenin tek kesin yolu: kullanılmayan DNS kayıtlarını silmek.",
  },
};

/** Bir finding_code için düzeltme rehberini döndürür (yoksa null). */
export function getRemediation(findingCode: string): RemediationGuide | null {
  return REMEDIATION[findingCode] ?? null;
}

/** Arayüzde gösterim için platform etiketleri. */
export const PLATFORM_LABELS: Record<RemediationPlatform, string> = {
  nginx: "Nginx",
  apache: "Apache",
  express: "Express",
  nextjs: "Next.js",
  vercel: "Vercel",
  cloudflare: "Cloudflare",
  dns: "DNS",
};
