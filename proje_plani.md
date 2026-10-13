# Site Güvenlik Tarayıcısı — Proje Planı (Free Tier / MVP)

VirusTotal'ın "yükle/linkle, sonucu al" mantığını web sitesi güvenlik taramasına uyarlayan, özellikle AI ile hızlı kotarılmış ("vibe-coded") sitelerdeki temel güvenlik açıklarını tespit eden bir ürün. Bu doküman, free-tier / MVP kapsamını uçtan uca planlar. Pro-tier fikirleri (SDK, log analizi, Chrome eklentisi ile derin izleme) bilinçli olarak bu fazın dışında tutulmuştur — ayrı bölümde not edilmiştir.

---

## 1. Yasal ve Etik Çerçeve (öncelikli — her kararın üstünde)

- Free-tier yalnızca **pasif/dış gözlem** yapar: normal HTTP GET/HEAD istekleri, standart DNS sorguları. Hiçbir aktif exploit denemesi (SQLi, XSS payload, brute-force login) yapılmaz.
- Tarayıcı kendini `User-Agent` header'ında açıkça tanıtır (ör. `SecurityScannerBot/1.0 (+https://site.com/about-bot)`).
- `robots.txt` disallow kurallarına saygı gösterilir; path-probing (bilinen dosya kontrolü) o site için atlanır.
- Aynı hedefe atılan istekler arasında nezaket aralığı (200–500ms) bırakılır — WAF/DDoS koruması tetiklenmesin diye.
- Her tarama denemesi (`audit_log`) domain, IP, kullanıcı, zaman damgasıyla loglanır — şikayet durumunda kanıt.
- Kullanım şartlarında "yalnızca sahibi olduğunuz veya test izniniz olan siteleri tarayın" ibaresi + tarama başlatılırken onay kutusu.
- Zone transfer (AXFR) gibi bazı güvenlik ekiplerinin recon/alarm olarak loglayabileceği kontroller opsiyonel/düşük öncelikli tutulur.

---

## 2. Free-Tier Tarama Kapsamı — 4 Modül

| # | Modül | Ne yapar | Veri kaynağı |
|---|-------|----------|---------------|
| 1 | **Header & TLS Analizi** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy kontrolü; TLS versiyonu, sertifika geçerliliği, zayıf cipher suite tespiti | Doğrudan HTTP(S) isteği + TLS socket |
| 2 | **Dosya & Bilgi Sızıntısı Taraması** | `.env`, `.git/config`, `.DS_Store`, `config.json`, backup dosyaları gibi ~40-50 bilinen path'e GET; HTML/JS kaynağında regex+entropy ile secret/API key pattern taraması | Hedefin public response'ları |
| 3 | **Framework & CVE Eşleştirme** | Header/meta/JS imzalarından teknoloji+versiyon fingerprint; NVD REST API 2.0 veya OSV.dev ile bilinen CVE eşleştirme | NVD API (key'siz ~1.5 req/sn, key ile ~5-10 req/sn, tamamen ücretsiz) |
| 4 | **DNS & Altyapı Hijyeni** | SPF/DKIM/DMARC eksikliği, subdomain takeover (dangling CNAME), açık zone transfer (düşük öncelik) | Standart DNS sorguları + crt.sh (sertifika şeffaflık logu) |

---

## 3. Skorlama Matematiği

**Kategori ağırlıkları (toplam 100):**
- Header & TLS: 30
- Dosya/Bilgi Sızıntısı: 30
- Framework & CVE: 25
- DNS & Altyapı: 15

**Bulgu bazlı kesinti (severity):**

| Severity | Örnek | Kesinti |
|---|---|---|
| Kritik | Açık `.env`/`.git`, CVSS 9+ | Kategori puanının %60-100'ü |
| Yüksek | HSTS yok, CVSS 7-8.9 | %30-40 |
| Orta | Eksik CSP, TLS 1.1 | %15-20 |
| Düşük | Eksik Referrer-Policy, SPF eksik | %5-10 |

Kategori puanı 0'ın altına inmez. Toplam skor 4 kategorinin toplamı → harf notu: 90-100 A, 75-89 B, 60-74 C, 40-59 D, <40 F.

**Tasarım kuralı:** Tek bir kritik bulgu, kategori puanını tek başına %60-100 düşürebilmeli — çok sayıda düşük risk bulgusunun tek bir kritik açığı gölgelemesini önlemek için.

---

## 4. Teknoloji Stack

- **Backend:** Node.js + TypeScript — I/O-bound tarama işleri için async model uygun, tek dilde frontend-backend tip paylaşımı
- **API framework:** Fastify
- **Frontend:** Next.js — rapor sayfalarını SSR ile paylaşılabilir link haline getirir (`/report/[scanId]`)
- **Queue:** BullMQ + Redis — retry/backoff/concurrency hazır
- **DB:** PostgreSQL (JSONB destekli, esnek bulgu verisi)
- **Deploy:** API ve worker ayrı container/process — worker'lar bağımsız yatay ölçeklenir

---

## 5. Veritabanı Şeması

```sql
-- Kullanıcılar
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE,
  password_hash TEXT,
  plan          TEXT NOT NULL DEFAULT 'free',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Her tarama isteği
CREATE TABLE scans (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain               TEXT NOT NULL,
  site_id              UUID REFERENCES sites(id),        -- giriş yapmış kullanıcı domaini "takibe" aldıysa dolar
  requested_by         UUID REFERENCES users(id),
  requester_ip         INET NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending',   -- pending|running|completed|failed
  score                INTEGER,
  grade                TEXT,
  detected_provider_id UUID REFERENCES hosting_providers(id),
  started_at           TIMESTAMPTZ,
  completed_at         TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_ip_created ON scans(requester_ip, created_at);
CREATE INDEX idx_scans_site ON scans(site_id, completed_at);

-- Her modülün ayrı sonucu
CREATE TABLE scan_modules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_type   TEXT NOT NULL,   -- 'header_tls' | 'leak' | 'cve' | 'dns'
  status        TEXT NOT NULL DEFAULT 'pending',
  module_score  INTEGER,
  raw_data      JSONB,
  completed_at  TIMESTAMPTZ
);

-- Tespit edilen her bulgu
CREATE TABLE findings (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_type      TEXT NOT NULL,
  finding_code     TEXT NOT NULL,   -- sabit kod, ör. 'missing_hsts','exposed_env','open_git'
  severity         TEXT NOT NULL,   -- critical|high|medium|low
  title            TEXT NOT NULL,
  description      TEXT,            -- teknik açıklama
  plain_explanation TEXT,            -- (i) ikonunda gösterilecek sade açıklama
  evidence         TEXT,
  points_deducted  INTEGER NOT NULL
);

-- 24 saatlik cache lookup
CREATE TABLE domain_cache (
  domain           TEXT PRIMARY KEY,
  latest_scan_id   UUID REFERENCES scans(id),
  last_scanned_at  TIMESTAMPTZ NOT NULL
);

-- Yasal koruma için tam log
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain      TEXT NOT NULL,
  ip          INET NOT NULL,
  user_id     UUID REFERENCES users(id),
  action      TEXT NOT NULL,   -- 'scan_requested'|'scan_blocked_robots'|'rate_limited'
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- Farklılaştırıcı özellikler için ek tablolar ----

-- Kullanıcının "takibe aldığı" siteler (ilerleme takibi + platform rehberi için gerekli kimlik)
CREATE TABLE sites (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain         TEXT NOT NULL,
  owner_user_id  UUID NOT NULL REFERENCES users(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(domain, owner_user_id)
);

-- Hosting sağlayıcı tanıma tablosu
CREATE TABLE hosting_providers (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name                TEXT NOT NULL,            -- 'Vercel','Netlify','Railway','Cloudflare Pages','GitHub Pages'
  header_patterns     TEXT[],                    -- ör. ['x-vercel-id','x-vercel-cache']
  dns_cname_patterns  TEXT[]                     -- ör. ['vercel-dns.com','netlify.app']
);

-- Bulgu + platform kombinasyonuna göre adım adım rehber
CREATE TABLE remediation_guides (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_code   TEXT NOT NULL,
  provider_id    UUID REFERENCES hosting_providers(id),  -- NULL = genel/varsayılan rehber
  steps_markdown TEXT NOT NULL,
  UNIQUE(finding_code, provider_id)
);

-- Başarı rozeti tanımları
CREATE TABLE badge_definitions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code          TEXT UNIQUE NOT NULL,   -- 'first_scan','first_critical_fixed','grade_a'
  title         TEXT NOT NULL,
  description   TEXT NOT NULL
);

-- Kullanıcının kazandığı rozetler
CREATE TABLE user_badges (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id),
  badge_id     UUID NOT NULL REFERENCES badge_definitions(id),
  site_id      UUID REFERENCES sites(id),
  earned_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, badge_id, site_id)
);
```

---

## 6. Job Queue Akışı

1. `POST /scan {domain}` → `domain_cache` kontrolü (24 saat içinde tarandıysa mevcut `scan_id` dönülür).
2. Cache miss → `requester_ip` bazlı rate limit kontrolü (`audit_log`'dan; free-tier örn. **günde 5 tarama/IP**).
3. `scans` kaydı (`status=pending`) oluşturulur, BullMQ'ya job eklenir, API **hemen** `scan_id` ile döner.
4. Worker job'ı alır, `status=running`, 4 modülü `Promise.allSettled` ile paralel çalıştırır (biri hata verirse diğerleri etkilenmez).
5. Her modül `scan_modules` + `findings` satırlarını yazar.
6. **Provider tespiti:** header/DNS pattern'leri `hosting_providers` tablosuyla eşleştirilir, `scans.detected_provider_id` set edilir.
7. Toplam skor hesaplanır, `scans.status=completed`, `domain_cache` güncellenir.
8. **Eğer `site_id` doluysa (kullanıcı bu domaini takibe almışsa):** aynı `site_id` için önceki tamamlanmış tarama çekilir, bulgular karşılaştırılır (severity=critical bir önceki taramada var, bu taramada yoksa → çözülmüş sayılır), uygun `badge_definitions` kontrol edilip `user_badges`'e yazılır.
9. Frontend `scan_id` ile rapor sayfasını çeker; `site_id` varsa geçmiş skorlar da çekilip ilerleme grafiği çizilir.

**Worker ölçekleme:** API ve worker ayrı process/container — tarama yoğunluğu artınca sadece worker yatay ölçeklenir.

---

## 7. Farklılaştırıcı Özellikler (nihai liste)

### 7.1 Bilgi ikonu (ⓘ) ile sade açıklama
Her bulgu satırında teknik başlık korunur, yanındaki (i) ikonu tıklanınca `findings.plain_explanation` alanındaki jargon içermeyen açıklama gösterilir. Böylece rapor hem deneyimli geliştiriciye hem yeni başlayana hitap eder.

### 7.2 Platforma özel adım adım düzeltme rehberi
- Tespit: response header'ları (`x-vercel-id`, `x-nf-request-id`, `cf-ray` vb.) ve DNS CNAME hedefleri (`vercel-dns.com`, `netlify.app`, `up.railway.app`, `pages.dev` vb.) `hosting_providers` tablosuyla eşleştirilir.
- Her `(finding_code, provider_id)` kombinasyonu için `remediation_guides` tablosunda önceden yazılmış, platforma özel adım adım metin tutulur (ör. "Vercel'de Settings → Environment Variables'a gidip ...").
- Provider tanınmazsa `provider_id = NULL` olan genel rehver fallback olarak gösterilir.
- Karmaşık bir AI çağrısı gerekmez — basit eşleştirme tablosu yeterli.

### 7.3 İlerleme takibi ve başarı rozetleri
- Kullanıcı giriş yapıp bir domaini "takibe" aldığında (`sites` tablosu) o domainin taramaları birbirine bağlanır.
- Rapor sayfasında skor-zaman grafiği: `sites.id` üzerinden geçmiş `scans` sorgulanıp çizilir (ekstra tablo gerekmez, mevcut `scans` verisinden türetilir).
- Ardışık iki tarama karşılaştırılarak (`badge_definitions` kriterlerine göre): `first_scan`, `first_critical_fixed`, `grade_a` gibi rozetler otomatik verilir.
- Öğrenci/junior kullanıcı için motive edici bir "gelişim hikayesi" oluşturur.

### 7.4 Gömülebilir güven rozeti
Skor hesaplandıktan sonra `<img src="/badge/{scanId}.svg">` şeklinde statik bir SVG/PNG üretilir. Kullanıcı bunu kendi sitesine veya CV/LinkedIn'e gömebilir; rozete tıklanınca rapor sayfasına link verir — ücretsiz, organik büyüme kanalı.

### 7.5 İş başvurusu için paylaşılabilir profesyonel rapor
Rapor sayfası (`/report/[scanId]`) baştan profesyonel/paylaşılabilir görünecek şekilde tasarlanır (SSR, temiz düzen) — öğrencinin iş başvurusunda link olarak paylaşabileceği bir çıktı olur. Ayrı bir teknik özellik değil, rapor sayfası tasarımının bir gereksinimi.

### 7.6 Maskot ve marka kimliği
Sade, sevimli, ikonik bir karakter (kullanıcı tarafından ayrıca tasarlanıyor) — rapor sayfasında durum ifadeleri için kullanılabilir (ör. skor A'da mutlu, F'de endişeli poz).

---

## 8. Pazar Araştırması Özeti

| Ürün | Odak | Not |
|---|---|---|
| Vibeship Scanner | AI-üretimi KAYNAK KODU (repo) taraması | Ücretsiz, MCP ile Claude/Cursor entegrasyonu |
| Vibe App Scanner | Canlı vibe-coded uygulama (DB/auth/API) | İlk tarama ücretsiz, detaylı bulgular ücretli |
| SSL Labs / SecurityHeaders.com | Genel header/TLS/DNS | Ücretsiz, sınırsız, AI-spesifik değil, yerelleşmemiş |

**Sonuç:** Doğrudan aynı fikir zaten var (özellikle Vibe App Scanner). Farklılaşma taklit değil, **konumlanma** üzerinden kurulmalı.

---

## 9. Nihai Konumlanma

**"Türkçe konuşan öğrenci/junior geliştiricinin AI ile kurduğu siteler için, anlaşılır dilde, platforma özel rehberlerle desteklenen güvenlik kontrolü."**

Gerekçe:
- Hedef kitle (öğrenci/hackathon/portföy sitesi sahibi) mevcut oyuncuların (girişimciye hitap eden, İngilizce, pahalı) hizmet etmediği bir segment.
- Kurucu bu kitlenin içinde — üniversite/hackathon ağı üzerinden organik büyüme mümkün.
- Yerelleşme (dil) + platforma özel rehber + ilerleme takibi + gömülebilir rozet, rakiplerin hiçbirinin birlikte sunmadığı bir kombinasyon.

---

## 10. Yol Haritası (Fazlar)

1. **Faz 0 (2-3 hafta):** Header/TLS/DNS checker, basit skor sistemi, domain cache, tek sayfalık MVP arayüz.
2. **Faz 1 (1-1.5 ay):** Sızıntı/exposure taraması, CVE eşleştirme (NVD entegrasyonu), kullanıcı hesapları, `sites` ile geçmiş takibi.
3. **Faz 2:** Platforma özel rehber tablosu + provider tespiti, bilgi ikonu (plain_explanation), rozet sistemi.
4. **Faz 3:** Gömülebilir güven rozeti, paylaşılabilir profesyonel rapor sayfası tasarımı.
5. **Faz 4 (pro-tier'a geçiş — bu dokümanın kapsamı dışında):** JS SDK + log entegrasyonu, Chrome eklentisi, gerçek pentester workflow entegrasyonları.

---

## 11. Notlar / Sonradan Değerlendirilecekler

- **Bulgu bazlı topluluk desteği (forum katmanı):** İyi bir SEO/topluluk fikri ama moderasyon yükü getirir — Faz 3-4 sonrası değerlendirilebilir.
- **Sürekli izleme / haftalık otomatik yeniden tarama:** `sites` tablosu zaten altyapıyı destekliyor; free-tier'da otomatik zamanlanmış tarama eklemek küçük bir cron job + BullMQ repeatable job ile mümkün, kaynak kullanımı nedeniyle dikkatli sınırlandırılmalı (ör. haftada 1).
- **Tek bir AI builder ekosistemine derin odak:** Riskli, kapsamı daraltıyor — ilk sürümde değil, kullanıcı tabanı büyüdükçe değerlendirilebilir.
- **"AI slop" tespiti:** Değerlendirildi, şimdilik kapsam dışı bırakıldı.
