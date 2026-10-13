# CatDef — Skorlama ve Metodoloji

Bu belge CatDef'in bir alan adını nasıl puanladığını, her kontrolün neden var
olduğunu, bilinçli tasarım kararlarını ve **ölçmediklerimizi** açıklar. Amaç:
skorun "kara kutu" olmaması — hem geliştirici hem işe alımcı formülü ve
gerekçeleri doğrulayabilsin.

> Kaynak kod: skorlama `packages/shared/src/scoring.ts`, bulgu tanımları ve
> standart eşlemeleri `packages/shared/src/findings-catalog.ts`.

## 1. Skor nasıl hesaplanır

Skor **kategori bazlı kesinti (deduction)** modeliyle üretilir; mutlak bir
"kaç kontrol geçti" sayımı değildir. Böylece **tek bir kritik açık**, çok sayıda
küçük eksikten daha ağır basar.

### 1.1 Kategori ağırlıkları

Her modül 100 puanlık bütçeden bir pay alır (`CATEGORY_WEIGHTS`):

| Kategori | Ağırlık | Faz 0'da aktif? |
|---|---|---|
| `header_tls` (Header & TLS) | 30 | ✅ |
| `leak` (Exposure/sızıntı) | 30 | ⛔ (sonraki faz) |
| `cve` (Bilinen zafiyetler) | 25 | ⛔ (sonraki faz) |
| `dns` (DNS & altyapı) | 15 | ✅ |

### 1.2 Severity → kesinti oranı

Bir bulgu, ait olduğu kategorinin ağırlığından severity'sine göre oran düşürür
(`SEVERITY_FRACTION`):

| Severity | Oran | Örnek: header_tls (30p) için kesinti |
|---|---|---|
| critical | 0.80 | 24 |
| high | 0.35 | ~11 |
| medium | 0.18 | ~5 |
| low | 0.08 | ~2 |

Kesinti: `round(kategori_ağırlığı × severity_oranı)`. Bir kategorinin puanı
**0'ın altına inmez** (kesintiler toplamı ağırlığı aşsa bile 0'da durur).

> **Tasarım kuralı:** tek bir `critical` bulgu, kategori ağırlığının %80'ini
> siler — yani kategoriyi neredeyse sıfırlar. Bu bilinçlidir: "kritik" gerçekten
> kritik olmalı; onlarca `low` bir `critical`'ı gölgeleyememeli.

### 1.3 Normalizasyon (neden 2 modülle de adil?)

Faz 0'da yalnızca `header_tls` ve `dns` çalışır (toplam ağırlık 45). Skor,
**fiilen çalışan (completed) modüllerin** kazandığı puanın, o modüllerin toplam
ağırlığına oranıdır:

```
skor = round( (çalışan modüllerin kazandığı puan) / (çalışan modüllerin toplam ağırlığı) × 100 )
```

Böylece `leak`/`cve` henüz yokken bile 0–100 arası adil bir skor çıkar; modüller
eklendikçe formül değişmeden pay otomatik yeniden dağılır. Hiç modül çalışmazsa
skor `null` olur (başarısız tarama).

### 1.4 Harf notu eşikleri

| Skor | Not |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

## 2. Her kontrolün gerekçesi

Kontrollerin tam listesi, teknik açıklaması, **neden önemli** (risk senaryosu) ve
**yanlış-pozitif notu** `findings-catalog.ts` içindedir ve rapor sayfasında da
gösterilir. Modüller:

- **Header & TLS** (`apps/worker/src/modules/headerTls.ts`): HTTPS erişilebilirliği
  (yoksa HTTP'ye düşer), 6 güvenlik başlığının varlığı (HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy), TLS sertifikası
  (süresi dolmuş / yakında dolacak / hostname uyuşmazlığı) ve bağlanılan TLS sürümü.
- **DNS & Altyapı** (`apps/worker/src/modules/dns.ts`): SPF (TXT), DMARC (`_dmarc`
  TXT), `www` için temel dangling-CNAME (subdomain takeover) sinyali.

## 3. Standart eşlemesi (metodoloji)

Her bulgu, kabul görmüş üç çerçeveye eşlenir (`StandardRefs`):

- **OWASP Top 10 2025** (birincil, güncel) — resmi kategoriler
  <https://top10.owasp.org/2025/>. 2025'te dikkat: SSRF, **A01 Broken Access
  Control** altına taşındı; "Software Supply Chain Failures" (A03) ve "Mishandling
  of Exceptional Conditions" (A10) yeni kategorilerdir.
- **OWASP Top 10 2021** (çapraz referans) — işe alımcıların/araçların hâlâ en çok
  tanıdığı sürüm <https://owasp.org/Top10/>.
- **CWE** — kök neden sınıfı (ör. `CWE-319 Cleartext Transmission`).
- **OWASP ASVS 5.0** (uygunsa, bölüm düzeyinde) — doğrulama maddesi
  <https://owasp.org/www-project-application-security-verification-standard/>.

### Bilinçli eşleme kararları

- **Güvenlik başlıkları → Security Misconfiguration** (A02:2025 / A05:2021).
  OWASP Secure Headers Project'in yaklaşımıyla tutarlı. (CSP ayrıca XSS/`A03
  Injection` savunmasıdır; bunu "neden önemli"de belirtiyoruz.)
- **Transport/TLS/sertifika → Cryptographic Failures** (A04:2025 / A02:2021).
- **SPF/DMARC → Security Misconfiguration**, CWE-290 (spoofing). Bunlar **e-posta
  katmanı** kontrolleridir; ASVS (web uygulaması odaklı) kapsamı dışında olduğu
  için ASVS maddesi bilinçli olarak boş bırakılmıştır.
- **ASVS 5.0 atıfları bölüm düzeyindedir** (ör. "V12 Secure Communication"); alt
  madde numaraları sürümden sürüme oynadığı ve doğrulanabilir tutmak istediğimiz
  için tek tek madde ID'si uydurmuyoruz.

## 4. Mozilla Observatory'den bilinçli farklarımız

CatDef, Observatory'den esinlenir ama aynısı değildir:

1. **Dil ve kitle.** Observatory geliştirici-merkezli İngilizce çıktıdır; CatDef'in
   çıktısı **anlaşılır Türkçe** olup her bulguda "bu ne demek?" ve "neden önemli?"
   açıklaması verir. Farklılaştırıcımız budur.
2. **Kapsam.** Observatory ağırlıkla HTTP/başlık odaklıdır; CatDef başlıklara ek
   olarak **DNS/e-posta hijyeni** (SPF/DMARC) ve **subdomain takeover** sinyalini
   tek skorda birleştirir. Buna karşılık Observatory'nin bazı başlık alt-kuralları
   (ör. CSP kalite analizi) bizde Faz 0'da **yok**.
3. **Skor modeli.** Observatory başlangıç 100'den başlar ve kurala göre +/− puan
   uygular; biz **kategori-ağırlıklı kesinti + normalizasyon** kullanırız; bu,
   modüller eklendikçe yeniden dengelenmeyi kolaylaştırır.
4. **Severity felsefesi.** Tek `critical`'ın kategoriyi ~sıfırlaması bilinçli bir
   tercihtir (bkz. §1.2); Observatory'nin puan dağılımından farklıdır.

## 5. Ölçmediklerimiz (sınırlılıklar)

Dürüstlük, bu aracın en önemli özelliğidir. **Faz 0'da ölçülmeyenler:**

- **Başlık kalitesi değil, yalnızca varlığı.** Zayıf bir CSP (`unsafe-inline`) ya
  da gözlem modundaki DMARC (`p=none`) "var" sayılır.
- **Eski TLS sürümleri aktif denenmez.** Kontrol yalnızca kurulan bağlantının
  protokolünü okur; sunucunun TLS 1.0/1.1'i *kabul edip etmediği* ayrıca el
  sıkışmayla denenmez (sonraki faz).
- **Şifre takımları (cipher suites), OCSP/stapling, HSTS preload, sertifika zinciri
  detayı** denetlenmez.
- **Uygulama katmanı** (XSS, SQLi, kimlik doğrulama, yetkilendirme, iş mantığı)
  taranmaz — CatDef **pasif** bir dış gözlemcidir, zafiyet sömürmez.
- **DNSSEC, CAA, DKIM, MX hijyeni, wildcard** ve `www` dışındaki alt alan adları
  Faz 0 kapsamında değildir.
- Tespitler **tek bir gözlem anına** dayanır; CDN/coğrafi varyasyon sonucu
  etkileyebilir.

Bu sınırlar sonraki fazlarda daraltılacaktır (bkz. `README.md` yol haritası).
