# CatDef — Tehdit Modeli (STRIDE)

CatDef'in **kendi** güvenliği. Bir güvenlik aracının, tarattığı sitelerden daha
güvenli olması gerekir. Bu belge varlıkları, güven sınırlarını, STRIDE tehditlerini,
alınan önlemleri ve kalan riskleri tanımlar.

## 1. Varlıklar

| Varlık | Neden değerli |
|---|---|
| Worker'ın giden ağ erişimi | **En kritik.** Worker, kullanıcının verdiği hedeflere bağlanır → SSRF yüzeyi. |
| Tarama sonuçları (`scans`, `findings`) | Üçüncü tarafların güvenlik duruşu; kötüye kullanılabilir. |
| `audit_log` | Yasal koruma + rate limit kaynağı; ziyaretçi IP'leri (kişisel veri). |
| API/Worker'ın ayakta kalması | DoS hedefi (ücretsiz, kimliksiz uç nokta). |
| Veritabanı kimlik bilgileri / ortam değişkenleri | Ele geçirilirse tüm veriye erişim. |

## 2. Güven sınırları ve veri akışı

```
[Browser]  ──1──>  [Next.js Web/SSR]  ──2──>  [Fastify API]  ──3──>  [PostgreSQL]
                                                    │
                                                    └──4── enqueue ──> [Worker]
                                                                         │ 5 (giden)
                                                                         ▼
                                                      [Kullanıcının verdiği HEDEF site + DNS]
```

- **Sınır 1 — Browser↔Web:** güvenilmeyen girdi (alan adı).
- **Sınır 2 — Web↔API:** CORS ile kısıtlı; API tüm girdiyi yeniden doğrular.
- **Sınır 3 — API↔DB:** parametreli sorgular.
- **Sınır 5 — Worker↔İnternet:** **en tehlikeli sınır.** Worker, saldırganın
  seçtiği bir hedefe bağlanır. Buradaki yanlış, iç ağa/metadata'ya erişim (SSRF) demektir.

## 3. Giriş noktaları

- `POST /scan` — gövdede `domain` (tamamen güvenilmez).
- `GET /scan/:id` — `id` (UUID doğrulanır; yoksa 404).

## 4. STRIDE

| Kategori | Tehdit | Önlem |
|---|---|---|
| **S**poofing (kimlik sahteciliği) | Saldırgan başka IP adına rate limit'i atlatır | Gerçek istemci IP'si `trustProxy` ile; audit_log IP bazlı. Kimlik doğrulama yok (pasif, kamuya açık araç). |
| **T**ampering (kurcalama) | Girdiyle iç hedefe yönlendirme (SSRF), SQL enjeksiyonu | **SSRF guard** (bkz. §5); tüm sorgular parametreli; girdi normalize + doğrulama. |
| **R**epudiation (inkâr) | "Bu taramayı ben yapmadım" | `audit_log`: IP + eylem + domain + zaman; `scan_requested`/`scan_blocked`/`rate_limited`/`cache_hit`. |
| **I**nformation Disclosure (bilgi sızıntısı) | İç servis/metadata verisi, DB sızıntısı | SSRF guard iç hedefleri engeller; hata mesajları jenerik; sırlar URL'de taşınmaz; sonuçlar yalnızca UUID ile erişilir. |
| **D**enial of Service | Pahalı taramalarla kaynak tüketimi | IP başına günlük rate limit; 24s domain cache; istek zaman aşımları (10s); worker eşzamanlılık sınırı. |
| **E**levation of Privilege | Worker üzerinden iç ağa yanal hareket | SSRF guard private/metadata aralıklarını reddeder; worker yalnızca HTTP(S)+DNS yapar, kabuk/komut çalıştırmaz. |

## 5. SSRF — derinlemesine savunma

SSRF, bu mimarinin bir numaralı riskidir. Katmanlar (`packages/shared/src/net-guard.ts`):

1. **Girdi doğrulama** (`isValidDomain`): ham IP (v4/v6), tek etiket, ondalık/oktal/hex
   IP gösterimleri, `user@host` kaçışı ve `[...]` literal'leri reddedilir.
2. **Tam çözümleme kontrolü** (`resolveAndGuard`): A **ve** AAAA kayıtlarının tamamı
   çözülür; **herhangi biri** private/reserved/loopback/link-local/metadata ise
   istek reddedilir (split-horizon DNS'e karşı).
3. **Bağlantı anında yeniden doğrulama** (`createGuardedLookup`): fiili TCP/TLS
   bağlantısı kurulurken domain yeniden çözülüp yeniden doğrulanır ve çözülen IP'ye
   sabitlenir → **DNS rebinding/TOCTOU** engellenir. Aynı guarded dispatcher,
   **yönlendirme (redirect)** hedeflerini de her hop'ta aynı kontrolden geçirir.

Ayrıntılı bypass denemeleri ve bulgular: [`SECURITY_TESTING.md`](SECURITY_TESTING.md).

## 6. Kalan riskler (bilinen sınırlar)

- **Public dış yönlendirme:** guard iç hedefleri engeller ama public bir host'a
  yönlendirmeye izin verir — pasif bir tarayıcı için kabul edilebilir; yine de hop
  sayısı sınırlıdır (maxRedirections=3).
- **Kimlik doğrulama yok:** araç kamuya açık ve kimliksizdir; kötüye kullanım yalnızca
  rate limit + cache ile sınırlanır (uygulama katmanı WAF yoktur).
- **IP tabanlı rate limit:** NAT/paylaşımlı IP'lerde adil olmayabilir; IPv6 /64 bazlı
  sınırlama ileride düşünülebilir.
- **embedded-postgres yalnızca geliştirme içindir**; üretimde yönetilen, kimlik
  bilgileri gizli tutulan bir Postgres kullanılmalıdır.
- **DoS:** tek örnekli dağıtımda uygulama düzeyinde hız sınırı vardır; ağ düzeyinde
  koruma (CDN/WAF) dağıtım ortamına bırakılmıştır.
