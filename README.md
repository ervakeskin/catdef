# CatDef 🐱🛡️

Pasif site güvenlik tarayıcısı — bir alan adını girin, HTTPS / güvenlik başlıkları / TLS / DNS
hijyeni için **anlaşılır Türkçe** bir güvenlik raporu ve harf notu (A–F) alın.

Bu depo **Faz 0 (MVP)** iskeletidir. Ürün planının tamamı için `proje_plani.md`'ye bakın.

## Mimari (monorepo)

| Paket | Rol |
|---|---|
| `packages/shared` | Ortak TS tipleri, skorlama matematiği, bulgu kataloğu, SSRF guard |
| `apps/api` | Fastify — `POST /scan`, `GET /scan/:id`, rate limit, cache, kuyruğa ekleme |
| `apps/worker` | BullMQ tüketici — Header/TLS ve DNS modüllerini çalıştırır, skorlar, DB'ye yazar |
| `apps/web` | Next.js — tek sayfa tarama formu + SSR paylaşılabilir rapor sayfası |

## Gereksinimler

- Node.js 20+
- pnpm (corepack ile: `corepack enable`)
- **Çalıştırma için harici bağımlılık yok** — yerel mod (`pnpm dev:local`) gerçek bir
  Postgres'i `embedded-postgres` ile process içinde başlatır ve Redis'i DB-polling ile
  değiştirir. Docker/Redis/Postgres kurmanız gerekmez. (Üretim yolu için Docker seçeneği aşağıda.)

## Kurulum

```bash
corepack enable
pnpm install
```

## Çalıştırma (önerilen: sıfır kurulum)

Docker/Postgres/Redis olmadan her şeyi tek komutla başlatır (embedded Postgres'i başlatır,
migration'ları uygular, api + worker + web'i çalıştırır):

```bash
pnpm dev:local
```

- Web: http://localhost:3000
- API: http://localhost:3001
- Veri `\.devdata/` altında kalıcıdır (git'e girmez). Durdurmak için `Ctrl+C`.

> Nasıl çalışır: yerel mod `CATDEF_LOCAL=1` ile açılır. Bu modda API kuyruğa yazmaz;
> worker `scans` tablosundaki `pending` kayıtları `FOR UPDATE SKIP LOCKED` ile poll ederek işler.
> Redis/BullMQ yalnızca `CATDEF_LOCAL` **olmadan** (Docker yolu) devreye girer.

## Çalıştırma (Docker ile — üretime yakın)

1. **Altyapıyı başlat** (Postgres + Redis):

```bash
docker compose up -d
```

> Docker yoksa kendi Postgres/Redis'inizi kurup `.env` içindeki `DATABASE_URL` / `REDIS_URL`'i güncelleyin.

2. **Migration uygula** (5 tabloyu oluşturur):

```bash
pnpm db:migrate
```

3. **Hepsini geliştirme modunda başlat** (api + worker + web):

```bash
pnpm dev
```

- Web: http://localhost:3000
- API: http://localhost:3001

## Doğrulama

```bash
# Skorlama birim testleri
pnpm --filter @catdef/shared test

# Tümünü derle / tip kontrolü
pnpm build
```

**Uçtan uca akış:** Web'de bir alan adı girin (ör. `example.com`) → `/report/[scanId]`
sayfasına yönlenir → tarama bitince harf notu + bulgular + her bulguda "ⓘ Bu ne demek?"
sade açıklaması görünür.

**Güvenlik (SSRF):** İç/özel IP'ye çözülen alan adları (localhost, 10.x, 192.168.x,
169.254.169.254 …) taranmadan reddedilir ve `audit_log`'a `scan_blocked` yazılır.

## Kapsam (Faz 0)

**Var:** Header & TLS analizi, DNS & altyapı hijyeni (SPF/DMARC/dangling CNAME), skor + harf
notu, 24s domain cache, IP başına günlük rate limit, SSRF koruması, audit log, maskotlu SSR rapor.

**Sonraki fazlar:** Dosya/exposure taraması, CVE/NVD eşleştirme, kullanıcı hesapları + site
takibi, rozetler, platforma özel düzeltme rehberleri, gömülebilir güven rozeti.
