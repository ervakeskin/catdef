# CatDef — Güvenlik Testi: SSRF Sağlamlaştırması

Bu belge, aracın kendi SSRF korumasına yönelik yaptığım **saldırgan bakış açılı**
incelemeyi "ne denedim / ne buldum / nasıl düzelttim" biçiminde kaydeder. Tüm
testler **yerel mock sunucular ve sahte DNS resolver** ile çalışır; gerçek sitelere
istek atılmaz (bkz. `packages/shared/src/net-guard.test.ts`,
`apps/worker/src/guard.integration.test.ts`).

## Özet

İlk tasarımda guard, tarama **başlamadan önce** domaini bir kez çözüp "public mi?"
diye bakıyor; ancak fiili HTTP/TLS isteğini atan `undici` ve `tls.connect` domaini
**bağımsız olarak yeniden** çözüyordu. Bu klasik bir **TOCTOU** açığıydı. İnceleme
sonunda guard, çözümlemeyi tek kaynağa indirip **bağlantı anında** yeniden doğrulayan
bir modele taşındı ve 6 ayrı sorun kapatıldı.

---

### 1. DNS rebinding / TOCTOU  🔴 (gerçek açık → düzeltildi)

- **Denedim:** Ön-kontrolde public, bağlantı anında private IP döndüren bir resolver
  (rebinding) simüle ettim.
- **Buldum:** `guardDomain()` yalnızca ön-kontrol yapıyor; `undici.request()` ve
  `tls.connect({host: domain})` sonra domaini yeniden çözüyordu. Çözülen IP hiçbir
  yere sabitlenmiyordu → saldırgan, doğrulama ile bağlanma arasında `169.254.169.254`'e
  kaydırabilirdi.
- **Düzelttim:** `createGuardedLookup` — net/tls/undici'nin `lookup` kancasına takılır,
  bağlantı anında yeniden çözer **ve** yeniden doğrular; IP'yi literal olarak döndürüp
  sabitler. `headerTls` modülündeki hem `undici.Agent` hem `tls.connect` bunu kullanır.
- **Regresyon:** "DNS rebinding — bağlantı anındaki private çözüm engellenir" (unit) +
  "guarded agent: loopback'e çözülen host'a istek ULAŞTIRMAZ" (gerçek yerel sunucu;
  iç servis hiç istek almıyor).

### 2. Yönlendirme (redirect) ile SSRF  🔴 (gerçek açık → düzeltildi)

- **Denedim:** Public bir sayfanın `302 Location: http://169.254.169.254/...` ile iç
  adrese yönlendirmesi senaryosu.
- **Buldum:** `undici` `maxRedirections: 3` ile yönlendirmeleri guard'dan geçmeden
  izliyordu.
- **Düzelttim:** Yönlendirmeler artık aynı guarded dispatcher üzerinden gider; her hop'ta
  `createGuardedLookup` yeniden devreye girer, iç hedefe giden hop bağlanamadan reddedilir.

### 3. Çoklu A kaydı yalnızca ilk IP kontrol ediliyordu  🟠 → düzeltildi

- **Buldum:** Eski `guardDomain`, `dns.lookup`'ın döndürdüğü **tek** adrese bakıyordu;
  bir alan adı hem public hem private A kaydı döndürürse (split-horizon) private kaçabilirdi.
- **Düzelttim:** `resolveAndGuard`, A+AAAA kayıtlarının **tamamını** çözer; **herhangi
  biri** private ise reddeder.
- **Regresyon:** "resolveAndGuard: HERHANGİ bir adres private ise reddeder".

### 4. IPv6 sınıflandırma boşlukları  🟠 → düzeltildi

- **Buldum:** Eski kontrol `fe80` için yalnızca `startsWith` kullanıyordu (fe90/fea0/feb0
  link-local'ı kaçırır) ve IPv4-mapped'in yalnızca noktalı biçimini yakalıyordu;
  NAT64 (`64:ff9b::/96`), multicast, ULA aralığının tamamı, documentation (`2001:db8::/32`)
  ve hex biçimli mapped (`::ffff:a9fe:a9fe`) kapsanmıyordu.
- **Düzelttim:** Tam bir IPv6 ayrıştırıcı (`parseIpv6`) + kapsamlı sınıflandırma:
  `::1`, `::`, `fe80::/10`, `fc00::/7`, `ff00::/8`, `2001:db8::/32`, `100::/64` ve
  gömülü IPv4'lü biçimler (mapped / IPv4-compatible / NAT64) IPv4 kurallarıyla denetlenir.
- **Regresyon:** "isPrivateIp: IPv6 private/reserved + gömülü IPv4" (12 vektör).

### 5. Alternatif IP gösterimleri  🟢 (zaten güvende → doğrulandı)

- **Denedim:** `2130706433` (ondalık), `0x7f000001` / `0x7f.0.0.1` (hex),
  `0177.0.0.1` (oktal görünümlü), `evil.com@127.0.0.1` (userinfo), `[::1]` (parantez).
- **Sonuç:** `isValidDomain` hepsini reddediyor (tümü-sayısal, hex etiket, `@`, `[`/`]`
  kontrolleri). Davranışı kalıcı kılmak için **regresyon testleri** eklendi.

### 6. `undici` `all:true` lookup — düzeltme sırasında yakalanan hata  🟠

- **Buldum:** Guarded lookup'ı eklerken, `undici` lookup'ı `{ all: true }` ile çağırıp
  callback'ten bir **dizi** (`[{address, family}]`) bekliyordu; tek string döndürünce
  **tüm** fetch'ler `ERR_INVALID_IP_ADDRESS` ile kırıldı (public dahil). Bu tehlikeli bir
  **yanlış-negatif**ti: her şey "engellenmiş" gibi görünüp testi yanıltabilirdi.
- **Düzelttim:** `createGuardedLookup` artık `options.all`'ı onurlandırır; dizi biçimi
  döndürür. Public fetch'in çalıştığı ayrıca doğrulandı (gerçek `example.com` → 200 ve
  uçtan uca tarama tekrar `header_tls=completed`).
- **Ders:** Negatif test tek başına yetmez; "engellendi" durumu, aracın bozulmasından mı
  yoksa guard'dan mı kaynaklandığını ayırt etmeli. Bu yüzden entegrasyon testi, undici'nin
  lookup'ı **gerçekten çağırdığını** da doğrular.

---

## Test kapsamı

- `net-guard.test.ts` — 20+ vektör: normalize, girdi doğrulama, IPv4/IPv6 sınıflandırma,
  `resolveAndGuard` (public/split-horizon/çözülemedi/geçersiz), guarded lookup (public/
  private/rebinding).
- `guard.integration.test.ts` — gerçek yerel HTTP sunucusu: loopback'e çözülen host'a
  bağlantının ulaşmadığı (iç servisin istek almadığı) ve undici'nin guarded lookup'ı
  kullandığı kanıtlanır.

## Kalan riskler

Public host'a yönlendirmeye izin verilir (pasif gözlem; hop sınırı var). TLS inceleme
ayrı bir bağlantı kurar ama o da guarded lookup kullanır. Ayrıntı: [`THREAT_MODEL.md`](THREAT_MODEL.md) §6.
