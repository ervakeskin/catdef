# CatDef — Türkiye Ölçüm Çalışması (Metodoloji)

> **Durum: tasarım + betik hazır. Taramayı proje sahibi çalıştırır.** Bu belge
> yöntemi, etik sınırları ve betiğin ne ürettiğini tanımlar. Betik:
> `apps/worker/src/measure.ts` (çalıştırma: `pnpm measure <domains.txt>`).

## Amaç

Türkiye'de yaygın web sitelerinin temel güvenlik hijyenini **toplu ve anonim**
olarak ölçmek: "sitelerin yüzde kaçında HSTS yok?", "yüzde kaçında SPF/DMARC
eksik?" gibi. Çıktı, tek tek siteleri **teşhir etmek** için değil, genel tabloyu
göstermek içindir.

## Temel ilke: anonimlik

- Betik çıktısında (JSON ve konsol özeti) **tek bir site adı dahi bulunmaz.**
- Yalnızca **toplu sayımlar ve oranlar** tutulur: not dağılımı (A–F), bulgu başına
  "% taranan", modül hata oranları.
- İlerleme göstergesi bile site adı değil, yalnızca sayaç gösterir.
- Alan adı listesini **kullanıcı sağlar**; betik hiçbir liste gömmez ve
  `domains*.txt` ile `measurement-results/` `.gitignore`'dadır.

## Etik ve yasal sınırlar

- **Pasiflik:** her hedefe yalnızca kök sayfaya tek bir `GET` ve DNS sorguları
  yapılır. Zafiyet sömürülmez, form/endpoint denenmez, yük bindirilmez.
- **Hız (politeness):** istekler arasında varsayılan **1 sn gecikme** vardır
  (`--delay`). Eşzamanlılık yoktur (sıralı tarama).
- **SSRF guard** her hedefte çalışır; iç/özel/çözülemeyen adresler taranmadan atlanır.
- **ToS/robots:** yalnızca herkese açık, taranmasına makul şekilde açık siteler
  ölçülmelidir; hedeflerin kullanım koşullarına uyun. Şüpheli durumda listeden çıkarın.
- **Kapsam:** yalnızca Faz 0 kontrollerini (Header/TLS + DNS) ölçer; uygulama
  katmanına dokunmaz.

## Yöntem

1. Kullanıcı satır başına bir alan adı içeren bir dosya hazırlar (ör. kamuya açık
   bir "en çok ziyaret edilen TR siteleri" listesi). `#` ile başlayan satırlar ve
   boş satırlar atlanır; adresler normalize edilir ve tekilleştirilir.
2. Her alan adı için: SSRF guard → geçerse Header/TLS ve DNS modülleri çalışır →
   mevcut skorlama ile not hesaplanır.
3. Bulgu kodları ve not **yalnızca sayaçlara** eklenir; site bazlı hiçbir kayıt
   diske yazılmaz.
4. Sonuç: `measurement-results/summary-<zaman>.json` (anonim) + konsolda özet.

## Çalıştırma

```bash
# 1) dev:local çalışmasına gerek yok; betik modülleri doğrudan kullanır.
# 2) Kendi listenizi verin:
pnpm measure domains.txt --delay=1000 --limit=500
```

Çıktı örneği (şema):

```json
{
  "generatedAt": "...",
  "note": "Toplu ve anonim — tek tek site adı içermez.",
  "totalInput": 500, "scanned": 480, "skipped": 20,
  "gradeDistributionPercent": { "A": 4.2, "B": 11.0, "C": 18.5, "D": 27.1, "F": 39.2 },
  "findingRates": { "missing_hsts": { "count": 300, "percentOfScanned": 62.5 } },
  "moduleFailures": { "header_tls": 12 }
}
```

## Sınırlılıklar

- Başlıkların yalnızca **varlığı** ölçülür (kalitesi değil) — bkz. `SCORING.md`.
- Tek gözlem anıdır; CDN/coğrafi varyasyon sonucu etkileyebilir.
- Örneklem, sağlanan listeye bağlıdır; "Türkiye geneli" temsil iddiası, listenin
  temsil gücüyle sınırlıdır. Raporlarken listenin kaynağını ve tarihini belirtin.
