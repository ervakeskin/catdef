"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { API_BASE } from "./lib/ui";

export default function HomePage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Bir hata oluştu.");
        setLoading(false);
        return;
      }
      router.push(`/report/${data.scanId}`);
    } catch {
      setError("API'ye ulaşılamadı. Sunucu çalışıyor mu?");
      setLoading(false);
    }
  }

  return (
    <main>
      <div className="hero">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/mascot.png" alt="CatDef maskotu" />
        <h1>CatDef</h1>
        <p>
          Sitenizi saniyeler içinde tarayın; HTTPS, güvenlik başlıkları ve DNS hijyeni için
          <strong> anlaşılır Türkçe</strong> bir güvenlik raporu ve harf notu alın.
        </p>
      </div>

      <form className="scan-form" onSubmit={onSubmit}>
        <input
          type="text"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          disabled={loading}
          autoComplete="off"
          aria-label="Alan adı"
        />
        <button type="submit" disabled={loading || domain.trim().length === 0}>
          {loading ? "Taranıyor…" : "Tara"}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      <p className="consent">
        Yalnızca sahibi olduğunuz veya test izniniz olan siteleri tarayın. Tüm taramalar pasif
        (dış gözlem) yapar ve kayıt altına alınır.
      </p>
    </main>
  );
}
