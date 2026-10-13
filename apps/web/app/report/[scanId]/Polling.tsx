"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Tarama pending/running iken çalışır: birkaç saniyede bir sunucu bileşenini
 * tazeleyerek (router.refresh) tamamlanınca SSR raporun görünmesini sağlar.
 */
export default function Polling({ domain }: { domain: string }) {
  const router = useRouter();

  useEffect(() => {
    const t = setInterval(() => router.refresh(), 2500);
    return () => clearInterval(t);
  }, [router]);

  return (
    <div className="empty">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/mascot.png" alt="CatDef" width={96} height={96} />
      <h2>{domain} taranıyor…</h2>
      <p>Bu birkaç saniye sürebilir. Sayfa otomatik güncellenecek.</p>
    </div>
  );
}
