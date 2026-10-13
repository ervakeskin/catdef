import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "CatDef — Site Güvenlik Tarayıcısı",
  description: "Sitenizi saniyeler içinde tarayın, anlaşılır Türkçe bir güvenlik raporu alın.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="tr">
      <body>
        <div className="container">{children}</div>
      </body>
    </html>
  );
}
