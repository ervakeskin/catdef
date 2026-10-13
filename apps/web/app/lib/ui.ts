import type { Grade, Severity } from "@catdef/shared";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001";

export function gradeColor(grade: Grade): string {
  return `var(--${grade.toLowerCase()})`;
}

export function severityColor(sev: Severity): string {
  const map: Record<Severity, string> = {
    critical: "var(--crit)",
    high: "var(--high)",
    medium: "var(--med)",
    low: "var(--low)",
  };
  return map[sev];
}

export function severityLabel(sev: Severity): string {
  const map: Record<Severity, string> = {
    critical: "Kritik",
    high: "Yüksek",
    medium: "Orta",
    low: "Düşük",
  };
  return map[sev];
}

/** Harf notuna göre maskotun ruh hali metni (farklılaştırıcı §7.6). */
export function moodFor(grade: Grade | null): string {
  switch (grade) {
    case "A":
      return "Harika! Siten çok güvenli 🎉";
    case "B":
      return "İyi görünüyor, ufak dokunuşlar kaldı 🙂";
    case "C":
      return "Fena değil ama iyileştirme şart 🤔";
    case "D":
      return "Dikkat! Önemli açıklar var 😟";
    case "F":
      return "Acil! Ciddi güvenlik sorunları var 😰";
    default:
      return "Taranıyor...";
  }
}

/** Severity sıralaması — kritik önce. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};
