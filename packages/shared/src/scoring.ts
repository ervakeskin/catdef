import type { Grade, ModuleResult, ModuleType, Severity } from "./types.js";

/**
 * Kategori ağırlıkları (proje_plani.md §3). Toplam 100.
 * Faz 0'da yalnızca header_tls ve dns modülleri çalışır; skor,
 * fiilen çalışan modüllerin ağırlıklarına göre normalize edilir
 * (bkz. computeTotalScore) — böylece 2 modülle de adil bir 0-100 üretir.
 */
export const CATEGORY_WEIGHTS: Record<ModuleType, number> = {
  header_tls: 30,
  leak: 30,
  cve: 25,
  dns: 15,
};

/**
 * Severity → kategori puanından düşülecek oran.
 * Tasarım kuralı: tek bir kritik bulgu kategoriyi %60-100 düşürebilmeli,
 * böylece çok sayıda düşük risk tek bir kritik açığı gölgelemez.
 */
export const SEVERITY_FRACTION: Record<Severity, number> = {
  critical: 0.8,
  high: 0.35,
  medium: 0.18,
  low: 0.08,
};

/** Harf notu eşikleri: 90-100 A, 75-89 B, 60-74 C, 40-59 D, <40 F. */
export function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/** Bir bulgu için, ait olduğu kategori ağırlığına göre puan kesintisi. */
export function deductionFor(moduleType: ModuleType, severity: Severity): number {
  const weight = CATEGORY_WEIGHTS[moduleType];
  return Math.round(weight * SEVERITY_FRACTION[severity]);
}

/**
 * Bir modülün puanını hesaplar ve her bulgunun pointsDeducted alanını doldurur.
 * Kategori puanı 0'ın altına inmez. Girdiyi mutasyona uğratmadan yeni obje döner.
 */
export function computeModuleScore(module: ModuleResult): ModuleResult {
  const weight = CATEGORY_WEIGHTS[module.moduleType];
  let totalDeduction = 0;

  const findings = module.findings.map((f) => {
    const pointsDeducted = deductionFor(module.moduleType, f.severity);
    totalDeduction += pointsDeducted;
    return { ...f, pointsDeducted };
  });

  const moduleScore = Math.max(0, weight - totalDeduction);
  return { ...module, findings, moduleScore };
}

/**
 * Çalışan (completed) modüllerin puanlarını, ağırlıklarına göre 0-100'e
 * normalize eder. Hiç modül çalışmadıysa null döner.
 */
export function computeTotalScore(modules: ModuleResult[]): {
  score: number | null;
  grade: Grade | null;
} {
  const completed = modules.filter((m) => m.status === "completed");
  if (completed.length === 0) return { score: null, grade: null };

  let earned = 0;
  let possible = 0;
  for (const m of completed) {
    possible += CATEGORY_WEIGHTS[m.moduleType];
    earned += m.moduleScore ?? CATEGORY_WEIGHTS[m.moduleType];
  }
  if (possible === 0) return { score: null, grade: null };

  const score = Math.round((earned / possible) * 100);
  return { score, grade: scoreToGrade(score) };
}
