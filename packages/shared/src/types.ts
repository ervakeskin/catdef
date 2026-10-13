// CatDef ortak tipleri — API, worker ve web arasında paylaşılır.

export type Severity = "critical" | "high" | "medium" | "low";

export type Grade = "A" | "B" | "C" | "D" | "F";

export type ModuleType = "header_tls" | "leak" | "cve" | "dns";

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type ModuleStatus = "pending" | "running" | "completed" | "failed";

/**
 * Bir bulgunun endüstri standartlarıyla eşlemesi. İşe alımcıya ve geliştiriciye
 * "bu bulgu hangi kabul görmüş risk kategorisine denk geliyor" diye gösterir.
 */
export interface StandardRefs {
  /** OWASP Top 10 2025, ör. "A04:2025 Cryptographic Failures". */
  owaspTop10_2025: string;
  /** OWASP Top 10 2021 (işe alımcının tanıdığı sürüm), ör. "A02:2021 Cryptographic Failures". */
  owaspTop10_2021: string;
  /** CWE kimliği + başlığı, ör. "CWE-319: Cleartext Transmission of Sensitive Information". */
  cwe: string;
  /** OWASP ASVS 5.0 bölümü (uygunsa), ör. "ASVS 5.0 V12: Secure Communication". */
  asvs?: string;
}

/** Bir modülün ürettiği tekil bulgu (DB'ye yazılmadan önceki hali). */
export interface Finding {
  moduleType: ModuleType;
  /** Sabit kod — findings-catalog ile eşleşir, ör. "missing_hsts". */
  findingCode: string;
  severity: Severity;
  title: string;
  /** Teknik açıklama. */
  description: string;
  /** (i) ikonunda gösterilen jargonsuz açıklama. */
  plainExplanation: string;
  /** Neden önemli — somut risk senaryosu (TR). */
  whyItMatters?: string;
  /** Yanlış-pozitif / bağlam notu: bu bulgu ne zaman önemsiz olabilir (TR). */
  falsePositiveNote?: string;
  /** OWASP / CWE / ASVS eşlemesi. */
  standards?: StandardRefs;
  /** Bulgunun kanıtı (ör. eksik header adı, sertifika tarihi). */
  evidence?: string;
  /** Skorlama sırasında hesaplanır; modül üretirken 0 olabilir. */
  pointsDeducted: number;
}

/** Tek bir tarama modülünün (header_tls / dns ...) çıktısı. */
export interface ModuleResult {
  moduleType: ModuleType;
  status: ModuleStatus;
  findings: Finding[];
  /** Ham veri (JSONB) — header'lar, sertifika detayı, DNS kayıtları vb. */
  rawData: Record<string, unknown>;
  /** Skorlama sonrası hesaplanan modül puanı. */
  moduleScore?: number;
}

/** Tarama sonucu API yanıtı. */
export interface ScanResult {
  id: string;
  domain: string;
  status: ScanStatus;
  score: number | null;
  grade: Grade | null;
  modules: ModuleResult[];
  findings: Finding[];
  createdAt: string;
  completedAt: string | null;
}
