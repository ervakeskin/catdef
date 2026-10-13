import Link from "next/link";
import { notFound } from "next/navigation";
import type { ScanResult } from "@catdef/shared";
import { getRemediation } from "@catdef/shared";
import { API_BASE, gradeColor, moodFor, severityColor, severityLabel, SEVERITY_ORDER } from "../../lib/ui";
import Polling from "./Polling";
import Remediation from "./Remediation";

// Her istekte taze veri — tarama durumu değişebilir.
export const dynamic = "force-dynamic";

async function fetchScan(scanId: string): Promise<ScanResult | null> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`API hatası: ${res.status}`);
  return (await res.json()) as ScanResult;
}

export default async function ReportPage({ params }: { params: { scanId: string } }) {
  const scan = await fetchScan(params.scanId);
  if (!scan) notFound();

  if (scan.status === "pending" || scan.status === "running") {
    return <Polling domain={scan.domain} />;
  }

  if (scan.status === "failed") {
    return (
      <div className="empty">
        <h2>{scan.domain} taranamadı</h2>
        <p>Tarama sırasında bir sorun oluştu. Lütfen alan adını kontrol edip tekrar deneyin.</p>
        <Link className="back-link" href="/">← Yeni tarama</Link>
      </div>
    );
  }

  const findings = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );

  return (
    <main>
      <Link className="back-link" href="/">← Yeni tarama</Link>

      <div className="report-head">
        {scan.grade && (
          <div className="grade-badge" style={{ background: gradeColor(scan.grade) }}>
            {scan.grade}
          </div>
        )}
        <div className="meta">
          <h2>{scan.domain}</h2>
          <div className="score">Güvenlik skoru: {scan.score ?? "—"}/100</div>
        </div>
        <div className="mascot-mood">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/mascot.png" alt="CatDef" />
          <div>{moodFor(scan.grade)}</div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty">
          <p>🎉 Kritik bir bulgu yok. Temel güvenlik kontrollerini geçtin!</p>
        </div>
      ) : (
        <div className="findings">
          {findings.map((f, i) => (
            <div
              key={`${f.findingCode}-${i}`}
              className="finding"
              style={{ borderLeftColor: severityColor(f.severity) }}
            >
              <div className="title-row">
                <span className="sev-tag" style={{ background: severityColor(f.severity) }}>
                  {severityLabel(f.severity)}
                </span>
                <h3>{f.title}</h3>
                {f.pointsDeducted > 0 && (
                  <span className="points" title="Bu bulgunun skora etkisi">
                    −{f.pointsDeducted} puan
                  </span>
                )}
              </div>
              {f.description && <p className="desc">{f.description}</p>}
              {f.evidence && <div className="evidence">Kanıt: {f.evidence}</div>}
              {f.standards && (
                <div className="standards">
                  <span className="std-chip owasp">{f.standards.owaspTop10_2025}</span>
                  <span className="std-chip owasp-old">{f.standards.owaspTop10_2021}</span>
                  <span className="std-chip cwe">{f.standards.cwe}</span>
                  {f.standards.asvs && <span className="std-chip asvs">{f.standards.asvs}</span>}
                </div>
              )}
              {f.whyItMatters && (
                <details className="plain why">
                  <summary>Neden önemli?</summary>
                  <div>{f.whyItMatters}</div>
                </details>
              )}
              {f.plainExplanation && (
                <details className="plain">
                  <summary>ⓘ Bu ne demek?</summary>
                  <div>{f.plainExplanation}</div>
                </details>
              )}
              {(() => {
                const guide = getRemediation(f.findingCode);
                return guide ? <Remediation guide={guide} domain={scan.domain} /> : null;
              })()}
              {f.falsePositiveNote && (
                <details className="plain fp">
                  <summary>Yanlış pozitif olabilir mi?</summary>
                  <div>{f.falsePositiveNote}</div>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
