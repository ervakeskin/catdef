"use client";

import { useState } from "react";
import type { RemediationGuide, RemediationPlatform } from "@catdef/shared";
import { PLATFORM_LABELS } from "@catdef/shared";

// Sekmelerde gösterim sırası.
const ORDER: RemediationPlatform[] = [
  "nginx",
  "apache",
  "express",
  "nextjs",
  "vercel",
  "cloudflare",
  "dns",
];

function fill(text: string, domain: string): string {
  return text.replaceAll("{{domain}}", domain);
}

export default function Remediation({
  guide,
  domain,
}: {
  guide: RemediationGuide;
  domain: string;
}) {
  const platforms = ORDER.filter((p) => guide.configs[p] != null);
  const [active, setActive] = useState<RemediationPlatform>(platforms[0]!);
  const config = guide.configs[active];

  return (
    <details className="plain remediation">
      <summary>🛠️ Nasıl düzeltirim?</summary>
      <div className="rem-body">
        {platforms.length > 1 && (
          <div className="rem-tabs" role="tablist">
            {platforms.map((p) => (
              <button
                key={p}
                type="button"
                role="tab"
                aria-selected={p === active}
                className={p === active ? "rem-tab active" : "rem-tab"}
                onClick={() => setActive(p)}
              >
                {PLATFORM_LABELS[p]}
              </button>
            ))}
          </div>
        )}

        {config && <pre className="rem-code">{fill(config, domain)}</pre>}

        <div className="rem-verify">
          <span className="rem-verify-label">Düzeldi mi? (doğrula)</span>
          <pre className="rem-code verify">{fill(guide.verify, domain)}</pre>
        </div>

        {guide.note && <p className="rem-note">Not: {guide.note}</p>}
      </div>
    </details>
  );
}
