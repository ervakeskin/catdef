-- CatDef Faz 0 şeması. proje_plani.md §5'ten yalnızca MVP için gerekli 5 tablo.
-- users/sites/rozet/remediation tabloları Faz 1+'e bırakıldı; scans.requested_by
-- ve site_id ileride eklenecek FK'ler için şimdilik nullable/ayrılmış tutulur.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Her tarama isteği
CREATE TABLE IF NOT EXISTS scans (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain        TEXT NOT NULL,
  requester_ip  INET NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending',   -- pending|running|completed|failed
  score         INTEGER,
  grade         TEXT,
  error         TEXT,
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_ip_created ON scans(requester_ip, created_at);

-- Her modülün ayrı sonucu
CREATE TABLE IF NOT EXISTS scan_modules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_type   TEXT NOT NULL,   -- 'header_tls' | 'leak' | 'cve' | 'dns'
  status        TEXT NOT NULL DEFAULT 'pending',
  module_score  INTEGER,
  raw_data      JSONB,
  completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_modules_scan ON scan_modules(scan_id);

-- Tespit edilen her bulgu
CREATE TABLE IF NOT EXISTS findings (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_type       TEXT NOT NULL,
  finding_code      TEXT NOT NULL,   -- ör. 'missing_hsts','tls_cert_expired'
  severity          TEXT NOT NULL,   -- critical|high|medium|low
  title             TEXT NOT NULL,
  description       TEXT,
  plain_explanation TEXT,            -- (i) ikonu için sade açıklama
  evidence          TEXT,
  points_deducted   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

-- 24 saatlik cache lookup
CREATE TABLE IF NOT EXISTS domain_cache (
  domain          TEXT PRIMARY KEY,
  latest_scan_id  UUID REFERENCES scans(id) ON DELETE SET NULL,
  last_scanned_at TIMESTAMPTZ NOT NULL
);

-- Yasal koruma + rate limit için tam log
CREATE TABLE IF NOT EXISTS audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain      TEXT,
  ip          INET NOT NULL,
  action      TEXT NOT NULL,   -- 'scan_requested'|'scan_blocked'|'rate_limited'|'cache_hit'
  detail      TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_ip_action_created ON audit_log(ip, action, created_at);
