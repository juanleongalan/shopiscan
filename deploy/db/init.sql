-- Esquema de PostgreSQL + pgvector para ShopiScan.
-- Se ejecuta automáticamente la primera vez que arranca el contenedor de
-- Postgres (docker-entrypoint-initdb.d). Idempotente.

CREATE EXTENSION IF NOT EXISTS vector;

-- ---------------------------------------------------------------------------
-- Tabla usada por vector_db.py (búsqueda semántica de hallazgos similares).
-- Es la mínima imprescindible para que la CLI funcione con --ai + DATABASE_URL.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_embeddings (
    id             BIGSERIAL PRIMARY KEY,
    store_domain   TEXT NOT NULL,
    scan_url       TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT,
    owasp_category TEXT,
    detail         TEXT,
    remediation    TEXT,
    embedding      vector(768),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Si la tabla ya existía de una versión anterior de ShopiScan sin esta
-- columna, la añade sin perder los datos ya indexados.
ALTER TABLE finding_embeddings ADD COLUMN IF NOT EXISTS owasp_category TEXT;
ALTER TABLE finding_embeddings ADD COLUMN IF NOT EXISTS remediation TEXT;

CREATE INDEX IF NOT EXISTS finding_embeddings_embedding_idx
    ON finding_embeddings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

CREATE INDEX IF NOT EXISTS finding_embeddings_store_idx
    ON finding_embeddings(store_domain);

-- ---------------------------------------------------------------------------
-- Esquema relacional más rico (opcional), útil para el modo servidor y para
-- consultas/dashboards en Grafana vía el datasource Postgres. Modela el
-- histórico completo: objetivos -> escaneos -> hallazgos -> recomendaciones.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS targets (
    id          SERIAL PRIMARY KEY,
    url         TEXT NOT NULL UNIQUE,
    label       TEXT,
    authorized  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id          SERIAL PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    risk_score  INTEGER,
    risk_label  TEXT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'running'  -- running | completed | failed
);

CREATE TABLE IF NOT EXISTS findings (
    id           SERIAL PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category     TEXT NOT NULL,      -- headers | ssl | tech | exposed_paths | shadow_apps | secrets
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    severity     TEXT NOT NULL,      -- info | low | medium | high | critical
    evidence     JSONB,
    embedding    vector(768),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS recommendations (
    id             SERIAL PRIMARY KEY,
    finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    recommendation TEXT NOT NULL,
    generated_by   TEXT NOT NULL DEFAULT 'ollama',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS findings_embedding_idx
    ON findings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
CREATE INDEX IF NOT EXISTS scans_target_idx ON scans(target_id);
