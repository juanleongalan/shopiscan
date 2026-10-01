"""
vector_db.py
--------------
Persistencia en PostgreSQL + pgvector para búsqueda semántica (vectorial)
de hallazgos entre escaneos.

Complementa a `local_vuln_db.py` (que usa SQLite y estadísticas exactas
por dominio/tema): aquí guardamos, por cada hallazgo de cada escaneo, un
**embedding** generado por Ollama (`nomic-embed-text`) en una columna
`vector` de pgvector. Eso permite, ante un hallazgo nuevo, recuperar los
hallazgos históricos SEMÁNTICAMENTE más parecidos (aunque el texto no sea
idéntico) y dárselos al LLM como contexto adicional (RAG-lite), o
simplemente detectar patrones recurrentes entre tiendas.

Todo es opcional y degrada con elegancia:
  - Si no hay `DATABASE_URL` configurada, o `psycopg`/`pgvector` no están
    instalados, o la base de datos no responde, estas funciones no hacen
    nada (o devuelven listas vacías) y el escaneo continúa igual.
  - La generación de embeddings depende de Ollama (ver ai_analyzer.get_embedding);
    si Ollama no está disponible, tampoco se indexan/consultan vectores.

Está pensado para el stack de docker-compose (Postgres con la imagen
`pgvector/pgvector`), pero funciona con cualquier PostgreSQL que tenga la
extensión `vector` instalable.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

from . import utils
from . import ai_analyzer

DATABASE_URL_ENV_VAR = "DATABASE_URL"
# Dimensión del modelo de embeddings por defecto (nomic-embed-text = 768).
EMBED_DIM = int(os.environ.get("EMBED_DIM", "768"))
DEFAULT_SIMILARITY_LIMIT = 5
# Distancia coseno máxima para considerar dos hallazgos "similares"
# (0 = idénticos, 2 = opuestos). 0.35 es un umbral conservador.
MAX_COSINE_DISTANCE = 0.35


def _get_database_url() -> Optional[str]:
    return os.environ.get(DATABASE_URL_ENV_VAR)


# Cachea si psycopg/pgvector están disponibles, para no reintentar el
# import ni repetir el aviso en cada llamada a _connect() (antes se
# llamaba una vez por cada hallazgo al buscar similares, mostrando el
# mismo aviso "PostgreSQL/pgvector no disponibles" hasta 8 veces por
# escaneo).
_deps_available: Optional[bool] = None


def _connect():
    """Abre una conexión a PostgreSQL y registra el tipo vector de pgvector.
    Devuelve None (con aviso, solo la primera vez) si algo no está
    disponible, para degradar."""
    global _deps_available

    dsn = _get_database_url()
    if not dsn:
        return None

    if _deps_available is None:
        try:
            import psycopg  # noqa: F401
            from pgvector.psycopg import register_vector  # noqa: F401

            _deps_available = True
        except ImportError:
            _deps_available = False
            utils.warning(
                "PostgreSQL/pgvector no disponibles ('pip install psycopg[binary] pgvector'). "
                "Se omite la búsqueda vectorial; el resto del escaneo sigue igual."
            )

    if not _deps_available:
        return None

    import psycopg
    from pgvector.psycopg import register_vector

    try:
        conn = psycopg.connect(dsn, connect_timeout=5)
        register_vector(conn)
        return conn
    except Exception as exc:  # noqa: BLE001
        utils.warning(f"No se pudo conectar a PostgreSQL ({DATABASE_URL_ENV_VAR}): {exc}")
        return None


def is_available() -> bool:
    """True si hay DATABASE_URL y se puede conectar (útil para tests/diagnóstico)."""
    conn = _connect()
    if conn is None:
        return False
    conn.close()
    return True


def ensure_schema() -> bool:
    """Crea la extensión vector y la tabla de hallazgos si no existen.
    Idempotente. Devuelve True si el esquema quedó listo."""
    conn = _connect()
    if conn is None:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS finding_embeddings (
                    id BIGSERIAL PRIMARY KEY,
                    store_domain TEXT NOT NULL,
                    scan_url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT,
                    detail TEXT,
                    embedding vector({EMBED_DIM}),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            # Auto-repara instalaciones existentes creadas antes de añadir la
            # columna owasp_category (init.sql solo se ejecuta al crear el
            # volumen de Postgres por primera vez, así que esto es necesario
            # para no obligar a borrar datos ya indexados).
            cur.execute("ALTER TABLE finding_embeddings ADD COLUMN IF NOT EXISTS owasp_category TEXT;")
            cur.execute("ALTER TABLE finding_embeddings ADD COLUMN IF NOT EXISTS remediation TEXT;")
            # Índice IVFFlat para búsqueda aproximada por distancia coseno.
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS finding_embeddings_embedding_idx
                ON finding_embeddings USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
                """
            )
        conn.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        utils.warning(f"No se pudo preparar el esquema de pgvector: {exc}")
        return False
    finally:
        conn.close()


def _finding_text(finding: dict) -> str:
    """Texto canónico de un hallazgo para generar su embedding."""
    return f"{finding.get('title', '')}. {finding.get('detail', '')}".strip()


def index_findings(scan_url: str, findings: List[dict]) -> tuple[int, Optional[str]]:
    """Genera embeddings (vía Ollama) e inserta los hallazgos del escaneo
    actual en pgvector. Devuelve (cuántos se indexaron, motivo del fallo
    o None si todo fue bien / no había nada que indexar). Nunca lanza:
    degrada con avisos.
    """
    if not findings:
        return 0, None
    conn = _connect()
    if conn is None:
        return 0, "No hay conexión a PostgreSQL (revisa DATABASE_URL y que psycopg/pgvector estén instalados)."

    store_domain = scan_url.split("//")[-1].split("/")[0]
    inserted = 0
    error_reason: Optional[str] = None
    try:
        with conn.cursor() as cur:
            for finding in findings:
                text = _finding_text(finding)
                if not text:
                    continue
                embedding, embed_error = ai_analyzer.get_embedding_verbose(text)
                if embedding is None:
                    # Ollama no disponible: abortamos la indexación entera
                    # (no tiene sentido insertar unos sí y otros no).
                    error_reason = embed_error or "No se pudieron generar embeddings."
                    utils.warning(f"Se omite la indexación vectorial: {error_reason}")
                    break
                cur.execute(
                    """
                    INSERT INTO finding_embeddings
                        (store_domain, scan_url, title, severity, owasp_category, detail, remediation, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector)
                    """,
                    (
                        store_domain,
                        scan_url,
                        finding.get("title", ""),
                        finding.get("level") or finding.get("severity"),
                        finding.get("owasp_category"),
                        finding.get("detail", ""),
                        finding.get("remediation"),
                        embedding,
                    ),
                )
                inserted += 1
        conn.commit()
        if inserted:
            utils.success(f"Indexados {inserted} hallazgo(s) en pgvector para búsqueda semántica.")
    except Exception as exc:  # noqa: BLE001
        error_reason = str(exc)
        utils.warning(f"Error indexando hallazgos en pgvector: {exc}")
    finally:
        conn.close()
    return inserted, error_reason


def find_similar_findings(
    finding: dict,
    limit: int = DEFAULT_SIMILARITY_LIMIT,
    exclude_url: Optional[str] = None,
) -> List[dict]:
    """Devuelve los hallazgos históricos semánticamente más parecidos al
    dado, usando distancia coseno en pgvector. Lista vacía si no hay
    infraestructura o no hay coincidencias por debajo del umbral.
    """
    conn = _connect()
    if conn is None:
        return []

    text = _finding_text(finding)
    embedding = ai_analyzer.get_embedding(text)
    if embedding is None:
        conn.close()
        return []

    results = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT title, severity, detail, scan_url,
                       embedding <=> %s::vector AS distance
                FROM finding_embeddings
                WHERE (%s::text IS NULL OR scan_url <> %s::text)
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (embedding, exclude_url, exclude_url, embedding, limit),
            )
            for title, severity, detail, scan_url, distance in cur.fetchall():
                if distance is None or distance > MAX_COSINE_DISTANCE:
                    continue
                results.append(
                    {
                        "title": title,
                        "severity": severity,
                        "detail": detail,
                        "scan_url": scan_url,
                        "similarity": round(1 - distance, 3),
                    }
                )
    except Exception as exc:  # noqa: BLE001
        utils.warning(f"Error consultando hallazgos similares en pgvector: {exc}")
    finally:
        conn.close()
    return results


def find_similar_for_scan(result_dict: dict, per_finding_limit: int = 3) -> List[dict]:
    """Recupera hallazgos similares para el conjunto de hallazgos de un
    escaneo (deduplicados por título), pensado para pasárselos al LLM como
    contexto RAG. Lista vacía si no hay infraestructura disponible.
    """
    if not _get_database_url():
        return []

    scan_url = result_dict.get("url", "")
    seen_titles = set()
    aggregated: List[dict] = []
    for finding in result_dict.get("findings", []) or []:
        similar = find_similar_findings(finding, limit=per_finding_limit, exclude_url=scan_url)
        for s in similar:
            key = s["title"]
            if key not in seen_titles:
                seen_titles.add(key)
                aggregated.append(s)
    return aggregated
