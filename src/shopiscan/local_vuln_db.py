"""
local_vuln_db.py
------------------
Base de datos local e incremental de "inteligencia de vulnerabilidades"
construida a partir de los propios escaneos de ShopiScan.

No existe un WPVulnDB equivalente público para Shopify (no hay un catálogo
centralizado de "tema X versión Y tiene la vulnerabilidad Z", y no es una
limitación de esta herramienta sino del ecosistema). En vez de inventar
datos que no tenemos, ShopiScan construye su propia base de datos LOCAL a
partir de patrones reales observados en cada escaneo:

  - Qué temas aparecen con más frecuencia y cuál es su score medio de
    riesgo (una señal estadística local, no una vulnerabilidad confirmada
    del tema en sí).
  - Qué scripts "sin identificar" (apps_generic) se repiten en varias
    tiendas distintas: si un dominio aparece en 3+ tiendas y no está en
    el catálogo de apps conocidas, es una señal útil para ampliar
    APP_FINGERPRINTS / SHADOW_APP_SIGNATURES más adelante.
  - Qué hallazgos (findings) son más frecuentes en general.

Cuantos más escaneos se acumulan, más útil se vuelve: es una base de datos
que crece con el uso, en vez de una lista estática que se queda obsoleta.

Todo se guarda en SQLite en ~/.shopiscan/local_vuln_db.sqlite3. Es 100%
local: no se sube a ningún sitio ni sale de la máquina del usuario.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from . import utils

DB_PATH = Path.home() / ".shopiscan" / "local_vuln_db.sqlite3"

# A partir de cuántas tiendas DISTINTAS un script "sin identificar" debe
# verse para considerarlo un patrón recurrente digno de mención.
RECURRING_SCRIPT_THRESHOLD = 3

# A partir de qué score medio (0-100) un tema se marca como "con
# historial de riesgo elevado" en la base de datos local.
HIGH_RISK_THEME_SCORE_THRESHOLD = 40

# Mínimo de observaciones antes de que el promedio de un tema sea fiable.
MIN_THEME_OBSERVATIONS = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS theme_stats (
    theme_name TEXT PRIMARY KEY,
    times_seen INTEGER NOT NULL DEFAULT 0,
    total_score INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT,
    last_label TEXT
);
CREATE TABLE IF NOT EXISTS script_stats (
    domain TEXT PRIMARY KEY,
    times_seen INTEGER NOT NULL DEFAULT 0,
    stores_seen TEXT NOT NULL DEFAULT '',
    first_seen TEXT,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS finding_stats (
    title TEXT PRIMARY KEY,
    severity TEXT,
    times_seen INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT
);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(_SCHEMA)
    return conn


def record_scan(result_dict: dict) -> None:
    """Registra los datos relevantes de un escaneo en la base de datos local.

    Se llama tras cada escaneo completado sobre una tienda Shopify. Nunca
    debe interrumpir el flujo principal: cualquier error de E/S local se
    convierte en un aviso, no en una excepción que tumbe el escaneo.
    """
    try:
        _record_scan_unsafe(result_dict)
    except Exception as exc:  # noqa: BLE001 - la persistencia local no debe romper el escaneo
        utils.warning(f"No se pudo actualizar la base de datos local de vulnerabilidades: {exc}")


def _record_scan_unsafe(result_dict: dict) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    url = result_dict.get("url", "")
    store_domain = url.split("//")[-1].split("/")[0]

    theme = result_dict.get("theme", {}) or {}
    theme_name = theme.get("name") or "Desconocido"
    score = (result_dict.get("risk") or {}).get("score", 0)
    label = (result_dict.get("risk") or {}).get("label", "BAJO")

    with closing(_connect()) as conn:
        if theme_name != "Desconocido":
            conn.execute(
                """
                INSERT INTO theme_stats (theme_name, times_seen, total_score, last_seen, last_label)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(theme_name) DO UPDATE SET
                    times_seen = times_seen + 1,
                    total_score = total_score + excluded.total_score,
                    last_seen = excluded.last_seen,
                    last_label = excluded.last_label
                """,
                (theme_name, score, now, label),
            )

        for domain in result_dict.get("apps_generic", []) or []:
            row = conn.execute(
                "SELECT stores_seen FROM script_stats WHERE domain = ?", (domain,)
            ).fetchone()
            stores_seen = set(row[0].split(",")) if row and row[0] else set()
            stores_seen.add(store_domain)
            stores_seen_str = ",".join(sorted(s for s in stores_seen if s))
            conn.execute(
                """
                INSERT INTO script_stats (domain, times_seen, stores_seen, first_seen, last_seen)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    times_seen = times_seen + 1,
                    stores_seen = excluded.stores_seen,
                    last_seen = excluded.last_seen
                """,
                (domain, stores_seen_str, now, now),
            )

        for finding in result_dict.get("findings", []) or []:
            title = finding.get("title")
            if not title:
                continue
            severity = finding.get("level", "Info")
            conn.execute(
                """
                INSERT INTO finding_stats (title, severity, times_seen, last_seen)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(title) DO UPDATE SET
                    times_seen = times_seen + 1,
                    last_seen = excluded.last_seen
                """,
                (title, severity, now),
            )

        conn.commit()


def enrich_findings(result_dict: dict) -> list[dict]:
    """Genera hallazgos adicionales de tipo 'inteligencia acumulada local'
    (mismo formato que build_findings(), listos para mezclar con los del
    escaneo actual):

    - Si el tema actual tiene un historial local de score medio elevado.
    - Si alguno de los scripts 'sin identificar' de este escaneo es un
      patrón recurrente visto en varias tiendas distintas (candidato a
      añadirse al catálogo de apps conocidas).

    Se ejecuta DESPUÉS de record_scan() para el escaneo actual, así que el
    escaneo en curso ya cuenta en las estadísticas consultadas.
    """
    extra: list[dict] = []
    try:
        extra.extend(_enrich_theme(result_dict))
        extra.extend(_enrich_scripts(result_dict))
    except Exception as exc:  # noqa: BLE001
        utils.warning(f"No se pudo consultar la base de datos local de vulnerabilidades: {exc}")
    return extra


def _enrich_theme(result_dict: dict) -> list[dict]:
    theme = result_dict.get("theme", {}) or {}
    theme_name = theme.get("name") or "Desconocido"
    if theme_name == "Desconocido":
        return []

    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT times_seen, total_score FROM theme_stats WHERE theme_name = ?",
            (theme_name,),
        ).fetchone()

    if not row or row[0] < MIN_THEME_OBSERVATIONS:
        return []

    times_seen, total_score = row
    avg_score = total_score / times_seen
    if avg_score < HIGH_RISK_THEME_SCORE_THRESHOLD:
        return []

    return [
        {
            "level": "Media",
            "title": f"Tema '{theme_name}' con historial local de riesgo elevado",
            "detail": (
                f"Este tema se ha visto en {times_seen} escaneo(s) previos de ShopiScan "
                f"(en distintas tiendas), con un score medio de {avg_score:.0f}/100. "
                "Esto NO es una vulnerabilidad confirmada del tema en sí (podría deberse "
                "a configuración de cada tienda), pero sí una señal estadística local: "
                "vale la pena revisar con más detalle la configuración de seguridad de "
                "las tiendas que usan este tema."
            ),
        }
    ]


def _enrich_scripts(result_dict: dict) -> list[dict]:
    findings = []
    apps_generic = result_dict.get("apps_generic", []) or []
    if not apps_generic:
        return findings

    with closing(_connect()) as conn:
        for domain in apps_generic:
            row = conn.execute(
                "SELECT stores_seen FROM script_stats WHERE domain = ?", (domain,)
            ).fetchone()
            if not row or not row[0]:
                continue
            stores = [s for s in row[0].split(",") if s]
            if len(stores) >= RECURRING_SCRIPT_THRESHOLD:
                findings.append(
                    {
                        "level": "Info",
                        "title": f"Script recurrente sin clasificar: {domain}",
                        "detail": (
                            f"Este dominio se ha visto en {len(stores)} tiendas distintas "
                            "escaneadas con ShopiScan y sigue sin estar en el catálogo de "
                            "apps/servicios conocidos. Buen candidato para investigar "
                            "manualmente y, si corresponde, añadirlo a APP_FINGERPRINTS "
                            "en core.py."
                        ),
                    }
                )
    return findings


def get_stats_summary() -> dict:
    """Devuelve un resumen legible del estado actual de la base de datos local."""
    with closing(_connect()) as conn:
        theme_count = conn.execute("SELECT COUNT(*) FROM theme_stats").fetchone()[0]
        script_count = conn.execute("SELECT COUNT(*) FROM script_stats").fetchone()[0]
        finding_count = conn.execute("SELECT COUNT(*) FROM finding_stats").fetchone()[0]

        top_themes = conn.execute(
            """
            SELECT theme_name, times_seen, total_score * 1.0 / times_seen AS avg_score
            FROM theme_stats WHERE times_seen >= ? ORDER BY avg_score DESC LIMIT 5
            """,
            (MIN_THEME_OBSERVATIONS,),
        ).fetchall()

        top_findings = conn.execute(
            "SELECT title, severity, times_seen FROM finding_stats ORDER BY times_seen DESC LIMIT 10"
        ).fetchall()

        recurring_scripts = conn.execute(
            "SELECT domain, times_seen, stores_seen FROM script_stats ORDER BY times_seen DESC LIMIT 10"
        ).fetchall()

    return {
        "db_path": str(DB_PATH),
        "themes_tracked": theme_count,
        "scripts_tracked": script_count,
        "findings_tracked": finding_count,
        "top_risk_themes": [
            {"theme": t, "times_seen": n, "avg_score": round(s, 1)} for t, n, s in top_themes
        ],
        "top_findings": [{"title": t, "severity": s, "times_seen": n} for t, s, n in top_findings],
        "recurring_scripts": [
            {"domain": d, "times_seen": n, "distinct_stores": len(s.split(",")) if s else 0}
            for d, n, s in recurring_scripts
        ],
    }


def print_stats_summary() -> None:
    from colorama import Fore, Style

    stats = get_stats_summary()
    utils.section("Base de datos local de vulnerabilidades (incremental)")
    print(f"Ubicación: {stats['db_path']}")
    print(f"Temas rastreados: {stats['themes_tracked']}")
    print(f"Scripts rastreados: {stats['scripts_tracked']}")
    print(f"Tipos de hallazgo rastreados: {stats['findings_tracked']}")

    if stats["top_risk_themes"]:
        print(f"\n{Fore.CYAN}Temas con mayor score medio (mín. {MIN_THEME_OBSERVATIONS} escaneos):{Style.RESET_ALL}")
        for t in stats["top_risk_themes"]:
            print(f"  - {t['theme']}: {t['avg_score']}/100 (visto {t['times_seen']}x)")

    if stats["top_findings"]:
        print(f"\n{Fore.CYAN}Hallazgos más frecuentes:{Style.RESET_ALL}")
        for f in stats["top_findings"]:
            print(f"  - [{f['severity']}] {f['title']} ({f['times_seen']}x)")

    if stats["recurring_scripts"]:
        print(f"\n{Fore.CYAN}Scripts recurrentes sin clasificar:{Style.RESET_ALL}")
        for s in stats["recurring_scripts"]:
            print(f"  - {s['domain']}: visto en {s['distinct_stores']} tienda(s) distinta(s) ({s['times_seen']} veces)")
