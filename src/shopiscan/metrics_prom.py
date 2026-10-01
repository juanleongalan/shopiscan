"""
metrics_prom.py
-----------------
Métricas Prometheus para el MODO SERVIDOR (server.py), usando la librería
oficial `prometheus_client` y su registro por defecto, expuesto en el
endpoint `/metrics` (que Prometheus scrapea directamente del proceso).

**Importante:** los nombres y etiquetas de las métricas aquí son
EXACTAMENTE los mismos que usa `metrics.py` (el camino CLI +
Pushgateway), a propósito: el dashboard de Grafana incluido en
`deploy/grafana/dashboards/shopiscan.json` consulta esos nombres
concretos (`shopiscan_risk_score`, `shopiscan_findings_total`,
`shopiscan_owasp_findings_total`, `shopiscan_scan_duration_seconds`,
`shopiscan_scan_timestamp_seconds`...). Si escaneas desde la interfaz web
o la API del servidor, quieres ver esos datos en el MISMO dashboard que
si escaneas con la CLI — antes este módulo usaba nombres distintos
(`shopiscan_last_risk_score`, `shopiscan_findings_by_severity_total`,
un histograma en vez de gauge para la duración...) y los escaneos hechos
desde la interfaz web nunca aparecían en Grafana, aunque Prometheus sí
los scrapeaba correctamente.

Import perezoso de prometheus_client: si no está instalado (no se usa el
modo servidor), este módulo no rompe el resto de ShopiScan.
"""

from __future__ import annotations

import time

_SEVERITIES = ["Crítica", "Alta", "Media", "Baja", "Info"]

try:
    from prometheus_client import Counter, Gauge

    # Contador propio del modo servidor (no lo consulta el dashboard por
    # nombre exacto, pero es útil para monitorizar la salud del servicio).
    scans_total = Counter("shopiscan_scans_total", "Total de escaneos ejecutados por el servidor", ["status"])

    risk_score = Gauge("shopiscan_risk_score", "Puntuación de riesgo del escaneo (0-100).", ["store"])
    findings_total = Gauge(
        "shopiscan_findings_total", "Número de hallazgos por severidad.", ["store", "severity"]
    )
    owasp_findings_total = Gauge(
        "shopiscan_owasp_findings_total",
        "Número de hallazgos por categoría OWASP Top 10 (2021).",
        ["store", "category"],
    )
    leaked_secrets_total = Gauge(
        "shopiscan_leaked_secrets_total", "Número de credenciales potencialmente filtradas.", ["store"]
    )
    shadow_apps_total = Gauge(
        "shopiscan_shadow_apps_total", "Número de residuos de apps desinstaladas.", ["store"]
    )
    outdated_libraries_total = Gauge(
        "shopiscan_outdated_libraries_total", "Número de librerías JS desactualizadas.", ["store"]
    )
    scan_timestamp_seconds = Gauge(
        "shopiscan_scan_timestamp_seconds", "Momento del último escaneo (unix time).", ["store"]
    )
    scan_duration_seconds = Gauge(
        "shopiscan_scan_duration_seconds", "Duración del escaneo en segundos.", ["store"]
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover - prometheus_client es opcional
    _AVAILABLE = False


def observe_scan(result_dict: dict, duration_seconds: float, status: str = "completed") -> None:
    """Registra las métricas de un escaneo completado en el registro de
    prometheus_client, con los mismos nombres/etiquetas que `metrics.py`
    usa para el camino CLI + Pushgateway. No hace nada si
    prometheus_client no está instalado.
    """
    if not _AVAILABLE:
        return

    scans_total.labels(status=status).inc()

    if status != "completed":
        return  # sin resultado válido, no hay más métricas que registrar

    store = result_dict.get("url", "unknown").split("//")[-1].split("/")[0]
    score = (result_dict.get("risk") or {}).get("score", 0)

    risk_score.labels(store=store).set(score)
    scan_duration_seconds.labels(store=store).set(duration_seconds)
    scan_timestamp_seconds.labels(store=store).set(time.time())
    leaked_secrets_total.labels(store=store).set(len(result_dict.get("leaked_secrets", []) or []))
    shadow_apps_total.labels(store=store).set(len(result_dict.get("shadow_apps", []) or []))
    outdated_libraries_total.labels(store=store).set(len(result_dict.get("outdated_libraries", []) or []))

    severity_counts = {sev: 0 for sev in _SEVERITIES}
    owasp_counts: dict[str, int] = {}
    for finding in result_dict.get("findings", []) or []:
        level = finding.get("level", "Info")
        severity_counts[level] = severity_counts.get(level, 0) + 1
        owasp = finding.get("owasp_category")
        if owasp:
            code = owasp.split(" - ", 1)[0]
            owasp_counts[code] = owasp_counts.get(code, 0) + 1

    for sev, count in severity_counts.items():
        findings_total.labels(store=store, severity=sev).set(count)
    for code, count in owasp_counts.items():
        owasp_findings_total.labels(store=store, category=code).set(count)
