"""
metrics.py
------------
Instrumentación para Prometheus, con DOS vías de entrega para la CLI
(que no es un proceso de larga vida, así que no puede exponer un
endpoint HTTP por sí sola):

1. **Textfile collector** (`write_scan_metrics`): escribe/actualiza un
   archivo `.prom` en un directorio. Requiere que algo lea ese
   directorio y lo exponga a Prometheus (normalmente `node_exporter`
   con `--collector.textfile.directory`). Útil si ya tienes
   node_exporter en tu infraestructura.

2. **Pushgateway** (`push_scan_metrics`): empuja las métricas por HTTP a
   un Prometheus Pushgateway (incluido en el `docker-compose` de
   `deploy/`). Es la opción MÁS SIMPLE para ver los datos de la CLI en
   Grafana sin instalar nada más: Prometheus scrapea el Pushgateway, y
   el Pushgateway solo necesita que le hagas un PUT tras cada escaneo
   (que es justo lo que hace esta función). Configúralo con
   PROMETHEUS_PUSHGATEWAY_URL=http://localhost:9091 en tu .env.

Métricas expuestas (todas etiquetadas por `store`):
  - shopiscan_risk_score{store="..."}            gauge 0-100
  - shopiscan_findings_total{store,severity}     gauge (nº hallazgos por severidad)
  - shopiscan_leaked_secrets_total{store}        gauge
  - shopiscan_shadow_apps_total{store}           gauge
  - shopiscan_scan_timestamp_seconds{store}      gauge (unix ts del último escaneo)
  - shopiscan_scan_duration_seconds{store}       gauge

Todo es opcional: si no configuras ni PROMETHEUS_TEXTFILE_DIR ni
PROMETHEUS_PUSHGATEWAY_URL, no se escribe/envía nada. Y si falla, se
avisa pero el escaneo no se interrumpe.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from . import utils

TEXTFILE_DIR_ENV_VAR = "PROMETHEUS_TEXTFILE_DIR"
PUSHGATEWAY_URL_ENV_VAR = "PROMETHEUS_PUSHGATEWAY_URL"
PUSHGATEWAY_JOB = "shopiscan"
PUSHGATEWAY_TIMEOUT = 10

_SEVERITIES = ["Crítica", "Alta", "Media", "Baja", "Info"]


def _resolve_dir(explicit_dir: Optional[str]) -> Optional[Path]:
    target = explicit_dir or os.environ.get(TEXTFILE_DIR_ENV_VAR)
    return Path(target) if target else None


def _sanitize_label(value: str) -> str:
    """Escapa el valor de una etiqueta Prometheus (comillas y backslashes)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _slug_for_filename(store: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in store) or "target"


def _store_domain(result_dict: dict) -> str:
    return result_dict.get("url", "unknown").split("//")[-1].split("/")[0]


def _build_metrics_text(result_dict: dict, duration_seconds: float, include_help: bool = True) -> tuple[str, str]:
    """Construye el cuerpo en formato de exposición de Prometheus.
    Devuelve (texto, store_domain). Compartido por write_scan_metrics()
    (textfile) y push_scan_metrics() (Pushgateway) para no duplicar la
    definición de las métricas en dos sitios.
    """
    store = _store_domain(result_dict)
    store_label = _sanitize_label(store)
    risk = result_dict.get("risk", {}) or {}
    score = risk.get("score", 0)

    severity_counts = {sev: 0 for sev in _SEVERITIES}
    owasp_counts: dict[str, int] = {}
    for finding in result_dict.get("findings", []) or []:
        level = finding.get("level", "Info")
        severity_counts[level] = severity_counts.get(level, 0) + 1
        owasp = finding.get("owasp_category")
        if owasp:
            code = owasp.split(" - ", 1)[0]  # p. ej. "A05:2021" a partir de "A05:2021 - Configuración..."
            owasp_counts[code] = owasp_counts.get(code, 0) + 1

    now = time.time()

    def _metric(name: str, help_text: str, mtype: str, value_lines: list[str]) -> list[str]:
        header = [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"] if include_help else []
        return header + value_lines

    lines: list[str] = []
    lines += _metric(
        "shopiscan_risk_score", "Puntuación de riesgo del escaneo (0-100).", "gauge",
        [f'shopiscan_risk_score{{store="{store_label}"}} {score}'],
    )
    lines += _metric(
        "shopiscan_findings_total", "Número de hallazgos por severidad.", "gauge",
        [
            f'shopiscan_findings_total{{store="{store_label}",severity="{_sanitize_label(sev)}"}} {count}'
            for sev, count in severity_counts.items()
        ],
    )
    if owasp_counts:
        lines += _metric(
            "shopiscan_owasp_findings_total", "Número de hallazgos por categoría OWASP Top 10 (2021).", "gauge",
            [
                f'shopiscan_owasp_findings_total{{store="{store_label}",category="{_sanitize_label(code)}"}} {count}'
                for code, count in owasp_counts.items()
            ],
        )
    lines += _metric(
        "shopiscan_leaked_secrets_total", "Número de credenciales potencialmente filtradas.", "gauge",
        [f'shopiscan_leaked_secrets_total{{store="{store_label}"}} {len(result_dict.get("leaked_secrets", []) or [])}'],
    )
    lines += _metric(
        "shopiscan_shadow_apps_total", "Número de residuos de apps desinstaladas.", "gauge",
        [f'shopiscan_shadow_apps_total{{store="{store_label}"}} {len(result_dict.get("shadow_apps", []) or [])}'],
    )
    lines += _metric(
        "shopiscan_outdated_libraries_total", "Número de librerías JS desactualizadas.", "gauge",
        [f'shopiscan_outdated_libraries_total{{store="{store_label}"}} {len(result_dict.get("outdated_libraries", []) or [])}'],
    )
    lines += _metric(
        "shopiscan_scan_timestamp_seconds", "Momento del último escaneo (unix time).", "gauge",
        [f'shopiscan_scan_timestamp_seconds{{store="{store_label}"}} {now:.0f}'],
    )
    lines += _metric(
        "shopiscan_scan_duration_seconds", "Duración del escaneo en segundos.", "gauge",
        [f'shopiscan_scan_duration_seconds{{store="{store_label}"}} {duration_seconds:.3f}'],
    )

    return "\n".join(lines) + "\n", store


def write_scan_metrics(
    result_dict: dict,
    duration_seconds: float = 0.0,
    metrics_dir: Optional[str] = None,
) -> Optional[str]:
    """Escribe un archivo .prom con las métricas del escaneo (textfile
    collector). Devuelve la ruta escrita, o None si no hay directorio
    configurado o falla.
    """
    target_dir = _resolve_dir(metrics_dir)
    if target_dir is None:
        return None

    content, store = _build_metrics_text(result_dict, duration_seconds)

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / f"shopiscan_{_slug_for_filename(store)}.prom"
        # Escritura atómica: escribe a un temporal y renombra, para que
        # Prometheus/node_exporter nunca lean un archivo a medio escribir.
        tmp_path = out_path.with_suffix(".prom.tmp")
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.replace(out_path)
        utils.success(f"Métricas Prometheus escritas en {out_path}")
        return str(out_path)
    except OSError as exc:
        utils.warning(f"No se pudieron escribir las métricas Prometheus: {exc}")
        return None


def push_scan_metrics(
    result_dict: dict,
    duration_seconds: float = 0.0,
    pushgateway_url: Optional[str] = None,
) -> bool:
    """Empuja las métricas del escaneo a un Prometheus Pushgateway vía
    HTTP PUT. Es la forma más directa de que un escaneo puntual de la CLI
    aparezca en Grafana sin necesidad de node_exporter: Prometheus scrapea
    el Pushgateway (ver deploy/docker-compose.yml y prometheus.yml), y
    esta función simplemente le empuja el resultado tras cada escaneo.

    Devuelve True si el push tuvo éxito. No lanza: cualquier fallo de red
    se traduce en un aviso, el escaneo continúa igual.
    """
    url = pushgateway_url or os.environ.get(PUSHGATEWAY_URL_ENV_VAR)
    if not url:
        return False

    try:
        import requests
    except ImportError:  # pragma: no cover - requests es dependencia base, esto no debería pasar
        utils.warning("No se pudo importar 'requests' para enviar métricas al Pushgateway.")
        return False

    content, store = _build_metrics_text(result_dict, duration_seconds, include_help=True)
    instance = _slug_for_filename(store)
    endpoint = f"{url.rstrip('/')}/metrics/job/{PUSHGATEWAY_JOB}/instance/{instance}"

    try:
        resp = requests.put(endpoint, data=content.encode("utf-8"), timeout=PUSHGATEWAY_TIMEOUT)
        if resp.status_code >= 300:
            utils.warning(f"El Pushgateway respondió {resp.status_code} al enviar las métricas.")
            return False
        utils.success(f"Métricas enviadas al Pushgateway de Prometheus ({url}).")
        return True
    except requests.exceptions.RequestException as exc:
        utils.warning(
            f"No se pudieron enviar las métricas al Pushgateway ({url}): {exc}. "
            "¿Está levantado? ('docker compose up -d pushgateway' en deploy/)."
        )
        return False
