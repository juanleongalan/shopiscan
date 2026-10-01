"""
ShopiScan - Auditor de seguridad para tiendas Shopify potenciado por IA.

Este paquete expone la función `main`, que es el punto de entrada del
comando de consola `shopiscan` (ver entry_points en setup.py).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from . import (
    ai_analyzer,
    core,
    history,
    local_vuln_db,
    metrics,
    notifications,
    owasp_mapping,
    remediation_mapping,
    report_html,
    scoring,
    utils,
    vector_db,
)

__version__ = "3.2.0"

# Carpeta base por defecto donde se guardan los informes (--json /
# --html-report), organizados en subcarpetas <tienda>/<fecha_hora>/ para
# no acumular archivos sueltos en el directorio desde el que se ejecuta
# ShopiScan. Se puede cambiar con --output-dir.
DEFAULT_OUTPUT_DIR = "shopiscan_reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shopiscan",
        description="ShopiScan - Auditor de seguridad pasivo para tiendas Shopify (o cualquier web con Shopify implementado), potenciado por IA local con Ollama.",
    )
    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument(
        "-u", "--url",
        help="URL de la tienda objetivo (ej: https://tienda.com). Debes tener autorización para escanearla.",
    )
    target.add_argument(
        "--url-file",
        help="Archivo de texto con una URL por línea, para escanear varias tiendas en batch.",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Activa el Informe Ejecutivo de Riesgo con IA local (requiere Ollama en marcha).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Modelo de chat de Ollama a usar (por defecto: llama3.1, o $OLLAMA_CHAT_MODEL).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Además de la salida en consola, exporta los resultados a un archivo JSON.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Ruta exacta del archivo JSON de salida (si se indica, ignora --output-dir para el JSON).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=f"Carpeta base donde guardar los informes, organizados en <tienda>/<fecha_hora>/ (por defecto: ./{DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Genera un informe HTML con diseño para presentar (abre en cualquier navegador; para PDF, usa 'Imprimir > Guardar como PDF').",
    )
    parser.add_argument(
        "--no-fetch-scripts",
        action="store_true",
        help="Desactiva la descarga de scripts externos para la búsqueda de credenciales filtradas (más rápido, menos profundo).",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="No guardes ni compares con el histórico de escaneos anteriores de esta tienda (~/.shopiscan/history/).",
    )
    parser.add_argument(
        "--no-local-db",
        action="store_true",
        help="No registres este escaneo en la base de datos local incremental (~/.shopiscan/local_vuln_db.sqlite3).",
    )
    parser.add_argument(
        "--no-vector-db",
        action="store_true",
        help="No uses PostgreSQL+pgvector para búsqueda semántica de hallazgos (aunque DATABASE_URL esté configurado).",
    )
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="No escribas métricas de Prometheus tras el escaneo.",
    )
    parser.add_argument(
        "--metrics-dir",
        default=None,
        help="Directorio donde escribir las métricas .prom de Prometheus (o usa PROMETHEUS_TEXTFILE_DIR).",
    )
    parser.add_argument(
        "--vuln-db-stats",
        action="store_true",
        help="Muestra un resumen de la base de datos local incremental y termina (no requiere -u/--url-file).",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="No envíes notificaciones (Slack/email) aunque el score haya empeorado y estén configuradas.",
    )
    parser.add_argument(
        "--notify-threshold",
        type=int,
        default=0,
        help="Puntos de empeoramiento del score a partir de los cuales notificar (por defecto: 0, cualquier empeoramiento).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Oculta el banner ASCII y el disclaimer (útil para scripting/CI).",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Confirma automáticamente que tienes autorización para escanear el objetivo (omite el prompt interactivo).",
    )
    return parser


def confirm_authorization(auto_yes: bool) -> bool:
    """Exige una confirmación explícita antes de escanear.

    Esto es una salvaguarda ética/legal simple: obliga al usuario a afirmar
    conscientemente que tiene permiso para auditar el/los objetivo(s).
    """
    if auto_yes:
        return True
    try:
        answer = input(
            "¿Confirmas que tienes autorización explícita para escanear el/los sitio(s) indicado(s)? [s/N]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("s", "si", "sí", "y", "yes")


def _prompt_continue_after_interrupt(context: str) -> bool:
    """Se invoca al capturar Ctrl+C (SIGINT) durante un escaneo.

    Pregunta explícitamente si continuar o parar, en vez de abortar sin
    más: un Ctrl+C accidental (o para copiar algo del terminal) no debería
    tirar todo un escaneo en batch de 50 tiendas.
    """
    print()
    utils.warning(f"Escaneo interrumpido (Ctrl+C) — {context}")
    try:
        answer = input("¿Deseas continuar el escaneo? [s/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("s", "si", "sí", "y", "yes")


def _slug_for(url: str) -> str:
    domain = urlparse(url if url.startswith("http") else f"https://{url}").netloc
    return domain.replace(":", "_") or "target"


def print_risk_banner(result) -> None:
    from colorama import Fore, Style

    from .utils import _ORANGE

    risk = result.risk or {}
    score = risk.get("score", 0)
    label = risk.get("label", "BAJO")
    color = {"CRÍTICO": Fore.RED, "ALTO": _ORANGE, "MEDIO": Fore.YELLOW, "BAJO": Fore.GREEN}.get(
        label, Fore.WHITE
    )
    utils.section("Score de riesgo")
    print(f"{color}{Style.BRIGHT}  {score}/100  -  RIESGO {label}{Style.RESET_ALL}")


def scan_one(url: str, args: argparse.Namespace) -> tuple:
    """Escanea una URL y devuelve (result, ai_report)."""
    scan_start = time.time()
    try:
        result = core.run_scan(url, fetch_scripts=not args.no_fetch_scripts)
    except Exception as exc:  # noqa: BLE001 - queremos que un fallo en 1 tienda no tumbe el batch
        utils.error(f"Fallo inesperado escaneando '{url}': {exc}")
        return core.ScanResult(url=url), None

    if not result.is_shopify:
        utils.warning(f"'{url}': el objetivo no parece ser una tienda Shopify.")
        return result, None

    utils.section("Resumen del escaneo")
    utils.info(f"Tema: {result.theme_name or 'Desconocido'} (ID: {result.theme_id or '-'}, rol: {result.theme_role or '-'})")
    utils.info(f"Servicios de terceros conocidos: {len(result.known_services)}")
    utils.info(f"Scripts externos sin identificar: {len(result.apps_generic)}")
    utils.info(f"Headers de seguridad faltantes: {len(result.missing_headers)}/{len(result.missing_headers) + len(result.present_headers)}")
    if result.leaked_secrets:
        utils.error(f"¡Credenciales potencialmente filtradas: {len(result.leaked_secrets)}!")
    if result.outdated_libraries:
        utils.warning(f"Librerías JS desactualizadas: {len(result.outdated_libraries)}")
    if result.shadow_apps:
        utils.warning(f"Posibles residuos de apps desinstaladas (shadow apps): {len(result.shadow_apps)}")
    if result.exposed_paths:
        utils.error(f"¡Rutas sensibles de infraestructura expuestas: {len(result.exposed_paths)}!")

    if not args.no_local_db:
        local_vuln_db.record_scan(result.to_dict())
        extra_findings = local_vuln_db.enrich_findings(result.to_dict())
        if extra_findings:
            owasp_mapping.enrich_findings_with_owasp(extra_findings)
            remediation_mapping.enrich_findings_with_remediation(extra_findings)
            result.findings.extend(extra_findings)
            result.risk = scoring.compute_risk_score(result.findings)

    utils.print_findings(result.findings)
    print_risk_banner(result)

    slug = _slug_for(result.url)
    comparison = None
    if not args.no_history:
        previous_snapshot = history.load_previous_snapshot(slug)
        if previous_snapshot:
            comparison = history.compare(previous_snapshot, result.to_dict())
            history.print_comparison(comparison)
        history.save_snapshot(slug, result.to_dict())

    if comparison and not args.no_notify:
        notifications.notify_score_regression(result.url, comparison, threshold=args.notify_threshold)

    # Búsqueda vectorial (PostgreSQL + pgvector): recupera hallazgos
    # históricos similares para dárselos al LLM como contexto (RAG), y luego
    # indexa los hallazgos de este escaneo. Todo degrada si no hay DB/Ollama.
    similar_findings = []
    if not args.no_vector_db:
        vector_db.ensure_schema()
        similar_findings = vector_db.find_similar_for_scan(result.to_dict())
        if similar_findings:
            utils.info(f"Hallazgos históricos similares recuperados (pgvector): {len(similar_findings)}")

    ai_report = None
    if args.ai:
        scan_data_for_ai = result.to_dict()
        if comparison:
            scan_data_for_ai["previous_scan_comparison"] = comparison.to_dict()
        ai_report = ai_analyzer.generate_executive_report(
            scan_data_for_ai, model=args.model, similar_findings=similar_findings or None
        )
        if ai_report:
            ai_analyzer.print_executive_report(ai_report)

    if not args.no_vector_db:
        vector_db.index_findings(result.url, result.findings)

    scan_duration = time.time() - scan_start
    if not args.no_metrics:
        metrics.write_scan_metrics(result.to_dict(), duration_seconds=scan_duration, metrics_dir=args.metrics_dir)
        metrics.push_scan_metrics(result.to_dict(), duration_seconds=scan_duration)

    utils.section("Escaneo finalizado")
    utils.success(f"Objetivo: {result.url}")

    needs_scan_folder = args.html_report or (args.json and not args.output)
    if needs_scan_folder:
        # Carpeta dedicada por escaneo: <output_dir>/<tienda>/<fecha_hora>/
        # En vez de acumular todos los informes sueltos en el mismo directorio,
        # cada ejecución tiene su propia carpeta con fecha y hora.
        scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
        scan_folder = output_base / slug / scan_timestamp
        try:
            scan_folder.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            utils.error(f"No se pudo crear la carpeta de salida '{scan_folder}': {exc}")
            scan_folder = Path(".")

    if args.json:
        export = result.to_dict()
        if ai_report:
            export["executive_ai_report"] = ai_report
        if comparison:
            export["previous_scan_comparison"] = comparison.to_dict()
        output_path = Path(args.output) if args.output else scan_folder / "report.json"
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export, f, indent=2, ensure_ascii=False)
            utils.success(f"Resultados exportados a {output_path}")
        except OSError as exc:
            utils.error(f"No se pudo escribir el archivo JSON '{output_path}': {exc}")

    if args.html_report:
        html_path = scan_folder / "report.html"
        html_content = report_html.generate_html_report(result.to_dict(), ai_report, comparison)
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            utils.success(f"Informe HTML generado: {html_path}")
        except OSError as exc:
            utils.error(f"No se pudo escribir el informe HTML '{html_path}': {exc}")

    return result, ai_report


def _run_batch(args: argparse.Namespace) -> int:
    try:
        with open(args.url_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except OSError as exc:
        utils.error(f"No se pudo leer el archivo de URLs: {exc}")
        return 1

    if not urls:
        utils.error("El archivo de URLs está vacío.")
        return 1

    utils.info(f"Modo batch: {len(urls)} tienda(s) a escanear.")
    summary = []
    interrupted = False
    i = 0
    while i < len(urls):
        url = urls[i]
        utils.section(f"[{i + 1}/{len(urls)}] {url}")
        try:
            result, _ = scan_one(url, args)
            summary.append((url, result))
            i += 1
        except KeyboardInterrupt:
            if _prompt_continue_after_interrupt(f"tienda {i + 1}/{len(urls)}: {url}"):
                utils.info("Reanudando el escaneo...")
                continue  # reintenta la misma URL, sin avanzar el índice
            utils.error("Escaneo en batch cancelado por el usuario.")
            interrupted = True
            break

    utils.section("Resumen del batch")
    for url, result in summary:
        if not result.is_shopify:
            print(f"  - {url}: no es Shopify")
            continue
        score = result.risk.get("score", 0)
        label = result.risk.get("label", "BAJO")
        print(f"  - {url}: {score}/100 ({label}), {len(result.findings)} alertas")

    if interrupted:
        pending = len(urls) - len(summary)
        if pending > 0:
            utils.warning(f"{pending} tienda(s) quedaron sin escanear por la interrupción.")
        return 130

    return 0


def _load_dotenv_if_available() -> Optional[bool]:
    """Carga variables desde un archivo .env si python-dotenv está instalado.

    Devuelve True si encontró y cargó un archivo .env, False si el paquete
    está disponible pero no encontró ningún .env, o None si python-dotenv
    no está instalado. Es opcional: Ollama no necesita ninguna API key,
    pero el .env sigue siendo útil para OLLAMA_URL, DATABASE_URL
    (PostgreSQL+pgvector) y las variables de notificación (Slack/email).

    Si el .env tiene líneas que python-dotenv no puede interpretar (p. ej.
    una línea de texto suelta sin '#' delante ni forma CLAVE=valor),
    python-dotenv las ignora y sigue cargando el resto con normalidad —
    pero por defecto imprime un mensaje de log crudo y poco claro por cada
    línea. Aquí lo interceptamos para mostrar un único aviso comprensible
    en su lugar (las variables del resto del archivo se cargan igual).
    """
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return None

    dotenv_path = find_dotenv(usecwd=True)
    if not dotenv_path:
        return False

    import logging

    class _CountingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.count = 0

        def emit(self, record: logging.LogRecord) -> None:
            self.count += 1

    dotenv_logger = logging.getLogger("dotenv.main")
    handler = _CountingHandler()
    previous_propagate = dotenv_logger.propagate
    dotenv_logger.propagate = False  # evita los mensajes crudos de python-dotenv
    dotenv_logger.addHandler(handler)
    try:
        load_dotenv(dotenv_path)
    finally:
        dotenv_logger.removeHandler(handler)
        dotenv_logger.propagate = previous_propagate

    if handler.count:
        utils.warning(
            f"Tu archivo .env tiene {handler.count} línea(s) que no se pudieron interpretar "
            "(deben empezar por '#' o tener la forma CLAVE=valor). Se ignoraron sin problema "
            "y el resto de variables se cargó con normalidad; revisa esas líneas si esperabas "
            "que alguna se aplicara."
        )
    return True


def main(argv: list[str] | None = None) -> int:
    dotenv_loaded = _load_dotenv_if_available()

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        utils.print_banner()

    if args.vuln_db_stats:
        local_vuln_db.print_stats_summary()
        return 0

    if not args.url and not args.url_file:
        parser.error("uno de los argumentos -u/--url --url-file es requerido (o usa --vuln-db-stats)")

    if args.ai and dotenv_loaded is None:
        utils.warning(
            "El paquete 'python-dotenv' no está instalado: el archivo .env no se "
            "cargará automáticamente (por ejemplo, OLLAMA_URL si Ollama corre en "
            "otra máquina). Ejecuta 'pip install -r requirements.txt' si lo necesitas."
        )

    if not confirm_authorization(args.yes):
        utils.error("Escaneo cancelado: se requiere autorización explícita.")
        return 1

    if args.url:
        while True:
            try:
                scan_one(args.url, args)
                return 0
            except KeyboardInterrupt:
                if _prompt_continue_after_interrupt(f"objetivo: {args.url}"):
                    utils.info("Reanudando el escaneo...")
                    continue
                utils.error("Escaneo cancelado por el usuario.")
                return 130

    return _run_batch(args)


if __name__ == "__main__":
    sys.exit(main())
