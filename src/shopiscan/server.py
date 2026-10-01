"""
server.py
-----------
Servidor HTTP opcional (FastAPI) para ShopiScan, con dos caras:

  1. API REST (`POST /scan`, `GET /metrics`) — para integraciones e
     infraestructura (Docker + Prometheus/Grafana).
  2. **Interfaz web propia** (`GET /`) — un formulario donde puedes pegar
     la URL objetivo, elegir TODOS los parámetros del escaneo (IA,
     modelo, histórico, base de datos vectorial, descarga de scripts,
     métricas, notificaciones, guardado en disco...) y ver el resultado
     con el mismo informe HTML coloreado que genera la CLI, sin tocar la
     terminal.

Se arranca con:  shopiscan-server   (o  python -m shopiscan.server)
Requiere las dependencias del extra 'server':  pip install -e ".[server]"

Cuando se usa el `docker-compose` de `deploy/`, este mismo servidor es el
que corre dentro del contenedor `shopiscan_app` (puerto 8000): NO hace
falta lanzar `shopiscan-server` por separado en tu máquina si ya tienes
el stack de Docker levantado — usa directamente http://localhost:8000.

Endpoints:
  GET  /                                                    -> interfaz web (formulario + resultados)
  POST /scan/ui          (form-data, ver create_scan_ui)     -> ejecuta el escaneo y devuelve el HTML del informe
  POST /scan             {"url": "...", "authorized": true}  -> API JSON (programática)
  GET  /health                                               -> health check
  GET  /metrics                                              -> métricas Prometheus (formato de exposición)

Todo lo pesado (IA, DB vectorial, histórico, notificaciones) sigue siendo
opcional y degrada igual que en la CLI: si Ollama/Postgres no están
disponibles, el escaneo técnico se muestra igual.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from . import core, metrics_prom, utils, vector_db, ai_analyzer

# Caché en memoria de páginas de resultado ya renderizadas (HTML completo),
# para el flujo "Escanear" -> redirección a /scan/result/<id>. Es
# intencionadamente simple (sin base de datos): el proceso del servidor es
# de un solo worker, así que un dict en memoria es suficiente y evita
# depender de infraestructura extra solo para esto. Se acota el tamaño
# para no crecer sin límite en un servidor de larga vida.
_RESULTS_CACHE: dict[str, str] = {}
_RESULTS_CACHE_MAX = 100


def _store_result_html(html: str) -> str:
    """Guarda una página de resultado ya renderizada y devuelve su ID
    (para la URL /scan/result/<id>). Si la caché supera el límite,
    descarta la entrada más antigua (los resultados son efímeros por
    diseño: para conservarlos de verdad, usa 'Guardar informe en disco')."""
    result_id = uuid.uuid4().hex[:12]
    if len(_RESULTS_CACHE) >= _RESULTS_CACHE_MAX:
        oldest_key = next(iter(_RESULTS_CACHE))
        del _RESULTS_CACHE[oldest_key]
    _RESULTS_CACHE[result_id] = html
    return result_id


def _get_result_html(result_id: str) -> Optional[str]:
    return _RESULTS_CACHE.get(result_id)


_BACK_NAV_HTML = """
<div style="background:#0a0e1a;border-bottom:1px solid #232a38;padding:12px 24px;
            font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <a href="/" style="color:#e7ecf3;text-decoration:none;font-weight:700;font-size:14px;
                      display:inline-flex;align-items:center;gap:8px;">
    <span style="font-size:16px;">&#8592;</span>
    <span>&#128737;&#65039; ShopiScan</span>
    <span style="color:#8b96a8;font-weight:400;font-size:12.5px;">— volver a escanear</span>
  </a>
</div>
"""


def _standalone_page(title: str, message: str, is_error: bool = False) -> str:
    """Página independiente (con su propia barra de 'volver') para casos
    donde no hay un informe HTML que mostrar: objetivo no es Shopify,
    error durante el escaneo, o falta de autorización."""
    color = "#f87171" if is_error else "#e7ecf3"
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - ShopiScan</title></head>
<body style="margin:0;background:#05070d;color:{color};
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
{_BACK_NAV_HTML}
<div style="max-width:640px;margin:60px auto;padding:0 24px;text-align:center;">
  <p style="font-size:16px;line-height:1.6;">{message}</p>
</div>
</body></html>"""


def _run_full_scan(
    url: str,
    *,
    use_ai: bool = False,
    model: Optional[str] = None,
    fetch_scripts: bool = True,
    use_history: bool = True,
    use_local_db: bool = True,
    use_vector_db: bool = True,
    use_notify: bool = False,
    notify_threshold: int = 0,
    save_files: bool = False,
    output_dir: Optional[str] = None,
):
    """Orquesta un escaneo completo (motor + histórico + base de datos
    local + búsqueda vectorial + IA + notificaciones + guardado en
    disco), replicando lo que hace `scan_one()` en la CLI. Centralizado
    aquí para que tanto la API JSON como la interfaz web (`/scan/ui`)
    compartan exactamente la misma lógica.

    Devuelve (result, ai_report, comparison, saved_paths, vector_db_note).
    `vector_db_note` es None si todo fue bien (o no se pidió pgvector);
    si se pidió pero no se pudo indexar nada, contiene un mensaje
    explicando por qué, para mostrarlo en la interfaz en vez de que el
    fallo solo quede en los logs del contenedor.
    """
    from . import history, local_vuln_db, notifications, owasp_mapping, remediation_mapping, scoring

    result = core.run_scan(url, fetch_scripts=fetch_scripts)
    if not result.is_shopify:
        return result, None, None, {}, None

    if use_local_db:
        local_vuln_db.record_scan(result.to_dict())
        extra_findings = local_vuln_db.enrich_findings(result.to_dict())
        if extra_findings:
            owasp_mapping.enrich_findings_with_owasp(extra_findings)
            remediation_mapping.enrich_findings_with_remediation(extra_findings)
            result.findings.extend(extra_findings)
            result.risk = scoring.compute_risk_score(result.findings)

    comparison = None
    if use_history:
        slug = url.split("//")[-1].split("/")[0]
        previous_snapshot = history.load_previous_snapshot(slug)
        if previous_snapshot:
            comparison = history.compare(previous_snapshot, result.to_dict())
        history.save_snapshot(slug, result.to_dict())

    if use_notify and comparison:
        notifications.notify_score_regression(result.url, comparison, threshold=notify_threshold)

    similar_findings = []
    if use_vector_db:
        vector_db.ensure_schema()
        similar_findings = vector_db.find_similar_for_scan(result.to_dict())

    ai_report = None
    if use_ai:
        scan_data = result.to_dict()
        if comparison:
            scan_data["previous_scan_comparison"] = comparison.to_dict()
        ai_report = ai_analyzer.generate_executive_report(
            scan_data, model=model, similar_findings=similar_findings or None
        )

    vector_db_note = None
    if use_vector_db:
        if not vector_db.is_available():
            vector_db_note = (
                "Búsqueda vectorial solicitada pero no disponible (revisa DATABASE_URL, "
                "que psycopg/pgvector estén instalados, y que PostgreSQL sea alcanzable)."
            )
        elif result.findings:
            indexed, index_error = vector_db.index_findings(result.url, result.findings)
            if indexed == 0:
                vector_db_note = index_error or (
                    "No se indexó ningún hallazgo en pgvector por un motivo desconocido."
                )

    saved_paths: dict = {}
    if save_files:
        saved_paths = _save_report_to_disk(result, ai_report, comparison, output_dir)

    return result, ai_report, comparison, saved_paths, vector_db_note


def _save_report_to_disk(result, ai_report, comparison, output_dir: Optional[str]) -> dict:
    """Guarda una copia del informe (JSON + HTML) en disco, en la misma
    carpeta por escaneo que usa la CLI (`shopiscan_reports/<tienda>/<fecha_hora>/`),
    para que los escaneos hechos desde la interfaz web también queden
    archivados igual que con `--json --html-report`.
    """
    import json as _json
    from datetime import datetime
    from pathlib import Path

    from . import report_html

    try:
        from . import DEFAULT_OUTPUT_DIR
    except ImportError:  # pragma: no cover - fallback si se importa de forma aislada
        DEFAULT_OUTPUT_DIR = "shopiscan_reports"

    slug = result.url.split("//")[-1].split("/")[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = Path(output_dir or DEFAULT_OUTPUT_DIR) / slug / timestamp

    try:
        folder.mkdir(parents=True, exist_ok=True)
        export = result.to_dict()
        if ai_report:
            export["executive_ai_report"] = ai_report
        if comparison:
            export["previous_scan_comparison"] = comparison.to_dict()
        json_path = folder / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            _json.dump(export, f, indent=2, ensure_ascii=False)

        html_path = folder / "report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(report_html.generate_html_report(result.to_dict(), ai_report, comparison))

        return {"json": str(json_path), "html": str(html_path)}
    except OSError as exc:
        utils.warning(f"No se pudo guardar el informe en disco: {exc}")
        return {}


_INDEX_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShopiScan - Auditor de seguridad para tiendas Shopify</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #05070d;
    --bg-2: #0a0e1a;
    --panel: #10151f;
    --panel-2: #141a26;
    --accent: #34d399;
    --accent-2: #22c55e;
    --accent-glow: rgba(52, 211, 153, 0.18);
    --blue: #38bdf8;
    --amber: #f59e0b;
    --red: #f87171;
    --border: #232a38;
    --border-light: #2e3646;
    --muted: #8b96a8;
    --text: #e7ecf3;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 0 0 50px 0; line-height: 1.6;
    background-image:
      radial-gradient(circle at 12% -10%, rgba(52,211,153,0.10) 0%, transparent 40%),
      radial-gradient(circle at 88% 0%, rgba(56,189,248,0.08) 0%, transparent 38%),
      radial-gradient(circle at 1.5px 1.5px, rgba(255,255,255,0.035) 1.4px, transparent 0);
    background-size: auto, auto, 26px 26px;
  }
  .container { max-width: 940px; margin: 0 auto; padding: 0 20px; }
  header {
    background: linear-gradient(160deg, var(--bg-2), #060910 78%);
    border-bottom: 1px solid var(--border);
    padding: 44px 0 60px 0; margin-bottom: -38px;
  }
  header .container { display: flex; align-items: center; gap: 18px; }
  header a.brand { display: flex; align-items: center; gap: 18px; text-decoration: none; color: inherit; }
  header .shield {
    font-size: 30px; line-height: 1; width: 58px; height: 58px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center; border-radius: 15px;
    background: var(--panel); border: 1px solid var(--border-light);
    box-shadow: 0 0 0 1px rgba(52,211,153,0.08), 0 0 22px var(--accent-glow);
  }
  header h1 {
    margin: 0 0 5px 0; font-size: 27px; letter-spacing: -0.02em; font-weight: 800;
    background: linear-gradient(90deg, #ffffff, #c9f7e3 60%, var(--accent));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  header p { margin: 0; color: var(--muted); font-size: 13.5px; max-width: 640px; }

  .card {
    background: var(--panel); border-radius: 18px; padding: 32px 34px; margin-bottom: 24px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset, 0 20px 50px rgba(0,0,0,0.45);
    border: 1px solid var(--border); position: relative; z-index: 1;
    animation: rise 0.45s ease both;
  }
  @keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

  .field { margin-bottom: 6px; }
  label.main { display: block; font-weight: 700; margin-bottom: 9px; font-size: 16px; color: var(--text); }
  input[type="text"], input[type="url"], input[type="number"], select {
    width: 100%; padding: 13px 16px; border: 1.5px solid var(--border-light); border-radius: 11px;
    font-size: 15px; font-family: inherit; transition: border-color 0.15s, box-shadow 0.15s;
    background: var(--bg-2); color: var(--text);
  }
  input::placeholder { color: #5b6577; }
  input[type="text"]:focus, input[type="url"]:focus, input[type="number"]:focus, select:focus {
    outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .hint { font-size: 12.5px; color: var(--muted); margin-top: 8px; }
  .center { text-align: center; }

  .btn-row { display: flex; justify-content: center; margin: 22px 0 6px 0; }

  #topFeedback { margin: 4px 0 0 0; text-align: center; }

  .auth-box {
    background: linear-gradient(135deg, rgba(245,158,11,0.10), rgba(245,158,11,0.04));
    border: 1.5px solid rgba(245,158,11,0.35); border-radius: 14px;
    padding: 16px 20px; margin: 18px auto; font-size: 13.5px; display: flex; gap: 12px; align-items: flex-start;
    max-width: 680px;
  }
  .auth-box .lock { font-size: 20px; line-height: 1; margin-top: 1px; }
  .auth-box label { display: flex; align-items: flex-start; gap: 10px; font-weight: 600; cursor: pointer; color: #fcd9a1; flex: 1; text-align: left; }
  .auth-box input { margin-top: 2px; accent-color: var(--amber); width: 17px; height: 17px; flex-shrink: 0; }

  .legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--muted); justify-content: center; margin-top: 4px; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .legend i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; box-shadow: 0 0 6px currentColor; }

  /* Secciones desplegables */
  .accordion {
    border: 1.5px solid var(--border); border-radius: 14px; margin: 14px 0; overflow: hidden;
    background: var(--panel-2);
  }
  .accordion summary {
    list-style: none; cursor: pointer; padding: 15px 20px; display: flex; align-items: center;
    gap: 10px; font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.07em;
    color: var(--text); user-select: none;
  }
  .accordion summary::-webkit-details-marker { display: none; }
  .accordion summary .chevron { margin-left: auto; color: var(--muted); transition: transform 0.2s; font-size: 12px; }
  .accordion[open] summary .chevron { transform: rotate(180deg); }
  .accordion summary:hover { background: rgba(52,211,153,0.06); }
  .accordion .accordion-body { padding: 4px 20px 20px 20px; }

  .option-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 20px; }
  @media (max-width: 640px) { .option-grid { grid-template-columns: 1fr; } }

  .opt {
    display: flex; align-items: flex-start; gap: 11px; padding: 13px 15px; border-radius: 12px;
    border: 1.5px solid var(--border); cursor: pointer; background: var(--bg-2);
    transition: border-color 0.15s, background 0.15s, transform 0.1s;
    font-size: 13.5px;
  }
  .opt:hover { border-color: var(--accent); background: #16342b1a; transform: translateY(-1px); }
  .opt input[type="checkbox"] { margin-top: 2px; accent-color: var(--accent); width: 17px; height: 17px; flex-shrink: 0; }
  .opt .opt-text strong { display: block; font-weight: 650; color: var(--text); margin-bottom: 2px; }
  .opt .opt-text span { color: var(--muted); font-size: 12.5px; }
  .opt.has-input { flex-direction: column; align-items: stretch; }
  .opt.has-input > .opt-row { display: flex; align-items: center; gap: 10px; }
  .opt.has-input input[type="number"] { margin-top: 8px; width: 110px; }

  button.primary {
    appearance: none; -webkit-appearance: none; -moz-appearance: none;
    font-family: inherit;
    background: linear-gradient(135deg, var(--accent-2), var(--accent)); color: #04120c; border: none; padding: 15px 34px;
    border-radius: 12px; font-size: 15.5px; font-weight: 800; cursor: pointer; letter-spacing: 0.01em;
    box-shadow: 0 6px 22px var(--accent-glow); transition: transform 0.12s, box-shadow 0.15s, opacity 0.15s;
  }
  button.primary:hover { box-shadow: 0 8px 28px rgba(52,211,153,0.3); transform: translateY(-1px); }
  button.primary:active { transform: scale(0.98); }
  button.primary:disabled { background: #384152; color: #8b96a8; box-shadow: none; cursor: not-allowed; opacity: 0.8; transform: none; }

  #status { font-size: 13.5px; color: var(--muted); display: flex; align-items: center; justify-content: center; gap: 8px; min-height: 20px; }
  #status.error { color: var(--red); font-weight: 600; }
  #status.ok { color: var(--accent); font-weight: 600; }

  .spinner {
    display: inline-block; width: 15px; height: 15px; border: 2.5px solid #2e3646;
    border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  footer { text-align: center; font-size: 12px; color: var(--muted); padding: 14px 20px 0 20px; }
  footer a { color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="container">
    <a class="brand" href="/">
      <div class="shield">&#128737;&#65039;</div>
      <div>
        <h1>ShopiScan</h1>
        <p>Auditor de seguridad para tiendas Shopify, con IA local (Ollama). Uso exclusivo sobre tiendas propias o con autorizacion explicita.</p>
      </div>
    </a>
  </div>
</header>

<div class="container">
  <form id="scanForm" class="card" autocomplete="off">
    <div class="field">
      <label class="main" for="url">Escanea tu tienda Shopify</label>
      <input type="url" id="url" name="url" placeholder="URL de la tienda" autocomplete="off" required>
      <div class="hint">Tambien funciona con dominios propios que tengan Shopify implementado (no solo *.myshopify.com).</div>
    </div>

    <div class="btn-row">
      <button type="submit" class="primary" id="submitBtnTop">Escanear</button>
    </div>

    <div class="auth-box">
      <div class="lock">&#128274;</div>
      <label>
        <input type="checkbox" name="authorized" id="authorized" autocomplete="off" required>
        Confirmo que tengo autorizacion explicita para escanear este sitio. Esta herramienta es
        solo para tiendas propias o auditorias autorizadas; escanear sin autorizacion puede ser ilegal.
      </label>
    </div>

    <div class="legend">
      <span><i style="background:#f87171;color:#f87171"></i>Critica</span>
      <span><i style="background:#fb923c;color:#fb923c"></i>Alta</span>
      <span><i style="background:#facc15;color:#facc15"></i>Media</span>
      <span><i style="background:#34d399;color:#34d399"></i>Baja</span>
      <span><i style="background:#38bdf8;color:#38bdf8"></i>Info</span>
    </div>

    <p class="hint center">O ajusta los parametros abajo antes de escanear.</p>

    <div id="topFeedback"><div id="status"></div></div>

    <details class="accordion">
      <summary><span>Alcance del escaneo</span><span class="chevron">&#9662;</span></summary>
      <div class="accordion-body">
        <div class="option-grid">
          <label class="opt">
            <input type="checkbox" name="fetch_scripts" checked>
            <span class="opt-text"><strong>Descargar scripts externos</strong><span>Busca credenciales filtradas en los .js enlazados</span></span>
          </label>
          <label class="opt">
            <input type="checkbox" name="use_history" checked>
            <span class="opt-text"><strong>Comparar con el historico</strong><span>Guarda y compara con el escaneo anterior de esta tienda</span></span>
          </label>
          <label class="opt">
            <input type="checkbox" name="use_local_db" checked>
            <span class="opt-text"><strong>Base de datos local incremental</strong><span>Patrones de temas/scripts recurrentes (SQLite)</span></span>
          </label>
          <label class="opt">
            <input type="checkbox" name="use_vector_db" checked>
            <span class="opt-text"><strong>Busqueda vectorial</strong><span>Hallazgos similares vía PostgreSQL + pgvector</span></span>
          </label>
        </div>
      </div>
    </details>

    <details class="accordion">
      <summary><span>Inteligencia artificial</span><span class="chevron">&#9662;</span></summary>
      <div class="accordion-body">
        <div class="option-grid">
          <label class="opt">
            <input type="checkbox" name="ai" id="ai">
            <span class="opt-text"><strong>Informe Ejecutivo con IA</strong><span>Requiere Ollama en marcha (modelo local, sin API keys)</span></span>
          </label>
          <label class="opt has-input">
            <div class="opt-row">
              <span class="opt-text"><strong>Modelo de Ollama (opcional)</strong><span>Vacio = usa el configurado por defecto (llama3.1)</span></span>
            </div>
            <input type="text" name="model" placeholder="p. ej. llama3.2, mistral..." autocomplete="off">
          </label>
        </div>
      </div>
    </details>

    <details class="accordion">
      <summary><span>Observabilidad</span><span class="chevron">&#9662;</span></summary>
      <div class="accordion-body">
        <div class="option-grid">
          <label class="opt">
            <input type="checkbox" name="use_metrics" checked>
            <span class="opt-text"><strong>Registrar en Prometheus</strong><span>Visible en el dashboard de Grafana</span></span>
          </label>
        </div>
      </div>
    </details>

    <details class="accordion">
      <summary><span>Guardado</span><span class="chevron">&#9662;</span></summary>
      <div class="accordion-body">
        <div class="option-grid">
          <label class="opt">
            <input type="checkbox" name="save_files" id="save_files">
            <span class="opt-text"><strong>Guardar informe en disco</strong><span>JSON + HTML en shopiscan_reports/&lt;tienda&gt;/&lt;fecha_hora&gt;/, ademas de mostrarlo aqui</span></span>
          </label>
        </div>
      </div>
    </details>

    <div class="btn-row">
      <button type="submit" class="primary" id="submitBtn">Escanear</button>
    </div>
  </form>

  <footer>ShopiScan · Herramienta educativa de codigo abierto · Uso autorizado unicamente</footer>
</div>

<script>
  const form = document.getElementById('scanForm');
  const statusEl = document.getElementById('status');
  const submitBtn = document.getElementById('submitBtn');
  const submitBtnTop = document.getElementById('submitBtnTop');
  const topFeedback = document.getElementById('topFeedback');

  // Evita que el navegador restaure el estado de los checkboxes (incluida
  // la casilla de autorizacion) al recargar la pagina o volver atras.
  window.addEventListener('pageshow', () => form.reset());

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    statusEl.className = '';
    statusEl.innerHTML = '<span class="spinner"></span> Escaneando... esto puede tardar varios segundos (mas si usas IA).';
    submitBtn.disabled = true;
    submitBtnTop.disabled = true;
    topFeedback.scrollIntoView({ behavior: 'smooth', block: 'center' });

    try {
      const formData = new FormData(form);
      const resp = await fetch('/scan/ui', { method: 'POST', body: formData });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        statusEl.className = 'error';
        statusEl.textContent = (data && data.error) || ('Error ' + resp.status);
        submitBtn.disabled = false;
        submitBtnTop.disabled = false;
        return;
      }
      statusEl.className = 'ok';
      statusEl.textContent = 'Escaneo completado. Redirigiendo...';
      window.location.href = '/scan/result/' + data.result_id;
    } catch (err) {
      statusEl.className = 'error';
      statusEl.textContent = 'Error de red: ' + err;
      submitBtn.disabled = false;
      submitBtnTop.disabled = false;
    }
  });
</script>
</body>
</html>
"""


def create_app():
    """Crea la app FastAPI. Import perezoso de fastapi para que el resto de
    ShopiScan no dependa de ella."""
    try:
        from fastapi import FastAPI, Form, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse, Response
        from pydantic import BaseModel
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(_MISSING_SERVER_DEPS_MSG.format(paquete="fastapi")) from exc

    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(_MISSING_SERVER_DEPS_MSG.format(paquete="prometheus-client")) from exc

    app = FastAPI(
        title="ShopiScan",
        description=(
            "Auditor de seguridad pasivo para tiendas Shopify (IA local con Ollama). "
            "Uso exclusivo sobre tiendas propias o con autorización explícita."
        ),
        version="3.3.0",
    )

    class ScanRequest(BaseModel):
        url: str
        authorized: bool = False
        ai: bool = False
        model: Optional[str] = None
        fetch_scripts: bool = True
        use_history: bool = True
        use_local_db: bool = True
        use_vector_db: bool = True
        use_metrics: bool = True
        use_notify: bool = False
        notify_threshold: int = 0
        save_files: bool = False

    @app.get("/", response_class=HTMLResponse)
    def index():
        """Interfaz web: formulario para lanzar un escaneo y ver el
        informe HTML, sin usar la terminal."""
        return HTMLResponse(_INDEX_HTML)

    @app.post("/scan")
    def create_scan(payload: ScanRequest):
        """API JSON, pensada para integraciones/automatización."""
        if not payload.authorized:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Debes confirmar authorized=true: solo se pueden escanear tiendas "
                    "propias o con autorización explícita para pruebas de seguridad."
                ),
            )
        start = time.time()
        try:
            result, ai_report, comparison, saved_paths, vector_db_note = _run_full_scan(
                payload.url,
                use_ai=payload.ai,
                model=payload.model,
                fetch_scripts=payload.fetch_scripts,
                use_history=payload.use_history,
                use_local_db=payload.use_local_db,
                use_vector_db=payload.use_vector_db,
                use_notify=payload.use_notify,
                notify_threshold=payload.notify_threshold,
                save_files=payload.save_files,
            )
        except Exception as exc:  # noqa: BLE001
            metrics_prom.observe_scan({}, 0, status="failed")
            raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {exc}")

        duration = time.time() - start
        if payload.use_metrics:
            metrics_prom.observe_scan(result.to_dict(), duration, status="completed")

        return {
            "url": result.url,
            "is_shopify": result.is_shopify,
            "risk": result.risk,
            "findings": result.findings,
            "executive_ai_report": ai_report,
            "previous_scan_comparison": comparison.to_dict() if comparison else None,
            "saved_paths": saved_paths,
            "vector_db_note": vector_db_note,
            "duration_seconds": round(duration, 3),
        }

    @app.post("/scan/ui")
    def create_scan_ui(
        url: str = Form(...),
        authorized: bool = Form(False),
        ai: bool = Form(False),
        model: str = Form(""),
        fetch_scripts: bool = Form(False),
        use_history: bool = Form(False),
        use_local_db: bool = Form(False),
        use_vector_db: bool = Form(False),
        use_metrics: bool = Form(False),
        use_notify: bool = Form(False),
        notify_threshold: int = Form(0),
        save_files: bool = Form(False),
    ):
        """Recibe el formulario de la interfaz web (`GET /`), ejecuta el
        escaneo y devuelve {"ok": true, "result_id": "..."} — el navegador
        redirige entonces a GET /scan/result/<result_id>, una página
        independiente con el informe completo (mismo generador que la CLI:
        colores por severidad, categoría OWASP, solución sugerida, etc.) y
        una barra superior para volver al formulario."""
        if not authorized:
            return JSONResponse(
                {"ok": False, "error": "Debes confirmar que tienes autorización explícita para escanear este sitio."},
                status_code=400,
            )
        if not url:
            return JSONResponse({"ok": False, "error": "Falta la URL objetivo."}, status_code=400)

        start = time.time()
        try:
            result, ai_report, comparison, saved_paths, vector_db_note = _run_full_scan(
                url,
                use_ai=ai,
                model=model or None,
                fetch_scripts=fetch_scripts,
                use_history=use_history,
                use_local_db=use_local_db,
                use_vector_db=use_vector_db,
                use_notify=use_notify,
                notify_threshold=notify_threshold,
                save_files=save_files,
            )
        except Exception as exc:  # noqa: BLE001
            metrics_prom.observe_scan({}, 0, status="failed")
            error_page = _standalone_page("Error", f"Error durante el escaneo: {exc}", is_error=True)
            result_id = _store_result_html(error_page)
            return JSONResponse({"ok": True, "result_id": result_id})

        duration = time.time() - start
        if use_metrics:
            metrics_prom.observe_scan(result.to_dict(), duration, status="completed")

        if not result.is_shopify:
            not_shopify_page = _standalone_page(
                "Sin resultados", f"No se ha detectado tienda Shopify.<br><span style='color:#8b96a8;font-size:13px;'>{url}</span>"
            )
            result_id = _store_result_html(not_shopify_page)
            return JSONResponse({"ok": True, "result_id": result_id})

        from . import report_html

        html_report = report_html.generate_html_report(result.to_dict(), ai_report, comparison)
        notes_html = ""
        if saved_paths:
            notes_html += (
                f"<p style='font-family:sans-serif;font-size:12px;color:#6b7280;"
                f"padding:8px 20px;margin:0;'>Informe guardado también en: {saved_paths.get('html', '')}</p>"
            )
        if vector_db_note:
            notes_html += (
                f"<p style='font-family:sans-serif;font-size:12px;color:#92400e;"
                f"background:#fffbeb;padding:8px 20px;margin:0;'>⚠️ Búsqueda vectorial: {vector_db_note}</p>"
            )
        if notes_html:
            html_report = html_report.replace("</header>", "</header>" + notes_html, 1)
        # Inserta la barra de "volver a ShopiScan" justo tras <body>, encima
        # de la cabecera propia del informe.
        html_report = html_report.replace("<body>", "<body>" + _BACK_NAV_HTML, 1)

        result_id = _store_result_html(html_report)
        return JSONResponse({"ok": True, "result_id": result_id})

    @app.get("/scan/result/{result_id}", response_class=HTMLResponse)
    def scan_result(result_id: str):
        """Página independiente con el resultado de un escaneo (ver
        create_scan_ui). Los resultados son efímeros (en memoria, se
        pierden si el servidor se reinicia); usa 'Guardar informe en
        disco' en el formulario si necesitas conservarlos."""
        html = _get_result_html(result_id)
        if html is None:
            return HTMLResponse(
                _standalone_page(
                    "No encontrado",
                    "Este resultado ya no está disponible (puede haber expirado o el servidor se reinició). "
                    "Vuelve a lanzar el escaneo desde la página principal.",
                    is_error=True,
                ),
                status_code=404,
            )
        return HTMLResponse(html)

    @app.get("/health")
    def health():
        import os as _os

        build_time = None
        try:
            with open("/app/.build_time") as f:
                build_time = f.read().strip()
        except OSError:
            pass

        return {
            "status": "ok",
            "version": "3.3.0",
            "build_time_utc": build_time,
            "running_in_docker": _os.path.exists("/.dockerenv"),
        }

    @app.get("/metrics")
    def prometheus_metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


# Mensaje reutilizado en todos los puntos donde falta una dependencia del
# modo servidor (fastapi, uvicorn, prometheus-client...). Se muestra el
# comando EXACTO a copiar y pegar, con el flag -e (instalación editable,
# la habitual en desarrollo) y las comillas correctas.
#
# Error común: escribir 'pip install -e . server' (con espacio) en vez de
# 'pip install -e ".[server]"' (el extra va PEGADO al punto, dentro de
# corchetes). Con el espacio, pip busca un paquete llamado "server" en
# PyPI y falla con "Could not find a version that satisfies the
# requirement server" — no tiene nada que ver con ShopiScan.
_MISSING_SERVER_DEPS_MSG = (
    "{paquete} no está instalado. Ejecuta exactamente este comando "
    '(el extra "server" va pegado al punto, entre corchetes, sin espacios):\n'
    "      pip install -e \".[server]\"\n"
    "  Si usas zsh (p. ej. Kali/Parrot) las comillas dobles son obligatorias "
    "para que el shell no interprete '[server]' como un patrón de fichero."
)


def main() -> int:
    """Punto de entrada del comando `shopiscan-server`."""
    try:
        from . import _load_dotenv_if_available

        _load_dotenv_if_available()
    except Exception:  # noqa: BLE001 - nunca debe impedir arrancar el servidor
        pass

    try:
        import uvicorn
    except ImportError:
        utils.error(_MISSING_SERVER_DEPS_MSG.format(paquete="uvicorn"))
        return 1

    import os

    host = os.environ.get("SHOPISCAN_HOST", "0.0.0.0")
    port = int(os.environ.get("SHOPISCAN_PORT", "8000"))
    ollama_url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
    database_url = os.environ.get("DATABASE_URL")

    utils.print_banner()
    utils.info(f"Arrancando servidor ShopiScan en http://{host}:{port}")
    utils.info(f"Interfaz web disponible en http://localhost:{port}/")
    utils.info(f"Ollama configurado en: {ollama_url}")
    utils.info(f"PostgreSQL/pgvector: {'configurado (' + database_url.split('@')[-1] + ')' if database_url else 'no configurado (DATABASE_URL vacío)'}")
    if not os.path.exists("/.dockerenv"):
        utils.warning(
            "Este proceso NO corre dentro de un contenedor Docker. Si además tienes el "
            "stack de 'deploy/docker-compose.yml' levantado, son dos instancias "
            "independientes con su propio Ollama/Postgres: los escaneos hechos aquí NO "
            "aparecerán en el Grafana del stack de Docker (y viceversa) salvo que "
            "OLLAMA_URL/DATABASE_URL de este proceso apunten explícitamente a los puertos "
            "que Docker expone en localhost (11434 y 5432). Si quieres todo integrado, usa "
            "solo 'docker compose up -d' desde deploy/ y no lances este comando aparte."
        )
    uvicorn.run(create_app(), host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
