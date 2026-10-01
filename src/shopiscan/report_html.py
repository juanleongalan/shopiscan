"""
report_html.py
----------------
Genera un informe HTML autocontenido (sin dependencias externas: todo el
CSS va embebido) a partir de un ScanResult y, opcionalmente, el informe de
IA. Pensado para abrir en el navegador y, si se necesita PDF, usar
"Imprimir > Guardar como PDF" del propio navegador — así evitamos añadir
una dependencia pesada (wkhtmltopdf/weasyprint) que complicaría la
instalación para "cualquier persona".

Tema oscuro, coherente con la paleta de la interfaz web (server.py):
fondo casi negro, tarjetas en gris azulado oscuro, acento verde esmeralda.
"""

from __future__ import annotations

import html as html_lib
from datetime import datetime

SEVERITY_COLORS = {
    "CRÍTICA": "#f87171",  # rojo
    "CRITICA": "#f87171",
    "ALTA": "#fb923c",     # naranja
    "MEDIA": "#facc15",    # amarillo
    "BAJA": "#34d399",     # verde
    "INFO": "#38bdf8",     # azul
}

RISK_COLORS = {
    "CRÍTICO": "#f87171",  # rojo
    "ALTO": "#fb923c",     # naranja
    "MEDIO": "#facc15",    # amarillo
    "BAJO": "#34d399",     # verde
}


def _esc(value) -> str:
    return html_lib.escape(str(value)) if value is not None else ""


def _findings_html(findings: list[dict]) -> str:
    if not findings:
        return "<p class='muted'>No se generaron alertas.</p>"

    order = {"CRÍTICA": 0, "CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.get("level", "INFO").upper(), 5))

    cards = []
    for f in sorted_findings:
        level = f.get("level", "Info").upper()
        color = SEVERITY_COLORS.get(level, "#8b96a8")
        owasp = f.get("owasp_category")
        owasp_html = f"<span class='owasp-tag'>{_esc(owasp)}</span>" if owasp else ""
        remediation = f.get("remediation")
        remediation_html = (
            f"<div class='remediation-box'><strong>💡 Solución sugerida:</strong> {_esc(remediation)}</div>"
            if remediation
            else ""
        )
        cards.append(
            f"""
            <div class="finding-card" style="border-left-color:{color}">
                <span class="badge" style="background:{color}">{_esc(level)}</span>
                <div class="finding-title">{_esc(f.get('title', ''))}</div>
                {owasp_html}
                <div class="finding-detail">{_esc(f.get('detail', ''))}</div>
                {remediation_html}
            </div>
            """
        )
    return f'<div class="findings-grid">{"".join(cards)}</div>'


def _owasp_summary_html(findings: list[dict]) -> str:
    """Resumen agregado: cuántos hallazgos caen en cada categoría OWASP.
    Da contexto de "qué TIPO de problema predomina" de un vistazo, útil
    sobre todo cuando la mayoría de hallazgos son de severidad Baja."""
    from . import owasp_mapping

    counts = owasp_mapping.owasp_breakdown(findings)
    if not counts:
        return ""

    items = "".join(
        f"<li><span class='owasp-count'>{n}</span> {_esc(cat)}</li>"
        for cat, n in sorted(counts.items(), key=lambda kv: -kv[1])
    )
    return f"""
    <section>
        <h2>🗂️ Distribución por categoría OWASP Top 10 (2021)</h2>
        <p class="muted">Clasificación basada en reglas, independiente de la IA — funciona igual con o sin <code>--ai</code>.</p>
        <ul class="owasp-list">{items}</ul>
    </section>
    """


def _list_or_none(items: list[str]) -> str:
    if not items:
        return "<span class='muted'>Ninguno detectado</span>"
    return ", ".join(_esc(i) for i in items)


def generate_html_report(result_dict: dict, ai_report: dict | None = None, comparison=None) -> str:
    """Construye el HTML completo del informe a partir de result.to_dict().

    `comparison` es opcional: un `history.ComparisonResult` (o None si es
    el primer escaneo de esta tienda o se desactivó con --no-history).
    """
    risk = result_dict.get("risk", {}) or {}
    score = risk.get("score", 0)
    label = risk.get("label", "BAJO")
    risk_color = RISK_COLORS.get(label, "#8b96a8")

    theme = result_dict.get("theme", {})
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    history_section = ""
    if comparison:
        c = comparison.to_dict() if hasattr(comparison, "to_dict") else comparison
        delta = c.get("score_delta", 0)
        if delta > 0:
            trend_label, trend_color = f"▲ +{delta} (empeoró)", "#f87171"
        elif delta < 0:
            trend_label, trend_color = f"▼ {delta} (mejoró)", "#34d399"
        else:
            trend_label, trend_color = "= sin cambios", "#facc15"

        new_items = "".join(f"<li>{_esc(t)}</li>" for t in c.get("new_findings", []))
        resolved_items = "".join(f"<li>{_esc(t)}</li>" for t in c.get("resolved_findings", []))
        history_section = f"""
        <section>
            <h2>📈 Comparación con el escaneo anterior</h2>
            <p><strong>Escaneo anterior:</strong> {_esc(c.get('previous_date', 'desconocida'))}</p>
            <p><strong>Score:</strong> {c.get('previous_score', 0)}/100 ({_esc(c.get('previous_label', ''))})
               → {c.get('current_score', 0)}/100 ({_esc(c.get('current_label', ''))})
               <span style="color:{trend_color}; font-weight:700;">{trend_label}</span></p>
            {f"<p><strong>Hallazgos nuevos:</strong></p><ul>{new_items}</ul>" if new_items else ""}
            {f"<p><strong>Hallazgos resueltos:</strong></p><ul>{resolved_items}</ul>" if resolved_items else ""}
        </section>
        """

    ai_section = ""
    if ai_report:
        ai_findings_html = []
        for f in ai_report.get("findings", []):
            sev = (f.get("severity") or "Info").upper()
            color = SEVERITY_COLORS.get(sev, "#8b96a8")
            steps = f.get("remediation_steps") or []
            steps_html = (
                "<ol class='remediation-steps'>" + "".join(f"<li>{_esc(s)}</li>" for s in steps) + "</ol>"
                if steps else ""
            )
            snippet = f.get("code_snippet")
            snippet_html = f"<pre class='code-snippet'>{_esc(snippet)}</pre>" if snippet else ""
            ai_findings_html.append(
                f"""
                <div class="finding-card" style="border-left-color:{color}">
                    <span class="badge" style="background:{color}">{_esc(sev)}</span>
                    <div class="finding-title">{_esc(f.get('title', ''))}</div>
                    <div class="finding-detail"><strong>Impacto de negocio:</strong> {_esc(f.get('business_impact', ''))}</div>
                    <div class="finding-detail"><strong>Explicación técnica:</strong> {_esc(f.get('technical_explanation', ''))}</div>
                    <div class="finding-detail"><strong>Remediación:</strong></div>
                    {steps_html}
                    {snippet_html}
                </div>
                """
            )
        quick_wins = ai_report.get("quick_wins", [])
        quick_wins_html = ""
        if quick_wins:
            items = "".join(f"<li>{_esc(step)}</li>" for step in quick_wins)
            quick_wins_html = f"<h3>Quick wins (prioridad esta semana)</h3><ol>{items}</ol>"
        ai_section = f"""
        <section>
            <h2>🧠 Informe Ejecutivo de Riesgo (IA local - Ollama)</h2>
            <p><strong>Riesgo según IA:</strong> {_esc(ai_report.get('overall_risk_level', 'N/D'))}</p>
            <p>{_esc(ai_report.get('executive_summary', ''))}</p>
            <div class="findings-grid">{''.join(ai_findings_html)}</div>
            {quick_wins_html}
        </section>
        """

    lower_grid_section = ""
    if history_section or True:  # la distribución OWASP casi siempre está presente
        owasp_html = _owasp_summary_html(result_dict.get('findings', []))
        if owasp_html and history_section:
            lower_grid_section = f'<div class="two-col">{owasp_html}{history_section}</div>'
        else:
            lower_grid_section = owasp_html + history_section

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe ShopiScan - {_esc(result_dict.get('url'))}</title>
<style>
  :root {{
    color-scheme: dark;
    --bg: #05070d;
    --panel: #10151f;
    --panel-2: #141a26;
    --border: #232a38;
    --border-light: #2e3646;
    --muted: #8b96a8;
    --text: #e7ecf3;
    --accent: #34d399;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 40px 28px 60px 28px;
    line-height: 1.55;
    background-image:
      radial-gradient(circle at 10% -10%, rgba(52,211,153,0.08) 0%, transparent 40%),
      radial-gradient(circle at 90% 0%, rgba(56,189,248,0.06) 0%, transparent 38%);
  }}
  .container {{ max-width: 1240px; margin: 0 auto; }}
  header {{
    background: linear-gradient(135deg, #10151f, #0a0e1a);
    border: 1px solid var(--border);
    padding: 28px 32px; border-radius: 16px; margin-bottom: 22px;
  }}
  header h1 {{ margin: 0 0 4px 0; font-size: 24px; }}
  header .url {{ color: var(--muted); font-size: 13.5px; word-break: break-all; }}

  .top-grid {{ display: grid; grid-template-columns: minmax(220px, 320px) 1fr 1fr; gap: 18px; margin-bottom: 22px; }}
  @media (max-width: 900px) {{ .top-grid {{ grid-template-columns: 1fr; }} }}

  .score-card {{
    display: flex; align-items: center; gap: 18px; background: var(--panel);
    border: 1px solid var(--border); border-radius: 16px; padding: 22px;
  }}
  .score-circle {{
    width: 78px; height: 78px; border-radius: 50%; display: flex;
    align-items: center; justify-content: center; color: #04120c;
    font-size: 24px; font-weight: 800; flex-shrink: 0;
    background: {risk_color};
  }}
  .score-label {{ font-size: 12.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .score-value {{ font-size: 19px; font-weight: 800; color: {risk_color}; }}

  section {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
    padding: 22px 24px; margin-bottom: 20px;
  }}
  section h2 {{ margin-top: 0; font-size: 16.5px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 13.5px; }}
  .grid div span.label {{ color: var(--muted); display: block; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.04em; }}

  .findings-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 14px; }}
  .finding-card {{
    background: var(--panel-2); border: 1px solid var(--border); border-left: 4px solid #8b96a8;
    border-radius: 12px; padding: 16px 18px;
  }}
  .badge {{
    display: inline-block; color: #04120c; font-size: 10.5px; font-weight: 800; padding: 3px 10px;
    border-radius: 999px; margin-bottom: 8px;
  }}
  .finding-title {{ font-weight: 700; margin-bottom: 6px; font-size: 14.5px; }}
  .finding-detail {{ font-size: 13px; color: var(--muted); margin-top: 4px; }}
  .owasp-tag {{
    display: inline-block; margin: 0 0 8px 0; font-size: 10.5px; font-weight: 700;
    color: #a5b4fc; background: rgba(99,102,241,0.14); border: 1px solid rgba(129,140,248,0.35);
    padding: 2px 9px; border-radius: 999px;
  }}
  .owasp-list {{ list-style: none; padding: 0; margin: 12px 0 0 0; font-size: 13.5px; }}
  .owasp-list li {{ padding: 9px 0; border-top: 1px solid var(--border); }}
  .owasp-list li:first-child {{ border-top: none; }}
  .owasp-count {{
    display: inline-block; min-width: 22px; text-align: center; font-weight: 800;
    color: #04120c; background: var(--accent); border-radius: 6px; padding: 1px 7px; margin-right: 8px;
  }}
  .remediation-box {{
    margin-top: 10px; padding: 10px 13px; background: rgba(52,211,153,0.08); border-left: 3px solid var(--accent);
    border-radius: 8px; font-size: 12.5px; color: #a7f3d0;
  }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .code-snippet {{
    background: #05070d; color: #cbd5e1; padding: 12px 14px; border-radius: 8px;
    border: 1px solid var(--border);
    font-family: "SF Mono", Consolas, Menlo, monospace; font-size: 12px;
    overflow-x: auto; margin-top: 10px; white-space: pre-wrap; word-break: break-word;
  }}
  .remediation-steps {{ margin: 6px 0 0 18px; padding: 0; font-size: 13px; color: var(--muted); }}
  .remediation-steps li {{ margin-bottom: 3px; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .two-col section {{ margin-bottom: 0; }}
  @media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
  footer {{ text-align: center; font-size: 12px; color: var(--muted); margin-top: 30px; }}
  a {{ color: var(--accent); }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ Informe ShopiScan</h1>
    <div class="url">{_esc(result_dict.get('url'))} · generado el {generated_at}</div>
  </header>

  <div class="top-grid">
    <div class="score-card">
      <div class="score-circle">{score}</div>
      <div>
        <div class="score-label">Nivel de riesgo</div>
        <div class="score-value">{_esc(label)}</div>
      </div>
    </div>

    <section style="margin-bottom:0;">
      <h2>📦 Tema y plataforma</h2>
      <div class="grid">
        <div><span class="label">Nombre del tema</span>{_esc(theme.get('name') or 'Desconocido')}</div>
        <div><span class="label">Rol</span>{_esc(theme.get('role') or '-')}</div>
        <div><span class="label">ID de tema</span>{_esc(theme.get('id') or '-')}</div>
        <div><span class="label">Versión</span>{_esc(theme.get('version') or 'Desconocido')}</div>
      </div>
    </section>

    <section style="margin-bottom:0;">
      <h2>🧩 Servicios y apps</h2>
      <p><strong>Identificados:</strong> {_list_or_none(result_dict.get('known_services', []))}</p>
      <p><strong>Sin identificar:</strong> {_list_or_none(result_dict.get('apps_generic', []))}</p>
      <p><strong>Shadow apps:</strong> {_list_or_none([s.get('app', '') for s in result_dict.get('shadow_apps', [])])}</p>
    </section>
  </div>

  <section>
    <h2>🚨 Alertas del escaneo</h2>
    {_findings_html(result_dict.get('findings', []))}
  </section>

  {lower_grid_section}

  {ai_section}

  <footer>
    Generado por ShopiScan · Herramienta educativa de código abierto · Uso autorizado únicamente
  </footer>
</div>
</body>
</html>
"""
