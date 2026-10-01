"""
scoring.py
-----------
Convierte la lista de findings (con severidad) en un único score de riesgo
0-100, fácil de comunicar a alguien no técnico (o al tribunal del proyecto).

El cálculo es intencionalmente simple y transparente (suma de pesos por
severidad, con techo en 100) en vez de una fórmula "caja negra": en un
proyecto académico es más defendible poder explicar exactamente cómo se
llegó al número.
"""

from __future__ import annotations

from . import owasp_mapping

SEVERITY_WEIGHTS = {
    "CRÍTICA": 30,
    "CRITICA": 30,
    "ALTA": 15,
    "MEDIA": 7,
    "BAJA": 3,
    "INFO": 0,
}

RISK_LABELS = [
    (80, "CRÍTICO"),
    (50, "ALTO"),
    (25, "MEDIO"),
    (0, "BAJO"),
]


def compute_risk_score(findings: list[dict]) -> dict:
    """Calcula el score de riesgo a partir de una lista de findings.

    Cada finding debe tener una clave 'severity' o 'level' con uno de los
    valores: Crítica, Alta, Media, Baja, Info.
    """
    raw_score = 0
    breakdown: dict[str, int] = {}

    for finding in findings:
        severity = (finding.get("severity") or finding.get("level") or "Info").upper()
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        raw_score += weight
        breakdown[severity] = breakdown.get(severity, 0) + 1

    score = min(raw_score, 100)

    label = "BAJO"
    for threshold, name in RISK_LABELS:
        if score >= threshold:
            label = name
            break

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        # Desglose por categoría OWASP Top 10 (2021): "¿qué TIPO de
        # problema predomina?", complementario al desglose por severidad
        # ("¿cuánto importa?"). Funciona igual con o sin --ai.
        "owasp_breakdown": owasp_mapping.owasp_breakdown(findings),
        "raw_score_before_cap": raw_score,
    }
