"""
owasp_mapping.py
------------------
Clasifica cada hallazgo de ShopiScan según el **OWASP Top 10 (2021)**.

La severidad (Crítica/Alta/Media/Baja) responde a "¿cuánto importa esto?".
La categoría OWASP responde a "¿qué TIPO de problema es esto?" — dos ejes
distintos y complementarios. Con solo la severidad, un informe con muchos
hallazgos "Baja" parece plano y poco informativo; agrupando por categoría
OWASP se ve de un vistazo, por ejemplo, que la mayoría de los hallazgos de
una tienda caen en "Seguridad mal configurada" (headers, shadow apps) y no
hay ningún problema de "Componentes desactualizados" — información mucho
más accionable para priorizar.

Esta clasificación es 100% basada en reglas (no depende de la IA): funciona
igual de bien con o sin `--ai`, coherente con que ShopiScan sigue siendo
plenamente funcional sin conexión a Ollama.

Referencia: https://owasp.org/Top10/
"""

from __future__ import annotations

import re
from typing import Optional

OWASP_TOP10_2021: dict[str, str] = {
    "A01": "A01:2021 - Pérdida de Control de Acceso",
    "A02": "A02:2021 - Fallos Criptográficos",
    "A03": "A03:2021 - Inyección",
    "A04": "A04:2021 - Diseño Inseguro",
    "A05": "A05:2021 - Configuración de Seguridad Incorrecta",
    "A06": "A06:2021 - Componentes Vulnerables y Desactualizados",
    "A07": "A07:2021 - Fallos de Identificación y Autenticación",
    "A08": "A08:2021 - Fallos de Integridad de Software y Datos",
    "A09": "A09:2021 - Fallos de Registro y Monitorización de Seguridad",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

# Reglas ordenadas: (patrón sobre el título del hallazgo, código OWASP o
# None si es puramente informativo y no representa un tipo de vulnerabilidad
# clasificable). Se evalúan en orden; la primera coincidencia gana.
_RULES: list[tuple[re.Pattern, Optional[str]]] = [
    (re.compile(r"^Posible credencial filtrada", re.I), "A07"),
    (re.compile(r"^Librería desactualizada", re.I), "A06"),
    (re.compile(r"^Certificado TLS", re.I), "A02"),
    (re.compile(r"^Versión de TLS obsoleta", re.I), "A02"),
    (re.compile(r"^Cookies enviadas sin el flag Secure", re.I), "A02"),
    (re.compile(r"^Archivo \.env accesible", re.I), "A01"),
    (re.compile(r"^Configuración de Git", re.I), "A01"),
    (re.compile(r"^Referencia de Git", re.I), "A01"),
    (re.compile(r"^Endpoints públicos de la Storefront API", re.I), "A01"),
    (re.compile(r"^Niveles de stock.*expuestos", re.I), "A01"),
    (re.compile(r"^Falta el header de seguridad", re.I), "A05"),
    (re.compile(r"^Posible residuo de app desinstalada", re.I), "A05"),
    (re.compile(r"^Meta tag 'generator'", re.I), "A05"),
    (re.compile(r"con historial local de riesgo elevado", re.I), "A05"),
    (re.compile(r"^Tienda protegida con contraseña", re.I), None),
    (re.compile(r"^No se detectaron apps de terceros", re.I), None),
    (re.compile(r"^Script recurrente sin clasificar", re.I), None),
]


def classify(title: str) -> Optional[str]:
    """Devuelve el nombre completo de la categoría OWASP para un título de
    hallazgo, o None si es puramente informativo (no es una vulnerabilidad
    clasificable, p. ej. "tienda protegida con contraseña")."""
    for pattern, code in _RULES:
        if pattern.search(title or ""):
            return OWASP_TOP10_2021[code] if code else None
    return None


def enrich_findings_with_owasp(findings: list[dict]) -> list[dict]:
    """Añade la clave 'owasp_category' a cada finding (in-place) según su
    título. Devuelve la misma lista por conveniencia de encadenado."""
    for finding in findings:
        category = classify(finding.get("title", ""))
        if category:
            finding["owasp_category"] = category
    return findings


def owasp_breakdown(findings: list[dict]) -> dict[str, int]:
    """Cuenta hallazgos por categoría OWASP (clave = nombre completo de la
    categoría). Los findings sin categoría (informativos) no se cuentan."""
    counts: dict[str, int] = {}
    for finding in findings:
        category = finding.get("owasp_category")
        if category:
            counts[category] = counts.get(category, 0) + 1
    return counts
