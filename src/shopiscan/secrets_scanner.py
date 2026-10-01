"""
secrets_scanner.py
--------------------
Detección de credenciales y tokens filtrados accidentalmente en el HTML
público o en los archivos JS que carga la tienda.

Esto es, con diferencia, el hallazgo de MAYOR impacto que una herramienta
como esta puede producir: un Admin API token de Shopify filtrado en el
frontend equivale a acceso total a la tienda (productos, pedidos, clientes).

Todo lo que hacemos es leer contenido público (HTML + scripts enlazados
desde el propio sitio) y aplicar expresiones regulares. No se realiza
ninguna petición a servicios externos con las credenciales encontradas:
solo se informa de que existen.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin

import requests

from . import utils

REQUEST_TIMEOUT = 8
MAX_SCRIPTS_TO_FETCH = 6  # límite para no tardar demasiado ni ser agresivos

# (nombre, regex, severidad, explicación)
SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "Shopify Admin API access token",
        r"shpat_[a-fA-F0-9]{32}",
        "Crítica",
        "Un token 'shpat_' filtrado da acceso administrativo completo a la tienda "
        "(productos, pedidos, clientes, configuración) según los permisos que tenga.",
    ),
    (
        "Shopify Admin API secret",
        r"shpss_[a-fA-F0-9]{32}",
        "Crítica",
        "Secreto de app privada de Shopify filtrado: permite generar tokens de acceso válidos.",
    ),
    (
        "Shopify Custom App token",
        r"shpca_[a-fA-F0-9]{32}",
        "Crítica",
        "Token de app personalizada de Shopify filtrado en el frontend.",
    ),
    (
        "AWS Access Key ID",
        r"AKIA[0-9A-Z]{16}",
        "Crítica",
        "Clave de acceso de AWS filtrada. Combinada con el secret key permite control de recursos en la nube.",
    ),
    (
        "Stripe live secret key",
        r"sk_live_[0-9a-zA-Z]{20,}",
        "Crítica",
        "Clave secreta de producción de Stripe filtrada: permite operar sobre pagos reales.",
    ),
    (
        "Google API key",
        r"AIza[0-9A-Za-z\-_]{35}",
        "Alta",
        "Clave de API de Google expuesta (Maps, Places, etc.). Aunque suele poder restringirse por dominio, "
        "es una credencial real filtrada con riesgo de abuso/consumo de cuota o uso indebido si no está restringida.",
    ),
    (
        "Generic Private Key block",
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Crítica",
        "Bloque de clave privada criptográfica expuesto en el HTML/JS público.",
    ),
    (
        "Slack token",
        r"xox[baprs]-[0-9A-Za-z-]{10,48}",
        "Alta",
        "Token de Slack filtrado: puede permitir leer/enviar mensajes en el workspace asociado.",
    ),
    (
        "Mailchimp API key",
        r"[0-9a-f]{32}-us[0-9]{1,2}",
        "Alta",
        "Clave de API de Mailchimp filtrada: acceso real a listas de suscriptores/campañas de email marketing.",
    ),
]


def _mask(secret: str) -> str:
    """Enmascara el secreto detectado para no imprimir la credencial completa en el informe."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _scan_text_for_secrets(text: str, source: str) -> list[dict]:
    findings = []
    for name, pattern, severity, explanation in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append(
                {
                    "type": name,
                    "severity": severity,
                    "masked_value": _mask(match.group(0)),
                    "source": source,
                    "explanation": explanation,
                }
            )
    return findings


def _discover_script_urls(html: str, base_url: str, limit: int) -> list[str]:
    """Extrae URLs de <script src> del HTML, priorizando scripts del propio dominio/CDN de Shopify."""
    urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    resolved = []
    for src in urls:
        full_url = urljoin(base_url, src)
        resolved.append(full_url)
    return resolved[:limit]


def scan_for_leaked_secrets(html: str, base_url: str, fetch_scripts: bool = True) -> list[dict]:
    """Escanea el HTML principal y, opcionalmente, un número limitado de scripts
    enlazados, en busca de patrones de credenciales filtradas.
    """
    utils.info("Buscando credenciales/tokens filtrados (HTML)...")
    findings = _scan_text_for_secrets(html, source="HTML principal")

    if fetch_scripts:
        script_urls = _discover_script_urls(html, base_url, MAX_SCRIPTS_TO_FETCH)
        if script_urls:
            utils.info(f"Analizando {len(script_urls)} scripts enlazados en busca de secretos...")
        for script_url in script_urls:
            try:
                resp = requests.get(script_url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200:
                    findings.extend(_scan_text_for_secrets(resp.text, source=script_url))
            except requests.exceptions.RequestException:
                continue

    if findings:
        utils.error(f"¡{len(findings)} posible(s) credencial(es) filtrada(s) detectada(s)!")
    else:
        utils.success("No se detectaron patrones de credenciales filtradas.")

    return findings
