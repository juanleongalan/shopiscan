"""
remediation_mapping.py
------------------------
Sugerencias de remediación **basadas en reglas** para cada tipo de
hallazgo de ShopiScan — funciona exactamente igual con o sin `--ai`.

El Informe Ejecutivo de IA (Ollama) ya da remediación detallada y
contextual, pero solo si se usa `--ai` y Ollama está disponible. Este
módulo cubre el caso base: cada hallazgo, aunque no se use IA, lleva una
sugerencia de solución corta y accionable — visible en consola, HTML,
JSON y en las tablas de Grafana/PostgreSQL.
"""

from __future__ import annotations

import re
from typing import Optional

# Reglas ordenadas: (patrón sobre el título del hallazgo, remediación).
# Se evalúan en orden; la primera coincidencia gana.
_RULES: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"^Posible credencial filtrada", re.I),
        "Revoca y regenera la credencial inmediatamente desde el panel del proveedor "
        "correspondiente, y elimínala del HTML/JS público. Nunca incrustes claves reales "
        "en código que se sirve al navegador.",
    ),
    (
        re.compile(r"^Librería desactualizada", re.I),
        "Actualiza la librería a la versión segura indicada en el hallazgo (o a la última "
        "estable). Si la carga un tema/app de terceros, contacta al proveedor o reemplázala.",
    ),
    (
        re.compile(r"^Certificado TLS expirado", re.I),
        "Renueva el certificado TLS de inmediato. En dominios *.myshopify.com Shopify lo "
        "gestiona automáticamente; en dominios propios, revisa Admin > Dominios > "
        "certificado SSL, o la renovación automática en tu proveedor de DNS/CDN.",
    ),
    (
        re.compile(r"^Certificado TLS próximo a expirar", re.I),
        "Confirma que la renovación automática del certificado esté activa (Admin > "
        "Dominios en Shopify, o en tu proveedor de DNS/CDN) antes de que caduque.",
    ),
    (
        re.compile(r"^Certificado TLS inválido", re.I),
        "Revisa la cadena de certificados del dominio (certificado intermedio faltante, "
        "nombre no coincidente, etc.) con tu proveedor de DNS/CDN o el panel de Shopify.",
    ),
    (
        re.compile(r"^Versión de TLS obsoleta", re.I),
        "Deshabilita TLS 1.0/1.1 en el servidor o CDN delante del sitio y fuerza TLS 1.2 "
        "o superior. En Shopify nativo esto ya está forzado; revisa si hay un proxy/CDN "
        "propio delante del dominio.",
    ),
    (
        re.compile(r"^Archivo \.env accesible", re.I),
        "Bloquea el acceso a archivos .env a nivel de servidor/CDN inmediatamente y rota "
        "TODAS las credenciales que contuviera, asumiendo que ya están comprometidas.",
    ),
    (
        re.compile(r"^(Configuración de Git|Referencia de Git)", re.I),
        "Elimina el directorio .git del despliegue público y bloquea el acceso a rutas "
        "'/.git/*' a nivel de servidor/CDN. Revisa el historial de commits por si contiene "
        "credenciales que deban rotarse.",
    ),
    (
        re.compile(r"^Falta el header de seguridad Content-Security-Policy", re.I),
        "Define una política CSP restrictiva (p. ej. \"default-src 'self'\") vía cabecera "
        "HTTP en tu CDN/proxy, o con una etiqueta <meta> en theme.liquid como alternativa "
        "más limitada.",
    ),
    (
        re.compile(r"^Falta el header de seguridad Strict-Transport-Security", re.I),
        "Añade 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' "
        "vía tu CDN/proxy, y considera inscribir el dominio en la lista de precarga HSTS.",
    ),
    (
        re.compile(r"^Falta el header de seguridad X-Frame-Options", re.I),
        "Añade 'X-Frame-Options: SAMEORIGIN' (o una directiva frame-ancestors en tu CSP) "
        "vía tu CDN/proxy para mitigar clickjacking.",
    ),
    (
        re.compile(r"^Falta el header de seguridad X-Content-Type-Options", re.I),
        "Añade 'X-Content-Type-Options: nosniff' vía tu CDN/proxy.",
    ),
    (
        re.compile(r"^Falta el header de seguridad Referrer-Policy", re.I),
        "Añade la cabecera 'Referrer-Policy: strict-origin-when-cross-origin' vía tu "
        "CDN/proxy, o una etiqueta <meta name=\"referrer\"> en theme.liquid.",
    ),
    (
        re.compile(r"^Falta el header de seguridad Permissions-Policy", re.I),
        "Añade 'Permissions-Policy: camera=(), microphone=(), geolocation=()' (ajustado a "
        "lo que realmente necesites) vía tu CDN/proxy.",
    ),
    (
        re.compile(r"^Cookies enviadas sin el flag Secure", re.I),
        "Fuerza HTTPS/HSTS en todo el dominio y, si generas cookies propias con "
        "JavaScript, añade siempre los atributos 'Secure; SameSite=Lax'.",
    ),
    (
        re.compile(r"^Endpoints públicos de la Storefront API", re.I),
        "Es el comportamiento nativo de Shopify (no un fallo de configuración). Si te "
        "preocupa el scraping de catálogo/precios por competidores, añade una regla "
        "anti-bot en tu CDN (p. ej. Cloudflare WAF) para /products.json y /collections.json.",
    ),
    (
        re.compile(r"^Niveles de stock.*expuestos", re.I),
        "Revisa en tu tema si el stock exacto necesita mostrarse públicamente; considera "
        "mostrar solo 'en stock / agotado' en vez del número exacto de unidades.",
    ),
    (
        re.compile(r"^Posible residuo de app desinstalada", re.I),
        "Abre el editor de código del tema activo (Admin > Tienda online > Temas > "
        "Editar código) y elimina cualquier snippet, sección o contenedor huérfano que "
        "referencie la app desinstalada.",
    ),
    (
        re.compile(r"con historial local de riesgo elevado", re.I),
        "Revisa manualmente la configuración de seguridad de otras tiendas que usan este "
        "mismo tema para identificar si el patrón es del tema o de cada configuración.",
    ),
    (
        re.compile(r"^Meta tag 'generator'", re.I),
        "Impacto bajo; si te interesa ocultar la plataforma subyacente, elimina o "
        "modifica la etiqueta <meta name=\"generator\"> en theme.liquid.",
    ),
    (
        re.compile(r"^Tienda protegida con contraseña", re.I),
        "No requiere acción de seguridad; ten en cuenta que el resto del escaneo puede "
        "ser incompleto mientras la tienda esté en modo privado/'Coming soon'.",
    ),
]


def get_remediation(title: str) -> Optional[str]:
    """Devuelve una sugerencia de remediación corta para un título de
    hallazgo, o None si no hay una regla específica (p. ej. hallazgos
    puramente informativos como "Script recurrente sin clasificar")."""
    for pattern, remediation in _RULES:
        if pattern.search(title or ""):
            return remediation
    return None


def enrich_findings_with_remediation(findings: list[dict]) -> list[dict]:
    """Añade la clave 'remediation' a cada finding (in-place) según su
    título. Devuelve la misma lista por conveniencia de encadenado."""
    for finding in findings:
        remediation = get_remediation(finding.get("title", ""))
        if remediation:
            finding["remediation"] = remediation
    return findings
